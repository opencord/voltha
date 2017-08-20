# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Adtran generic VOLTHA device handler
"""
import argparse
import datetime
import pprint
import shlex
import time

import arrow
import structlog
import json
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.adapters.adtran_olt.net.adtran_netconf import AdtranNetconfClient
from voltha.adapters.adtran_olt.net.adtran_rest import AdtranRestClient
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory
from voltha.protos.device_pb2 import Image
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS
from voltha.registry import registry
from adapter_alarms import AdapterAlarms
from common.frameio.frameio import BpfProgramFilter, hexify
from adapter_pm_metrics import AdapterPmMetrics
from common.utils.asleep import asleep
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import Raw

_ = third_party

_PACKET_IN_VLAN = 4000
_MULTICAST_VLAN = 4092
_MANAGEMENT_VLAN = 4093
_is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(_PACKET_IN_VLAN))

_DEFAULT_RESTCONF_USERNAME = ""
_DEFAULT_RESTCONF_PASSWORD = ""
_DEFAULT_RESTCONF_PORT = 8081

_DEFAULT_NETCONF_USERNAME = ""
_DEFAULT_NETCONF_PASSWORD = ""
_DEFAULT_NETCONF_PORT = 830


class AdtranDeviceHandler(object):
    """
    A device that supports the ADTRAN RESTCONF protocol for communications
    with a VOLTHA/VANILLA managed device.

    Port numbering guidelines for Adtran OLT devices.  Derived classes may augment
    the numbering scheme below as needed.

      - Reserve port 0 for the CPU capture port. All ports to/from this port should
        be related to messages destined to/from the OpenFlow controller.

      - Begin numbering northbound ports (network facing) at port 1 contiguously.
        Consider the northbound ports to typically be the highest speed uplinks.
        If these ports are removable or provided by one or more slots in a chassis
        subsystem, still reserve the appropriate amount of port numbers whether they
        are populated or not.

      - Number southbound ports (customer facing) ports next starting at the next
        available port number. If chassis based, follow the same rules as northbound
        ports and reserve enough port numbers.

      - Number any out-of-band management ports (if any) last.  It will be up to the
        Device Adapter developer whether to expose these to openflow or not. If you do
        not expose them, but do have the ports, still reserve the appropriate number of
        port numbers just in case.
    """
    # HTTP shortcuts
    HELLO_URI = '/restconf/adtran-hello:hello'

    # RPC XML shortcuts
    RESTART_RPC = '<system-restart xmlns="urn:ietf:params:xml:ns:yang:ietf-system"/>'

    def __init__(self, adapter, device_id, timeout=20):
        from net.adtran_zmq import DEFAULT_ZEROMQ_OMCI_TCP_PORT

        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.startup = None
        self.channel = None  # Proxy messaging channel with 'send' method
        self.io_port = None
        self.logical_device_id = None
        self.interface = registry('main').get_args().interface
        self.pm_metrics = None
        self.alarms = None

        # Northbound and Southbound ports
        self.northbound_ports = {}  # port number -> Port
        self.southbound_ports = {}  # port number -> Port  (For PON, use pon-id as key)
        # self.management_ports = {}  # port number -> Port   TODO: Not currently supported

        self.num_northbound_ports = None
        self.num_southbound_ports = None
        # self.num_management_ports = None

        self.ip_address = None
        self.timeout = timeout
        self.restart_failure_timeout = 5 * 60   # 5 Minute timeout

        # REST Client
        self.rest_port = _DEFAULT_RESTCONF_PORT
        self.rest_username = _DEFAULT_RESTCONF_USERNAME
        self.rest_password = _DEFAULT_RESTCONF_PASSWORD
        self._rest_client = None

        # NETCONF Client
        self.netconf_port = _DEFAULT_NETCONF_PORT
        self.netconf_username = _DEFAULT_NETCONF_USERNAME
        self.netconf_password = _DEFAULT_NETCONF_PASSWORD
        self._netconf_client = None

        # If Auto-activate is true, all PON ports (up to a limit below) will be auto-enabled
        # and any ONU's discovered will be auto-activated.
        #
        # If it is set to False, then the xPON API/CLI should be used to enable any PON
        # ports. Before enabling a PON, set it's polling interval. If the polling interval
        # is 0, then manual ONU discovery is in effect. If >0, then every 'polling' seconds
        # autodiscover is requested. Any discovered ONUs will need to have their serial-numbers
        # registered (via xPON API/CLI) before they are activated.

        self._autoactivate = False

        # TODO Remove items below after one PON fully supported and working as expected
        self.max_nni_ports = 1
        self.max_pon_ports = 1

        # OMCI ZMQ Channel
        self.zmq_port = DEFAULT_ZEROMQ_OMCI_TCP_PORT

        # Heartbeat support
        self.heartbeat_count = 0
        self.heartbeat_miss = 0
        self.heartbeat_interval = 10  # TODO: Decrease before release or any scale testing
        self.heartbeat_failed_limit = 3
        self.heartbeat_timeout = 5
        self.heartbeat = None
        self.heartbeat_last_reason = ''

        # Virtualized OLT Support
        self.is_virtual_olt = False

        # Installed flows
        self._evcs = {}  # Flow ID/name -> FlowEntry

    def __del__(self):
        # Kill any startup or heartbeat defers

        d, self.startup = self.startup, None
        h, self.heartbeat = self.heartbeat, None
        ldi, self.logical_device_id = self.logical_device_id, None

        if d is not None and not d.called:
            d.cancel()

        if h is not None and not h.called:
            h.cancel()

        self._deactivate_io_port()

        # Remove the logical device

        if ldi is not None:
            logical_device = self.adapter_agent.get_logical_device(ldi)
            self.adapter_agent.delete_logical_device(logical_device)

        self.northbound_ports.clear()
        self.southbound_ports.clear()

    def __str__(self):
        return "AdtranDeviceHandler: {}".format(self.ip_address)

    @property
    def netconf_client(self):
        return self._netconf_client

    @property
    def rest_client(self):
        return self._rest_client

    @property
    def evcs(self):
        return list(self._evcs.values())

    def add_evc(self, evc):
        if self._evcs is not None:
            self._evcs[evc.name] = evc

    def remove_evc(self, evc):
        if self._evcs is not None and evc.name in self._evcs:
            del self._evcs[evc.name]

    def parse_provisioning_options(self, device):
        from net.adtran_zmq import DEFAULT_ZEROMQ_OMCI_TCP_PORT

        if not device.ipv4_address:
            self.activate_failed(device, 'No ip_address field provided')

        self.ip_address = device.ipv4_address

        #############################################################
        # Now optional parameters

        def check_tcp_port(value):
            ivalue = int(value)
            if ivalue <= 0 or ivalue > 65535:
                raise argparse.ArgumentTypeError("%s is a not a valid port number" % value)
            return ivalue

        parser = argparse.ArgumentParser(description='Adtran Device Adapter')
        parser.add_argument('--nc_username', '-u', action='store', default=_DEFAULT_NETCONF_USERNAME,
                            help='NETCONF username')
        parser.add_argument('--nc_password', '-p', action='store', default=_DEFAULT_NETCONF_PASSWORD,
                            help='NETCONF Password')
        parser.add_argument('--nc_port', '-t', action='store', default=_DEFAULT_NETCONF_PORT, type=check_tcp_port,
                            help='NETCONF TCP Port')
        parser.add_argument('--rc_username', '-U', action='store', default=_DEFAULT_RESTCONF_USERNAME,
                            help='REST username')
        parser.add_argument('--rc_password', '-P', action='store', default=_DEFAULT_RESTCONF_PASSWORD,
                            help='REST Password')
        parser.add_argument('--rc_port', '-T', action='store', default=_DEFAULT_RESTCONF_PORT, type=check_tcp_port,
                            help='RESTCONF TCP Port')
        parser.add_argument('--zmq_port', '-z', action='store', default=DEFAULT_ZEROMQ_OMCI_TCP_PORT,
                            type=check_tcp_port, help='ZeroMQ Port')
        parser.add_argument('--autoactivate', '-a', action='store_true', default=False,
                            help='Autoactivate / Demo mode')

        try:
            args = parser.parse_args(shlex.split(device.extra_args))

            self.netconf_username = args.nc_username
            self.netconf_password = args.nc_password
            self.netconf_port = args.nc_port

            self.rest_username = args.rc_username
            self.rest_password = args.rc_password
            self.rest_port = args.rc_port

            self.zmq_port = args.zmq_port

            self._autoactivate = args.autoactivate

        except argparse.ArgumentError as e:
            self.activate_failed(device,
                                 'Invalid arguments: {}'.format(e.message),
                                 reachable=False)
        except Exception as e:
            self.log.exception('option_parsing_error: {}'.format(e.message))

    @property
    def autoactivate(self):
        """
        Flag indicating if auto-discover/enable of PON ports is enabled as
        well as ONU auto activation. useful for demos

        If autoactivate is enabled, the default startup state (first time) for a PON port is disabled
        If autoactivate is disabled, the efault startup state for a PON port is enabled
        """
        return self._autoactivate

    @inlineCallbacks
    def activate(self, device, reconciling=False):
        """
        Activate the OLT device

        :param device: A voltha.Device object, with possible device-type
                       specific extensions.
        :param reconciling: If True, this adapter is taking over for a previous adapter
                            for an existing OLT
        """
        self.log.info('AdtranDeviceHandler.activating', reconciling=reconciling)

        if self.logical_device_id is None:
            # Parse our command line options for this device
            self.parse_provisioning_options(device)

            ############################################################################
            # Start initial discovery of RESTCONF support (if any)

            try:
                self.startup = self.make_restconf_connection()
                results = yield self.startup
                self.log.debug('HELLO_Contents: {}'.format(pprint.PrettyPrinter().pformat(results)))

                # See if this is a virtualized OLT. If so, no NETCONF support available

                self.is_virtual_olt = 'module-info' in results and\
                                      any(mod.get('module-name', None) == 'adtran-ont-mock'
                                          for mod in results['module-info'])

            except Exception as e:
                self.log.exception('Initial_RESTCONF_hello_failed', e=e)
                self.activate_failed(device, e.message, reachable=False)

            ############################################################################
            # Start initial discovery of NETCONF support (if any)

            try:
                self.startup = self.make_netconf_connection()
                yield self.startup

            except Exception as e:
                self.log.exception('NETCONF_connection_failed', e=e)
                self.activate_failed(device, e.message, reachable=False)

            ############################################################################
            # Get the device Information

            if reconciling:
                device.connect_status = ConnectStatus.REACHABLE
                self.adapter_agent.update_device(device)
            else:
                try:
                    self.startup = self.get_device_info(device)
                    results = yield self.startup

                    device.model = results.get('model', 'unknown')
                    device.hardware_version = results.get('hardware_version', 'unknown')
                    device.firmware_version = results.get('firmware_version', 'unknown')
                    device.serial_number = results.get('serial_number', 'unknown')

                    def get_software_images():
                        leafs = ['running-revision', 'candidate-revision', 'startup-revision']
                        image_names = list(set([results.get(img, 'unknown') for img in leafs]))

                        images = []
                        for name in image_names:
                            # TODO: Look into how to find out hash, is_valid, and install date/time
                            image = Image(name=name, version=name,
                                          is_active=(name == results.get('running-revision', 'xxx')),
                                          is_committed=(name == results.get('startup-revision', 'xxx')))
                            images.append(image)
                        return images

                    device.images.image.extend(get_software_images())
                    device.root = True
                    device.vendor = results.get('vendor', 'Adtran, Inc.')
                    device.connect_status = ConnectStatus.REACHABLE
                    self.adapter_agent.update_device(device)

                except Exception as e:
                    self.log.exception('Device_info_failed', e=e)
                    self.activate_failed(device, e.message, reachable=False)

            try:
                # Enumerate and create Northbound NNI interfaces

                self.startup = self.enumerate_northbound_ports(device)
                results = yield self.startup

                self.startup = self.process_northbound_ports(device, results)
                yield self.startup

                if not reconciling:
                    for port in self.northbound_ports.itervalues():
                        self.adapter_agent.add_port(device.id, port.get_port())

            except Exception as e:
                self.log.exception('NNI_enumeration', e=e)
                self.activate_failed(device, e.message)

            try:
                # Enumerate and create southbound interfaces

                self.startup = self.enumerate_southbound_ports(device)
                results = yield self.startup

                self.startup = self.process_southbound_ports(device, results)
                yield self.startup

                if not reconciling:
                    for port in self.southbound_ports.itervalues():
                        self.adapter_agent.add_port(device.id, port.get_port())

            except Exception as e:
                self.log.exception('PON_enumeration', e=e)
                self.activate_failed(device, e.message)

            if reconciling:
                if device.admin_state == AdminState.ENABLED:
                    if device.parent_id:
                        self.logical_device_id = device.parent_id
                        self.adapter_agent.reconcile_logical_device(device.parent_id)
                    else:
                        self.log.info('no-logical-device-set')

                # Reconcile child devices
                self.adapter_agent.reconcile_child_devices(device.id)
                ld_initialized = self.adapter_agent.get_logical_device()
                assert device.parent_id == ld_initialized.id

            else:
                # Complete activation by setting up logical device for this OLT and saving
                # off the devices parent_id

                ld_initialized = self.create_logical_device(device)

            ############################################################################
            # Setup PM configuration for this device

            # self.pm_metrics = AdapterPmMetrics(device)
            # pm_config = self.pm_metrics.make_proto()
            # self.log.info("initial-pm-config", pm_config=pm_config)
            # self.adapter_agent.update_device_pm_config(pm_config, init=True)

            ############################################################################
            # Setup Alarm handler

            self.alarms = AdapterAlarms(self.adapter, device)

            ############################################################################
            # Create logical ports for all southbound and northbound interfaces
            try:
                self.startup = self.create_logical_ports(device, ld_initialized, reconciling)
                yield self.startup

            except Exception as e:
                self.log.exception('logical-port', e=e)
                self.activate_failed(device, e.message)

            # Complete device specific steps
            try:
                self.log.debug('device-activation-procedures')
                self.startup = self.complete_device_specific_activation(device, reconciling)
                yield self.startup

            except Exception as e:
                self.log.exception('device-activation-procedures', e=e)
                self.activate_failed(device, e.message)

            # Schedule the heartbeat for the device

            self.log.debug('Starting-heartbeat')
            self.start_heartbeat(delay=5)

            device = self.adapter_agent.get_device(device.id)
            device.parent_id = ld_initialized.id
            device.oper_status = OperStatus.ACTIVE
            device.reason = ''
            self.adapter_agent.update_device(device)
            self.logical_device_id = ld_initialized.id

            # finally, open the frameio port to receive in-band packet_in messages
            self._activate_io_port()

            # Start collecting stats from the device after a brief pause
            reactor.callLater(5, self.start_kpi_collection, device.id)

            self.log.info('Activated')

    def activate_failed(self, device, reason, reachable=True):
        """
        Activation process (adopt_device) has failed.

        :param device:  A voltha.Device object, with possible device-type
                        specific extensions. Such extensions shall be described as part of
                        the device type specification returned by device_types().
        :param reason: (string) failure reason
        :param reachable: (boolean) Flag indicating if device may be reachable
                                    via RESTConf or NETConf even after this failure.
        """
        device.oper_status = OperStatus.FAILED
        if not reachable:
            device.connect_status = ConnectStatus.UNREACHABLE

        device.reason = reason
        self.adapter_agent.update_device(device)
        raise RuntimeError('Failed to activate OLT: {}'.format(device.reason))

    @inlineCallbacks
    def make_netconf_connection(self, connect_timeout=None):
        ############################################################################
        # Start initial discovery of NETCONF support

        client = self._netconf_client

        if client is None:
            if not self.is_virtual_olt:
                client = AdtranNetconfClient(self.ip_address,
                                             self.netconf_port,
                                             self.netconf_username,
                                             self.netconf_password,
                                             self.timeout)
            else:
                from voltha.adapters.adtran_olt.net.mock_netconf_client import MockNetconfClient
                client = MockNetconfClient(self.ip_address,
                                           self.netconf_port,
                                           self.netconf_username,
                                           self.netconf_password,
                                           self.timeout)
        if client.connected:
            self._netconf_client = client
            returnValue(True)

        timeout = connect_timeout or self.timeout

        try:
            request = client.connect(timeout)
            results = yield request
            self._netconf_client = client
            returnValue(results)

        except Exception as e:
            self.log.exception('Failed to create NETCONF Client', e=e)
            self._netconf_client = None
            raise

    @inlineCallbacks
    def make_restconf_connection(self, get_timeout=None):
        client = self._rest_client

        if client is None:
            client = AdtranRestClient(self.ip_address,
                                      self.rest_port,
                                      self.rest_username,
                                      self.rest_password,
                                      self.timeout)

        timeout = get_timeout or self.timeout

        try:
            request = client.request('GET', self.HELLO_URI, name='hello', timeout=timeout)
            results = yield request
            if isinstance(results, dict) and 'module-info' in results:
                self._rest_client = client
                returnValue(results)
            else:
                from twisted.internet.error import ConnectError
                self._rest_client = None
                raise ConnectError(string='Results received but unexpected data type or contents')
        except Exception:
            self._rest_client = None
            raise

    def create_logical_device(self, device):
        version = device.images.image[0].version

        ld = LogicalDevice(
            # NOTE: not setting id and datapath_id will let the adapter agent pick id
            desc=ofp_desc(mfr_desc=device.vendor,
                          hw_desc=device.hardware_version,
                          sw_desc=version,
                          serial_num=device.serial_number,
                          dp_desc='n/a'),
            switch_features=ofp_switch_features(n_buffers=256,  # TODO fake for now
                                                n_tables=2,  # TODO ditto
                                                capabilities=(
                                                    OFPC_FLOW_STATS |
                                                    OFPC_TABLE_STATS |
                                                    OFPC_GROUP_STATS |
                                                    OFPC_PORT_STATS)),
            root_device_id=device.id)

        ld_initialized = self.adapter_agent.create_logical_device(ld)

        return ld_initialized

    @inlineCallbacks
    def create_logical_ports(self, device, ld_initialized, reconciling):
        results = defer.fail()

        if not reconciling:
            for port in self.northbound_ports.itervalues():
                lp = port.get_logical_port()
                if lp is not None:
                    self.adapter_agent.add_logical_port(ld_initialized.id, lp)

            for port in self.southbound_ports.itervalues():
                lp = port.get_logical_port()
                if lp is not None:
                    self.adapter_agent.add_logical_port(ld_initialized.id, lp)

            # Set the ports in a known good initial state
            try:
                for port in self.northbound_ports.itervalues():
                    self.startup = yield port.reset()
                    results = yield self.startup

                for port in self.southbound_ports.itervalues():
                    self.startup = yield port.reset()
                    results = yield self.startup

            except Exception as e:
                    self.log.exception('Failed to reset ports to known good initial state', e=e)
                    self.activate_failed(device, e.message)

            # Clean up all EVC and EVC maps (exceptions ok/not-fatal)
            try:
                from flow.evc import EVC
                self.startup = yield EVC.remove_all(self.netconf_client)

            except Exception as e:
                self.log.exception('Failed attempting to clean up existing EVCs', e=e)

            try:
                from flow.evc_map import EVCMap
                self.startup = yield EVCMap.remove_all(self.netconf_client)

            except Exception as e:
                self.log.exception('Failed attempting to clean up existing EVC-Maps', e=e)

        # Start/stop the interfaces as needed

        for port in self.northbound_ports.itervalues():
            self.startup = port.start()
            results = yield self.startup

        if reconciling:
            start_downlinks = device.admin_state == AdminState.ENABLED
        else:
            start_downlinks = self.autoactivate

        for port in self.southbound_ports.itervalues():
            self.startup = port.start() if start_downlinks else port.stop()
            results = yield self.startup

        returnValue(results)

    @inlineCallbacks
    def device_information(self, device):
        """
        Examine the various managment models and extract device information for
        VOLTHA use

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
        yield defer.Deferred(lambda c: c.callback("Not Required"))

    @inlineCallbacks
    def enumerate_northbound_ports(self, device):
        """
        Enumerate all northbound ports of a device. You should override
        this method in your derived class as necessary. Should you encounter
        a non-recoverable error, throw an appropriate exception.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
        yield defer.Deferred(lambda c: c.callback("Not Required"))

    @inlineCallbacks
    def process_northbound_ports(self, device, results):
        """
        Process the results from the 'enumerate_northbound_ports' method.
        You should override this method in your derived class as necessary and
        create an NNI Port object (of your own choosing) that supports a 'get_port'
        method. Once created, insert it into this base class's northbound_ports
        collection.

        Should you encounter a non-recoverable error, throw an appropriate exception.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :param results: Results from the 'enumerate_northbound_ports' method that
                you implemented. The type and contents are up to you to
        :return:
        """
        yield defer.Deferred(lambda c: c.callback("Not Required"))

    @inlineCallbacks
    def enumerate_southbound_ports(self, device):
        """
        Enumerate all southbound ports of a device. You should override
        this method in your derived class as necessary. Should you encounter
        a non-recoverable error, throw an appropriate exception.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
        yield defer.Deferred(lambda c: c.callback("Not Required"))

    @inlineCallbacks
    def process_southbound_ports(self, device, results):
        """
        Process the results from the 'enumerate_southbound_ports' method.
        You should override this method in your derived class as necessary and
        create an Port object (of your own choosing) that supports a 'get_port'
        method. Once created, insert it into this base class's southbound_ports
        collection.

        Should you encounter a non-recoverable error, throw an appropriate exception.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :param results: Results from the 'enumerate_southbound_ports' method that
                you implemented. The type and contents are up to you to
        :return:
        """
        yield defer.Deferred(lambda c: c.callback("Not Required"))

    # TODO: Move some of the items below from here and the EVC to a utility class

    def is_nni_port(self, port):
        return port in self.northbound_ports

    def is_uni_port(self, port):
        raise NotImplementedError('implement in derived class')

    def is_pon_port(self, port):
        raise NotImplementedError('implement in derived class')

    def is_logical_port(self, port):
        return not self.is_nni_port(port) and not self.is_uni_port(port) and not self.is_pon_port(port)

    def get_port_name(self, port):
        raise NotImplementedError('implement in derived class')

    @inlineCallbacks
    def complete_device_specific_activation(self, _device, _reconciling):
        return defer.succeed('NOP')

    def deactivate(self, device):
        # Clear off logical device ID
        self.logical_device_id = None

        # Kill any heartbeat poll
        h, self.heartbeat = self.heartbeat, None

        if h is not None and not h.called:
            h.cancel()

        # TODO: What else (delete logical device, ???)

    def disable(self):
        """
        This is called when a previously enabled device needs to be disabled based on a NBI call.
        """
        self.log.info('disabling', device_id=self.device_id)

        # Cancel any running enable/disable/... in progress
        d, self.startup = self.startup, None
        if d is not None and not d.called:
            d.cancel()

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Deactivate in-band packets
        self._deactivate_io_port()

        # Suspend any active healthchecks / pings

        h, self.heartbeat = self.heartbeat, None

        if h is not None and not h.called:
            h.cancel()

        # Update the operational status to UNKNOWN

        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the logical device
        ldi, self.logical_device_id = self.logical_device_id, None

        if ldi is not None:
            logical_device = self.adapter_agent.get_logical_device(ldi)
            self.adapter_agent.delete_logical_device(logical_device)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      admin_state=AdminState.DISABLED)

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        # Set all ports to disabled
        self.adapter_agent.disable_all_ports(self.device_id)

        dl = []
        for port in self.northbound_ports.itervalues():
            dl.append(port.stop())

        for port in self.southbound_ports.itervalues():
            dl.append(port.stop())

        # NOTE: Flows removed before this method is called
        # Wait for completion

        self.startup = defer.gatherResults(dl)

        def _drop_netconf():
            return self.netconf_client.close() if \
                self.netconf_client is not None else defer.succeed('NOP')

        def _null_clients():
            self._netconf_client = None
            self._rest_client = None

        # Shutdown communications with OLT

        self.startup.addCallbacks(_drop_netconf, _null_clients)
        self.startup.addCallbacks(_null_clients, _null_clients)

        #  Update the logical device mapping
        if ldi in self.adapter.logical_device_id_to_root_device_id:
            del self.adapter.logical_device_id_to_root_device_id[ldi]

        self.log.info('disabled', device_id=device.id)
        return self.startup

    @inlineCallbacks
    def reenable(self):
        """
        This is called when a previously disabled device needs to be enabled based on a NBI call.
        """
        self.log.info('re-enabling', device_id=self.device_id)

        # Cancel any running enable/disable/... in progress
        d, self.startup = self.startup, None
        if d is not None and not d.called:
            d.cancel()

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Set all ports to enabled
        self.adapter_agent.enable_all_ports(self.device_id)

        try:
            yield self.make_restconf_connection()

        except Exception as e:
            self.log.exception('adtran-hello-reconnect', e=e)
            # TODO: What is best way to handle reenable failure?

        try:
            yield self.make_netconf_connection()

        except Exception as e:
            self.log.exception('NETCONF-re-connection', e=e)
            # TODO: What is best way to handle reenable failure?

        # Recreate the logical device

        ld_initialized = self.create_logical_device(device)

        # Create logical ports for all southbound and northbound interfaces

        self.create_logical_ports(device, ld_initialized, False)

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        device.reason = ''
        self.adapter_agent.update_device(device)
        self.logical_device_id = ld_initialized.id

        # Reenable all child devices
        self.adapter_agent.update_child_devices_state(device.id,
                                                      admin_state=AdminState.ENABLED)
        dl = []

        for port in self.northbound_ports.itervalues():
            dl.append(port.start())

        for port in self.southbound_ports.itervalues():
            dl.append(port.start())

        # Flows should not exist on re-enable. They are re-pushed
        if len(self._evcs):
            self.log.error('evcs-found', evcs=self._evcs)
        self._evcs.clear()

        # Wait for completion

        self.startup = defer.gatherResults(dl)
        results = yield self.startup

        # TODO:
        # 1) Restart health check / pings

        # Activate in-band packets
        self._activate_io_port()

        self.log.info('re-enabled', device_id=device.id)
        returnValue(results)

    @inlineCallbacks
    def reboot(self):
        """
        This is called to reboot a device based on a NBI call.  The admin state of the device
        will not change after the reboot.
        """
        self.log.debug('reboot')

        # Cancel any running enable/disable/... in progress
        d, self.startup = self.startup, None
        if d is not None and not d.called:
            d.cancel()

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE

        device = self.adapter_agent.get_device(self.device_id)
        previous_oper_status = device.oper_status
        previous_conn_status = device.connect_status
        device.oper_status = OperStatus.ACTIVATING
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Update the child devices connect state to UNREACHABLE
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      connect_status=ConnectStatus.UNREACHABLE)
        # Issue reboot command

        if not self.is_virtual_olt:
            try:
                yield self.netconf_client.rpc(AdtranDeviceHandler.RESTART_RPC)

            except Exception as e:
                self.log.exception('NETCONF-shutdown', e=e)
                # TODO: On failure, what is the best thing to do?

            # Shutdown communications with OLT. Typically it takes about 2 seconds
            # or so after the reply before the restart actually occurs

            try:
                response = yield self.netconf_client.close()
                self.log.debug('Restart response XML was: {}'.format('ok' if response.ok else 'bad'))

            except Exception as e:
                self.log.exception('NETCONF-client-shutdown', e=e)

        #  Clear off clients

        self._netconf_client = None
        self._rest_client = None

        # Run remainder of reboot process as a new task. The OLT then may be up in a
        # few moments or may take 3 minutes or more depending on any self tests enabled

        current_time = time.time()
        timeout = current_time + self.restart_failure_timeout

        try:
            yield reactor.callLater(10, self._finish_reboot, timeout,
                                    previous_oper_status, previous_conn_status)
        except Exception as e:
            self.log.exception('finish-reboot', e=e)

        returnValue('Waiting for reboot')

    @inlineCallbacks
    def _finish_reboot(self, timeout, previous_oper_status, previous_conn_status):
        # Now wait until REST & NETCONF are re-established or we timeout

        self.log.info('Resuming-activity',
                      remaining=timeout - time.time(), timeout=timeout, current=time.time())

        if self.rest_client is None:
            try:
                response = yield self.make_restconf_connection(get_timeout=10)
                # self.log.debug('Restart RESTCONF connection JSON was: {}'.format(response))

            except Exception:
                self.log.debug('No RESTCONF connection yet')
                self._rest_client = None

        if self.netconf_client is None:
            try:
                yield self.make_netconf_connection(connect_timeout=10)
                # self.log.debug('Restart NETCONF connection succeeded')

            except Exception as e:
                try:
                    if self.netconf_client is not None:
                        yield self.netconf_client.close()
                except Exception as e:
                    self.log.exception(e.message)
                finally:
                    self._netconf_client = None

        if (self.netconf_client is None and not self.is_virtual_olt) or self.rest_client is None:
            current_time = time.time()
            if current_time < timeout:
                try:
                    yield reactor.callLater(5, self._finish_reboot, timeout,
                                            previous_oper_status, previous_conn_status)
                except Exception:
                    self.log.debug('Rebooted-check', e=e)

                returnValue('Waiting some more...')

            if self.netconf_client is None and not self.is_virtual_olt:
                self.log.error('NETCONF-restore-failure')
                pass        # TODO: What is best course of action if cannot get clients back?

            if self.rest_client is None:
                self.log.error('RESTCONF-restore-failure')
                pass        # TODO: What is best course of action if cannot get clients back?

        # Pause additional 5 seconds to let allow OLT microservices to complete some more initialization
        yield asleep(5)

        # Get the latest device reference

        device = self.adapter_agent.get_device(self.device_id)
        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        self.adapter_agent.update_device(device)

        # Update the child devices connect state to REACHABLE
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      connect_status=ConnectStatus.REACHABLE)
        # Restart ports to previous state

        dl = []

        for port in self.northbound_ports.itervalues():
            dl.append(port.restart())

        for port in self.southbound_ports.itervalues():
            dl.append(port.restart())

        try:
            yield defer.gatherResults(dl)
        except Exception as e:
            self.log.exception('port-restart', e=e)

        # Request reflow of any EVC/EVC-MAPs

        if len(self._evcs) > 0:
            dl = []
            for evc in self.evcs:
                dl.append(evc.reflow())

            try:
                yield defer.gatherResults(dl)
            except Exception as e:
                self.log.exception('flow-restart', e=e)

        self.log.info('rebooted', device_id=self.device_id)
        returnValue('Rebooted')

    @inlineCallbacks
    def delete(self):
        """
        This is called to delete a device from the PON based on a NBI call.
        If the device is an OLT then the whole PON will be deleted.
        """
        self.log.info('deleting', device_id=self.device_id)

        # Cancel any outstanding tasks

        d, self.startup = self.startup, None
        if d is not None and not d.called:
            d.cancel()

        h, self.heartbeat = self.heartbeat, None
        if h is not None and not h.called:
            h.cancel()

        # Remove all flows from the device
        # TODO: Create a bulk remove-all by device-id

        evcs = self._evcs()
        self._evcs.clear()

        for evc in evcs:
            evc.delete()   # TODO: implement bulk-flow procedures

        # Remove all child devices
        self.adapter_agent.delete_all_child_devices(self.device_id)

        # Remove the logical device
        logical_device = self.adapter_agent.get_logical_device(self.logical_device_id)
        self.adapter_agent.delete_logical_device(logical_device)
        # TODO: For some reason, the logical device does not seem to get deleted

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        # Tell all ports to stop any background processing

        for port in self.northbound_ports.itervalues():
            port.delete()

        for port in self.southbound_ports.itervalues():
            port.delete()

        self.northbound_ports.clear()
        self.southbound_ports.clear()

        # Shutdown communications with OLT

        if self.netconf_client is not None:
            try:
                yield self.netconf_client.close()
            except Exception as e:
                self.log.exception('NETCONF-shutdown', e=e)

            self._netconf_client = None

        self._rest_client = None

        self.log.info('deleted', device_id=self.device_id)

    def _activate_io_port(self):
        if self.io_port is None:
            self.log.info('registering-frameio')
            self.io_port = registry('frameio').open_port(
                self.interface, self._rcv_io, _is_inband_frame)

    def _deactivate_io_port(self):
        io, self.io_port = self.io_port, None

        if io is not None:
            registry('frameio').close_port(io)

    def _rcv_io(self, port, frame):
        self.log.info('received', iface_name=port.iface_name, frame_len=len(frame))

        pkt = Ether(frame)
        if pkt.haslayer(Dot1Q):
            outer_shim = pkt.getlayer(Dot1Q)

            if isinstance(outer_shim.payload, Dot1Q):
                inner_shim = outer_shim.payload
                cvid = inner_shim.vlan
                logical_port = cvid
                popped_frame = (Ether(src=pkt.src, dst=pkt.dst, type=inner_shim.type) /
                                inner_shim.payload)
                kw = dict(
                    logical_device_id=self.logical_device_id,
                    logical_port_no=logical_port,
                )
                self.log.info('sending-packet-in', **kw)
                self.adapter_agent.send_packet_in(
                    packet=str(popped_frame), **kw)

            elif pkt.haslayer(Raw):
                raw_data = json.loads(pkt.getlayer(Raw).load)
                self.alarms.send_alarm(self, raw_data)

    def packet_out(self, egress_port, msg):
        if self.io_port is not None:
            self.log.info('sending-packet-out', egress_port=egress_port,
                          msg=hexify(msg))
            pkt = Ether(msg)
            out_pkt = (
                Ether(src=pkt.src, dst=pkt.dst) /
                Dot1Q(vlan=_PACKET_IN_VLAN) /
                Dot1Q(vlan=egress_port, type=pkt.type) /
                pkt.payload
            )
            self.io_port.send(str(out_pkt))

    def update_pm_config(self, device, pm_config):
        # TODO: This has not been tested
        self.log.info('update_pm_config', pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    def start_kpi_collection(self, device_id):
        # TODO: This has not been tested
        def _collect(device_id, prefix):
            from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs

            try:
                # Step 1: gather metrics from device
                port_metrics = self.pm_metrics.collect_port_metrics(self.get_channel())

                # Step 2: prepare the KpiEvent for submission
                # we can time-stamp them here (or could use time derived from OLT
                ts = arrow.utcnow().timestamp
                kpi_event = KpiEvent(
                    type=KpiEventType.slice,
                    ts=ts,
                    prefixes={
                        # OLT NNI port
                        prefix + '.nni': MetricValuePairs(metrics=port_metrics['nni']),
                        # OLT PON port
                        prefix + '.pon': MetricValuePairs(metrics=port_metrics['pon'])
                    }
                )
                # Step 3: submit
                self.adapter_agent.submit_kpis(kpi_event)

            except Exception as e:
                self.log.exception('failed-to-submit-kpis', e=e)

        # self.pm_metrics.start_collector(_collect)

    @inlineCallbacks
    def get_device_info(self, device):
        """
        Perform an initial network operation to discover the device hardware
        and software version. Serial Number would be helpful as well.

        Upon successfully retrieving the information, remember to call the
        'start_heartbeat' method to keep in contact with the device being managed

        :param device: A voltha.Device object, with possible device-type
                specific extensions. Such extensions shall be described as part of
                the device type specification returned by device_types().
        """
        device = {}
        returnValue(device)

    def start_heartbeat(self, delay=10):
        assert delay > 1
        self.log.info('Starting-Device-Heartbeat ***')
        self.heartbeat = reactor.callLater(delay, self.check_pulse)
        return self.heartbeat

    def check_pulse(self):
        if self.logical_device_id is not None:
            self.heartbeat = self.rest_client.request('GET', self.HELLO_URI, name='hello')
            self.heartbeat.addCallbacks(self.heartbeat_check_status, self.heartbeat_fail)

    def heartbeat_check_status(self, results):
        """
        Check the number of heartbeat failures against the limit and emit an alarm if needed
        """
        device = self.adapter_agent.get_device(self.device_id)

        if self.heartbeat_miss >= self.heartbeat_failed_limit and device.connect_status == ConnectStatus.REACHABLE:
            self.log.warning('olt-heartbeat-failed', count=self.heartbeat_miss)
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.FAILED
            device.reason = self.heartbeat_last_reason
            self.adapter_agent.update_device(device)

            self.heartbeat_alarm(False, self.heartbeat_miss)
        else:
            assert results
            # Update device states

            self.log.info('heartbeat-success')

            if device.connect_status != ConnectStatus.REACHABLE:
                device.connect_status = ConnectStatus.REACHABLE
                device.oper_status = OperStatus.ACTIVE
                device.reason = ''
                self.adapter_agent.update_device(device)

                self.heartbeat_alarm(True)

            self.heartbeat_miss = 0
            self.heartbeat_last_reason = ''
            self.heartbeat_count += 1

        # Reschedule next heartbeat
        if self.logical_device_id is not None:
            self.heartbeat = reactor.callLater(self.heartbeat_interval, self.check_pulse)

    def heartbeat_fail(self, failure):
        self.heartbeat_miss += 1
        self.log.info('heartbeat-miss', failure=failure,
                      count=self.heartbeat_count, miss=self.heartbeat_miss)
        self.heartbeat_check_status(None)

    def heartbeat_alarm(self, status, heartbeat_misses=0):
        alarm = 'Heartbeat'
        alarm_data = {
            'ts': arrow.utcnow().timestamp,
            'description': self.alarms.format_description('olt', alarm, status),
            'id': self.alarms.format_id(alarm),
            'type': AlarmEventType.EQUIPMENT,
            'category': AlarmEventCategory.PON,
            'severity': AlarmEventSeverity.CRITICAL,
            'state': AlarmEventState.RAISED if status else AlarmEventState.CLEARED
        }
        context_data = {'heartbeats_missed': heartbeat_misses}
        self.alarms.send_alarm(context_data, alarm_data)

    @staticmethod
    def parse_module_revision(revision):
        try:
            return datetime.datetime.strptime(revision, '%Y-%m-%d')
        except Exception:
            return None
