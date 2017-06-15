#
# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
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

from common.utils.asleep import asleep

_ = third_party


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

    def __init__(self, adapter, device_id, username='', password='', timeout=20):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.startup = None
        self.channel = None  # Proxy messaging channel with 'send' method
        self.io_port = None
        self.logical_device_id = None
        self.interface = registry('main').get_args().interface

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
        self.rest_port = None
        self.rest_username = username
        self.rest_password = password
        self.rest_client = None

        # NETCONF Client
        self.netconf_port = None
        self.netconf_username = username
        self.netconf_password = password
        self.netconf_client = None

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
        self.flow_entries = {}  # Flow ID/name -> FlowEntry

        # TODO Remove items below after one PON fully supported and working as expected
        self.max_ports = 1

    def __del__(self):
        # Kill any startup or heartbeat defers

        d, self.startup = self.startup, None
        if d is not None:
            d.cancel()

        ldi, self.logical_device_id = self.logical_device_id, None

        h, self.heartbeat = self.heartbeat, None

        if h is not None:
            h.cancel()

        # Remove the logical device

        if ldi is not None:
            logical_device = self.adapter_agent.get_logical_device(ldi)
            self.adapter_agent.delete_logical_device(logical_device)

        self.northbound_ports.clear()
        self.southbound_ports.clear()

    def __str__(self):
        return "AdtranDeviceHandler: {}".format(self.ip_address)

    def parse_provisioning_options(self, device):
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
        parser.add_argument('--nc_username', '-u', action='store', default='hsvroot', help='NETCONF username')
        parser.add_argument('--nc_password', '-p', action='store', default='BOSCO', help='NETCONF Password')
        parser.add_argument('--nc_port', '-t', action='store', default=830, type=check_tcp_port,
                            help='NETCONF TCP Port')
        parser.add_argument('--rc_username', '-U', action='store', default='ADMIN', help='REST username')
        parser.add_argument('--rc_password', '-P', action='store', default='PASSWORD', help='REST Password')
        parser.add_argument('--rc_port', '-T', action='store', default=8081, type=check_tcp_port,
                            help='REST TCP Port')

        try:
            args = parser.parse_args(shlex.split(device.extra_args))

            self.netconf_username = args.nc_username
            self.netconf_password = args.nc_password
            self.netconf_port = args.nc_port

            self.rest_username = args.rc_username
            self.rest_password = args.rc_password
            self.rest_port = args.rc_port

        except argparse.ArgumentError as e:
            self.activate_failed(device,
                                 'Invalid arguments: {}'.format(e.message),
                                 reachable=False)
        except Exception as e:
            self.log.exception('parsing error: {}'.format(e.message))

    @inlineCallbacks
    def activate(self, device, reconciling=False):
        """
        Activate the OLT device

        :param device: A voltha.Device object, with possible device-type
                       specific extensions.
        :param reconciling: If True, this adapter is taking over for a previous adapter
                            for an existing OLT
        """
        self.log.info('AdtranDeviceHandler.activating', device=device, reconciling=reconciling)

        if self.logical_device_id is None:
            # Parse our command line options for this device
            self.parse_provisioning_options(device)

            ############################################################################
            # Start initial discovery of RESTCONF support (if any)

            try:
                self.startup = self.make_restconf_connection()
                results = yield self.startup
                self.log.debug('HELLO Contents: {}'.format(pprint.PrettyPrinter().pformat(results)))

                # See if this is a virtualized OLT. If so, no NETCONF support available

                self.is_virtual_olt = 'module-info' in results and\
                                      any(mod.get('module-name', None) == 'adtran-ont-mock'
                                          for mod in results['module-info'])
                if self.is_virtual_olt:
                    self.log.info('*** VIRTUAL OLT detected ***')

            except Exception as e:
                self.log.exception('Initial RESTCONF adtran-hello failed', e=e)
                self.activate_failed(device, e.message, reachable=False)

            ############################################################################
            # Start initial discovery of NETCONF support (if any)

<<<<<<< HEAD
            device.model = 'TODO: Adtran PizzaBox, YUM'
            device.hardware_version = 'TODO: H/W Version'
            device.firmware_version = 'TODO: S/W Version'
            device.images.image.extend([
                                         Image(version="TODO: S/W Version")
                                       ])
            device.serial_number = 'TODO: Serial Number'
=======
            if not self.is_virtual_olt:
                try:
                    self.startup = self.make_netconf_connection()
                    yield self.startup
>>>>>>> c577acb... netconf client support and disable-enable support

                except Exception as e:
                    self.log.exception('Initial NETCONF connection failed', e=e)
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
                    device.software_version = results.get('software_version', 'unknown')
                    device.serial_number = results.get('serial_number', 'unknown')

                    device.root = True
                    device.vendor = results.get('vendor', 'Adtran, Inc.')
                    device.connect_status = ConnectStatus.REACHABLE
                    self.adapter_agent.update_device(device)

                except Exception as e:
                    self.log.exception('Device Information request(s) failed', e=e)
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
                self.log.exception('Northbound port enumeration and creation failed', e=e)
                self.activate_failed(device, e.message)
                results = None

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
                self.log.exception('Southbound port enumeration and creation failed', e=e)
                self.activate_failed(device, e.message)

<<<<<<< HEAD
            # Complete activation by setting up logical device for this OLT and saving
            # off the devices parent_id

            # There could be multiple software version on the device,
            # active, standby etc. Choose the active or running software
            # below. See simulated_olt for example implementation
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
                                                    capabilities=(OFPC_FLOW_STATS |
                                                                  OFPC_TABLE_STATS |
                                                                  OFPC_PORT_STATS |
                                                                  OFPC_GROUP_STATS)),  # TODO and ditto
                root_device_id=device.id)

            ld_initialized = self.adapter_agent.create_logical_device(ld)

            # Create logical ports for all southbound and northbound interfaces

            for port in self.northbound_ports.itervalues():
                lp = port.get_logical_port()
                if lp is not None:
                    self.adapter_agent.add_logical_port(ld_initialized.id, lp)

            for port in self.southbound_ports.itervalues():
                lp = port.get_logical_port()
                if lp is not None:
                    self.adapter_agent.add_logical_port(ld_initialized.id, lp)

            # Set the downlinks in a known good initial state

            try:
                for port in self.southbound_ports.itervalues():
                    self.startup = port.reset()
                    yield self.startup

            except Exception as e:
                self.log.exception('Failed to reset southbound ports to known good initial state', e=e)
                self.activate_failed(device, e.message)

            # Start/stop the interfaces as needed

            try:
                for port in self.northbound_ports.itervalues():
                    self.startup = port.start()
                    yield self.startup
=======
            if reconciling:
                if device.admin_state == AdminState.ENABLED:
                    if device.parent_id:
                        self.logical_device_id = device.parent_id
                        self.adapter_agent.reconcile_logical_device(device.parent_id)
                    else:
                        self.log.info('no-logical-device-set')
>>>>>>> c577acb... netconf client support and disable-enable support

                # Reconcile child devices
                self.adapter_agent.reconcile_child_devices(device.id)
            else:
                # Complete activation by setting up logical device for this OLT and saving
                # off the devices parent_id

                self.logical_device_id = self.create_logical_device(device)

            # Create logical ports for all southbound and northbound interfaces

            self.create_logical_ports(device, self.logical_device_id, reconciling)

            # Complete device specific steps
            try:
                self.startup = self.complete_device_specific_activation(device, reconciling)
                if self.startup is not None:
                    yield self.startup

            except Exception as e:
                self.log.exception('Device specific activation failed', e=e)
                self.activate_failed(device, e.message)

            # Schedule the heartbeat for the device

            self.start_heartbeat(delay=10)

            device = self.adapter_agent.get_device(device.id)
            device.parent_id = self.logical_device_id
            device.oper_status = OperStatus.ACTIVE
            self.adapter_agent.update_device(device)

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

    def make_netconf_connection(self, connect_timeout=None):
        ############################################################################
        # Start initial discovery of NETCONF support

        if self.netconf_client is None:
            self.netconf_client = AdtranNetconfClient(self.ip_address,
                                                      self.netconf_port,
                                                      self.netconf_username,
                                                      self.netconf_password,
                                                      self.timeout)
        if self.netconf_client.connected:
            return defer.returnValue(True)

        timeout = connect_timeout or self.timeout
        return self.netconf_client.connect(timeout)

    def make_restconf_connection(self, get_timeout=None):
        if self.rest_client is None:
            self.rest_client = AdtranRestClient(self.ip_address,
                                                self.rest_port,
                                                self.rest_username,
                                                self.rest_password,
                                                self.timeout)

        timeout = get_timeout or self.timeout
        return self.rest_client.request('GET', self.HELLO_URI, name='hello', timeout=timeout)

    def create_logical_device(self, device):
        ld = LogicalDevice(
            # NOTE: not setting id and datapath_id will let the adapter agent pick id
            desc=ofp_desc(mfr_desc=device.vendor,
                          hw_desc=device.hardware_version,
                          sw_desc=device.software_version,
                          serial_num=device.serial_number,
                          dp_desc='n/a'),
            switch_features=ofp_switch_features(n_buffers=256,  # TODO fake for now
                                                n_tables=2,  # TODO ditto
                                                capabilities=(
                                                    # OFPC_FLOW_STATS |  # TODO: Enable if we support it
                                                    # OFPC_TABLE_STATS | # TODO: Enable if we support it
                                                    # OFPC_GROUP_STATS | # TODO: Enable if we support it
                                                    OFPC_PORT_STATS)),
            root_device_id=device.id)

        ld_initialized = self.adapter_agent.create_logical_device(ld)

        return ld_initialized

    @inlineCallbacks
    def create_logical_ports(self, device, ld_initialized, reconciling):

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
                    self.startup = port.reset()
                    results = yield self.startup
                    self.log.debug('Northbound Port reset results', results=results)

            except Exception as e:
                self.log.exception('Failed to reset northbound ports to known good initial state', e=e)
                self.activate_failed(device, e.message)

            try:
                for port in self.southbound_ports.itervalues():
                    self.startup = port.reset()
                    results = yield self.startup
                    self.log.debug('Southbound Port reset results', results=results)

            except Exception as e:
                self.log.exception('Failed to reset southbound ports to known good initial state', e=e)
                self.activate_failed(device, e.message)

        # Start/stop the interfaces as needed
        try:
            for port in self.northbound_ports.itervalues():
                self.startup = port.start()
                results = yield self.startup
                self.log.debug('Northbound Port start results', results=results)

        except Exception as e:
            self.log.exception('Failed to start northbound port(s)', e=e)
            self.activate_failed(device, e.message)

        try:
            if reconciling:
                start_downlinks = device.admin_state == AdminState.ENABLED
            else:
                start_downlinks = self.initial_port_state == AdminState.ENABLED

            for port in self.southbound_ports.itervalues():
                self.startup = port.start() if start_downlinks else port.stop()
                results = yield self.startup
                self.log.debug('Southbound Port start results', results=results)

        except Exception as e:
            self.log.exception('Failed to start southbound port(s)', e=e)
            self.activate_failed(device, e.message)

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

    @inlineCallbacks
    def complete_device_specific_activation(self, _device, _reconciling):
        return None

    def deactivate(self, device):
        # Clear off logical device ID
        self.logical_device_id = None

        # Kill any heartbeat poll
        h, self.heartbeat = self.heartbeat, None

        if h is not None:
            h.cancel()

        # TODO: What else (delete logical device, ???)

    @inlineCallbacks
    def disable(self):
        """
        This is called when a previously enabled device needs to be disabled based on a NBI call.
        """
        self.log.info('disabling', device_id=self.device_id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Suspend any active healthchecks / pings

        h, self.heartbeat = self.heartbeat, None

        if h is not None:
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

        for port in self.northbound_ports.itervalues():
            port.stop()

        for port in self.southbound_ports.itervalues():
            port.stop()

        # Disable all flows            TODO: Do we want to delete them?
        # TODO: Use bulk methods if possible

        for flow in self.flow_entries.itervalues():
            flow.disable()

        # Shutdown communications with OLT

        if self.netconf_client is not None:
            try:
                yield self.netconf_client.close()
            except Exception as e:
                self.log.exception('NETCONF client shutdown failed', e=e)

        def _null_clients():
            self.netconf_client = None
            self.rest_client = None

        reactor.callLater(0, _null_clients)

        self.log.info('disabled', device_id=device.id)

    @inlineCallbacks
    def reenable(self):
        """
        This is called when a previously disabled device needs to be enabled based on a NBI call.
        """
        self.log.info('re-enabling', device_id=self.device_id)

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
            self.log.exception('RESTCONF adtran-hello reconnect failed', e=e)
            # TODO: What is best way to handle reenable failure?

        if not self.is_virtual_olt:
            try:
                yield self.make_netconf_connection()

            except Exception as e:
                self.log.exception('NETCONF re-connection failed', e=e)
                # TODO: What is best way to handle reenable failure?

        # Recreate the logical device

        ld_initialized = self.create_logical_device(device)

        # Create logical ports for all southbound and northbound interfaces

        self.create_logical_ports(device, ld_initialized, False)

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)
        self.logical_device_id = ld_initialized.id

        # Reenable all child devices
        self.adapter_agent.update_child_devices_state(device.id,
                                                      admin_state=AdminState.ENABLED)

        for port in self.northbound_ports.itervalues():
            port.start()

        for port in self.southbound_ports.itervalues():
            port.start()

        # TODO:
        # 1) Restart health check / pings

        # Enable all flows
        # TODO: Use bulk methods if possible

        for flow in self.flow_entries:
            flow.enable()

        self.log.info('re-enabled', device_id=device.id)

    @inlineCallbacks
    def reboot(self):
        """
        This is called to reboot a device based on a NBI call.  The admin state of the device
        will not change after the reboot.
        """
        self.log.debug('reboot')

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
                self.log.exception('NETCONF client shutdown', e=e)
                # TODO: On failure, what is the best thing to do?

            # Shutdown communications with OLT. Typically it takes about 2 seconds
            # or so after the reply before the restart actually occurs

            try:
                response = yield self.netconf_client.close()
                self.log.debug('Restart response XML was: {}'.format('ok' if response.ok else 'bad'))

            except Exception as e:
                self.log.exception('NETCONF client shutdown', e=e)

        def _null_clients():
            self.netconf_client = None
            self.rest_client = None

        yield reactor.callLater(0, _null_clients)

        # Run remainder of reboot process as a new task. The OLT then may be up in a
        # few moments or may take 3 minutes or more depending on any self tests enabled

        current_time = time.time();
        timeout = current_time + self.restart_failure_timeout

        self.log('*** Current time is {}, timeout is {}'.format(current_time, timeout))

        yield reactor.callLater(10, self._finish_reboot, timeout,
                                previous_oper_status, previous_conn_status)

    @inlineCallbacks
    def _finish_reboot(self, timeout, previous_oper_status, previous_conn_status):
        # Now wait until REST & NETCONF are re-established or we timeout

        if self.netconf_client is None and not self.is_virtual_olt:
            self.log.debug('Attempting to restore NETCONF connection')
            try:
                response = yield self.make_netconf_connection(connect_timeout=3)
                self.log.debug('Restart NETCONF connection XML was: {}'.format(response.xml))

            except Exception as e:
                self.log.debug('No NETCONF connection yet: {}'.format(e.message))
                try:
                    yield self.netconf_client.close()
                except Exception as e:
                    self.log.exception(e.message)
                finally:
                    def _null_netconf():
                        self.log.debug('Nulling out the NETCONF client')
                        self.netconf_client = None
                    reactor.callLater(0, _null_netconf)

        elif self.rest_client is None:
            self.log.debug('Attempting to restore RESTCONF connection')
            try:
                response = yield self.make_restconf_connection(get_timeout=3)
                self.log.debug('Restart RESTCONF connection XML was: {}'.format(response.xml))

            except Exception:
                self.log.debug('No RESTCONF connection yet')
                self.rest_client = None

        if (self.netconf_client is None and not self.is_virtual_olt) or self.rest_client is None:
            current_time = time.time();

            self.log('Current time is {}, timeout is {}'.format(current_time, timeout))

            if current_time < timeout:
                self.log.info('Device not responding yet, will try again...')
                yield reactor.callLater(10, self._finish_reboot, timeout,
                                        previous_oper_status, previous_conn_status)

            if self.netconf_client is None and not self.is_virtual_olt:
                self.log.error('Could not restore NETCONF communications after device RESET')
                pass        # TODO: What is best course of action if cannot get clients back?

            if self.rest_client is None:
                self.log.error('Could not restore RESTCONF communications after device RESET')
                pass        # TODO: What is best course of action if cannot get clients back?

        # Pause additional 5 seconds to let things OLT microservices complete some more initialization

        yield asleep(5)

        # Get the latest device reference

        device = self.adapter_agent.get_device(self.device_id)
        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        self.adapter_agent.update_device(device)

        # Update the child devices connect state to REACHABLE
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      connect_status=ConnectStatus.REACHABLE)

        # Connect back up to OLT so heartbeats/polls start working again
        try:
            yield self.make_restconf_connection()

        except Exception as e:
            self.log.exception('RESTCONF adtran-hello connect after reboot failed', e=e)
            # TODO: What is best way to handle reenable failure?

        if not self.is_virtual_olt:
            try:
                yield self.make_netconf_connection()

            except Exception as e:
                self.log.exception('NETCONF re-connection after reboot failed', e=e)
                # TODO: What is best way to handle reenable failure?

        self.log.info('rebooted', device_id=self.device_id)

    @inlineCallbacks
    def delete(self):
        """
        This is called to delete a device from the PON based on a NBI call.
        If the device is an OLT then the whole PON will be deleted.
        """
        self.log.info('deleting', device_id=self.device_id)

        # Cancel any outstanding tasks

        d, self.startup = self.startup, None
        if d is not None:
            d.cancel()

        h, self.heartbeat = self.heartbeat, None
        if h is not None:
            h.cancel()

        # TODO:
        # 1) Remove all flows from the device

        self.flow_entries.clear()

        # Remove all child devices
        self.adapter_agent.delete_all_child_devices(self.device_id)

        # Remove the logical device
        logical_device = self.adapter_agent.get_logical_device(self.logical_device_id)
        self.adapter_agent.delete_logical_device(logical_device)

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
                self.log.exception('NETCONF client shutdown', e=e)

            self.netconf_client = None

        self.rest_client = None

        self.log.info('deleted', device_id=self.device_id)

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
        # device['model'] = 'TODO: Adtran PizzaBox, YUM'
        # device['hardware_version'] = 'TODO: H/W Version'
        # device['firmware_version'] = 'TODO: S/W Version'
        # device['software_version'] = 'TODO: S/W Version'
        # device['serial_number'] = 'TODO: Serial Number'
        # device['vendor'] = 'Adtran, Inc.'

        returnValue(device)

    def start_heartbeat(self, delay=10):
        assert delay > 1
        self.heartbeat = reactor.callLater(delay, self.check_pulse)

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

            self.heartbeat_alarm(self.device_id, False, self.heartbeat_miss)
        else:
            assert results
            # Update device states

            self.log.info('heartbeat success')

            if device.connect_status != ConnectStatus.REACHABLE:
                device.connect_status = ConnectStatus.REACHABLE
                device.oper_status = OperStatus.ACTIVE
                device.reason = ''
                self.adapter_agent.update_device(device)

                self.heartbeat_alarm(self.device_id, True)

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

    def heartbeat_alarm(self, device_id, status, heartbeat_misses=0):
        try:
            ts = arrow.utcnow().timestamp
            alarm_data = {'heartbeats_missed': str(heartbeat_misses)}

            alarm_event = self.adapter_agent.create_alarm(
                id='voltha.{}.{}.olt'.format(self.adapter.name, device_id),
                resource_id='olt',
                type=AlarmEventType.EQUIPMENT,
                category=AlarmEventCategory.PON,
                severity=AlarmEventSeverity.CRITICAL,
                state=AlarmEventState.RAISED if status else AlarmEventState.CLEARED,
                description='OLT Alarm - Heartbeat - {}'.format('Raised'
                                                                if status
                                                                else 'Cleared'),
                context=alarm_data,
                raised_ts=ts)
            self.adapter_agent.submit_alarm(device_id, alarm_event)

        except Exception as e:
            self.log.exception('failed-to-submit-alarm', e=e)

    @staticmethod
    def parse_module_revision(revision):
        try:
            return datetime.datetime.strptime(revision, '%Y-%m-%d')
        except Exception:
            return None
