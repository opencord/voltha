# Copyright 2017-present Adtran, Inc.
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
import shlex
import time

import structlog
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python.failure import Failure

from voltha.adapters.adtran_olt.net.adtran_netconf import AdtranNetconfClient
from voltha.adapters.adtran_olt.net.adtran_rest import AdtranRestClient
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS
from voltha.extensions.alarms.adapter_alarms import AdapterAlarms
from voltha.extensions.kpi.olt.olt_pm_metrics import OltPmMetrics
from common.utils.asleep import asleep
from flow.flow_tables import DeviceFlows, DownstreamFlows
from net.pio_zmq import DEFAULT_PIO_TCP_PORT
from net.pon_zmq import DEFAULT_PON_AGENT_TCP_PORT

_ = third_party

DEFAULT_MULTICAST_VLAN = 4000
BROADCOM_UNTAGGED_VLAN = 4091
DEFAULT_UTILITY_VLAN = BROADCOM_UNTAGGED_VLAN

_DEFAULT_RESTCONF_USERNAME = ""
_DEFAULT_RESTCONF_PASSWORD = ""
_DEFAULT_RESTCONF_PORT = 8081

_DEFAULT_NETCONF_USERNAME = ""
_DEFAULT_NETCONF_PASSWORD = ""
_DEFAULT_NETCONF_PORT = 830

_STARTUP_RETRY_TIMEOUT = 5       # 5 seconds delay after activate failed before we
_DEFAULT_RESOURCE_MGR_KEY = "adtran"


#############################################################
# Raise any Parsing Errors rather than sys.exit
def _parser_error(message):
    raise argparse.ArgumentTypeError(message)


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

    # CONFIG PARSING
    PARSER = argparse.ArgumentParser(description='Adtran Device Adapter')
    PARSER.add_argument('--nc_username', '-u', action='store', default=_DEFAULT_NETCONF_USERNAME,
                        help='NETCONF username')
    PARSER.add_argument('--nc_password', '-p', action='store', default=_DEFAULT_NETCONF_PASSWORD,
                        help='NETCONF Password')
    PARSER.add_argument('--nc_port', '-t', action='store', default=_DEFAULT_NETCONF_PORT,
                        type=int, choices=range(1, 65536), help='NETCONF TCP Port')
    PARSER.add_argument('--rc_username', '-U', action='store', default=_DEFAULT_RESTCONF_USERNAME,
                        help='REST username')
    PARSER.add_argument('--rc_password', '-P', action='store', default=_DEFAULT_RESTCONF_PASSWORD,
                        help='REST Password')
    PARSER.add_argument('--rc_port', '-T', action='store', default=_DEFAULT_RESTCONF_PORT,
                        type=int, choices=range(1, 65536), help='RESTCONF TCP Port')
    PARSER.add_argument('--zmq_port', '-z', action='store', default=DEFAULT_PON_AGENT_TCP_PORT,
                        type=int, choices=range(1, 65536), help='PON Agent ZeroMQ Port')
    PARSER.add_argument('--pio_port', '-Z', action='store', default=DEFAULT_PIO_TCP_PORT,
                        type=int, choices=range(1, 65536), help='PIO Service ZeroMQ Port')
    PARSER.add_argument('--multicast_vlan', '-M', action='store',
                        metavar='int', type=int, choices=range(1, 4095),
                        default=[DEFAULT_MULTICAST_VLAN],
                        nargs='+', help='Multicast VLANs are 1..4094'),
    PARSER.add_argument('--utility_vlan', '-B', action='store',
                        metavar='int', type=int, choices=range(1, 4095),
                        default=DEFAULT_UTILITY_VLAN,
                        help='VLAN for Controller based upstream flows from ONUs')
    PARSER.add_argument('--resource_mgr_key', '-o', action='store',
                        default=_DEFAULT_RESOURCE_MGR_KEY,
                        help='OLT Type to look up associated resource manager configuration')
    PARSER.error = _parser_error

    # Timeout Waiting on Rest Connectivity before initiating next HEARTBEAT
    HEARTBEAT_TIMEOUT = 5

    NC_CLIENT = AdtranNetconfClient

    def __init__(self, **kwargs):
        super(AdtranDeviceHandler, self).__init__()

        adapter = kwargs['adapter']
        device_id = kwargs['device-id']
        timeout = kwargs.get('timeout', 20)

        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.startup = None  # Startup/reboot deferred
        self.channel = None  # Proxy messaging channel with 'send' method
        self.logical_device_id = None
        self.pm_metrics = None
        self.alarms = None
        self.multicast_vlans = [DEFAULT_MULTICAST_VLAN]
        self.utility_vlan = DEFAULT_UTILITY_VLAN
        self.mac_address = '00:13:95:00:00:00'
        self._rest_support = None
        self._initial_enable_complete = False
        self.resource_mgr = None
        self.tech_profiles = None       # dict():  intf_id -> ResourceMgr.TechProfile

        # Northbound and Southbound ports
        self.northbound_ports = {}  # port number -> Port
        self.southbound_ports = {}  # port number -> Port  (For PON, use pon-id as key)
        # self.management_ports = {}  # port number -> Port   TODO: Not currently supported

        self.num_northbound_ports = None
        self.num_southbound_ports = None
        # self.num_management_ports = None

        self.ip_address = None
        self.host_and_port = None
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

        # Flow entries
        self.upstream_flows = DeviceFlows()
        self.downstream_flows = DownstreamFlows()

        self.max_nni_ports = 1  # TODO: This is a VOLTHA imposed limit in 'flow_decomposer.py
                                # and logical_device_agent.py

        self.resource_manager_key = _DEFAULT_RESOURCE_MGR_KEY
        # OMCI ZMQ Channel
        self.pon_agent_port = DEFAULT_PON_AGENT_TCP_PORT
        self.pio_port = DEFAULT_PIO_TCP_PORT

        # Heartbeat support
        self.heartbeat_count = 0
        self.heartbeat_miss = 0
        self.heartbeat_interval = 2  # TODO: Decrease before release or any scale testing
        self.heartbeat_failed_limit = 3
        self.heartbeat_timeout = 5
        self.heartbeat = None
        self.heartbeat_last_reason = ''

        # Installed flows
        self._evcs = {}  # Flow ID/name -> FlowEntry

    def _delete_logical_device(self):
        ldi, self.logical_device_id = self.logical_device_id, None

        if ldi is None:
            return

        self.log.debug('delete-logical-device', ldi=ldi)

        logical_device = self.adapter_agent.get_logical_device(ldi)
        self.adapter_agent.delete_logical_device(logical_device)

        device = self.adapter_agent.get_device(self.device_id)
        device.parent_id = ''

        #  Update the logical device mapping
        if ldi in self.adapter.logical_device_id_to_root_device_id:
            del self.adapter.logical_device_id_to_root_device_id[ldi]

    def __del__(self):
        # Kill any startup or heartbeat defers
        self._cancel_tasks()
        self._suspend_heartbeat()

        # Remove the logical device
        self._delete_logical_device()

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

    @property
    def all_ports(self):
        for port in self.northbound_ports.itervalues():
            yield port
        for port in self.southbound_ports.itervalues():
            yield port

    def add_evc(self, evc):
        if self._evcs is not None and evc.name not in self._evcs:
            self._evcs[evc.name] = evc

    def remove_evc(self, evc):
        if self._evcs is not None and evc.name in self._evcs:
            del self._evcs[evc.name]

    def parse_provisioning_options(self, device):
        if device.ipv4_address:
            self.ip_address = device.ipv4_address
            self.host_and_port = '{}:{}'.format(self.ip_address,
                                                self.netconf_port)
        elif device.host_and_port:
            self.host_and_port = device.host_and_port.split(":")
            self.ip_address = self.host_and_port[0]
            self.netconf_port = int(self.host_and_port[1])
            self.adapter_agent.update_device(device)

        else:
            self.activate_failed(device, 'No IP_address field provided')

        try:
            args = self.PARSER.parse_args(shlex.split(device.extra_args))

            # May have multiple multicast VLANs
            self.multicast_vlans = args.multicast_vlan
            self.utility_vlan = args.utility_vlan

            self.netconf_username = args.nc_username
            self.netconf_password = args.nc_password
            self.netconf_port = args.nc_port

            self.rest_username = args.rc_username
            self.rest_password = args.rc_password
            self.rest_port = args.rc_port

            self.pon_agent_port = args.zmq_port
            self.pio_port = args.pio_port
            self.resource_manager_key = args.resource_mgr_key

            if not self.rest_username:
                self.rest_username = 'NDE0NDRkNDk0ZQ==\n'.\
                    decode('base64').decode('hex')
            if not self.rest_password:
                self.rest_password = 'NTA0MTUzNTM1NzRmNTI0NA==\n'.\
                    decode('base64').decode('hex')
            if not self.netconf_username:
                self.netconf_username = 'Njg3Mzc2NzI2ZjZmNzQ=\n'.\
                    decode('base64').decode('hex')
            if not self.netconf_password:
                self.netconf_password = 'NDI0ZjUzNDM0Zg==\n'.\
                    decode('base64').decode('hex')

        except argparse.ArgumentTypeError as e:
            self.activate_failed(device,
                                 'Invalid arguments: {}'.format(e.message),
                                 reachable=False)
        except Exception as e:
            self.log.exception('option_parsing_error: {}'.format(e.message))

    @inlineCallbacks
    def activate(self, done_deferred, reconciling):
        """
        Activate the OLT device

        :param done_deferred: (Deferred) Deferred to fire when done
        :param reconciling: If True, this adapter is taking over for a previous adapter
                            for an existing OLT
        """
        self.log.info('AdtranDeviceHandler.activating', reconciling=reconciling)

        if self.logical_device_id is None:
            device = self.adapter_agent.get_device(self.device_id)

            try:
                # Parse our command line options for this device
                self.parse_provisioning_options(device)

                ############################################################################
                # Start initial discovery of NETCONF support (if any)
                try:
                    device.reason = 'establishing NETCONF connection'
                    self.adapter_agent.update_device(device)

                    self.startup = self.make_netconf_connection()
                    yield self.startup

                except Exception as e:
                    self.log.exception('netconf-connection', e=e)
                    returnValue(self.restart_activate(done_deferred, reconciling))

                ############################################################################
                # Update access information on network device for full protocol support
                try:
                    device.reason = 'device networking validation'
                    self.adapter_agent.update_device(device)
                    self.startup = self.ready_network_access()
                    yield self.startup

                except Exception as e:
                    self.log.exception('network-setup', e=e)
                    returnValue(self.restart_activate(done_deferred, reconciling))

                ############################################################################
                # Restconf setup
                try:
                    device.reason = 'establishing RESTConf connections'
                    self.adapter_agent.update_device(device)
                    self.startup = self.make_restconf_connection()
                    yield self.startup

                except Exception as e:
                    self.log.exception('restconf-setup', e=e)
                    returnValue(self.restart_activate(done_deferred, reconciling))

                ############################################################################
                # Get the device Information
                if reconciling:
                    device.connect_status = ConnectStatus.REACHABLE
                    self.adapter_agent.update_device(device)
                else:
                    try:
                        device.reason = 'retrieving device information'
                        self.adapter_agent.update_device(device)
                        self.startup = self.get_device_info(device)
                        results = yield self.startup

                        device.model = results.get('model', 'unknown')
                        device.hardware_version = results.get('hardware_version', 'unknown')
                        device.firmware_version = results.get('firmware_version', 'unknown')
                        device.serial_number = results.get('serial_number', 'unknown')
                        device.images.image.extend(results.get('software-images', []))

                        device.root = True
                        device.vendor = results.get('vendor', 'Adtran Inc.')
                        device.connect_status = ConnectStatus.REACHABLE
                        self.adapter_agent.update_device(device)

                    except Exception as e:
                        self.log.exception('device-info', e=e)
                        returnValue(self.restart_activate(done_deferred, reconciling))

                try:
                    # Enumerate and create Northbound NNI interfaces
                    device.reason = 'enumerating northbound interfaces'
                    self.adapter_agent.update_device(device)
                    self.startup = self.enumerate_northbound_ports(device)
                    results = yield self.startup

                    self.startup = self.process_northbound_ports(device, results)
                    yield self.startup

                    device.reason = 'adding northbound interfaces to adapter'
                    self.adapter_agent.update_device(device)

                    if not reconciling:
                        for port in self.northbound_ports.itervalues():
                            self.adapter_agent.add_port(device.id, port.get_port())

                except Exception as e:
                    self.log.exception('NNI-enumeration', e=e)
                    returnValue(self.restart_activate(done_deferred, reconciling))

                try:
                    # Enumerate and create southbound interfaces
                    device.reason = 'enumerating southbound interfaces'
                    self.adapter_agent.update_device(device)
                    self.startup = self.enumerate_southbound_ports(device)
                    results = yield self.startup

                    self.startup = self.process_southbound_ports(device, results)
                    yield self.startup

                    device.reason = 'adding southbound interfaces to adapter'
                    self.adapter_agent.update_device(device)

                    if not reconciling:
                        for port in self.southbound_ports.itervalues():
                            self.adapter_agent.add_port(device.id, port.get_port())

                except Exception as e:
                    self.log.exception('PON_enumeration', e=e)
                    returnValue(self.restart_activate(done_deferred, reconciling))

                # Initialize resource manager
                self.initialize_resource_manager()

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
                    assert device.parent_id == ld_initialized.id, \
                        'parent ID not Logical device ID'

                else:
                    # Complete activation by setting up logical device for this OLT and saving
                    # off the devices parent_id
                    ld_initialized = self.create_logical_device(device)

                ############################################################################
                # Setup PM configuration for this device
                if self.pm_metrics is None:
                    try:
                        device.reason = 'setting up Performance Monitoring configuration'
                        self.adapter_agent.update_device(device)

                        kwargs = {
                            'nni-ports': self.northbound_ports.values(),
                            'pon-ports': self.southbound_ports.values()
                        }
                        self.pm_metrics = OltPmMetrics(self.adapter_agent, self.device_id,
                                                       ld_initialized.id, grouped=True,
                                                       freq_override=False, **kwargs)

                        pm_config = self.pm_metrics.make_proto()
                        self.log.debug("initial-pm-config", pm_config=pm_config)
                        self.adapter_agent.update_device_pm_config(pm_config, init=True)

                    except Exception as e:
                        self.log.exception('pm-setup', e=e)
                        self.activate_failed(device, e.message, reachable=False)

                ############################################################################
                # Set the ports in a known good initial state
                if not reconciling:
                    device.reason = 'setting device to a known initial state'
                    self.adapter_agent.update_device(device)
                    try:
                        for port in self.all_ports:
                            self.startup = yield port.reset()

                    except Exception as e:
                        self.log.exception('port-reset', e=e)
                        returnValue(self.restart_activate(done_deferred, reconciling))

                ############################################################################
                # Create logical ports for all southbound and northbound interfaces
                try:
                    device.reason = 'creating logical ports'
                    self.adapter_agent.update_device(device)
                    self.startup = self.create_logical_ports(device, ld_initialized, reconciling)
                    yield self.startup

                except Exception as e:
                    self.log.exception('logical-port', e=e)
                    returnValue(self.restart_activate(done_deferred, reconciling))

                ############################################################################
                # Setup Alarm handler
                device.reason = 'setting up adapter alarms'
                self.adapter_agent.update_device(device)

                self.alarms = AdapterAlarms(self.adapter_agent, device.id, ld_initialized.id)

                ############################################################################
                # Register for ONU detection
                # self.adapter_agent.register_for_onu_detect_state(device.id)
                # Complete device specific steps
                try:
                    self.log.debug('device-activation-procedures')
                    device.reason = 'performing model specific activation procedures'
                    self.adapter_agent.update_device(device)
                    self.startup = self.complete_device_specific_activation(device, reconciling)
                    yield self.startup

                except Exception as e:
                    self.log.exception('device-activation-procedures', e=e)
                    returnValue(self.restart_activate(done_deferred, reconciling))

                # Schedule the heartbeat for the device
                self.log.debug('starting-heartbeat')
                self.start_heartbeat(delay=10)

                device = self.adapter_agent.get_device(device.id)
                device.parent_id = ld_initialized.id
                device.oper_status = OperStatus.ACTIVE
                device.reason = ''
                self.adapter_agent.update_device(device)
                self.logical_device_id = ld_initialized.id

                # Start collecting stats from the device after a brief pause
                reactor.callLater(10, self.pm_metrics.start_collector)

                # Signal completion
                self._initial_enable_complete = True
                self.log.info('activated')

            except Exception as e:
                self.log.exception('activate', e=e)
                if done_deferred is not None:
                    done_deferred.errback(e)

        if done_deferred is not None:
            done_deferred.callback('activated')

        returnValue('activated')

    def restart_activate(self, done_deferred, reconciling):
        """
        Startup activation failed, pause a short period of time and retry

        :param done_deferred: (deferred) Deferred to fire upon completion of activation
        :param reconciling: (bool) If true, we are reconciling after moving to a new vCore
        """
        self._cancel_tasks()
        device = self.adapter_agent.get_device(self.device_id)
        device.reason = 'Failed during {}, retrying'.format(device.reason)
        self.adapter_agent.update_device(device)
        self.startup = reactor.callLater(_STARTUP_RETRY_TIMEOUT, self.activate,
                                         done_deferred, reconciling)
        return 'retrying'

    @inlineCallbacks
    def ready_network_access(self):
        # Override in device specific class if needed
        yield defer.Deferred()

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
        raise Exception('Failed to activate OLT: {}'.format(device.reason))

    @inlineCallbacks
    def _close_netconf_connection(self):
        resp = None
        if self.netconf_client:
            try:
                resp = yield self.netconf_client.close()
            except Exception as e:
                self.log.exception('NETCONF-shutdown', e, device_id=self.device_id)
            finally:
                self._netconf_client = None
        returnValue(resp)

    @inlineCallbacks
    def make_netconf_connection(self, connect_timeout=None,
                                close_existing_client=False):

        if close_existing_client:
            yield self._close_netconf_connection()

        client = self.netconf_client

        if client is None:
            client = self.NC_CLIENT(self.ip_address,
                                    self.netconf_port,
                                    self.netconf_username,
                                    self.netconf_password,
                                    self.timeout)
        if client.connected:
            self._netconf_client = client
            returnValue(True)

        timeout = connect_timeout or self.timeout

        try:
            results = yield client.connect(timeout)
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
            desc=ofp_desc(mfr_desc='VOLTHA Project',
                          hw_desc=device.hardware_version,
                          sw_desc=version,
                          serial_num=device.serial_number,
                          dp_desc='n/a'),
            switch_features=ofp_switch_features(n_buffers=256,
                                                n_tables=2,
                                                capabilities=(
                                                    OFPC_FLOW_STATS |
                                                    OFPC_TABLE_STATS |
                                                    OFPC_GROUP_STATS |
                                                    OFPC_PORT_STATS)),
            root_device_id=device.id)

        ld_initialized = self.adapter_agent.create_logical_device(ld,
                                                                  dpid=self.mac_address)
        return ld_initialized

    @inlineCallbacks
    def create_logical_ports(self, device, ld_initialized, reconciling):
        if not reconciling:
            # Add the ports to the logical device

            for port in self.all_ports:
                lp = port.get_logical_port()
                if lp is not None:
                    self.adapter_agent.add_logical_port(ld_initialized.id, lp)

            # Clean up all EVCs, EVC maps and ACLs (exceptions are ok)
            try:
                from flow.evc import EVC
                self.startup = yield EVC.remove_all(self.netconf_client)
                from flow.utility_evc import UtilityEVC
                self.startup = yield UtilityEVC.remove_all(self.netconf_client)

            except Exception as e:
                self.log.exception('evc-cleanup', e=e)

            try:
                from flow.evc_map import EVCMap
                self.startup = yield EVCMap.remove_all(self.netconf_client)

            except Exception as e:
                self.log.exception('evc-map-cleanup', e=e)

            from flow.acl import ACL
            ACL.clear_all(device.id)
            try:
                self.startup = yield ACL.remove_all(self.netconf_client)

            except Exception as e:
                self.log.exception('acl-cleanup', e=e)

            from flow.flow_entry import FlowEntry
            FlowEntry.clear_all(self)

            from download import Download
            Download.clear_all(self.netconf_client)

        # Start/stop the interfaces as needed. These are deferred calls

        dl = []
        for port in self.northbound_ports.itervalues():
            try:
                dl.append(port.start())
            except Exception as e:
                self.log.exception('northbound-port-startup', e=e)

        for port in self.southbound_ports.itervalues():
            try:
                dl.append(port.start() if port.admin_state == AdminState.ENABLED else port.stop())
            except Exception as e:
                self.log.exception('southbound-port-startup', e=e)

        results = yield defer.gatherResults(dl, consumeErrors=True)

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

    def initialize_resource_manager(self):
        raise NotImplementedError('implement in derived class')

    @inlineCallbacks
    def complete_device_specific_activation(self, _device, _reconciling):
        # NOTE: Override this in your derived class for any device startup completion
        yield defer.Deferred()

    @inlineCallbacks
    def disable(self):
        """
        This is called when a previously enabled device needs to be disabled based on a NBI call.
        """
        self.log.info('disabling', device_id=self.device_id)
        self._cancel_tasks()

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)
        device.reason = 'Disabling'
        self.adapter_agent.update_device(device)

        # Drop registration for ONU detection
        # self.adapter_agent.unregister_for_onu_detect_state(self.device.id)
        self._suspend_heartbeat()
        
        # Update the operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      admin_state=AdminState.DISABLED)

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        # Remove the logical device to clear out logical device ports for any
        # previously activated ONUs
        self._delete_logical_device()

        # Set all ports to disabled
        self.adapter_agent.disable_all_ports(self.device_id)

        dl = []
        for port in self.all_ports:
            dl.append(port.stop())

        # NOTE: Flows removed before this method is called
        # Wait for completion

        self.startup = defer.gatherResults(dl, consumeErrors=True)
        yield self.startup

        if self.netconf_client:
            self.netconf_client.close()

        self._netconf_client = None
        self._rest_client = None

        device.reason = ''
        self.adapter_agent.update_device(device)
        self.log.info('disabled', device_id=device.id)
        returnValue(None)

    @inlineCallbacks
    def reenable(self, done_deferred=None):
        """
        This is called when a previously disabled device needs to be enabled based on a NBI call.
        :param done_deferred: (Deferred) Deferred to fire when done
        """
        self.log.info('re-enabling', device_id=self.device_id)
        self._cancel_tasks()

        if not self._initial_enable_complete:
            # Never contacted the device on the initial startup, do 'activate' steps instead
            self.startup = reactor.callLater(0, self.activate, done_deferred, False)
            returnValue('activating')

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

        # Reenable any previously configured southbound ports
        for port in self.southbound_ports.itervalues():
            self.log.debug('reenable-pon-port', pon_id=port.pon_id)
            port.enabled = True

        # Flows should not exist on re-enable. They are re-pushed
        if len(self._evcs):
            self.log.warn('evcs-found', evcs=self._evcs)
        self._evcs.clear()

        try:
            yield self.make_restconf_connection()

        except Exception as e:
            self.log.exception('adtran-hello-reconnect', e=e)

        try:
            yield self.make_netconf_connection()

        except Exception as e:
            self.log.exception('NETCONF-re-connection', e=e)

        # Recreate the logical device
        # NOTE: This causes a flow update event
        ld_initialized = self.create_logical_device(device)

        # Create logical ports for all southbound and northbound interfaces
        try:
            self.startup = self.create_logical_ports(device, ld_initialized, False)
            yield self.startup

        except Exception as e:
            self.log.exception('logical-port-creation', e=e)

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        device.reason = ''
        self.logical_device_id = ld_initialized.id

        # update device active status now
        self.adapter_agent.update_device(device)

        # Reenable all child devices
        self.adapter_agent.update_child_devices_state(device.id,
                                                      admin_state=AdminState.ENABLED)
        # Schedule the heartbeat for the device
        self.log.debug('starting-heartbeat')
        self.start_heartbeat(delay=5)

        self.log.info('re-enabled', device_id=device.id)

        if done_deferred is not None:
            done_deferred.callback('Done')

        returnValue('reenabled')

    @inlineCallbacks
    def reboot(self):
        """
        This is called to reboot a device based on a NBI call.  The admin state of the device
        will not change after the reboot.
        """
        self.log.debug('reboot', device_id=self.device_id)

        if not self._initial_enable_complete:
            # Never contacted the device on the initial startup, do 'activate' steps instead
            returnValue('failed')

        self._cancel_tasks()
        # Issue reboot command

        try:
            yield self.netconf_client.rpc(AdtranDeviceHandler.RESTART_RPC)

        except Exception as e:
            self.log.exception('NETCONF-shutdown', e=e)
            returnValue(defer.fail(Failure()))

        # self.adapter_agent.unregister_for_onu_detect_state(self.device.id)
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

        # Shutdown communications with OLT. Typically it takes about 2 seconds
        # or so after the reply before the restart actually occurs

        response = yield self._close_netconf_connection()
        if hasattr(response, 'ok'):
            self.log.debug('Restart response XML was: {}'.format('ok' if response.ok else 'bad'))

        self._rest_client = None

        # Run remainder of reboot process as a new task. The OLT then may be up in a
        # few moments or may take 3 minutes or more depending on any self tests enabled

        current_time = time.time()
        timeout = current_time + self.restart_failure_timeout

        self.startup = reactor.callLater(10, self._finish_reboot, timeout,
                                         previous_oper_status,
                                         previous_conn_status)
        returnValue(self.startup)

    @inlineCallbacks
    def _finish_reboot(self, timeout, previous_oper_status, previous_conn_status):
        # Now wait until REST & NETCONF are re-established or we timeout

        self.log.info('Resuming-activity',
                      remaining=timeout - time.time(), timeout=timeout, current=time.time())

        if self.rest_client is None:
            try:
                yield self.make_restconf_connection(get_timeout=10)

            except Exception:
                self.log.debug('No RESTCONF connection yet')
                self._rest_client = None

        if self.netconf_client is None:
            try:
                yield self.make_netconf_connection(connect_timeout=10)
            except:
                yield self._close_netconf_connection()

        if self.netconf_client is None or self.rest_client is None:
            current_time = time.time()
            if current_time < timeout:
                self.startup = reactor.callLater(5, self._finish_reboot, timeout,
                                                 previous_oper_status,
                                                 previous_conn_status)
                returnValue(self.startup)

            if self.netconf_client is None:
                self.log.error('NETCONF-restore-failure')
                pass        # TODO: What is best course of action if cannot get clients back?

            if self.rest_client is None:
                self.log.error('RESTCONF-restore-failure')
                pass        # TODO: What is best course of action if cannot get clients back?

        # Pause additional 5 seconds to let allow OLT microservices to complete some more initialization
        yield asleep(5)
        # TODO: Update device info. The software images may have changed...
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

        for port in self.all_ports:
            dl.append(port.restart())

        try:
            yield defer.gatherResults(dl, consumeErrors=True)

        except Exception as e:
            self.log.exception('port-restart', e=e)

        # Re-subscribe for ONU detection
        # self.adapter_agent.register_for_onu_detect_state(self.device.id)
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

    def _cancel_tasks(self):
        # Cancel any outstanding tasks
        d, self.startup = self.startup, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    @inlineCallbacks
    def delete(self):
        """
        This is called to delete a device from the PON based on a NBI call.
        If the device is an OLT then the whole PON will be deleted.
        """
        self.log.info('deleting', device_id=self.device_id)
        self._cancel_tasks()
        self._suspend_heartbeat()

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)
        device.reason = 'Deleting'
        self.adapter_agent.update_device(device)

        # self.adapter_agent.unregister_for_onu_detect_state(self.device.id)

        # Remove all flows from the device
        # TODO: Create a bulk remove-all by device-id

        evcs = self._evcs
        self._evcs.clear()

        for evc in evcs:
            evc.delete()   # TODO: implement bulk-flow procedures

        # Remove all child devices
        self.adapter_agent.delete_all_child_devices(self.device_id)

        # Remove the logical device (should already be gone if disable came first)
        self._delete_logical_device()

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        # Tell all ports to stop any background processing

        for port in self.all_ports:
            port.delete()

        self.northbound_ports.clear()
        self.southbound_ports.clear()

        # Shutdown communications with OLT
        yield self._close_netconf_connection()
        self._rest_client = None
        mgr, self.resource_mgr = self.resource_mgr, None
        if mgr:
            del mgr

        self.log.info('deleted', device_id=self.device_id)

    def delete_child_device(self, proxy_address):
        self.log.debug('sending-deactivate-onu',
                       olt_device_id=self.device_id,
                       proxy_address=proxy_address)
        try:
            children = self.adapter_agent.get_child_devices(self.device_id)
            for child in children:
                if child.proxy_address.onu_id == proxy_address.onu_id and \
                        child.proxy_address.channel_id == proxy_address.channel_id:
                    self.adapter_agent.delete_child_device(self.device_id,
                                                           child.id,
                                                           onu_device=child)
                    break

        except Exception as e:
            self.log.error('adapter_agent error', error=e)

    def packet_out(self, egress_port, msg):
        raise NotImplementedError('Overload in a derived class')

    def update_pm_config(self, device, pm_config):
        # TODO: This has not been tested
        self.log.info('update_pm_config', pm_config=pm_config)
        self.pm_metrics.update(pm_config)

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
        yield None
        device = {}
        returnValue(device)

    def start_heartbeat(self, delay=10):
        assert delay > 1, 'Minimum heartbeat is 1 second'
        self.log.info('Starting-Device-Heartbeat ***')
        self.heartbeat = reactor.callLater(delay, self.check_pulse)
        return self.heartbeat

    def _suspend_heartbeat(self):
        # Suspend any active health-checks / pings
        h, self.heartbeat = self.heartbeat, None
        try:
            if h is not None and not h.called:
                h.cancel()
        except:
            pass

    def check_pulse(self):
        if self.logical_device_id is not None:
            try:
                self.heartbeat = self.rest_client.request('GET', self.HELLO_URI,
                                                          name='hello', timeout=self.HEARTBEAT_TIMEOUT)
                self.heartbeat.addCallbacks(self._heartbeat_success)
            except Exception as e:
                self.heartbeat = reactor.callLater(self.HEARTBEAT_TIMEOUT, self._heartbeat_fail, e)

    def on_heatbeat_alarm(self, active):
        if active and (self.netconf_client is None or not self.netconf_client.connected):
            self.make_netconf_connection(close_existing_client=True)

    def heartbeat_check_status(self, _):
        """
        Check the number of heartbeat failures against the limit and emit an alarm if needed
        """
        device = self.adapter_agent.get_device(self.device_id)

        try:
            from voltha.extensions.alarms.heartbeat_alarm import HeartbeatAlarm

            if self.heartbeat_miss >= self.heartbeat_failed_limit:
                if device.connect_status == ConnectStatus.REACHABLE:
                    self.log.warning('heartbeat-failed', count=self.heartbeat_miss)
                    device.connect_status = ConnectStatus.UNREACHABLE
                    device.oper_status = OperStatus.FAILED
                    device.reason = self.heartbeat_last_reason
                    self.adapter_agent.update_device(device)
                    HeartbeatAlarm(self.alarms, 'olt', self.heartbeat_miss).raise_alarm()
                    self.on_heatbeat_alarm(True)
            else:
                # Update device states
                if device.connect_status != ConnectStatus.REACHABLE:
                    device.connect_status = ConnectStatus.REACHABLE
                    device.oper_status = OperStatus.ACTIVE
                    device.reason = ''
                    self.adapter_agent.update_device(device)
                    HeartbeatAlarm(self.alarms, 'olt').clear_alarm()
                    self.on_heatbeat_alarm(False)

                if self.netconf_client is None or not self.netconf_client.connected:
                    self.make_netconf_connection(close_existing_client=True)

        except Exception as e:
            self.log.exception('heartbeat-check', e=e)

        # Reschedule next heartbeat
        if self.logical_device_id is not None:
            self.heartbeat_count += 1
            self.heartbeat = reactor.callLater(self.heartbeat_interval, self.check_pulse)

    def _heartbeat_success(self, results):
        self.log.debug('heartbeat-success')
        self.heartbeat_miss = 0
        self.heartbeat_last_reason = ''
        self.heartbeat_check_status(results)

    def _heartbeat_fail(self, failure):
        self.heartbeat_miss += 1
        self.log.info('heartbeat-miss', failure=failure,
                      count=self.heartbeat_count,
                      miss=self.heartbeat_miss)
        self.heartbeat_last_reason = 'RESTCONF connectivity error'
        self.heartbeat_check_status(None)

    @staticmethod
    def parse_module_revision(revision):
        try:
            return datetime.datetime.strptime(revision, '%Y-%m-%d')
        except Exception:
            return None
