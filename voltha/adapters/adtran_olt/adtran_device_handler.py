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
import datetime
import pprint

import arrow
import re
import structlog
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks

from voltha.adapters.adtran_olt.net.adtran_rest import AdtranRestClient
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS
from voltha.registry import registry

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
        self.management_ports = {}  # port number -> Port   TODO: Not currently supported

        self.num_northbound_ports = None
        self.num_southbound_ports = None
        self.num_management_ports = None

        # REST Client
        self.ip_address = None
        self.rest_port = None
        self.rest_timeout = timeout
        self.rest_username = username
        self.rest_password = password
        self.rest_client = None

        # Heartbeat support
        self.heartbeat_count = 0
        self.heartbeat_miss = 0
        self.heartbeat_interval = 10  # TODO: Decrease before release
        self.heartbeat_failed_limit = 3
        self.heartbeat_timeout = 5
        self.heartbeat = None
        self.heartbeat_last_reason = ''

        self.max_ports = 1  # TODO: Remove later

    def __del__(self):
        # Kill any startup or heartbeat defers

        d, self.startup = self.startup, None
        if d is not None:
            d.cancel()

        h, self.heartbeat = self.heartbeat, None

        if h is not None:
            h.cancel()

        self.northbound_ports.clear()
        self.southbound_ports.clear()

    def __str__(self):
        return "AdtranDeviceHandler: {}:{}".format(self.ip_address, self.rest_port)

    @inlineCallbacks
    def activate(self, device):
        """
        Activate the OLT device

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        """
        self.log.info('AdtranDeviceHandler.activating', device=device)

        if self.logical_device_id is None:
            if not device.host_and_port:
                self.activate_failed(device, 'No host_and_port field provided')

            pattern = '(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
            info = re.match(pattern, device.host_and_port)

            if not info or len(info.group('host')) == 0 or len(info.group('port')) == 0 or \
                            (int(info.group('port')) if info.group('port') else None) is None:
                self.activate_failed(device, 'Invalid Host or Port provided',
                                     reachable=False)

            self.ip_address = str(info.group('host'))
            self.rest_port = int(info.group('port'))

            ############################################################################
            # Start initial discovery of RESTCONF support (if any)
            self.rest_client = AdtranRestClient(self.ip_address,
                                                self.rest_port,
                                                self.rest_username,
                                                self.rest_password,
                                                self.rest_timeout)
            try:
                # content: (dict) Modules from the hello message

                self.startup = self.rest_client.request('GET', self.HELLO_URI, name='hello')

                results = yield self.startup
                self.log.debug('HELLO Contents: {}'.format(pprint.PrettyPrinter().pformat(results)))

            except Exception as e:
                results = None
                self.log.exception('Initial RESTCONF adtran-hello failed', e=e)
                self.activate_failed(device, e.message, reachable=False)

            ############################################################################
            # TODO: Get these six via NETCONF and from the derived class

            device.model = 'TODO: Adtran PizzaBox, YUM'
            device.hardware_version = 'TODO: H/W Version'
            device.firmware_version = 'TODO: S/W Version'
            device.software_version = 'TODO: S/W Version'
            device.serial_number = 'TODO: Serial Number'

            device.root = True
            device.vendor = 'Adtran, Inc.'
            device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(device)

            try:
                # Enumerate and create Northbound NNI interfaces

                self.startup = self.enumerate_northbound_ports(device)
                results = yield self.startup

                self.startup = self.process_northbound_ports(device, results)
                yield self.startup

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

                for port in self.southbound_ports.itervalues():
                    self.adapter_agent.add_port(device.id, port.get_port())

            except Exception as e:
                self.log.exception('Southbound port enumeration and creation failed', e=e)
                self.activate_failed(device, e.message)

            # Complete activation by setting up logical device for this OLT and saving
            # off the devices parent_id

            ld = LogicalDevice(
                # NOTE: not setting id and datapath_id will let the adapter agent pick id
                desc=ofp_desc(mfr_desc=device.vendor,
                              hw_desc=device.hardware_version,
                              sw_desc=device.software_version,
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

            except Exception as e:
                self.log.exception('Failed to start northbound port(s)', e=e)
                self.activate_failed(device, e.message)

            try:
                start_downlinks = self.initial_port_state == AdminState.ENABLED

                for port in self.southbound_ports.itervalues():
                    self.startup = port.start() if start_downlinks else port.stop()
                    yield self.startup

            except Exception as e:
                self.log.exception('Failed to start southbound port(s)', e=e)
                self.activate_failed(device, e.message)

            # Complete device specific steps
            try:
                self.startup = self.complete_device_specific_activation(device, results)
                if self.startup is not None:
                    yield self.startup

            except Exception as e:
                self.log.exception('Device specific activation failed', e=e)
                self.activate_failed(device, e.message)

            # Schedule the heartbeat for the device

            self.start_heartbeat(delay=10)

            # Save off logical ID and specify that we active

            self.logical_device_id = ld_initialized.id

            device = self.adapter_agent.get_device(device.id)
            device.parent_id = ld_initialized.id
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
    def complete_device_specific_activation(self, _device, _content):
        return None

    def deactivate(self, device):
        # Clear off logical device ID
        self.logical_device_id = None

        # Kill any heartbeat poll
        h, self.heartbeat = self.heartbeat, None

        if h is not None:
            h.cancel()

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
        pass
        return None  # raise NotImplementedError('TODO: You should override this in your derived class???')

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
