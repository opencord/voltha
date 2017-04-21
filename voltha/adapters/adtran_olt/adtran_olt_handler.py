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
import datetime
import pprint
import random

from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks

from adtran_device_handler import AdtranDeviceHandler
from codec.olt_state import OltState
from net.adtran_zmq import AdtranZmqClient
from voltha.extensions.omci.omci import *
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Device
from voltha.protos.openflow_13_pb2 import OFPPF_100GB_FD, OFPPF_FIBER, OFPPS_LIVE


# from ncclient import manager


class AdtranOltHandler(AdtranDeviceHandler):
    """
    The OLT Handler is used to wrap a single instance of a 10G OLT 1-U pizza-box
    """
    MIN_OLT_HW_VERSION = datetime.datetime(2017, 1, 5)

    # Full table output

    GPON_OLT_HW_URI = '/restconf/data/gpon-olt-hw'
    GPON_OLT_HW_STATE_URI = '/restconf/data/gpon-olt-hw:olt-state'
    GPON_PON_CONFIG_LIST_URI = '/restconf/data/gpon-olt-hw:olt/pon'

    # Per-PON info

    GPON_PON_PON_STATE_URI = '/restconf/data/gpon-olt-hw:olt-state/pon={}'  # .format(pon)
    GPON_PON_CONFIG_URI = '/restconf/data/gpon-olt-hw:olt/pon={}'  # .format(pon)
    GPON_PON_ONU_CONFIG_URI = '/restconf/data/gpon-olt-hw:olt/pon={}/onus/onu'  # .format(pon)

    GPON_PON_DISCOVER_ONU = '/restconf/operations/gpon-olt-hw:discover-onu'

    def __init__(self, adapter, device_id, username="", password="",
                 timeout=20, initial_port_state=True):
        super(AdtranOltHandler, self).__init__(adapter, device_id, username=username,
                                               password=password, timeout=timeout)
        self.gpon_olt_hw_revision = None
        self.status_poll = None
        self.status_poll_interval = 5.0
        self.status_poll_skew = self.status_poll_interval / 10
        self.initial_port_state = AdminState.ENABLED if initial_port_state else AdminState.DISABLED
        self.initial_onu_state = AdminState.DISABLED

        self.zmq_client = None
        self.nc_client = None

    def __del__(self):
        # OLT Specific things here.
        #
        # If you receive this during 'enable' of the object, you probably threw an
        # uncaught exception which trigged an errback in the VOLTHA core.

        d, self.status_poll = self.status_poll, None

        # TODO Any OLT device specific cleanup here
        #     def get_channel(self):
        #         if self.channel is None:
        #             device = self.adapter_agent.get_device(self.device_id)
        #         return self.channel
        #
        # Clean up base class as well

        AdtranDeviceHandler.__del__(self)

    def __str__(self):
        return "AdtranOltHandler: {}:{}".format(self.ip_address, self.rest_port)

    @inlineCallbacks
    def enumerate_northbound_ports(self, device):
        """
        Enumerate all northbound ports of this device.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
        # TODO: For now, hard code some JSON. Eventually will be XML from NETConf

        ports = [
            {'port_no': 1,
             'admin_state': AdminState.ENABLED,
             'oper_status': OperStatus.ACTIVE,
             'ofp_state': OFPPS_LIVE,
             'ofp_capabilities': OFPPF_100GB_FD | OFPPF_FIBER,
             'current_speed': OFPPF_100GB_FD,
             'max_speed': OFPPF_100GB_FD},
            {'port_no': 2,
             'admin_state': AdminState.ENABLED,
             'oper_status': OperStatus.ACTIVE,
             'ofp_state': OFPPS_LIVE,
             'ofp_capabilities': OFPPF_100GB_FD | OFPPF_FIBER,
             'current_speed': OFPPF_100GB_FD,
             'max_speed': OFPPF_100GB_FD},
            {'port_no': 3,
             'admin_state': AdminState.ENABLED,
             'oper_status': OperStatus.ACTIVE,
             'ofp_state': OFPPS_LIVE,
             'ofp_capabilities': OFPPF_100GB_FD | OFPPF_FIBER,
             'current_speed': OFPPF_100GB_FD,
             'max_speed': OFPPF_100GB_FD},
            {'port_no': 4,
             'admin_state': AdminState.ENABLED,
             'oper_status': OperStatus.ACTIVE,
             'ofp_state': OFPPS_LIVE,
             'ofp_capabilities': OFPPF_100GB_FD | OFPPF_FIBER,
             'current_speed': OFPPF_100GB_FD,
             'max_speed': OFPPF_100GB_FD}
        ]

        yield returnValue(ports)

    def process_northbound_ports(self, device, results):
        """
        Process the results from the 'enumerate_northbound_ports' method.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :param results: Results from the 'enumerate_northbound_ports' method that
                you implemented. The type and contents are up to you to
        :return: (Deferred or None).
        """
        from nni_port import NniPort

        for port in results:
            port_no = port['port_no']
            self.log.info('Processing northbound port {}/{}'.format(port_no, port['port_no']))
            assert port_no
            assert port_no not in self.northbound_ports
            self.northbound_ports[port_no] = NniPort(self, **port)

        self.num_northbound_ports = len(self.northbound_ports)

    @inlineCallbacks
    def enumerate_southbound_ports(self, device):
        """
        Enumerate all southbound ports of this device.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
        ###############################################################################
        # Determine number of southbound ports. We know it is 16, but this keeps this
        # device adapter generic for our other OLTs up to this point.

        self.startup = self.rest_client.request('GET', self.GPON_PON_CONFIG_LIST_URI, 'pon-config')
        results = yield self.startup
        returnValue(results)

    def process_southbound_ports(self, device, results):
        """
        Process the results from the 'enumerate_southbound_ports' method.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :param results: Results from the 'enumerate_southbound_ports' method that
                you implemented. The type and contents are up to you to
        :return: (Deferred or None).
        """
        from pon_port import PonPort

        for pon in results:

            # Number PON Ports after the NNI ports
            pon_id = pon['pon-id']
            log.info('Processing pon port {}'.format(pon_id))

            assert pon_id not in self.southbound_ports

            admin_state = AdminState.ENABLED if pon.get('enabled',
                                                        PonPort.DEFAULT_ENABLED) else AdminState.DISABLED

            self.southbound_ports[pon_id] = PonPort(pon_id,
                                                    self._pon_id_to_port_number(pon_id),
                                                    self,
                                                    admin_state=admin_state)

            # TODO: For now, limit number of PON ports to make debugging easier

            if len(self.southbound_ports) >= self.max_ports:
                break

        self.num_southbound_ports = len(self.southbound_ports)

    def complete_device_specific_activation(self, device, results):
        """
        Perform an initial network operation to discover the device hardware
        and software version. Serial Number would be helpful as well.

        This method is called from within the base class's activate generator.

        :param device: A voltha.Device object, with possible device-type
                specific extensions. Such extensions shall be described as part of
                the device type specification returned by device_types().

        :param results: (dict) original adtran-hello RESTCONF results body
        """
        #
        # For the pizzabox OLT, periodically query the OLT state of all PONs. This
        # is simpler then having each PON port do its own poll.  From this, we can:
        #
        # o Discover any new or missing ONT/ONUs
        #
        # o TODO Discover any LOS for any ONT/ONUs
        #
        # o TODO Update some PON level statistics

        self.zmq_client = AdtranZmqClient(self.ip_address, self.rx_packet)
        # self.nc_client = manager.connect(host='',  # self.ip_address,
        #                                  username=self.rest_username,
        #                                  password=self.rest_password,
        #                                  hostkey_verify=False,
        #                                  allow_agent=False,
        #                                  look_for_keys=False)

        self.status_poll = reactor.callLater(1, self.poll_for_status)
        return None

    def rx_packet(self, message):
        try:
            self.log.info('rx_Packet: Message from ONU')

            pon_id, onu_id, msg, is_omci = AdtranZmqClient.decode_packet(message)

            if is_omci:
                proxy_address = Device.ProxyAddress(device_id=self.device_id,
                                                    channel_id=self._get_channel_id(pon_id, onu_id),
                                                    onu_id=onu_id)

                self.adapter_agent.receive_proxied_message(proxy_address, msg)
            else:
                pass  # TODO: Packet in support not yet supported
                # self.adapter_agent.send_packet_in(logical_device_id=logical_device_id,
                #                                   logical_port_no=cvid,  # C-VID encodes port no
                #                                   packet=str(msg))
        except Exception as e:
            self.log.exception('Exception during RX Packet processing', e=e)

    def poll_for_status(self):
        self.log.debug('Initiating status poll')

        device = self.adapter_agent.get_device(self.device_id)

        if device.admin_state == AdminState.ENABLED:
            uri = AdtranOltHandler.GPON_OLT_HW_STATE_URI
            name = 'pon-status-poll'
            self.startup = self.rest_client.request('GET', uri, name=name)
            self.startup.addBoth(self.status_poll_complete)

    def status_poll_complete(self, results):
        """
        Results of the status poll
        
        :param results: 
        """
        self.log.debug('Status poll results: {}'.
                       format(pprint.PrettyPrinter().pformat(results)))

        if isinstance(results, dict) and 'pon' in results:
            try:
                for pon_id, pon in OltState(results).pons.iteritems():
                    if pon_id in self.southbound_ports:
                        self.southbound_ports[pon_id].process_status_poll(pon)

            except Exception as e:
                self.log.exception('Exception during PON status poll processing', e=e)
        else:
            self.log.warning('Had some kind of polling error')

        # Reschedule

        delay = self.status_poll_interval
        delay += random.uniform(-delay / 10, delay / 10)

        self.status_poll = reactor.callLater(delay, self.poll_for_status)

    @inlineCallbacks
    def deactivate(self, device):
        # OLT Specific things here

        d, self.startup = self.startup, None
        if d is not None:
            d.cancel()

        self.pons.clear()

        # TODO: Any other? OLT specific deactivate steps

        # Call into base class and have it clean up as well
        super(AdtranOltHandler, self).deactivate(device)

    @inlineCallbacks
    def update_flow_table(self, flows, device):
        self.log.info('bulk-flow-update', device_id=device.id, flows=flows)
        raise NotImplementedError('TODO: Not yet implemented')

    @inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        self.log.info('sending-proxied-message: message type: {}'.format(type(msg)))

        if isinstance(msg, Packet):
            msg = str(msg)

        if self.zmq_client is not None:
            pon_id = self._channel_id_to_pon_id(proxy_address.channel_id, proxy_address.onu_id)
            onu_id = proxy_address.onu_id

            data = AdtranZmqClient.encode_omci_message(msg, pon_id, onu_id)

            try:
                self.zmq_client.send(data)

            except Exception as e:
                self.log.info('zmqClient.send exception', exc=str(e))
                raise

    @staticmethod
    def is_gpon_olt_hw(content):
        """
        If the hello content

        :param content: (dict) Results of RESTCONF adtran-hello GET request
        :return: (string) GPON OLT H/w RESTCONF revision number or None on error/not GPON
        """
        for item in content.get('module-info', None):
            if item.get('module-name') == 'gpon-olt-hw':
                return AdtranDeviceHandler.parse_module_revision(item.get('revision', None))
        return None

    def _onu_offset(self, onu_id):
        return self.num_northbound_ports + self.num_southbound_ports + onu_id

    def _get_channel_id(self, pon_id, onu_id):
        from pon_port import PonPort

        return self._onu_offset(onu_id) + (pon_id * PonPort.MAX_ONUS_SUPPORTED)

    def _channel_id_to_pon_id(self, channel_id, onu_id):
        from pon_port import PonPort

        return (channel_id - self._onu_offset(onu_id)) / PonPort.MAX_ONUS_SUPPORTED

    def _pon_id_to_port_number(self, pon_id):
        return pon_id + 1 + self.num_northbound_ports
