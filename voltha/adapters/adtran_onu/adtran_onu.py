#
# Copyright 2017 the original author or authors.
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
Adtran ONU adapter.
"""

from uuid import uuid4
from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue

from voltha.adapters.iadapter import OnuAdapter
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceTypes, Port, Image
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPF_10GB_FD
from voltha.protos.openflow_13_pb2 import ofp_port
from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *
from voltha.protos.bbf_fiber_base_pb2 import OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.adapters.adtran_olt.tcont import TCont, TrafficDescriptor, BestEffort
from voltha.adapters.adtran_olt.gem_port import GemPort

_ = third_party

_MAX_INCOMING_OMCI_MESSAGES = 10
_OMCI_TIMEOUT = 10
_STARTUP_RETRY_WAIT = 5


class AdtranOnuAdapter(OnuAdapter):
    def __init__(self, adapter_agent, config):
        super(AdtranOnuAdapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class=AdtranOnuHandler,
                                               name='adtran_onu',
                                               vendor='Adtran, Inc.',
                                               version='0.2',
                                               device_type='adtran_onu',
                                               vendor_id='ADTN')

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to create tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        self.log.info('create-tcont', tcont_data=tcont_data,
                      traffic_descriptor_data=traffic_descriptor_data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_tcont(tcont_data, traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to update tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        self.log.info('update-tcont', tcont_data=tcont_data,
                      traffic_descriptor_data=traffic_descriptor_data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_tcont(tcont_data, traffic_descriptor_data)

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to delete tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        self.log.info('remove-tcont', tcont_data=tcont_data,
                      traffic_descriptor_data=traffic_descriptor_data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_tcont(tcont_data, traffic_descriptor_data)

    def create_gemport(self, device, data):
        """
        API to create gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        self.log.info('create-gemport', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_gemport(data)

    def update_gemport(self, device, data):
        """
        API to update gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        self.log.info('update-gemport', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_gemport(data)

    def remove_gemport(self, device, data):
        """
        API to delete gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        self.log.info('remove-gemport', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_gemport(data)

    def create_multicast_gemport(self, device, data):
        """
        API to create multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """
        self.log.info('create-mcast-gemport', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_multicast_gemport(data)

    def update_multicast_gemport(self, device, data):
        """
        API to update  multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """
        self.log.info('update-mcast-gemport', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_multicast_gemport(data)

    def remove_multicast_gemport(self, device, data):
        """
        API to delete multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """
        self.log.info('remove-mcast-gemport', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_multicast_gemport(data)

    def create_multicast_distribution_set(self, device, data):
        """
        API to create multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """
        self.log.info('create-mcast-distribution-set', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_multicast_distribution_set(data)

    def update_multicast_distribution_set(self, device, data):
        """
        API to update multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """
        self.log.info('update-mcast-distribution-set', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_multicast_distribution_set(data)

    def remove_multicast_distribution_set(self, device, data):
        """
        API to delete multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """
        self.log.info('remove-mcast-distribution-set', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_multicast_distribution_set(data)


class AdtranOnuHandler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.logical_device_id = None
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue(size=_MAX_INCOMING_OMCI_MESSAGES)
        self.proxy_address = None
        self.tx_id = 0
        self.last_response = None
        self.ofp_port_no = None
        self.control_vlan = None
        # reference of uni_port is required when re-enabling the device if
        # it was disabled previously
        self.uni_port = None
        self.pon_port = None
        self._v_ont_anis = {}             # Name -> dict
        self._ont_anis = {}               # Name -> dict
        self._v_enets = {}                # Name -> dict
        self._tconts = {}                 # Name -> dict
        self._traffic_descriptors = {}    # Name -> dict
        self._gem_ports = {}              # Name -> dict
        self._deferred = None

    def receive_message(self, msg):
        try:
            self.incoming_messages.put(msg)

        except Exception as e:
            self.log.exception('rx-msg', e=e)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id, 'Invalid Parent ID'
        assert device.proxy_address.device_id, 'Invalid Device ID'
        assert device.proxy_address.channel_id, 'invalid Channel ID'

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # populate device info
        device.root = True
        device.vendor = 'Adtran Inc.'
        device.model = '10G GPON ONU'           # TODO: get actual number
        device.model = '10G GPON ONU'           # TODO: get actual number
        device.hardware_version = 'NOT AVAILABLE'
        device.firmware_version = 'NOT AVAILABLE'

        # TODO: Support more versions as needed
        images = Image(version='NOT AVAILABLE')
        device.images.image.extend([images])

        device.connect_status = ConnectStatus.UNKNOWN
        self.adapter_agent.update_device(device)

        # register physical ports
        self.pon_port = Port(port_no=1,
                             label='PON port',
                             type=Port.PON_ONU,
                             admin_state=AdminState.ENABLED,
                             oper_status=OperStatus.ACTIVE,
                             peers=[Port.PeerPort(device_id=device.parent_id,
                                                  port_no=device.parent_port_no)])

        self.uni_port = Port(port_no=2,
                             label='Ethernet port',
                             type=Port.ETHERNET_UNI,
                             admin_state=AdminState.ENABLED,
                             oper_status=OperStatus.ACTIVE)

        self.adapter_agent.add_port(device.id, self.uni_port)
        self.adapter_agent.add_port(device.id, self.pon_port)

        # add uni port to logical device
        parent_device = self.adapter_agent.get_device(device.parent_id)
        self.logical_device_id = parent_device.parent_id
        assert self.logical_device_id, 'Invalid logical device ID'

        if device.vlan:
            # vlan non-zero if created via legacy method (not xPON). Also
            # Set a random serial number since not xPON based

            device.serial_number = uuid4().hex
            self._add_logical_port(device.vlan, control_vlan=device.vlan)

        # Begin ONU Activation sequence
        self._deferred = reactor.callLater(0, self.message_exchange)

        self.adapter_agent.update_device(device)

    def _add_logical_port(self, openflow_port_no, control_vlan=None,
                          capabilities=OFPPF_10GB_FD | OFPPF_FIBER,
                          speed=OFPPF_10GB_FD):

        if self.ofp_port_no is None:
            self.ofp_port_no = openflow_port_no
            self.control_vlan = control_vlan

            device = self.adapter_agent.get_device(self.device_id)

            openflow_port = ofp_port(
                    port_no=openflow_port_no,
                    hw_addr=mac_str_to_tuple('08:00:%02x:%02x:%02x:%02x' %
                                             ((device.parent_port_no >> 8 & 0xff),
                                              device.parent_port_no & 0xff,
                                              (openflow_port_no >> 8) & 0xff,
                                              openflow_port_no & 0xff)),
                    name='uni-{}'.format(openflow_port_no),
                    config=0,
                    state=OFPPS_LIVE,
                    curr=capabilities,
                    advertised=capabilities,
                    peer=capabilities,
                    curr_speed=speed,
                    max_speed=speed
                )
            self.adapter_agent.add_logical_port(self.logical_device_id,
                                                LogicalPort(
                                                    id='uni-{}'.format(openflow_port),
                                                    ofp_port=openflow_port,
                                                    device_id=device.id,
                                                    device_port_no=self.uni_port.port_no))
            if control_vlan is not None and device.vlan != control_vlan:
                device.vlan = control_vlan
                self.adapter_agent.update_device(device)

    def _get_uni_port(self):
        ports = self.adapter_agent.get_ports(self.device_id, Port.ETHERNET_UNI)
        if ports:
            # For now, we use on one uni port
            return ports[0]

    def _get_pon_port(self):
        ports = self.adapter_agent.get_ports(self.device_id, Port.PON_ONU)
        if ports:
            # For now, we use on one uni port
            return ports[0]

    def reconcile(self, device):
        self.log.info('reconciling-ONU-device-starts')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # Set the connection status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # TODO: Verify that the uni, pon and logical ports exists

        # Mark the device as REACHABLE and ACTIVE
        device = self.adapter_agent.get_device(device.id)
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        self.log.info('reconciling-ONU-device-ends')

    @inlineCallbacks
    def update_flow_table(self, device, flows):
        import voltha.core.flow_decomposer as fd
        from voltha.protos.openflow_13_pb2 import OFPP_IN_PORT, OFPP_TABLE, OFPP_NORMAL, OFPP_FLOOD, OFPP_ALL
        from voltha.protos.openflow_13_pb2 import OFPP_CONTROLLER, OFPP_LOCAL, OFPP_ANY, OFPP_MAX
        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        self.log.info('update_flow_table', device_id=device.id, flows=flows)

        for flow in flows:
            # TODO: Do we get duplicates here (ie all flows re-pushed on each individual flow add?)

            in_port = fd.get_in_port(flow)
            out_port = fd.get_out_port(flow)
            self.log.debug('InPort: {}, OutPort: {}'.format(in_port, out_port))

            for field in fd.get_ofb_fields(flow):
                self.log.debug('Found OFB field', field=field)

            for action in fd.get_actions(flow):
                self.log.debug('Found Action', action=action)

        raise NotImplementedError()

    def get_tx_id(self):
        self.tx_id += 1
        return self.tx_id

    def send_omci_message(self, frame):
        _frame = hexify(str(frame))
        self.log.info('send-omci-message-%s' % _frame)
        device = self.adapter_agent.get_device(self.device_id)
        try:
            self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        except Exception as e:
            self.log.info('send-omci-message-exception', exc=str(e))

    @inlineCallbacks
    def wait_for_response(self):
        self.log.info('wait-for-response')       # TODO: Add timeout

        def add_watchdog(deferred, timeout=_OMCI_TIMEOUT):
            from twisted.internet import defer

            def callback(value):
                if not watchdog.called:
                    watchdog.cancel()
                return value

            deferred.addBoth(callback)

            from twisted.internet import reactor
            watchdog = reactor.callLater(timeout, defer.timeout, deferred)
            return deferred

        try:
            response = yield add_watchdog(self.incoming_messages.get())

            self.log.info('got-response')
            resp = OmciFrame(response)
            resp.show()
            #returnValue(resp)
            self.last_response = resp

        except Exception as e:
            self.last_response = None
            self.log.info('wait-for-response-exception', exc=str(e))
            raise e

    @inlineCallbacks
    def message_exchange(self):
        self.log.info('message-exchange')
        self._deferred = None

        # reset incoming message queue
        while self.incoming_messages.pending:
            _ = yield self.incoming_messages.get()

        ####################################################
        # Start by getting some useful device information

        device = self.adapter_agent.get_device(self.device_id)
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

        device.connect_status = ConnectStatus.UNREACHABLE
        try:
            # TODO: Handle tx/wait-for-response timeouts and retry logic.
            # May timeout to ONU not fully discovered (can happen in xPON case)
            # or other errors.

            # Decode fields in response and update device info
            self.send_get_OntG('vendor_id')
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.vendor = data["vendor_id"]

            # Mark as reachable if at least first message gets through
            device.connect_status = ConnectStatus.REACHABLE

            self.send_get_cardHolder('actual_plugin_unit_type', 257)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.type = str(data["actual_plugin_unit_type"])

            self.send_get_circuit_pack('number_of_ports', 257)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.type = str(data["number_of_ports"])

            self.send_get_IpHostConfigData('mac_address', 515)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.mac_address = str(data["mac_address"])

            self.send_get_Ont2G('equipment_id', 0)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            eqptId_bootVersion = str(data["equipment_id"])
            eqptId = eqptId_bootVersion[0:10]
            bootVersion = eqptId_bootVersion[12:20]

            self.send_get_Ont2G('omcc_version', 0)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            #decimal version
            omciVersion = str(data["omcc_version"])

            self.send_get_Ont2G('vendor_product_code', 0)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            #decimal value
            vedorProductCode = str(data["vendor_product_code"])

            self.send_get_OntG('version', 0)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.hardware_version = str(data["version"])

            # Possbility of bug in ONT Firmware. uncomment this code after it is fixed.
            # self.send_get_SoftwareImage('version',0)
            # yield self.wait_for_response()
            # response = self.last_response
            # omci_response = response.getfieldval("omci_message")
            # data = omci_response.getfieldval("data")
            # device.firmware_version = str(data["version"])

            self.send_set_adminState(257)
            yield self.wait_for_response()
            response = self.last_response

            # device.model = '10G GPON ONU'           # TODO: get actual number
            # device.hardware_version = 'TODO: to be filled'
            # device.firmware_version = 'TODO: to be filled'
            # device.serial_number = uuid4().hex
            # TODO: Support more versions as needed
            # images = Image(version=results.get('software_version', 'unknown'))
            # device.images.image.extend([images])

            # self.adapter_agent.update_device(device)
            device.oper_status = OperStatus.ACTIVE
            device.connect_status = ConnectStatus.REACHABLE

        except Exception as e:
            self.log.exception('Failed', e=e)

            # Try again later. May not have been discovered
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self.message_exchange)

        ####################################################

        self.log.info('onu-activated')

        # self.send_get_circuit_pack()
        # yield self.wait_for_response()
        self.adapter_agent.update_device(device)

    def send_mib_reset(self, entity_id=0):
        self.log.info('send_mib_reset')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=OntData.class_id,
                entity_id=entity_id
            )
        )
        self.send_omci_message(frame)

    def send_set_tcont(self, entity_id, alloc_id):
        data = dict(
            alloc_id=alloc_id
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Tcont.class_id,
                entity_id=entity_id,
                attributes_mask=Tcont.mask_for(*data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_gem_port_network_ctp(self, entity_id, port_id,
                                         tcont_id, direction, tm):
        _directions = {"upstream": 1, "downstream": 2, "bi-directional": 3}
        if _directions.has_key(direction):
            _direction = _directions[direction]
        else:
            self.log.error('invalid-gem-port-direction', direction=direction)
            raise ValueError('Invalid GEM port direction: {_dir}'.format(_dir=direction))

        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemPortNetworkCtp.class_id,
                entity_id=entity_id,
                data=dict(
                    port_id=port_id,
                    tcont_pointer=tcont_id,
                    direction=_direction,
                    traffic_management_pointer_upstream=tm
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_8021p_mapper_service_profile(self, entity_id, interwork_tp_id):
        data = dict(
            interwork_tp_pointer_for_p_bit_priority_0=interwork_tp_id
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=entity_id,
                attributes_mask=Ieee8021pMapperServiceProfile.mask_for(
                    *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_mac_bridge_service_profile(self, entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgeServiceProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    spanning_tree_ind=False,
                    learning_ind=True,
                    priority=0x8000,
                    max_age=20 * 256,
                    hello_time=2 * 256,
                    forward_delay=15 * 256,
                    unknown_mac_address_discard=True
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_8021p_mapper_service_profile(self, entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    tp_pointer=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_0=OmciNullPointer,
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_gal_ethernet_profile(self, entity_id, max_gem_payload_size):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GalEthernetProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    max_gem_payload_size=max_gem_payload_size
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_gem_inteworking_tp(self, entity_id, gem_port_net_ctp_id,
                                       service_profile_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemInterworkingTp.class_id,
                entity_id=entity_id,
                data=dict(
                    gem_port_network_ctp_pointer=gem_port_net_ctp_id,
                    interworking_option=5,
                    service_profile_pointer=service_profile_id,
                    interworking_tp_pointer=0x0,
                    gal_profile_pointer=0x1
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_mac_bridge_port_configuration_data(self, entity_id, bridge_id,
                                                       port_id, tp_type, tp_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgePortConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    bridge_id_pointer=bridge_id,
                    port_num=port_id,
                    tp_type=tp_type,
                    tp_pointer=tp_id
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_vlan_tagging_filter_data(self, entity_id, vlan_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=entity_id,
                data=dict(
                    vlan_filter_0=vlan_id,
                    forward_operation=0x10,
                    number_of_entries=1
                )
            )
        )
        self.send_omci_message(frame)

    def send_get_circuit_pack(self, attribute, entity_id=0):
        self.log.info('send_get_circuit_pack: entry')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=CircuitPack.class_id,
                entity_id=entity_id,
                attributes_mask=CircuitPack.mask_for(attribute)
            )
        )
        self.send_omci_message(frame)

    def send_get_device_info(self, attribute, entity_id=0):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=CircuitPack.class_id,
                entity_id=entity_id,
                attributes_mask=CircuitPack.mask_for(attribute)
            )
        )
        self.send_omci_message(frame)

    def send_get_OntG(self, attribute, entity_id=0):
        self.log.info('send_get_OntG: entry')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=OntG.class_id,
                entity_id=entity_id,
                attributes_mask=OntG.mask_for(attribute)
            )
        )
        self.send_omci_message(frame)

    # def send_get_OntG(self, entity_id=0):
    #     self.log.info('send_get_OntG: entry')
    #     frame = OmciFrame(
    #         transaction_id=self.get_tx_id(),
    #         message_type=OmciGet.message_id,
    #         omci_message=OmciGet(
    #             entity_class=OntG.class_id,
    #             entity_id=0,
    #             attributes_mask=OntG.mask_for('vendor_id')
    #         )
    #     )
    #     self.log.info('send_get_OntG: sending')
    #     self.send_omci_message(frame)
    #     self.log.info('send_get_OntG: sent')

    def send_get_Ont2G(self, attribute, entity_id=0):
        self.log.info('send_get_Ont2G: entry')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=Ont2G.class_id,
                entity_id=entity_id,
                attributes_mask=Ont2G.mask_for(attribute)
            )
        )

        self.send_omci_message(frame)

    def send_get_cardHolder(self, attribute, entity_id=0):
        self.log.info('send_get_cardHolder: entry')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=Cardholder.class_id,
                entity_id=entity_id,
                attributes_mask=Cardholder.mask_for(attribute)
            )
        )
        self.send_omci_message(frame)

    def send_set_adminState(self,entity_id):
        self.log.info('send_set_AdminState: entry')
        data = dict(
            administrative_state=0
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=PptpEthernetUni.class_id,
                entity_id=entity_id,
                attributes_mask=PptpEthernetUni.mask_for(*data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_get_IpHostConfigData(self, attribute, entity_id=0):
        self.log.info('send_get_IpHostConfigData: entry')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=IpHostConfigData.class_id,
                entity_id=entity_id,
                attributes_mask=IpHostConfigData.mask_for(attribute)
            )
        )
        self.send_omci_message(frame)

    def send_get_SoftwareImage(self, attribute, entity_id=0):
        self.log.info('send_get_SoftwareImage: entry')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=SoftwareImage.class_id,
                entity_id=entity_id,
                attributes_mask=SoftwareImage.mask_for(attribute)
            )
        )
        self.send_omci_message(frame)

    @inlineCallbacks
    def reboot(self):
        from common.utils.asleep import asleep
        self.log.info('rebooting', device_id=self.device_id)

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE
        device = self.adapter_agent.get_device(self.device_id)
        previous_oper_status = device.oper_status
        previous_conn_status = device.connect_status
        device.oper_status = OperStatus.ACTIVATING
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Sleep 10 secs, simulating a reboot
        # TODO: send alert and clear alert after the reboot
        yield asleep(10)    # TODO: Need to reboot for real

        # Change the operational status back to its previous state.  With a
        # real OLT the operational state should be the state the device is
        # after a reboot.
        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)
        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        self.adapter_agent.update_device(device)
        self.log.info('rebooted', device_id=self.device_id)

    def self_test_device(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        self.log.info('self-test-device', device=device.id)
        raise NotImplementedError()

    def disable(self):
        self.log.info('disabling', device_id=self.device_id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        # Update the device operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the uni logical port from the OLT, if still present
        parent_device = self.adapter_agent.get_device(device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no, self.ofp_port_no = self.ofp_port_no, None
        port_id = 'uni-{}'.format(port_no)

        try:
            port = self.adapter_agent.get_logical_port(logical_device_id,
                                                       port_id)
            self.adapter_agent.delete_logical_port(logical_device_id, port)
        except KeyError:
            self.log.info('logical-port-not-found', device_id=self.device_id,
                          portid=port_id)

        # Remove pon port from parent
        self.pon_port = self._get_pon_port()
        self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                             self.pon_port)

        # Just updating the port status may be an option as well
        # port.ofp_port.config = OFPPC_NO_RECV
        # yield self.adapter_agent.update_logical_port(logical_device_id,
        #                                             port)
        # Unregister for proxied message
        self.adapter_agent.unregister_for_proxied_messages(
            device.proxy_address)

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('disabled', device_id=device.id)

    def reenable(self):
        self.log.info('re-enabling', device_id=self.device_id)
        try:
            # Get the latest device reference
            device = self.adapter_agent.get_device(self.device_id)

            # First we verify that we got parent reference and proxy info
            assert device.parent_id
            assert device.proxy_address.device_id
            assert device.proxy_address.channel_id

            # Re-register for proxied messages right away
            self.proxy_address = device.proxy_address
            self.adapter_agent.register_for_proxied_messages(
                device.proxy_address)

            # Re-enable the ports on that device
            self.adapter_agent.enable_all_ports(self.device_id)

            # Refresh the port reference
            self.uni_port = self._get_uni_port()
            self.pon_port = self._get_pon_port()

            # Add the pon port reference to the parent
            self.adapter_agent.add_port_reference_to_parent(device.id,
                                                            self.pon_port)

            # Update the connect status to REACHABLE
            device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(device)

            # re-add uni port to logical device
            parent_device = self.adapter_agent.get_device(device.parent_id)
            self.logical_device_id = parent_device.parent_id
            assert self.logical_device_id, 'Invalid logical device ID'

            if device.vlan:
                # vlan non-zero if created via legacy method (not xPON)
                self._add_logical_port(device.vlan, device.vlan,
                                       control_vlan=device.vlan)

            device = self.adapter_agent.get_device(device.id)
            device.oper_status = OperStatus.ACTIVE
            self.adapter_agent.update_device(device)

            self.log.info('re-enabled', device_id=device.id)
        except Exception, e:
            self.log.exception('error-reenabling', e=e)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)
        # A delete request may be received when an OLT is disabled
        # TODO:  Need to implement this
        # 1) Remove all flows from the device
        self.log.info('deleted', device_id=self.device_id)

    # PON Mgnt APIs #


    def _get_xpon_collection(self, data):
        if isinstance(data, OntaniConfig):
            return self._ont_anis
        elif isinstance(data, VOntaniConfig):
            return self._v_ont_anis
        elif isinstance(data, VEnetConfig):
            return self._v_enets
        return None

    def create_interface(self, data):
        """
        Create XPON interfaces
        :param data: (xpon config info)
        """
        name = data.name
        interface = data.interface
        inst_data = data.data

        items = self._get_xpon_collection(data)
        if items is None:
            raise NotImplemented('xPON {} is not implemented'.
                                 format(type(data)))

        if isinstance(data, OntaniConfig):
            self.log.debug('create_interface-ont-ani', interface=interface, data=inst_data)

            if name not in items:
                items[name] = {
                    'name': name,
                    'enabled': interface.enabled,
                    'upstream-fec': inst_data.upstream_fec_indicator,
                    'mgnt-gemport-aes': inst_data.mgnt_gemport_aes_indicator
                }

        elif isinstance(data, VOntaniConfig):
            self.log.debug('create_interface-v-ont-ani', interface=interface, data=inst_data)

            if name not in items:
                items[name] = {
                    'name': name,
                    'enabled': interface.enabled,
                    'onu-id': inst_data.onu_id,
                    'expected-serial-number': inst_data.expected_serial_number,
                    'preferred-channel-pair': inst_data.preferred_chanpair,
                    'channel-partition': inst_data.parent_ref,
                    'upstream-channel-speed': inst_data.upstream_channel_speed
                }

        elif isinstance(data, VEnetConfig):
            self.log.debug('create_interface-v-enet', interface=interface, data=inst_data)

            if name not in items:
                items[name] = {
                    'name': name,
                    'enabled': interface.enabled,
                    'v-ont-ani': inst_data.v_ontani_ref
                }
                ofp_port_no, cntl_vlan = self._decode_openflow_port_and_control_vlan(items[name])
                self._add_logical_port(ofp_port_no, control_vlan=cntl_vlan)

        else:
            raise NotImplementedError('Unknown data type')

    def _decode_openflow_port_and_control_vlan(self, venet_info):
        try:
            ofp_port_no = int(venet_info['name'].split('-')[1])
            cntl_vlan = ofp_port_no

            return ofp_port_no, cntl_vlan

        except ValueError:
            self.log.error('invalid-uni-port-name', name=venet_info['name'])
        except KeyError:
            self.log.error('invalid-venet-data', data=venet_info)

    def update_interface(self, data):
        """
        Update XPON interfaces
        :param data: (xpon config info)
        """
        name = data.name
        interface = data.interface
        inst_data = data.data

        items = self._get_xpon_collection(data)

        if items is None:
            raise ValueError('Unknown data type: {}'.format(type(data)))

        if name not in items:
            raise KeyError("'{}' not found. Type: {}".format(name, type(data)))

        raise NotImplementedError('TODO: not yet supported')

    def delete_interface(self, data):
        """
        Deleete XPON interfaces
        :param data: (xpon config info)
        """
        name = data.name
        interface = data.interface
        inst_data = data.data

        items = self._get_xpon_collection(data)
        item = items.get(name)

        if item in items:
            del items[name]
            pass    # TODO Do something....
            raise NotImplementedError('TODO: not yet supported')

    def create_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Create TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        traffic_descriptor = TrafficDescriptor.create(traffic_descriptor_data)
        tcont = TCont.create(tcont_data, traffic_descriptor)

        if tcont.name in self._tconts:
            raise KeyError("TCONT '{}' already exists".format(tcont.name))

        if traffic_descriptor.name in self._traffic_descriptors:
            raise KeyError("Traffic Descriptor '{}' already exists".format(traffic_descriptor.name))

        self._tconts[tcont.name] = tcont
        self._traffic_descriptors[traffic_descriptor.name] = traffic_descriptor

    def update_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Update TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        if tcont_data.name not in self._tconts:
            raise KeyError("TCONT '{}' does not exists".format(tcont_data.name))

        if traffic_descriptor_data.name not in self._traffic_descriptors:
            raise KeyError("Traffic Descriptor '{}' does not exists".
                           format(traffic_descriptor_data.name))

        traffic_descriptor = TrafficDescriptor.create(traffic_descriptor_data)
        tcont = TCont.create(tcont_data, traffic_descriptor)
        #
        pass
        raise NotImplementedError('TODO: Not yet supported')

    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Remove TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        tcont = self._tconts.get(tcont_data.name)
        traffic_descriptor = self._traffic_descriptors.get(traffic_descriptor_data.name)

        if traffic_descriptor is not None:
            del self._traffic_descriptors[traffic_descriptor_data.name]
            pass         # Perform any needed operations
            # raise NotImplementedError('TODO: Not yet supported')

        if tcont is not None:
            del self._tconts[tcont_data.name]
            pass         # Perform any needed operations
            raise NotImplementedError('TODO: Not yet supported')

    def create_gemport(self, data):
        """
        Create GEM Port
        :param data:
        """
        gem_port = GemPort.create(data)

        if gem_port.name in self._gem_ports:
            raise KeyError("GEM Port '{}' already exists".format(gem_port.name))

        self._gem_ports[gem_port.name] = gem_port

        # TODO: On GEM Port changes, may need to add ONU Flow(s)

    def update_gemport(self, data):
        """
        Update GEM Port
        :param data:
        """
        if data.name not in self._gem_ports:
            raise KeyError("GEM Port '{}' does not exists".format(data.name))

        gem_port = GemPort.create(data)
        #
        # TODO: On GEM Port changes, may need to add/delete/modify ONU Flow(s)
        pass
        raise NotImplementedError('TODO: Not yet supported')

    def remove_gemport(self, data):
        """
        Delete GEM Port
        :param data:
        """
        gem_port = self._gem_ports.get(data.name)

        if gem_port is not None:
            del self._gem_ports[data.name]
            #
            # TODO: On GEM Port changes, may need to delete ONU Flow(s)
            pass         # Perform any needed operations
            raise NotImplementedError('TODO: Not yet supported')

    def create_multicast_gemport(self, data):
        """
        API to create multicast gemport object in the devices
        :data: multicast gemport data object
        :return: None
        """
        pass    # TODO: Implement

    def update_multicast_gemport(self, data):
        """
        API to update  multicast gemport object in the devices
        :data: multicast gemport data object
        :return: None
        """
        pass    # TODO: Implement

    def remove_multicast_gemport(self, data):
        """
        API to delete multicast gemport object in the devices
        :data: multicast gemport data object
        :return: None
        """
        pass    # TODO: Implement

    def create_multicast_distribution_set(self, data):
        """
        API to create multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :data: multicast distribution data object
        :return: None
        """
        pass    # TODO: Implement

    def update_multicast_distribution_set(self, data):
        """
        API to update multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :data: multicast distribution data object
        :return: None
        """
        pass    # TODO: Implement

    def remove_multicast_distribution_set(self, data):
        """
        API to delete multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :data: multicast distribution data object
        :return: None
        """
        pass    # TODO: Implement
