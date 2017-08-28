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
from zope.interface import implementer

from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Image
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPF_10GB_FD
from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, ofp_port
from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *
from voltha.protos.bbf_fiber_base_pb2 import \
    ChannelgroupConfig, ChannelpartitionConfig, ChannelpairConfig, ChannelterminationConfig, \
    OntaniConfig, VOntaniConfig, VEnetConfig

_ = third_party
log = structlog.get_logger()


@implementer(IAdapterInterface)
class AdtranOnuAdapter(object):
    name = 'adtran_onu'
    version = '0.1'

    supported_device_types = [
        DeviceType(
            id=name,
            vendor_id='ADTN',
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Adtran, Inc.',
            version=self.version,
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.devices_handlers = dict()  # device_id -> AdtranOnuHandler()

    def start(self):
        log.debug('starting')
        log.info('started')

    def stop(self):
        log.debug('stopping')
        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        log.info('adopt_device', device_id=device.id)
        self.devices_handlers[device.proxy_address.channel_id] = AdtranOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.proxy_address.channel_id].activate, device)
        return device

    def reconcile_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        raise NotImplementedError()

    def reenable_device(self, device):
        raise NotImplementedError()

    def reboot_device(self, device):
        raise NotImplementedError()

    def download_image(self, device, request):
        raise NotImplementedError()

    def get_image_download_status(self, device, request):
        raise NotImplementedError()

    def cancel_image_download(self, device, request):
        raise NotImplementedError()

    def activate_image_update(self, device, request):
        raise NotImplementedError()

    def revert_image_update(self, device, request):
        raise NotImplementedError()

    def self_test_device(self, device):
        raise NotImplementedError()

    def delete_device(self, device):
        raise NotImplementedError()

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0
        handler = self.devices_handlers[device.proxy_address.channel_id]
        return handler.update_flow_table(device, flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.info('receive-proxied-message', proxy_address=proxy_address,
                 device_id=proxy_address.device_id, msg=hexify(msg))
        handler = self.devices_handlers[proxy_address.channel_id]
        handler.receive_message(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))
        raise NotImplementedError()

    def receive_inter_adapter_message(self, msg):
        log.info('rx_inter_adapter_msg')
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        log.info('suppress_alarm', filter=filter)
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        log.info('unsuppress_alarm', filter=filter)
        raise NotImplementedError()

    def receive_onu_detect_state(self, device_id, state):
        """
        Receive onu detect state in ONU adapter
        :param proxy_address: ONU device address
        :param state: ONU detect state (bool)
        :return: None
        """
        raise NotImplementedError()

    # PON Mgnt APIs #
    def create_interface(self, device, data):
        """
        API to create various interfaces (only some PON interfaces as of now)
        in the devices
        """
        raise NotImplementedError()

    def update_interface(self, device, data):
        """
        API to update various interfaces (only some PON interfaces as of now)
        in the devices
        """
        raise NotImplementedError()

    def remove_interface(self, device, data):
        """
        API to delete various interfaces (only some PON interfaces as of now)
        in the devices
        """
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to create tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        log.info('create-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to update tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        log.info('update-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to delete tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        log.info('remove-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def create_gemport(self, device, data):
        """
        API to create gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        log.info('create-gemport', data=data)
        raise NotImplementedError()

    def update_gemport(self, device, data):
        """
        API to update gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        log.info('update-gemport', data=data)
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        """
        API to delete gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        log.info('remove-gemport', data=data)
        raise NotImplementedError()

    def create_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def update_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def remove_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def update_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def remove_multicast_distribution_set(self, device, data):
        raise NotImplementedError()


class AdtranOnuHandler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue()
        self.proxy_address = None
        self.tx_id = 0
        self.last_response = None

    def receive_message(self, msg):
        self.incoming_messages.put(msg)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # populate device info
        device.root = True
        device.vendor = 'Adtran Inc.'
        device.model = '10G GPON ONU'           # TODO: get actual number
        device.hardware_version = 'NOT AVAILABLE'
        device.firmware_version = 'NOT AVAILABLE'
        # TODO: Support more versions as needed
        images = Image(version='NOT AVAILABLE')
        device.images.image.extend([images])

        device.serial_number = uuid4().hex
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # register physical ports
        nni_port = Port(port_no=1,
                        label='PON port',
                        type=Port.PON_ONU,
                        admin_state=AdminState.ENABLED,
                        oper_status=OperStatus.ACTIVE,
                        peers=[Port.PeerPort(device_id=device.parent_id,
                                             port_no=device.parent_port_no)])

        self.adapter_agent.add_port(device.id, nni_port)

        uni_port = Port(port_no=2,
                        label='Ethernet port',
                        type=Port.ETHERNET_UNI,
                        admin_state=AdminState.ENABLED,
                        oper_status=OperStatus.ACTIVE)

        self.adapter_agent.add_port(device.id, uni_port)

        # add uni port to logical device
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id

        port_no = device.proxy_address.channel_id

        log.info('ONU OPENFLOW PORT WILL BE {}'.format(port_no))

        cap = OFPPF_10GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
            id='uni-{}'.format(port_no),
            ofp_port=ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('08:00:%02x:%02x:%02x:%02x' %
                                         ((device.parent_port_no >> 8 & 0xff),
                                          device.parent_port_no & 0xff,
                                          (port_no >> 8) & 0xff,
                                          port_no & 0xff)),
                name='uni-{}'.format(port_no),
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_10GB_FD,
                max_speed=OFPPF_10GB_FD
            ),
            device_id=device.id,
            device_port_no=uni_port.port_no
        ))

        # Begin ONU Activation sequence
        reactor.callLater(0, self.message_exchange)

        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

    @inlineCallbacks
    def update_flow_table(self, device, flows):
        import voltha.core.flow_decomposer as fd
        from voltha.protos.openflow_13_pb2 import OFPP_IN_PORT, OFPP_TABLE, OFPP_NORMAL, OFPP_FLOOD, OFPP_ALL
        from voltha.protos.openflow_13_pb2 import OFPP_CONTROLLER, OFPP_LOCAL, OFPP_ANY, OFPP_MAX
        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        log.info('update_flow_table', device_id=device.id, flows=flows)

        for flow in flows:
            # TODO: Do we get duplicates here (ie all flows re-pushed on each individual flow add?)

            in_port = fd.get_in_port(flow)
            out_port = fd.get_out_port(flow)
            self.log.debug('InPort: {}, OutPort: {}'.format(in_port, out_port))

            for field in fd.get_ofb_fields(flow):
                self.log.debug('Found OFB field', field=field)

            for action in fd.get_actions(flow):
                log.debug('Found Action', action=action)

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
        log.info('wait-for-response')
        try:
            response = yield self.incoming_messages.get()
            log.info('got-response')
            resp = OmciFrame(response)
            resp.show()
            #returnValue(resp)
            self.last_response = resp

        except Exception as e:
            self.log.info('wait-for-response-exception', exc=str(e))
            raise e
            #returnValue(None)
            self.last_response = None

    @inlineCallbacks
    def message_exchange(self):
        log.info('message_exchange')
        # reset incoming message queue
        while self.incoming_messages.pending:
            _ = yield self.incoming_messages.get()

        ####################################################
        # Start by getting some useful device information

        device = self.adapter_agent.get_device(self.device_id)

        try:
            #pass

            # Decode fields in response and update device info
            self.send_get_OntG('vendor_id')
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.vendor = data["vendor_id"]


            self.send_get_cardHolder('actual_plugin_unit_type',257)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.type = str(data["actual_plugin_unit_type"])

            self.send_get_circuit_pack('number_of_ports',257)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.type = str(data["number_of_ports"])


            self.send_get_IpHostConfigData('mac_address',515)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.mac_address = str(data["mac_address"])

            self.send_get_Ont2G('equipment_id',0)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            eqptId_bootVersion = str(data["equipment_id"])
            eqptId = eqptId_bootVersion[0:10]
            bootVersion = eqptId_bootVersion[12:20]

            self.send_get_Ont2G('omcc_version',0)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            #decimal version
            omciVersion = str(data["omcc_version"])


            self.send_get_Ont2G('vendor_product_code',0)
            yield self.wait_for_response()
            response = self.last_response
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            #decimal value
            vedorProductCode = str(data["vendor_product_code"])

            self.send_get_OntG('version',0)
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
        except Exception as e:

            log.exception('Failed', e=e)

        ####################################################

        log.info('***************   ONU IS ACTIVATED   ****************')

        # self.send_get_circuit_pack()
        # yield self.wait_for_response()

        pass

    def send_mib_reset(self, entity_id=0):
        log.info('send_mib_reset')
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
        log.info('send_get_circuit_pack: entry')
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
        log.info('send_get_OntG: entry')
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
    #     log.info('send_get_OntG: entry')
    #     frame = OmciFrame(
    #         transaction_id=self.get_tx_id(),
    #         message_type=OmciGet.message_id,
    #         omci_message=OmciGet(
    #             entity_class=OntG.class_id,
    #             entity_id=0,
    #             attributes_mask=OntG.mask_for('vendor_id')
    #         )
    #     )
    #     log.info('send_get_OntG: sending')
    #     self.send_omci_message(frame)
    #     log.info('send_get_OntG: sent')


    def send_get_Ont2G(self, attribute, entity_id=0):
        log.info('send_get_Ont2G: entry')
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
        log.info('send_get_cardHolder: entry')
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
        log.info('send_set_AdminState: entry')
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
        log.info('send_get_IpHostConfigData: entry')
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
        log.info('send_get_SoftwareImage: entry')
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

    # PON Mgnt APIs #
    def create_interface(self, data):
        """
        Create XPON interfaces
        :param data: (xpon config info)
        """
        name = data.name
        interface = data.interface
        inst_data = data.data

        if isinstance(data, ChannelgroupConfig):
            self.log.debug('create_interface-channel-group', interface=interface, data=inst_data)
            pass

        elif isinstance(data, ChannelpartitionConfig):
            self.log.debug('create_interface-channel-partition', interface=interface, data=inst_data)
            pass

        elif isinstance(data, ChannelpairConfig):
            self.log.debug('create_interface-channel-pair', interface=interface, data=inst_data)
            pass

        elif isinstance(data, ChannelterminationConfig):
            self.log.debug('create_interface-channel-termination', interface=interface, data=inst_data)
            pass

        elif isinstance(data, OntaniConfig):
            self.log.debug('create_interface-ont-ani', interface=interface, data=inst_data)
            pass

        elif isinstance(data, VOntaniConfig):
            self.log.debug('create_interface-v-ont-ani', interface=interface, data=inst_data)
            pass

        elif isinstance(data, VEnetConfig):
            self.log.debug('create_interface-v-enet', interface=interface, data=inst_data)
            pass

        else:
            raise NotImplementedError('Unknown data type')

    def update_interface(self, data):
        """
        Update XPON interfaces
        :param data: (xpon config info)
        """
        pass

    def delete_interface(self, data):
        """
        Deleete XPON interfaces
        :param data: (xpon config info)
        """
        pass

    def create_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Create TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        pass

    def update_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Update TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        pass

    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Remove TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        pass

    def create_gemport(self, data):
        """
        Create GEM Port
        :param data:
        """
        pass

    def update_gemport(self, data):
        """
        Update GEM Port
        :param data:
        """
        pass

    def delete_gemport(self, data):
        """
        Delete GEM Port
        :param data:
        """
        pass
