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
Broadcom OLT/ONU adapter.
"""

from uuid import uuid4
import structlog
from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from zope.interface import implementer

from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
import voltha.core.flow_decomposer as fd
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPF_1GB_FD
from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, ofp_port
from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *

_ = third_party
log = structlog.get_logger()


@implementer(IAdapterInterface)
class BroadcomOnuAdapter(object):

    name = 'broadcom_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Voltha project',
            version='0.4',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.devices_handlers = dict()  # device_id -> BroadcomOnuHandler()

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
        self.devices_handlers[device.proxy_address.channel_id] = BroadcomOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.proxy_address.channel_id].activate, device)
        return device

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        raise NotImplementedError()

    def reenable_device(self, device):
        raise NotImplementedError()

    def reboot_device(self, device):
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


class BroadcomOnuHandler(object):

    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue()
        self.proxy_address = None
        self.tx_id = 0

    def receive_message(self, msg):
        self.incoming_messages.put(msg)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # populate device info
        device.root = True
        device.vendor = 'Broadcom'
        device.model ='n/a'
        device.hardware_version = 'to be filled'
        device.firmware_version = 'to be filled'
        device.software_version = 'to be filled'
        device.serial_number = uuid4().hex
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # register physical ports
        uni_port = Port(
            port_no=2,
            label='UNI facing Ethernet port',
            type=Port.ETHERNET_UNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.adapter_agent.add_port(device.id, uni_port)
        self.adapter_agent.add_port(device.id, Port(
            port_no=1,
            label='PON port',
            type=Port.PON_ONU,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE,
            peers=[
                Port.PeerPort(
                    device_id=device.parent_id,
                    port_no=device.parent_port_no
                )
            ]
        ))

        # add uni port to logical device
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
            id='uni-{}'.format(port_no),
            ofp_port=ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:%02x:%02x' % ((port_no >> 8) & 0xff, port_no & 0xff)),
                name='uni-{}'.format(port_no),
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=device.id,
            device_port_no=uni_port.port_no
        ))

        reactor.callLater(10, self.message_exchange)

        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

    @inlineCallbacks
    def update_flow_table(self, device, flows):
        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        self.log.info('bulk-flow-update', device_id=device.id, flows=flows)

        def is_downstream(port):
            return port == 2  # Need a better way

        def is_upstream(port):
            return not is_downstream(port)

        for flow in flows:
            try:
                _in_port = fd.get_in_port(flow)
                assert _in_port is not None

                if is_downstream(_in_port):
                    self.log.info('downstream-flow')
                elif is_upstream(_in_port):
                    self.log.info('upstream-flow')
                else:
                    raise Exception('port should be 1 or 2 by our convention')

                _out_port = fd.get_out_port(flow)  # may be None
                self.log.info('out-port', out_port=_out_port)

                for field in fd.get_ofb_fields(flow):
                    if field.type == fd.ETH_TYPE:
                        _type = field.eth_type
                        self.log.info('field-type-eth-type',
                                      eth_type=_type)

                    elif field.type == fd.IP_PROTO:
                        _proto = field.ip_proto
                        self.log.info('field-type-ip-proto',
                                      ip_proto=_proto)

                    elif field.type == fd.IN_PORT:
                        _port = field.port
                        self.log.info('field-type-in-port',
                                      in_port=_port)

                    elif field.type == fd.VLAN_VID:
                        _vlan_vid = field.vlan_vid & 0xfff
                        self.log.info('field-type-vlan-vid',
                                      vlan=_vlan_vid)

                    elif field.type == fd.VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        self.log.info('field-type-vlan-pcp',
                                      pcp=_vlan_pcp)

                    elif field.type == fd.UDP_DST:
                        _udp_dst = field.udp_dst
                        self.log.info('field-type-udp-dst',
                                      udp_dst=_udp_dst)

                    elif field.type == fd.UDP_SRC:
                        _udp_src = field.udp_src
                        self.log.info('field-type-udp-src',
                                      udp_src=_udp_src)

                    elif field.type == fd.IPV4_DST:
                        _ipv4_dst = field.ipv4_dst
                        self.log.info('field-type-ipv4-dst',
                                      ipv4_dst=_ipv4_dst)

                    elif field.type == fd.IPV4_SRC:
                        _ipv4_src = field.ipv4_src
                        self.log.info('field-type-ipv4-src',
                                      ipv4_dst=_ipv4_src)

                    elif field.type == fd.METADATA:
                        _metadata = field.metadata
                        self.log.info('field-type-metadata',
                                      metadata=_metadata)

                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in fd.get_actions(flow):

                    if action.type == fd.OUTPUT:
                        _output = action.output.port
                        self.log.info('action-type-output',
                                      output=_output, in_port=_in_port)

                    elif action.type == fd.POP_VLAN:
                        self.log.info('action-type-pop-vlan',
                                      in_port=_in_port)

                    elif action.type == fd.PUSH_VLAN:
                        _push_tpid = action.push.ethertype
                        log.info('action-type-push-vlan',
                                 push_tpid=_push_tpid, in_port=_in_port)
                        if action.push.ethertype != 0x8100:
                            self.log.error('unhandled-tpid',
                                           ethertype=action.push.ethertype)

                    elif action.type == fd.SET_FIELD:
                        _field = action.set_field.field.ofb_field
                        assert (action.set_field.field.oxm_class ==
                                OFPXMC_OPENFLOW_BASIC)
                        self.log.info('action-type-set-field',
                                      field=_field, in_port=_in_port)
                        if _field.type == fd.VLAN_VID:
                            self.log.info('set-field-type-valn-vid',
                                          vlan_vid=_field.vlan_vid & 0xfff)
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type)
                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type, in_port=_in_port)

                #
                # All flows created from ONU adapter should be OMCI based
                #

            except Exception as e:
                log.exception('failed-to-install-flow', e=e, flow=flow)


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

    def send_get_circuit_pack(self, entity_id=0):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=CircuitPack.class_id,
                entity_id=entity_id,
                attributes_mask=CircuitPack.mask_for('vendor_id')
            )
        )
        self.send_omci_message(frame)

    def send_mib_reset(self, entity_id=0):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=OntData.class_id,
                entity_id=entity_id
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

    def send_set_tcont(self, entity_id, alloc_id):
        data = dict(
            alloc_id=alloc_id
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Tcont.class_id,
                entity_id = entity_id,
                attributes_mask=Tcont.mask_for(*data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_8021p_mapper_service_profile(self, entity_id):
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
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

    def send_create_mac_bridge_service_profile(self, entity_id):
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
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

    def send_create_gem_port_network_ctp(self, entity_id, port_id, tcont_id):
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemPortNetworkCtp.class_id,
                entity_id=entity_id,
                data=dict(
                    port_id=port_id,
                    tcont_pointer=tcont_id,
                    direction=3,
                    traffic_management_pointer_upstream=0x100
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_multicast_gem_interworking_tp(self, entity_id, gem_port_net_ctp_id):
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MulticastGemInterworkingTp.class_id,
                entity_id=entity_id,
                data=dict(
                    gem_port_network_ctp_pointer=gem_port_net_ctp_id,
                    interworking_option=0,
                    service_profile_pointer=0x1,
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_gem_inteworking_tp(self, entity_id, gem_port_net_ctp_id, service_profile_id):
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
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

    def send_set_8021p_mapper_service_profile(self, entity_id, interwork_tp_id):
        data = dict(
            interwork_tp_pointer_for_p_bit_priority_0 = interwork_tp_id
        )
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
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

    def send_create_mac_bridge_port_configuration_data(self,
                                                       entity_id,
                                                       bridge_id,
                                                       port_id,
                                                       tp_type,
                                                       tp_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgePortConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    bridge_id_pointer = bridge_id,
                    port_num=port_id,
                    tp_type=tp_type,
                    tp_pointer = tp_id
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_vlan_tagging_filter_data(self, entity_id, vlan_id):
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
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

    def send_create_extended_vlan_tagging_operation_configuration_data(self, entity_id):
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    association_type=10,
                    associated_me_pointer=0x401
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_tpid_configuration_data(self, entity_id, input_tpid, output_tpid):
        data = dict(
            input_tpid = input_tpid,
            output_tpid = output_tpid,
            downstream_mode=0,  # inverse of upstream
        )
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=\
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask= \
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data(self,
                                                                         entity_id,
                                                                         filter_inner_vid,
                                                                         treatment_inner_vid):
        data = dict(
            received_frame_vlan_tagging_operation_table=\
                VlanTaggingOperation(
                    filter_outer_priority=15,
                    filter_inner_priority=8,
                    filter_inner_vid = filter_inner_vid,
                    filter_inner_tpid_de=5,
                    filter_ether_type=0,
                    treatment_tags_to_remove=1,
                    pad3=2,
                    treatment_outer_priority=15,
                    treatment_inner_priority=8,
                    treatment_inner_vid = treatment_inner_vid,
                    treatment_inner_tpid_de=4
                )
        )
        frame = OmciFrame(
            transaction_id = self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=\
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id = entity_id,
                attributes_mask= \
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    @inlineCallbacks
    def wait_for_response(self):
        log.info('wait-for-response')
        try:
            response = yield self.incoming_messages.get()
            resp = OmciFrame(response)
            resp.show()
        except Exception as e:
            self.log.info('wait-for-response-exception', exc=str(e))

    @inlineCallbacks
    def message_exchange(self):
        log.info('message_exchange')
        # reset incoming message queue
        while self.incoming_messages.pending:
            _ = yield self.incoming_messages.get()

        # construct message
        # MIB Reset - OntData - 0
        self.send_mib_reset()
        yield self.wait_for_response()

        # Create AR - GalEthernetProfile - 1
        self.send_create_gal_ethernet_profile(1, 48)
        yield self.wait_for_response()

        # Set AR - TCont - 32768 - 1024
        self.send_set_tcont(0x8000, 0x400)
        yield self.wait_for_response()

        # Set AR - TCont - 32769 - 1025
        self.send_set_tcont(0x8001, 0x401)
        yield self.wait_for_response()

        # Set AR - TCont - 32770 - 1026
        self.send_set_tcont(0x8002, 0x402)
        yield self.wait_for_response()

        # Set AR - TCont - 32771 - 1027
        self.send_set_tcont(0x8003, 0x403)
        yield self.wait_for_response()

        # Create AR - 802.1pMapperServiceProfile - 32768
        self.send_create_8021p_mapper_service_profile(0x8000)
        yield self.wait_for_response()

        # Create AR - 802.1pMapperServiceProfile - 32769
        self.send_create_8021p_mapper_service_profile(0x8001)
        yield self.wait_for_response()

        # Create AR - 802.1pMapperServiceProfile - 32770
        self.send_create_8021p_mapper_service_profile(0x8002)
        yield self.wait_for_response()

        # Create AR - 802.1pMapperServiceProfile - 32771
        self.send_create_8021p_mapper_service_profile(0x8003)
        yield self.wait_for_response()

        # Create AR - MacBridgeServiceProfile - 513
        self.send_create_mac_bridge_service_profile(0x201)
        yield self.wait_for_response()

        # Create AR - GemPortNetworkCtp - 256 - 1024 - 32768
        self.send_create_gem_port_network_ctp(0x100, 0x400, 0x8000)
        yield self.wait_for_response()

        # Create AR - GemPortNetworkCtp - 257 - 1025 - 32769
        self.send_create_gem_port_network_ctp(0x101, 0x401, 0x8001)
        yield self.wait_for_response()

        # Create AR - GemPortNetworkCtp - 258 - 1026 - 32770
        self.send_create_gem_port_network_ctp(0x102, 0x402, 0x8002)
        yield self.wait_for_response()

        # Create AR - GemPortNetworkCtp - 259 - 1027 - 32771
        self.send_create_gem_port_network_ctp(0x103, 0x403, 0x8003)
        yield self.wait_for_response()

        # Create AR - MulticastGemInterworkingTp - 6 - 260
        self.send_create_multicast_gem_interworking_tp(0x6, 0x104)
        yield self.wait_for_response()

        # Create AR - GemInterworkingTp - 32769 - 256 -32768 - 1
        self.send_create_gem_inteworking_tp(0x8001, 0x100, 0x8000)
        yield self.wait_for_response()

        # Create AR - GemInterworkingTp - 32770 - 257 -32769 - 1
        self.send_create_gem_inteworking_tp(0x8002, 0x101, 0x8001)
        yield self.wait_for_response()

        # Create AR - GemInterworkingTp - 32771 - 258 -32770 - 1
        self.send_create_gem_inteworking_tp(0x8003, 0x102, 0x8002)
        yield self.wait_for_response()

        # Create AR - GemInterworkingTp - 32772 - 259 -32771 - 1
        self.send_create_gem_inteworking_tp(0x8004, 0x103, 0x8003)
        yield self.wait_for_response()

        # Set AR - 802.1pMapperServiceProfile - 32768 - 32769
        self.send_set_8021p_mapper_service_profile(0x8000, 0x8001)
        yield self.wait_for_response()

        # Set AR - 802.1pMapperServiceProfile - 32769 - 32770
        self.send_set_8021p_mapper_service_profile(0x8001, 0x8002)
        yield self.wait_for_response()

        # Set AR - 802.1pMapperServiceProfile - 32770 - 32771
        self.send_set_8021p_mapper_service_profile(0x8002, 0x8003)
        yield self.wait_for_response()

        # Set AR - 802.1pMapperServiceProfile - 32771 - 32772
        self.send_set_8021p_mapper_service_profile(0x8003, 0x8004)
        yield self.wait_for_response()

        # Create AR - MacBridgePortConfigData - 8449 - 513 - 2 - 3 - 32768
        self.send_create_mac_bridge_port_configuration_data(0x2101, 0x201, 2, 3, 0x8000)
        yield self.wait_for_response()

        # Create AR - MacBridgePortConfigData - 8450 - 513 - 3 - 3 - 32769
        self.send_create_mac_bridge_port_configuration_data(0x2102, 0x201, 3, 3, 0x8001)
        yield self.wait_for_response()

        # Create AR - MacBridgePortConfigData - 8451 - 513 - 4 - 3 - 32770
        self.send_create_mac_bridge_port_configuration_data(0x2103, 0x201, 4, 3, 0x8002)
        yield self.wait_for_response()

        # Create AR - MacBridgePortConfigData - 8452 - 513 - 5 - 3 - 32771
        self.send_create_mac_bridge_port_configuration_data(0x2104, 0x201, 5, 3, 0x8003)
        yield self.wait_for_response()

        # Create AR - MacBridgePortConfigData - 9000 - 513 - 6 - 6 - 6
        self.send_create_mac_bridge_port_configuration_data(0x2328, 0x201, 6, 6, 6)
        yield self.wait_for_response()

        # Create AR - VlanTaggingFilterData - 8449 - 040000000000000000000000000000000000000000000000
        self.send_create_vlan_tagging_filter_data(0x2101, 0x0400)
        yield self.wait_for_response()

        # Create AR - VlanTaggingFilterData - 8450 - 040100000000000000000000000000000000000000000000
        self.send_create_vlan_tagging_filter_data(0x2102, 0x0401)
        yield self.wait_for_response()

        # Create AR - VlanTaggingFilterData - 8451 - 040200000000000000000000000000000000000000000000
        self.send_create_vlan_tagging_filter_data(0x2103, 0x0402)
        yield self.wait_for_response()

        # Create AR - VlanTaggingFilterData - 8452 - 040300000000000000000000000000000000000000000000
        self.send_create_vlan_tagging_filter_data(0x2104, 0x0403)
        yield self.wait_for_response()

        # Create AR - ExtendedVlanTaggingOperationConfigData - 514 - 10 - 1025
        self.send_create_extended_vlan_tagging_operation_configuration_data(0x202)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - 8100 - 8100
        self.send_set_extended_vlan_tagging_operation_tpid_configuration_data(0x202,0x8100,0x8100)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - RxVlanTaggingOperationTable - 0x400 - 5 - 0x400 - 4
        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data(0x202, 0x400, 0x400)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - RxVlanTaggingOperationTable - 0x401 - 5 - 0x401 - 4
        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data(0x202, 0x401, 0x401)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - RxVlanTaggingOperationTable - 0x402 - 5 - 0x402 - 4
        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data(0x202, 0x402, 0x402)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - RxVlanTaggingOperationTable - 0x403 - 5 - 0x403 - 4
        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data(0x202, 0x403, 0x403)
        yield self.wait_for_response()

        # Create AR - MacBridgePortConfigData - 513 - 513 - 1 - 11 - 1025
        self.send_create_mac_bridge_port_configuration_data(0x201, 0x201, 1, 11, 0x401)
        yield self.wait_for_response()

