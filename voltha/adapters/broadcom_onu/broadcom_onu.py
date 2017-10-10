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
from twisted.internet import reactor, task
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
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Image
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPF_1GB_FD, OFPPS_LINK_DOWN
from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, ofp_port
from voltha.protos.bbf_fiber_base_pb2 import VEnetConfig
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData

from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *

_ = third_party
log = structlog.get_logger()


BRDCM_DEFAULT_VLAN = 4091

@implementer(IAdapterInterface)
class BroadcomOnuAdapter(object):

    name = 'broadcom_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            vendor_id='BRCM',
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

        # register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

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
        self.devices_handlers[device.id] = BroadcomOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device

    def reconcile_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        log.info('disable-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.disable(device)

    def reenable_device(self, device):
        log.info('reenable-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.reenable(device)

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
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        log.info('self-test-device', device=device.id)
        raise NotImplementedError()

    def delete_device(self, device):
        raise NotImplementedError()

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        '''
        log.info('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)
        '''
        assert len(groups.items) == 0
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(device, flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.info('receive-proxied-message', proxy_address=proxy_address,
                 device_id=proxy_address.device_id, msg=hexify(msg))
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.receive_message(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        log.info('receive_inter_adapter_message', msg=msg)
        proxy_address = msg['proxy_address']
        assert proxy_address is not None
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.event_messages.put(msg)

    def create_interface(self, device, data):
        log.info('create-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_interface(data)

    def update_interface(self, device, data):
        log.info('update-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_interface(data)

    def remove_interface(self, device, data):
        log.info('remove-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_interface(data)

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('create-tcont', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_tcont(tcont_data, traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def create_gemport(self, device, data):
        log.info('create-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_gemport(data)

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_gemport(self, device, data):
        log.info('create-multicast-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_multicast_gemport(data)

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

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

class BroadcomOnuHandler(object):

    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue()
        self.event_messages = DeferredQueue()
        self.proxy_address = None
        self.tx_id = 0

        # Need to query ONU for number of supported uni ports
        # For now, temporarily set number of ports to 1 - port #2
        self.uni_ports = (2,)

        # Handle received ONU event messages
        reactor.callLater(0, self.handle_onu_events)

    def receive_message(self, msg):
        self.incoming_messages.put(msg)

    @inlineCallbacks
    def handle_onu_events(self):
        event_msg = yield self.event_messages.get()

        if event_msg['event'] == 'activation-completed':

            if event_msg['event_data']['activation_successful'] == True:
                device = self.adapter_agent.get_device(self.device_id)
                for uni in self.uni_ports:
                    port_no = self.proxy_address.channel_id + uni
                    reactor.callLater(1,
                      self.message_exchange,
                      self.proxy_address.onu_id,
                      self.proxy_address.onu_session_id,
                      port_no)

            else:
                device = self.adapter_agent.get_device(self.device_id)
                device.oper_status = OperStatus.FAILED
                self.adapter_agent.update_device(device)

        elif (event_msg['event'] == 'deactivation-completed'):
                device = self.adapter_agent.get_device(self.device_id)
                device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(device)

        elif (event_msg['event'] == 'deactivate-onu'):
                device = self.adapter_agent.get_device(self.device_id)
                device.connect_status = ConnectStatus.UNREACHABLE
                device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(device)
                self.delete_logical_port(device)

        elif event_msg['event'] == 'ranging-completed':

            if event_msg['event_data']['ranging_successful'] == True:
                device = self.adapter_agent.get_device(self.device_id)
                device.oper_status = OperStatus.ACTIVATING
                self.adapter_agent.update_device(device)

            else:
                device = self.adapter_agent.get_device(self.device_id)
                device.oper_status = OperStatus.FAILED
                self.adapter_agent.update_device(device)

        # Handle next event
        reactor.callLater(0, self.handle_onu_events)

    def disable(self, device):
        device = self.adapter_agent.get_device(self.device_id)
        device.admin_state = AdminState.DISABLED
        self.adapter_agent.update_device(device)
        event_data = dict()
        event_data['serial_number'] = device.serial_number
        msg = {'proxy_address': device.proxy_address,
              'event': 'onu-deactivation', 'event_data': event_data}
        self.adapter_agent.publish_inter_adapter_message(device.proxy_address.device_id,
                                                         msg)
        self.log.info('disabled', device_id=device.id)

    def reenable(self, device):
        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)
        device.admin_state = AdminState.ENABLED
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)
        event_data = dict()
        event_data['serial_number'] = device.serial_number
        msg = {'proxy_address': device.proxy_address,
              'event': 'onu-activation', 'event_data': event_data}
        self.adapter_agent.publish_inter_adapter_message(device.proxy_address.device_id,
                                                         msg)
        self.log.info('reenabled', device_id=device.id)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        #assert device.proxy_address.channel_id      # c-vid

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)


        # populate device info
        device.root = True
        device.vendor = 'Broadcom'
        device.model = 'n/a'
        device.hardware_version = 'to be filled'
        device.firmware_version = 'to be filled'
        device.images.image.extend([
                                        Image(version="to be filled")
                                       ])
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        self.adapter_agent.add_port(device.id, Port(
            port_no=100,
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

        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.DISCOVERED
        self.adapter_agent.update_device(device)

    @inlineCallbacks
    def update_flow_table(self, device, flows):
        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        #self.log.info('bulk-flow-update', device_id=device.id, flows=flows)

        def is_downstream(port):
            return port == 100  # Need a better way

        def is_upstream(port):
            return not is_downstream(port)

        for flow in flows:
            _type = None
            _port = None
            _vlan_vid = None
            _udp_dst = None
            _udp_src = None
            _ipv4_dst = None
            _ipv4_src = None
            _metadata = None
            _output = None
            _push_tpid = None
            _field = None
            _set_vlan_vid = None
            self.log.info('bulk-flow-update', device_id=device.id, flow=flow)
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
                        _metadata = field.table_metadata
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
                            _set_vlan_vid = _field.vlan_vid & 0xfff
                            self.log.info('set-field-type-valn-vid', _set_vlan_vid)
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type)
                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type, in_port=_in_port)

                #
                # All flows created from ONU adapter should be OMCI based
                #
                if _vlan_vid == 0 and _set_vlan_vid != None and _set_vlan_vid != 0:
                    # allow priority tagged packets
                    # Set AR - ExtendedVlanTaggingOperationConfigData
                    #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid

                    self.send_delete_vlan_tagging_filter_data(0x2102)
                    yield self.wait_for_response()

                    #self.send_set_vlan_tagging_filter_data(0x2102, _set_vlan_vid)
                    self.send_create_vlan_tagging_filter_data(0x2102, _set_vlan_vid)
                    yield self.wait_for_response()

                    self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(0x202, 0x1000, _set_vlan_vid)
                    yield self.wait_for_response()

                    self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x202, 8, 0, 0,
                                                                                                     1, 8, _set_vlan_vid)
                    yield self.wait_for_response()

                    # Set AR - ExtendedVlanTaggingOperationConfigData
                    #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
                    '''
                    self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x205, 8, 0, 0,
                                                                                                     1, 8, _set_vlan_vid)
                    yield self.wait_for_response()
                    '''

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

    def send_create_gal_ethernet_profile(self,
                                         entity_id,
                                         max_gem_payload_size):
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

    def send_set_tcont(self,
                       entity_id,
                       alloc_id):
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

    def send_create_8021p_mapper_service_profile(self,
                                                 entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    tp_pointer=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_0=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_1=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_2=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_3=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_4=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_5=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_6=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_7=OmciNullPointer
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_mac_bridge_service_profile(self,
                                               entity_id):
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

    def send_create_gem_port_network_ctp(self,
                                         entity_id,
                                         port_id,
                                         tcont_id,
                                         direction,
                                         tm):
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

    def send_create_multicast_gem_interworking_tp(self,
                                                  entity_id,
                                                  gem_port_net_ctp_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MulticastGemInterworkingTp.class_id,
                entity_id=entity_id,
                data=dict(
                    gem_port_network_ctp_pointer=gem_port_net_ctp_id,
                    interworking_option=0,
                    service_profile_pointer=0x1
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_gem_inteworking_tp(self,
                                       entity_id,
                                       gem_port_net_ctp_id,
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

    def send_set_8021p_mapper_service_profile(self,
                                              entity_id,
                                              interwork_tp_id):
        data = dict(
            interwork_tp_pointer_for_p_bit_priority_0=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_1=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_2=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_3=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_4=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_5=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_6=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_7=interwork_tp_id
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
                    tp_pointer=tp_id
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_vlan_tagging_filter_data(self,
                                             entity_id,
                                             vlan_id):
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

    def send_set_vlan_tagging_filter_data(self,
                                          entity_id,
                                          vlan_id):
        data = dict(
            vlan_filter_0=vlan_id,
            forward_operation=0x10,
            number_of_entries=1
        )

        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=entity_id,
                attributes_mask=VlanTaggingFilterData.mask_for(
                    *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_delete_vlan_tagging_filter_data(self,
                                          entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciDelete.message_id,
            omci_message=OmciDelete(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=entity_id
            )
        )
        self.send_omci_message(frame)

    def send_create_extended_vlan_tagging_operation_configuration_data(self,
                                                                       entity_id,
                                                                       assoc_type,
                                                                       assoc_me):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    association_type=assoc_type,
                    associated_me_pointer=assoc_me
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_tpid_configuration_data(self,
                                                                         entity_id,
                                                                         input_tpid,
                                                                         output_tpid):
        data = dict(
            input_tpid=input_tpid,
            output_tpid=output_tpid,
            downstream_mode=0,  # inverse of upstream
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(self,
                                                                                  entity_id,
                                                                                  filter_inner_vid,
                                                                                  treatment_inner_vid):
        data = dict(
            received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,
                    filter_outer_vid=4096,
                    filter_outer_tpid_de=0,

                    filter_inner_priority=15,
                    filter_inner_vid=filter_inner_vid,
                    filter_inner_tpid_de=0,
                    filter_ether_type=0,

                    treatment_tags_to_remove=0,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,
                    treatment_outer_tpid_de=0,

                    treatment_inner_priority=0,
                    treatment_inner_vid=treatment_inner_vid,
                    treatment_inner_tpid_de=4
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(self,
                                                                                    entity_id,
                                                                                    filter_inner_priority,
                                                                                    filter_inner_vid,
                                                                                    filter_inner_tpid_de,
                                                                                    treatment_tags_to_remove,
                                                                                    treatment_inner_priority,
                                                                                    treatment_inner_vid):
        data = dict(
            received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,
                    filter_outer_vid=4096,
                    filter_outer_tpid_de=0,

                    filter_inner_priority=filter_inner_priority,
                    filter_inner_vid=filter_inner_vid,
                    filter_inner_tpid_de=filter_inner_tpid_de,
                    filter_ether_type=0,

                    treatment_tags_to_remove=treatment_tags_to_remove,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,
                    treatment_outer_tpid_de=0,

                    treatment_inner_priority=treatment_inner_priority,
                    treatment_inner_vid=treatment_inner_vid,
                    treatment_inner_tpid_de=4
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_multicast_operations_profile(self,
                                                 entity_id,
                                                 igmp_ver):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                    MulticastOperationsProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    igmp_version=igmp_ver,
                    igmp_function=0,
                    immediate_leave=0
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_operations_profile_acl_row0(self,
                                                       entity_id,
                                                       acl_table,
                                                       row_key,
                                                       gem_port,
                                                       vlan,
                                                       src_ip,
                                                       dst_ip_start,
                                                       dst_ip_end):
        row0 = AccessControlRow0(
                    set_ctrl=1,
                    row_part_id=0,
                    test=0,
                    row_key=row_key,
                    gem_port_id=gem_port,
                    vlan_id=vlan,
                    src_ip=src_ip,
                    dst_ip_start=dst_ip_start,
                    dst_ip_end=dst_ip_end,
                    ipm_group_bw=0
                )

        if acl_table == 'dynamic':
            data = dict(
                dynamic_access_control_list_table=row0
            )
        else:
            data = dict(
                static_access_control_list_table=row0
            )

        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastOperationsProfile.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastOperationsProfile.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_operations_profile_ds_igmp_mcast_tci(self,
                                                                entity_id,
                                                                ctrl_type,
                                                                tci):
        data = dict(
            ds_igmp_mcast_tci=
                DownstreamIgmpMulticastTci(
                    ctrl_type=ctrl_type,
                    tci=tci
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastOperationsProfile.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastOperationsProfile.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_multicast_subscriber_config_info(self,
                                                     entity_id,
                                                     me_type,
                                                     mcast_oper_profile):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                data=dict(
                    me_type=me_type,
                    mcast_operations_profile_pointer=mcast_oper_profile
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_subscriber_config_info(self,
                                                  entity_id,
                                                  max_groups=0,
                                                  max_mcast_bw=0,
                                                  bw_enforcement=0):
        data = dict(
            max_simultaneous_groups=max_groups,
            max_multicast_bandwidth=max_mcast_bw,
            bandwidth_enforcement=bw_enforcement
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_service_package(self,
                                           entity_id,
                                           row_key,
                                           vid_uni,
                                           max_groups,
                                           max_mcast_bw,
                                           mcast_oper_profile):
        data = dict(
            multicast_service_package_table=
                MulticastServicePackage(
                    set_ctrl=1,
                    row_key=row_key,

                    vid_uni=vid_uni,
                    max_simultaneous_groups=max_groups,
                    max_multicast_bw=max_mcast_bw,
                    mcast_operations_profile_pointer=mcast_oper_profile
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_allowed_preview_groups_row0(self,
                                                       entity_id,
                                                       row_key,
                                                       src_ip,
                                                       vlan_id_ani,
                                                       vlan_id_uni):
        data = dict(
            allowed_preview_groups_table=
                AllowedPreviewGroupsRow0(
                    set_ctrl=1,
                    row_part_id=0,
                    row_key=row_key,

                    src_ip=src_ip,
                    vlan_id_ani=vlan_id_ani,
                    vlan_id_uni=vlan_id_uni
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_allowed_preview_groups_row1(self,
                                                       entity_id,
                                                       row_key,
                                                       dst_ip,
                                                       duration,
                                                       time_left):
        data = dict(
            allowed_preview_groups_table=
                AllowedPreviewGroupsRow1(
                    set_ctrl=1,
                    row_part_id=1,
                    row_key=row_key,

                    dst_ip=dst_ip,
                    duration=duration,
                    time_left=time_left
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
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
            log.info('got-response')
            # resp = OmciFrame(response)
            # resp.show()
        except Exception as e:
            self.log.info('wait-for-response-exception', exc=str(e))

    @inlineCallbacks
    def message_exchange(self, onu, gem, cvid):
        log.info('message_exchange', onu=onu, gem=gem, cvid=cvid)
        # reset incoming message queue
        while self.incoming_messages.pending:
            _ = yield self.incoming_messages.get()

        cvid = BRDCM_DEFAULT_VLAN

        # construct message
        # MIB Reset - OntData - 0
        self.send_mib_reset()
        yield self.wait_for_response()

        # Create AR - GalEthernetProfile - 1
        self.send_create_gal_ethernet_profile(1, 48)
        yield self.wait_for_response()

        # Port 2
        # Extended VLAN Tagging Operation config
        # Create AR - ExtendedVlanTaggingOperationConfigData - 514 - 2 - 0x102(Uni-Port-Num)
        # TODO: add entry here for additional UNI interfaces
        self.send_create_extended_vlan_tagging_operation_configuration_data(0x202, 2, 0x102)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - 8100 - 8100
        self.send_set_extended_vlan_tagging_operation_tpid_configuration_data(0x202, 0x8100, 0x8100)
        yield self.wait_for_response()

        # MAC Bridge Service config
        # Create AR - MacBridgeServiceProfile - 513
        self.send_create_mac_bridge_service_profile(0x201)
        yield self.wait_for_response()

        # Create AR - MacBridgePortConfigData - Entity_id -
        #                                       bridge ID -
        #                                       port num -
        #                                       tp_type -
        #                                       IEEE MApper poniter
        self.send_create_mac_bridge_port_configuration_data(0x201, 0x201, 2, 1, 0x102)
        yield self.wait_for_response()

        # Mapper Service config
        # Create AR - 802.1pMapperServiceProfile - 32769
        self.send_create_8021p_mapper_service_profile(0x8001)
        yield self.wait_for_response()

        # MAC Bridge Port config
        # Create AR - MacBridgePortConfigData - 8450 - 513 - 3 - 3 - 32769
        self.send_create_mac_bridge_port_configuration_data(0x2102, 0x201, 3, 3, 0x8001)
        yield self.wait_for_response()

        # VLAN Tagging Filter config
        # Create AR - VlanTaggingFilterData - 8450 - c-vid
        self.send_create_vlan_tagging_filter_data(0x2102, cvid)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData
        #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x202, 8, 0, 0, 1, 8, cvid)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData
        #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to untagged pkts - c-vid
        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(0x202, 0x1000, cvid)
        yield self.wait_for_response()

        # Multicast related MEs
        # Set AR - MulticastOperationsProfile - Dynamic Access Control List table
        # Create AR - MacBridgePortConfigData - 9000 - 513 - 6 - 6 - 6
        self.send_create_mac_bridge_port_configuration_data(0x2328, 0x201, 6, 6, 6)
        yield self.wait_for_response()

        # Multicast Operation Profile config
        # Create AR - MulticastOperationsProfile
        self.send_create_multicast_operations_profile(0x201, 3)
        yield self.wait_for_response()

        # Multicast Subscriber config
        # Create AR - MulticastSubscriberConfigInfo
        self.send_create_multicast_subscriber_config_info(0x201, 0, 0x201)
        yield self.wait_for_response()

        # Create AR - GemPortNetworkCtp - 260 - 4000 - 0 Multicast
        self.send_create_gem_port_network_ctp(0x104, 0x0FA0, 0, "downstream", 0)
        yield self.wait_for_response()

        # Multicast GEM Interworking config Multicast
        # Create AR - MulticastGemInterworkingTp - 6 - 260
        self.send_create_multicast_gem_interworking_tp(0x6, 0x104)
        yield self.wait_for_response()

        self.send_set_multicast_operations_profile_acl_row0(0x201,
                                                            'dynamic',
                                                            0,
                                                            0x0fa0,
                                                            0x0fa0,
                                                            '0.0.0.0',
                                                            '224.0.0.0',
                                                            '239.255.255.255')
        yield self.wait_for_response()

        # Multicast Operation Profile config
        # Set AR - MulticastOperationsProfile - Downstream IGMP Multicast TCI
        self.send_set_multicast_operations_profile_ds_igmp_mcast_tci(0x201, 4, cvid)
        yield self.wait_for_response()

        '''
        # Port 5
        # Extended VLAN Tagging Operation config
        # Create AR - ExtendedVlanTaggingOperationConfigData - 514 - 2 - 0x102
        # TODO: add entry here for additional UNI interfaces
        self.send_create_extended_vlan_tagging_operation_configuration_data(0x205, 2, 0x105)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - 8100 - 8100
        self.send_set_extended_vlan_tagging_operation_tpid_configuration_data(0x205, 0x8100, 0x8100)
        yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData
        #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
        #self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x205, 8, 0, 0, 1, 8, cvid)
        #yield self.wait_for_response()

        # Set AR - ExtendedVlanTaggingOperationConfigData
        #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to untagged pkts - c-vid
        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(0x205, 0x1000, cvid)
        yield self.wait_for_response()

        # MAC Bridge Port config
        # Create AR - MacBridgePortConfigData - 513 - 513 - 1 - 1 - 0x102
        # TODO: add more entries here for other UNI ports
        self.send_create_mac_bridge_port_configuration_data(0x205, 0x201, 5, 1, 0x105)
        yield self.wait_for_response()
        '''
        device = self.adapter_agent.get_device(self.device_id)
        device.admin_state = AdminState.ENABLED
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

    def add_uni_port(self, device, parent_logical_device_id,
                     name, parent_port_num=None):
        self.log.info('adding-logical-port', device_id=device.id,
                      logical_device_id=parent_logical_device_id,
                      name=name)
        if parent_port_num is not None:
            uni = parent_port_num
            port_no = parent_port_num
        else:
            uni = self.uni_ports[0]
            port_no = device.proxy_address.channel_id + uni    
            # register physical ports
        uni_port = Port(
            port_no=uni,
            label='UNI facing Ethernet port '+str(uni),
            type=Port.ETHERNET_UNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.adapter_agent.add_port(device.id, uni_port)
        # add uni port to logical device
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(parent_logical_device_id,
            LogicalPort(
                id='uni-{}'.format(port_no),
                ofp_port=ofp_port(
                    port_no=port_no,
                    hw_addr=mac_str_to_tuple('00:00:00:%02x:%02x:%02x' %
                                             (device.proxy_address.onu_id & 0xff,
                                              (port_no >> 8) & 0xff,
                                              port_no & 0xff)),
                    #name='uni-{}'.format(port_no),
                    name=name,
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

    def create_interface(self, data):
        if isinstance(data, VEnetConfig):
            parent_port_num = None
            onu_device = self.adapter_agent.get_device(self.device_id)
            if (onu_device.oper_status == OperStatus.ACTIVE):
                ports = self.adapter_agent.get_ports(onu_device.parent_id, Port.ETHERNET_UNI)
                parent_port_num = None
                for port in ports:
                    if port.label == data.interface.name:
                        parent_port_num = port.port_no
                        break

                parent_device = self.adapter_agent.get_device(onu_device.parent_id)
                logical_device_id = parent_device.parent_id
                assert logical_device_id
                self.add_uni_port(onu_device, logical_device_id,
                                  data.name, parent_port_num)

                if parent_port_num is None:
                    self.log.error("matching-parent-uni-port-num-not-found")
                    return

                onu_ports = self.adapter_agent.get_ports(self.device_id, Port.PON_ONU)
                if onu_ports:
                    # To-Do :
                    # Assumed only one PON port and UNI port per ONU.
                    pon_port = onu_ports[0]
                else:
                    self.log.error("No-Pon-port-configured-yet")
                    return

                self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                                     pon_port)

                pon_port.peers[0].device_id = onu_device.parent_id
                pon_port.peers[0].port_no = parent_port_num
                self.adapter_agent.add_port_reference_to_parent(self.device_id,
                                                                pon_port)
            else:
                self.log.error("ONU is not yet activated")
        else:
            self.log.info('Not handled Yet')
        return

    def update_interface(self, data):
        self.log.info('Not Implemented yet')
        return

    def remove_interface(self, data):
        self.log.info('Not Implemented yet')
        return

    @inlineCallbacks
    def create_gemport(self, data):
        onu_device = self.adapter_agent.get_device(self.device_id)
        if (onu_device.oper_status != OperStatus.ACTIVE):
           self.log.error("ONU is not yet activated")
           return
        log.info('create-gemport')
	gem_port= GemportsConfigData()
	gem_port.CopyFrom(data)
        if gem_port.tcont_ref is None:
            self.log.info('Recevied NULL Gem Port Data')
        else:
            #To-Do Need to see how the valuse 0x8001 is derived
            self.send_create_gem_port_network_ctp(gem_port.gemport_id,
                                                  gem_port.gemport_id, 0x8001,
                                                  "bi-directional", 0x100)
            yield self.wait_for_response()

            # GEM Interworking config
            # Create AR - GemInterworkingTp - Gem_port,TP_pointer -
            #                                 Gem port CTP pointer -
            #                                 Mapper service profile id
            self.send_create_gem_inteworking_tp(gem_port.gemport_id,
                                                gem_port.gemport_id, 0x8001)
            yield self.wait_for_response()

            # Mapper Service Profile config
            # Set AR - 802.1pMapperServiceProfile - Mapper_ profile_id -
            #                                       gem_port_tp pointer
            self.send_set_8021p_mapper_service_profile(0x8001,
                                                       gem_port.gemport_id)
            yield self.wait_for_response()


    @inlineCallbacks
    def create_tcont(self, tcont_data, traffic_descriptor_data):
        onu_device = self.adapter_agent.get_device(self.device_id)
        if (onu_device.oper_status != OperStatus.ACTIVE):
           self.log.error("ONU is not yet activated")
           return
        log.info('create-tcont')
	tcont = TcontsConfigData()
        tcont.CopyFrom(tcont_data)
        if (tcont.interface_reference is not None):
                self.log.info('tcont created is', tcont= tcont.alloc_id)
                self.send_set_tcont(0x8001, tcont.alloc_id)
                yield self.wait_for_response()
	else:
            self.log.info('Recevied NULL tcont Data', tcont= tcont.alloc_id)

    def create_multicast_gemport(self, data):
        self.log.info('Send relevant OMCI message')


    def delete_logical_port(self, onu_device):
        self.log.info('disabling', device_id=self.device_id)

        # Get the latest device reference
        onu_device = self.adapter_agent.get_device(self.device_id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        # Remove the uni logical port from the OLT, if still present
        parent_device = self.adapter_agent.get_device(onu_device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        ports = self.adapter_agent.get_ports(onu_device.id, Port.ETHERNET_UNI)
        port_id = 'uni-{}'.format(ports[0].port_no)
        try:
            lgcl_port = self.adapter_agent.get_logical_port(logical_device_id, port_id);
            self.adapter_agent.delete_logical_port(logical_device_id, lgcl_port)
        except KeyError:
            self.log.info('logical-port-not-found', device_id=self.device_id,
                          portid=port_id)
        # Remove pon port from parent
        if ports:
            # To-Do :
            # Assumed only one PON port and UNI port per ONU.
            pon_port = ports[0]
        else:
            self.log.error("No-Pon-port-configured-yet")
            return
        self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                             pon_port)
