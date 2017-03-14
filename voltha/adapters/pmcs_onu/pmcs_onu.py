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
PMC Sierra ONU adapter
"""

import structlog
from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from zope.interface import implementer

from voltha.adapters.interface import IAdapterInterface
from voltha.adapters.microsemi_olt.DeviceManager import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, ConnectStatus, AdminState, OperStatus
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_1GB_FD, OFPPF_FIBER, ofp_port, OFPPS_LIVE

from voltha.extensions.omci.omci_entities import CircuitPack
from voltha.extensions.omci.omci_frame import OmciFrame
<<<<<<< HEAD
from voltha.extensions.omci.omci_messages import OmciGet, OmciGetResponse
=======
from voltha.extensions.omci.omci_messages import OmciGet, OmciGetResponse, OmciCreate
>>>>>>> pmcs message sequence completed

_ = third_party
log = structlog.get_logger()

@implementer(IAdapterInterface)
class PmcsOnu(object):

    name = 'pmcs_onu'

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
            vendor='PMCS',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.incoming_messages = DeferredQueue()

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
        log.info('adopt-device', device=device)
        reactor.callLater(0.1, self._onu_device_activation, device)
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

    def deactivate_device(self, device):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.info('receive-proxied-message', proxy_address=proxy_address,
                 device_id=proxy_address.device_id, msg=msg)
        self.incoming_messages.put(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    @inlineCallbacks
    def _onu_device_activation(self, device):
        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        device.model = 'GPON ONU'
        device.hardware_version = 'tbd'
        device.firware_version = 'tbd'
        device.software_version = 'tbd'

        device.connect_status = ConnectStatus.REACHABLE

        self.adapter_agent.update_device(device)

        uni_port = Port(port_no=self.port_id,
                    label="{} ONU".format('PMCS'),
                    type=Port.ETHERNET_UNI,
                    admin_state=AdminState.ENABLED,
                    oper_status=OperStatus.ACTIVE
                    )
        self.device.add_port(uni_port)

        pon_port = Port(
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
        )

        self.adapter_agent.add_port(device.id, pon_port)

        # obtain logical device id
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id

        # we are going to use the proxy_address.channel_id as unique number
        # and name for the virtual ports, as this is guaranteed to be unique
        # in the context of the OLT port, so it is also unique in the context
        # of the logical device
        port_no = device.proxy_address.channel_id
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
            id=str(port_no),
            ofp_port=ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple(device.mac_address),
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

        self._initialize_onu(device)

        # and finally update to "ACTIVE"
        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)


    def _initialize_onu(self, device):
        # DO things to the ONU


        # |###[ OmciFrame ]### 
        #     |  transaction_id= 1
        #     |  message_type= 79
        #     |  omci      = 10
        #     |  \omci_message\
        #     |   |###[ OmciMibReset ]### 
        #     |   |  entity_class= 2
        #     |   |  entity_id = 0
        #     |  omci_trailer= 40

        # OmciMibReset
        msg = OmciMibReset(entity_class = 2, entity_id = 0)
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciMibResetResponse in response:
            pass

        # ###[ PAS5211Dot3 ]### 
        #   dst       = 00:0c:d5:00:01:00
        #   src       = 90:e2:ba:82:f9:77
        #   len       = 22
        # ###[ PAS5211FrameHeader ]### 
        #      part      = 1
        #      total_parts= 1
        #      size      = 16
        #      magic_number= 0x1234abcd
        # ###[ PAS5211MsgHeader ]### 
        #         sequence_number= 51
        #         opcode    = 0x3009
        #         event_type= 0
        #         channel_id= 0
        #         onu_id    = 0
        #         onu_session_id= 1
        # ###[ PAS5211GetOnuAllocs ]### 
        #            nothing   = 0
        # ###[ Raw ]### 
        #               load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


        
        msg = PAS5211GetOnuAllocs()
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not PAS5211GetOnuAllocsResponse in response:
            pass

        #  ###[ PAS5211Dot3 ]### 
        #   dst       = 00:0c:d5:00:01:00
        #   src       = 90:e2:ba:82:f9:77
        #   len       = 30
        # ###[ PAS5211FrameHeader ]### 
        #      part      = 1
        #      total_parts= 1
        #      size      = 24
        #      magic_number= 0x1234abcd
        # ###[ PAS5211MsgHeader ]### 
        #         sequence_number= 52
        #         opcode    = 0x3007
        #         event_type= 0
        #         channel_id= 0
        #         onu_id    = -1
        #         onu_session_id= -1
        # ###[ PAS5211GetSnInfo ]### 
        #            serial_number= 'PMCS\xd5b\x84\xac'
        # ###[ Raw ]### 
        #               load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


        msg = PAS5211GetSnInfo(serial_number=device.serial_number)
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)   

        if not PAS5211GetSnInfoResponse in response:
            pass

        # ###[ PAS5211Dot3 ]### 
        #   dst       = 00:0c:d5:00:01:00
        #   src       = 90:e2:ba:82:f9:77
        #   len       = 22
        # ###[ PAS5211FrameHeader ]### 
        #      part      = 1
        #      total_parts= 1
        #      size      = 16
        #      magic_number= 0x1234abcd
        # ###[ PAS5211MsgHeader ]### 
        #         sequence_number= 53
        #         opcode    = 0x3074
        #         event_type= 0
        #         channel_id= 0
        #         onu_id    = -1
        #         onu_session_id= -1
        # ###[ PAS5211GetOnusRange ]### 
        #            nothing   = 0
        # ###[ Raw ]### 
        #               load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
        msg = PAS5211GetOnusRange()
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)  

        if not PAS5211GetOnusRangeResponse in response:
            pass       
       
        #  |  ###[ OmciFrame ]###
        # | transaction_id = 2
        # | message_type = 72
        # | omci = 10
        # |   \omci_message \
        #      | |  ###[ OmciSet ]###
        # | | entity_class = 262
        # | | entity_id = 32769
        # | | attributes_mask = 32768
        # | | data = {'alloc_id': 1000}
        # | omci_trailer = 40

        # OmciSet
        # TODO: maskdata
        msg = OmciSet(entity_class = 262, entity_id = 32769, attributes_mask = 32768,
                      data=dict(
                        alloc_id = 1000
                    ))
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciSetResponse in response:
            pass


        # ﻿  ###[ PAS5211MsgSendFrame ]###
        # length = 44
        # port_type = 0
        # port_id = 0
        # management_frame = 1
        # \frame \
        #  |  ###[ OmciFrame ]###
        # | transaction_id = 3
        # | message_type = 68
        # | omci = 10
        # |   \omci_message \
        #      | |  ###[ OmciCreate ]###
        # | | entity_class = 45
        # | | entity_id = 1
        # | | data = {'max_age': 5120, 'hello_time': 512, 'priority': 32768, 'port_bridging_ind': 0,
        #             'spanning_tree_ind': 0, 'unknown_mac_address_discard': 0, 'mac_learning_depth': 128,
        #             'learning_ind': 0, 'forward_delay': 3840}
        # | |  ###[ Raw ]###
        # | | load = '\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        # | omci_trailer = 40


        # OmciCreate
        msg = OmciCreate(entity_class=45, entity_id=1,
                         data=dict(
                             max_age = 5120, hello_time = 512, priority = 32768,
                             port_bridging_ind = 0, spanning_tree_ind= 0, unknown_mac_address_discard= 0, mac_learning_depth=128
                             learning_ind= 0, forward_delay= 3840
                         ))
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciCreateResponse in response:
            pass


        # |###[ OmciFrame ]### 
        #     |  transaction_id= 4
        #     |  message_type= 68
        #     |  omci      = 10
        #     |  \omci_message\
        #     |   |###[ OmciCreate ]### 
        #     |   |  entity_class= 47
        #     |   |  entity_id = 0
        #     |   |  data      = {'tp_pointer': 257, 'encapsulation_methods': 1, 'port_num': 0, 'port_priority': 10, 'tp_type': 1, 'port_path_cost': 100, 'port_spanning_tree_in': 0, 'lan_fcs_ind': 0, 'bridge_id_pointer': 1}
        #     |  omci_trailer= 40

        # OmciCreate
        msg = OmciCreate(entity_class=47, entity_id=0,
                         data=dict(
                                tp_pointer= 257, encapsulation_methods =  1,
                                port_num = 0, port_priority = 10, tp_type = 1,
                                port_path_cost = 100, port_spanning_tree_in = 0,
                                lan_fcs_ind = 0, bridge_id_pointer = 1
                         ))
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)
        
        if not OmciCreateResponse in response:
            pass

        # |###[ OmciFrame ]### 
        # |  transaction_id= 5
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]### 
        # |   |  entity_class= 171
        # |   |  entity_id = 0
        # |   |  data      = {'association_type': 2, 'associated_me_pointer': 257}
        # |  omci_trailer= 40

        msg = OmciCreate(entity_class=171, entity_id=0,
                         data=dict(
                                association_type= 2, associated_me_pointer= 257
                         ))
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciCreateResponse in response:
            pass

        # |###[ OmciFrame ]### 
        # |  transaction_id= 6
        # |  message_type= 72
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciSet ]### 
        # |   |  entity_class= 171
        # |   |  entity_id = 0
        # |   |  attributes_mask= 47616
        # |   |  data      = {'association_type': 2, 'input_tpid': 33024, 'associated_me_pointer': 257, 'downstream_mode': 0, 'output_tpid': 33024}
        # |  omci_trailer= 40

        msg = OmciSet(entity_class = 171, entity_id = 0, attributes_mask = 47616,
                      data=dict(
                        association_type = 2, input_tpid = 33024, associated_me_pointer= 257,
                    downstream_mode= 0, output_tpid= 33024
                    ))

        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciSetResponse in response:
            pass

        # |###[ OmciFrame ]### 
        # |  transaction_id= 7
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]### 
        # |   |  entity_class= 130
        # |   |  entity_id = 1
        # |   |  data      = {'tp_pointer': 65535, 'unmarked_frame_option': 1, 'interwork_tp_pointer_for_p_bit_priority_6': 65535, 'interwork_tp_pointer_for_p_bit_priority_7': 65535, 'interwork_tp_pointer_for_p_bit_priority_4': 65535, 'interwork_tp_pointer_for_p_bit_priority_5': 65535, 'interwork_tp_pointer_for_p_bit_priority_2': 65535, 'interwork_tp_pointer_for_p_bit_priority_3': 65535, 'interwork_tp_pointer_for_p_bit_priority_0': 65535, 'interwork_tp_pointer_for_p_bit_priority_1': 65535, 'tp_type': 0, 'default_p_bit_marking': 0}
        # |  omci_trailer= 40

        msg = OmciCreate(entity_class=130, entity_id=1,
                         data=dict(
                                tp_pointer= 65535, unmarked_frame_option= 1, interwork_tp_pointer_for_p_bit_priority_6= 65535, 
                                interwork_tp_pointer_for_p_bit_priority_7= 65535, interwork_tp_pointer_for_p_bit_priority_4= 65535, 
                                interwork_tp_pointer_for_p_bit_priority_5= 65535, interwork_tp_pointer_for_p_bit_priority_2= 65535, 
                                interwork_tp_pointer_for_p_bit_priority_3= 65535, interwork_tp_pointer_for_p_bit_priority_0: 65535, 
                                interwork_tp_pointer_for_p_bit_priority_1= 65535, tp_type= 0, default_p_bit_marking= 0}
                         ))
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciCreateResponse in response:
            pass

        # |###[ OmciFrame ]### 
        # |  transaction_id= 8
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]### 
        # |   |  entity_class= 130
        # |   |  entity_id = 1
        # |   |  data      = {'tp_pointer': 1, 'encapsulation_methods': 1, 'port_num': 1, 'port_priority': 3, 'tp_type': 5, 'port_path_cost': 32, 'port_spanning_tree_in': 1, 'lan_fcs_ind': 0, 'bridge_id_pointer': 1}
        # |  omci_trailer= 40

        msg = OmciCreate(entity_class=130, entity_id=1,
                         data=dict(
                                tp_pointer= 1, encapsulation_methods= 1, port_num= 1, port_priority= 3, tp_type= 5, 
                                port_path_cost= 32, port_spanning_tree_in= 1, lan_fcs_ind= 0, bridge_id_pointer= 1
                         ))
        response = yield self.adapter_agent.send_proxied_message(self, device.proxy_address, msg)

        if not OmciCreateResponse in response:
            pass

        # |###[ OmciFrame ]### 
        # |  transaction_id= 9
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]### 
        # |   |  entity_class= 268
        # |   |  entity_id = 1
        # |   |  data      = {'priority_queue_pointer_downstream': 0, 'direction': 3, 'tcont_pointer': 32769, 'traffic_descriptor_profile_pointer': 0, 'traffic_management_pointer_upstream': 4, 'port_id': 1000}
        # |  omci_trailer= 40

        msg = OmciCreate(entity_class=268, entity_id=1,
                         data=dict(
                                priority_queue_pointer_downstream= 0, direction= 3, tcont_pointer= 32769, 
                                traffic_descriptor_profile_pointer= 0, traffic_management_pointer_upstream= 4, 
                                port_id= 1000
                         ))
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciCreateResponse in response:
            pass

        # |###[ OmciFrame ]### 
        # |  transaction_id= 10
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]### 
        # |   |  entity_class= 266
        # |   |  entity_id = 1
        # |   |  data      = {'gem_port_network_ctp_pointer': 1, 'gal_profile_pointer': 0, 'service_profile_pointer': 1, 'interworking_option': 5, 'interworking_tp_pointer': 0}
        # |  omci_trailer= 40

        msg = OmciCreate(entity_class=266, entity_id=1,
                         data=dict(
                                gem_port_network_ctp_pointer= 1, gal_profile_pointer= 0, 
                                service_profile_pointer= 1, interworking_option= 5, 
                                interworking_tp_pointer= 0
                         ))
        response = yield self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        if not OmciCreateResponse in response:
            pass

        pass