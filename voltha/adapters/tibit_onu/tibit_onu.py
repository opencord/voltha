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
Tibit ONU device adapter
"""

import time
import struct
import re

from uuid import uuid4

import arrow
import structlog
from twisted.internet.task import LoopingCall
from zope.interface import implementer

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet import reactor

from voltha.core.flow_decomposer import *
from voltha.core.logical_device_agent import mac_str_to_tuple
from common.frameio.frameio import BpfProgramFilter, hexify
from voltha.adapters.interface import IAdapterInterface
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.device_pb2 import Port, Image
from voltha.protos.device_pb2 import DeviceType, DeviceTypes
from voltha.protos.events_pb2 import KpiEventType
from voltha.protos.events_pb2 import MetricValuePairs, KpiEvent
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.common_pb2 import LogLevel, ConnectStatus
from voltha.protos.common_pb2 import OperStatus, AdminState

from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_port, OFPPF_10GB_FD, \
    OFPPF_FIBER, OFPPS_LIVE, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS

from scapy.packet import Packet, bind_layers
from scapy.fields import StrField

log = structlog.get_logger()

from voltha.extensions.eoam.EOAM_TLV import UserPortObject
from voltha.extensions.eoam.EOAM_TLV import AddStaticMacAddress, DeleteStaticMacAddress
from voltha.extensions.eoam.EOAM_TLV import ClearStaticMacTable
from voltha.extensions.eoam.EOAM_TLV import DeviceId
from voltha.extensions.eoam.EOAM_TLV import ClauseSubtypeEnum, RuleClauses
from voltha.extensions.eoam.EOAM_TLV import RuleOperatorEnum, RuleOperators
from voltha.extensions.eoam.EOAM_TLV import DPoEOpcodeEnum, DPoEVariableResponseEnum
from voltha.extensions.eoam.EOAM_TLV import DPoEOpcode_MulticastRegister, MulticastRegisterSet
from voltha.extensions.eoam.EOAM_TLV import VendorName, OnuMode, HardwareVersion, ManufacturerInfo
from voltha.extensions.eoam.EOAM_TLV import SlowProtocolsSubtypeEnum, DeviceReset
from voltha.extensions.eoam.EOAM_TLV import DONUObject, \
     UserPortObject, PonPortObject, \
     PortIngressRuleClauseMatchLength00, PortIngressRuleClauseMatchLength01, \
     PortIngressRuleClauseMatchLength02, PortIngressRuleResultForward, \
     PortIngressRuleResultSet, PortIngressRuleResultInsert, \
     PortIngressRuleResultCopy, PortIngressRuleResultReplace, \
     PortIngressRuleResultDelete, PortIngressRuleResultOLTQueue, \
     PortIngressRuleTerminator, AddPortIngressRule, DPoEOpcodes
from voltha.extensions.eoam.EOAM_TLV import PortIngressRuleHeader
from voltha.extensions.eoam.EOAM_TLV import EndOfPDU

from voltha.extensions.eoam.EOAM_Layers import EOAMPayload, EOAM_EventMsg, EOAM_VendSpecificMsg
from voltha.extensions.eoam.EOAM_Layers import EOAM_TibitMsg, EOAM_DpoeMsg
from voltha.extensions.eoam.EOAM_Layers import OAM_ETHERTYPE
from voltha.extensions.eoam.EOAM_Layers import CABLELABS_OUI, TIBIT_OUI
from voltha.extensions.eoam.EOAM_Layers import RxedOamMsgTypeEnum, RxedOamMsgTypes
from voltha.extensions.eoam.EOAM import DPoEOpcode_GetRequest, DPoEOpcode_SetRequest
from voltha.extensions.eoam.EOAM import mcastIp2McastMac, get_oam_msg_type, get_value_from_msg, check_set_resp, check_resp


TIBIT_MSG_WAIT_TIME = 3


@implementer(IAdapterInterface)
class TibitOnuAdapter(object):

    name = 'tibit_onu'

    supported_device_types = [
        DeviceType(
            id='tibit_onu',
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Tibit Communications Inc.',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.incoming_messages = DeferredQueue()
        self.mode = "GPON"

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

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def adopt_device(self, device):
        log.info('adopt-device', device=device)
        reactor.callLater(0.1, self._onu_device_activation, device)
        return device

    def reconcile_device(self, device):
        raise NotImplementedError()

    @inlineCallbacks
    def _onu_device_activation(self, device):
        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # Device information will be updated later on
        device.vendor = 'Tibit Communications, Inc.'
        device.model = '10G GPON ONU'
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # then shortly after we create some ports for the device
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

        # TODO adding vports to the logical device shall be done by agent?
        # then we create the logical device port that corresponds to the UNI
        # port of the device

        # obtain logical device id
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id

        # we are going to use the proxy_address.channel_id as unique number
        # and name for the virtual ports, as this is guaranteed to be unique
        # in the context of the OLT port, so it is also unique in the context
        # of the logical device
        port_no = device.proxy_address.channel_id
        cap = OFPPF_10GB_FD | OFPPF_FIBER
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
                curr_speed=OFPPF_10GB_FD,
                max_speed=OFPPF_10GB_FD
            ),
            device_id=device.id,
            device_port_no=uni_port.port_no
        ))

        # simulate a proxied message sending and receving a reply
        reply = yield self._message_exchange(device)

        # TODO - Need to add validation of reply and decide what to do upon failure

        # and finally update to "ACTIVE"
        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        # TODO - Disable Stats Reporting for the moment
        #self.start_kpi_collection(device.id)

    def abandon_device(self, device):
        raise NotImplementedError(0
                                  )
    def disable_device(self, device):
        log.info('disabling', device_id=device.id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(device.id)

        # Update the device operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the uni logical port from the OLT, if still present
        parent_device = self.adapter_agent.get_device(device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
#        port_id = 'uni-{}'.format(port_no)
        port_id = '{}'.format(port_no)
        try:
            port = self.adapter_agent.get_logical_port(logical_device_id,
                                                       port_id)
            self.adapter_agent.delete_logical_port(logical_device_id, port)
        except KeyError:
            log.info('logical-port-not-found', device_id=device.id,
                     portid=port_id)

        # Remove pon port from parent
        #self.adapter_agent.delete_port_reference_from_parent(device.id,
        #                                                     self.pon_port)

        # Just updating the port status may be an option as well
        # port.ofp_port.config = OFPPC_NO_RECV
        # yield self.adapter_agent.update_logical_port(logical_device_id,
        #                                             port)
        # Unregister for proxied message
        self.adapter_agent.unregister_for_proxied_messages(device.proxy_address)

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        log.info('disabled', device_id=device.id)

        return device

    def reenable_device(self, device):
        log.info('re-enabling', device_id=device.id)

        # First we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # Re-register for proxied messages right away
        #self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # Re-enable the ports on that device
        self.adapter_agent.enable_all_ports(device.id)

        # Add the pon port reference to the parent
        #self.adapter_agent.add_port_reference_to_parent(device.id,
        #                                                self.pon_port)

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # re-add uni port to logical device
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
        cap = OFPPF_10GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
#            id='uni-{}'.format(port_no),
            id= str(port_no),
            ofp_port=ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple(device.mac_address),
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
            device_port_no=2
        ))

        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        log.info('re-enabled', device_id=device.id)


    @inlineCallbacks
    def reboot_device(self, device):
        log.info('Rebooting ONU: {}'.format(device.mac_address))

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE
        previous_oper_status = device.oper_status
        previous_conn_status = device.connect_status
        device.oper_status = OperStatus.ACTIVATING
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # send message
        action = "Device Reset"
        rc = []
        tlvs = DeviceReset()
        yield self._set_req_rsp(device, action, tlvs, rc)

        # Change the operational status back to its previous state.
        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        self.adapter_agent.update_device(device)

        log.info('ONU Rebooted: {}'.format(device.mac_address))

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
        log.info('deleting', device_id=device.id)

        # A delete request may be received when an OLT is disabled

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        log.info('deleted', device_id=device.id)

    def get_device_details(self, device):
        raise NotImplementedError()

    @inlineCallbacks
    def update_flows_bulk(self, device, flows, groups):
        log.info('########################################')
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0, "Cannot yet deal with groups"

        # Only do something if there are flows to program
        if (len(flows.items) > 0):
            # Clear the existing entries in the Static MAC Address Table
            yield self._send_clear_static_mac_table(device)

            # Re-add the IGMP Multicast Address
            yield self._send_igmp_mcast_addr(device)

        for flow in flows.items:
            in_port = get_in_port(flow)
            assert in_port is not None

            precedence = 255 - min(flow.priority / 256, 255)

            if in_port == 2:
                log.info('#### Upstream Rule ####')

                up_req = UserPortObject()
                up_req /= PortIngressRuleHeader(precedence=precedence)

                for field in get_ofb_fields(flow):

                    if field.type == ETH_TYPE:
                        _type = field.eth_type
                        log.info('#### field.type == ETH_TYPE ####',field_type=_type)

                    elif field.type == IP_PROTO:
                        _proto = field.ip_proto
                        log.info('#### field.type == IP_PROTO ####')

                    elif field.type == IN_PORT:
                        _port = field.port
                        log.info('#### field.type == IN_PORT ####', port=_port)

                    elif field.type == VLAN_VID:
                        _vlan_vid = field.vlan_vid & 0xfff
                        log.info('#### field.type == VLAN_VID ####', vlan=_vlan_vid)
                        up_req /= PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=0,
                                                                     operator=RuleOperators['=='], match=_vlan_vid)

                    elif field.type == VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        log.info('#### field.type == VLAN_PCP ####', pcp=_vlan_pcp)

                    elif field.type == UDP_DST:
                        _udp_dst = field.udp_dst
                        log.info('#### field.type == UDP_DST ####', udp_dst=_udp_dst)

                    elif field.type == IPV4_DST:
                        _ipv4_dst = field.ipv4_dst
                        log.info('#### field.type == IPV4_DST ####', ipv4_dst=_ipv4_dst)

                    elif field.type == METADATA:
                        _metadata = field.table_metadata
                        log.info('#### field.type == METADATA ####', metadata=_metadata)

                    else:
                        log.info('#### field.type == NOT IMPLEMENTED!! ####')
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in get_actions(flow):

                    if action.type == OUTPUT:
                        log.info('#### action.type == OUTPUT ####')
                        up_req /= PortIngressRuleResultInsert(fieldcode=RuleClauses['C-VLAN Tag'])

                    elif action.type == POP_VLAN:
                        log.info('#### action.type == POP_VLAN ####')

                    elif action.type == PUSH_VLAN:
                        log.info('#### action.type == PUSH_VLAN ####')
                        up_req /= PortIngressRuleResultInsert(fieldcode=RuleClauses['C-VLAN Tag'])
#                        if action.push.ethertype != 0x8100:
#                            log.error('unhandled-tpid',
#                                      ethertype=action.push.ethertype)

                    elif action.type == SET_FIELD:
                        log.info('#### action.type == SET_FIELD ####')
                        assert (action.set_field.field.oxm_class ==
                                ofp.OFPXMC_OPENFLOW_BASIC)
                        field = action.set_field.field.ofb_field
                        if field.type == VLAN_VID:
                            log.info("#### action.field.vlan {} ####".format(field.vlan_vid & 0xfff))
                            # need to convert value in Set to a variable length value
                            ctagStr = struct.pack('>H', (field.vlan_vid & 0xfff))

                            up_req /= PortIngressRuleResultSet(
                                    fieldcode=RuleClauses['C-VLAN Tag'], value=ctagStr)
                        else:
                            raise NotImplementedError('unsupported-action-set-field-type={}'.format(field.type))
                    else:
                        raise NotImplementedError('unsupported-action-type={}'.format(action.type))

                up_req /= PortIngressRuleTerminator()
                up_req /= AddPortIngressRule()

                # send message
                action = "Set ONU US Rule"
                rc = []
                yield self._set_req_rsp(device, action, up_req, rc)


            elif in_port == 1:
                log.info('#### Downstream Rule ####')
                Is_MCast = False

                dn_req = PonPortObject()
                dn_req /= PortIngressRuleHeader(precedence=precedence)

                #### Loop through fields again...

                for field in get_ofb_fields(flow):

                    if field.type == ETH_TYPE:
                        _type = field.eth_type
                        log.info('#### field.type == ETH_TYPE ####', in_port=in_port,
                                 match=_type)

                    elif field.type == IP_PROTO:
                        _proto = field.ip_proto
                        log.info('#### field.type == IP_PROTO ####', in_port=in_port,
                                 ip_proto=_proto)

                    elif field.type == IN_PORT:
                        _port = field.port
                        log.info('#### field.type == IN_PORT ####')

                    elif field.type == VLAN_VID:
                        _vlan_vid = field.vlan_vid & 0xfff
                        log.info('#### field.type == VLAN_VID ####')
                        dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=0,
                                                                     operator=RuleOperators['=='], match=_vlan_vid)

                    elif field.type == VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        log.info('#### field.type == VLAN_PCP ####')

                    elif field.type == UDP_DST:
                        _udp_dst = field.udp_dst
                        log.info('#### field.type == UDP_DST ####')

                    elif field.type == IPV4_DST:
                        _ipv4_dst = field.ipv4_dst
                        log.info('#### field.type == IPV4_DST ####')
                        a = int(hex(_ipv4_dst)[2:4], 16)
                        b = int(hex(_ipv4_dst)[4:6], 16)
                        c = int(hex(_ipv4_dst)[6:8], 16)
                        d = int(hex(_ipv4_dst)[8:], 16)
                        dn_req = AddStaticMacAddress(mac=mcastIp2McastMac('%d.%d.%d.%d' % (a,b,c,d)))
                        Is_MCast = True

                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in get_actions(flow):

                    if action.type == OUTPUT:
                        log.info('#### action.type == OUTPUT ####')

                    elif action.type == POP_VLAN:
                        log.info('#### action.type == POP_VLAN ####')

                        # TODO - This is not the correct operation for a POP operation.
                        #        This should be a Delete result
                        dn_req /= PortIngressRuleResultReplace(fieldcode=RuleClauses['C-VLAN Tag'])
                        # need to convert value in Set to a variable length value
                        ctagStr = struct.pack('>H', (field.vlan_vid & 0xfff))
                        dn_req /= PortIngressRuleResultSet(
                                fieldcode=RuleClauses['C-VLAN Tag'], value=ctagStr)

                    elif action.type == PUSH_VLAN:
                        log.info('#### action.type == PUSH_VLAN ####')
                        if action.push.ethertype != 0x8100:
                            raise NotImplementedError('unhandled-ether-type={}'.format(action.push.ethertype))

                    elif action.type == SET_FIELD:
                        log.info('#### action.type == SET_FIELD ####')
                        assert (action.set_field.field.oxm_class ==
                                ofp.OFPXMC_OPENFLOW_BASIC)
                        field = action.set_field.field.ofb_field
                        if field.type == VLAN_VID:
                            log.info("#### action.field.vlan {} ####".format(field.vlan_vid & 0xfff))

                            # TODO - Currently only support setting the VID in the DS to zero (clearing the VID)
                            if ((field.vlan_vid & 0xfff) == 0):
                                dn_req /= PortIngressRuleResultReplace(fieldcode=RuleClauses['C-VLAN Tag'])
                                # need to convert value in Set to a variable length value
                                ctagStr = struct.pack('>H', (field.vlan_vid & 0xfff))
                                dn_req /= PortIngressRuleResultSet(
                                        fieldcode=RuleClauses['C-VLAN Tag'], value=ctagStr)
                            else:
                                raise NotImplementedError('unsupported-set-vlan-id={}'.format(field.vlan_vid & 0xfff))
                        else:
                            raise NotImplementedError('unsupported-action-set-field-type={}'.format(field.type))
                    else:
                        raise NotImplementedError('unsupported-action-type={}'.format(action.type))

                if Is_MCast is True:
                    action = "Set Static IP MCAST address"
                else:
                    dn_req /= PortIngressRuleTerminator()
                    dn_req /= AddPortIngressRule()
                    action = "Set ONU DS Rule"

                # send message
                rc = []
                yield self._set_req_rsp(device, action, dn_req, rc)

            else:
                raise Exception('Port should be 1 or 2 by our convention')

        log.info('bulk-flow-update finished', device_id=device.id,
                 flows=flows, groups=groups)
        log.info('########################################')

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_proxied_message(self, proxy_address, msg):
        log.info('receive-proxied-message',
                  proxy_address=proxy_address, msg=msg.show(dump=True))
        self.incoming_messages.put(msg)

    def create_interface(self, device, data):
        raise NotImplementedError()

    def update_interface(self, device, data):
        raise NotImplementedError()

    def remove_interface(self, device, data):
        raise NotImplementedError()

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def create_gemport(self, device, data):
        raise NotImplementedError()

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
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

    @inlineCallbacks
    def _message_exchange(self, device):

        # register for receiving async messages
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # reset incoming message queue
        while self.incoming_messages.pending:
            _ = yield self.incoming_messages.get()

        resp = []
        action = "Get Device Info"
        body = VendorName()/OnuMode()/HardwareVersion()/ManufacturerInfo()
        yield self._get_req_rsp(device, action, body, resp)
        if resp is not []: frame = resp[0]

        if frame:
            log.info('ONU-response received for Get Version Info for ONU: {}'.format(device.mac_address))
            self._process_ping_frame_response(device, frame)


        if self.mode.upper()[0] == "G":  # GPON

            hw_vers = int(device.hardware_version, 16)

            if hw_vers >= 0x170618:
                mcastLidx = 0x04bc
            elif hw_vers >= 0x170517:
                mcastLidx = 0x14bc
            else:
                mcastLidx = 0x10bc

            log.info("Using Multicast LIDX {:04X}".format(mcastLidx))

            tlvs = MulticastRegisterSet(MulticastLink=mcastLidx, UnicastLink=0)
            msg = self._build_dpoe_oam_msg(DPoEOpcodes["Multicast Register"], tlvs)
            # send message
            log.info('ONU-send-proxied-message to Multicast Register Set for ONU: {}'.format(device.mac_address))
            self.adapter_agent.send_proxied_message(device.proxy_address, msg)

            # The MulticastRegisterSet does not currently return a response. Just hope it worked.

        # by returning we allow the device to be shown as active, which
        # indirectly verified that message passing works

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

    def start_kpi_collection(self, device_id):

        """TMP Simulate periodic KPI metric collection from the device"""
        import random

        @inlineCallbacks  # pretend that we need to do async calls
        def _collect(device_id, prefix):

            try:
                # Step 1: gather metrics from device (pretend it here) - examples
                uni_port_metrics = yield dict(
                    tx_pkts=random.randint(0, 100),
                    rx_pkts=random.randint(0, 100),
                    tx_bytes=random.randint(0, 100000),
                    rx_bytes=random.randint(0, 100000),
                )
                pon_port_metrics = yield dict(
                    tx_pkts=uni_port_metrics['rx_pkts'],
                    rx_pkts=uni_port_metrics['tx_pkts'],
                    tx_bytes=uni_port_metrics['rx_bytes'],
                    rx_bytes=uni_port_metrics['tx_bytes'],
                )
                onu_metrics = yield dict(
                    cpu_util=20 + 5 * random.random(),
                    buffer_util=10 + 10 * random.random()
                )

                # Step 2: prepare the KpiEvent for submission
                # we can time-stamp them here (or could use time derived from OLT
                ts = arrow.utcnow().timestamp
                kpi_event = KpiEvent(
                    type=KpiEventType.slice,
                    ts=ts,
                    prefixes={
                        # OLT-level
                        prefix: MetricValuePairs(metrics=onu_metrics),
                        # OLT NNI port
                        prefix + '.nni': MetricValuePairs(metrics=uni_port_metrics),
                        # OLT PON port
                        prefix + '.pon': MetricValuePairs(metrics=pon_port_metrics)
                    }
                )

                # Step 3: submit
                self.adapter_agent.submit_kpis(kpi_event)

            except Exception as e:
                log.exception('failed-to-submit-kpis', e=e)

        prefix = 'voltha.{}.{}'.format(self.name, device_id)
        lc = LoopingCall(_collect, device_id, prefix)
        lc.start(interval=15)  # TODO make this configurable


# Methods for Get / Set  Response Processing from eoam_messages

    @inlineCallbacks
    def _send_igmp_mcast_addr(self, device):
        # construct install of igmp query address
        action = "Set Static IGMP MAC address"
        rc = []
        tlvs = AddStaticMacAddress(mac='01:00:5e:00:00:01')
        yield self._set_req_rsp(device, action, tlvs, rc)


    @inlineCallbacks
    def _send_clear_static_mac_table(self, device):
        action = "Clear Static MAC Table"
        rc = []
        tlvs = ClearStaticMacTable()
        yield self._set_req_rsp(device, action, tlvs, rc)


    def _process_ping_frame_response(self, device, frame):
        vendor       = [VendorName().branch, VendorName().leaf]
        ponMode      = [OnuMode().branch, OnuMode().leaf]
        hw_version   = [HardwareVersion().branch, HardwareVersion().leaf]
        manufacturer = [ManufacturerInfo().branch, ManufacturerInfo().leaf]

        branch_leaf_pairs = [vendor, ponMode, hw_version, manufacturer]

        for pair in branch_leaf_pairs:
            temp_pair = pair
            (rc, value) = (get_value_from_msg(log, frame, pair[0], pair[1]))
            temp_pair.append(rc)
            temp_pair.append(value)
            if rc:
                overall_rc = True
            else:
                log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(temp_pair[0], temp_pair[1]))
                ack = True

        if vendor[rc]:
            device.vendor = vendor.pop()
            if device.vendor.endswith(''):
                device.vendor = device.vendor[:-1]
        else:
            device.vendor = "UNKNOWN"

        # mode: 3 = EPON OLT, 7 = GPON OLT
        # mode: 2 = EPON ONU, 6 = GPON ONU
        if ponMode[rc]:
            value = ponMode.pop()
            mode = "UNKNOWN"
            self.mode = "UNKNOWN"

            if value == 6:
                mode = "10G GPON ONU"
                self.mode = "GPON"
            if value == 2:
                mode = "10G EPON ONU"
                self.mode = "EPON"
            if value == 1:
                mode = "10G Point to Point"
                self.mode = "Unsupported"

            device.model = mode

        else:
            device.model = "UNKNOWN"
            self.mode = "UNKNOWN"

        log.info("PON Mode is {}".format(self.mode))

        if hw_version[rc]:
            device.hardware_version = hw_version.pop()
            device.hardware_version = device.hardware_version.replace("FA","")
            if device.hardware_version.endswith(''):
                device.hardware_version = device.hardware_version[:-1]
        else:
            device.hardware_version = "UNKNOWN"

        if manufacturer[rc]:
            manu_value = manufacturer.pop()
            device.firmware_version = re.search('\Firmware: (.+?) ', manu_value).group(1)
            image_1 = Image(version = \
                                    re.search('\Build: (.+?) ', manu_value).group(1))
            device.images.image.extend([ image_1 ])
            device.serial_number = re.search('\Serial #: (.+?) ', manu_value).group(1)
        else:
            device.firmware_version = "UNKNOWN"
            image_1 = Image(version="UNKNOWN")
            device.images.image.extend([ image_1 ])
            device.serial_number = "UNKNOWN"

        device.connect_status = ConnectStatus.REACHABLE


    # Generic Request handlers

    def _build_dpoe_oam_msg(self, opcode, body):
        msg = (
            EOAMPayload() / EOAM_VendSpecificMsg(oui=CABLELABS_OUI) /
            EOAM_DpoeMsg(dpoe_opcode = opcode, body=body)/
            EndOfPDU()
            )
        return msg

    @inlineCallbacks
    def _get_req_rsp(self, device, action, body, resp):
        msg = self._build_dpoe_oam_msg(DPoEOpcodes["Get Request"], body)
        log.info('Send to {} for {}: {}'.format(action, device.model, device.mac_address))

        self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        # Loop until we have a Get Response or timeout
        ack = False
        start_time = time.time()
        while not ack:
            frame = yield self.incoming_messages.get()
            #TODO - Need to add proper timeout functionality
            #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
            #    break  # don't wait forever

            respType = get_oam_msg_type(log, frame)

            if (respType == RxedOamMsgTypeEnum["DPoE Get Response"]):
                ack = True
                resp.append(frame)
            else:
                # Handle unexpected events/OMCI messages
                check_resp(log, frame)

    @inlineCallbacks
    def _handle_set_resp(self, device, action, retcode):
        # Get and process the Set Response
        ack = False
        #start_time = time.time()

        # Loop until we have a set response or timeout
        while not ack:
            frame = yield self.incoming_messages.get()
            #TODO - Need to add proper timeout functionality
            #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
            #    break  # don't wait forever

            respType = get_oam_msg_type(log, frame)

            #Check that the message received is a Set Response
            if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                ack = True
            else:
                log.info('Received Unexpected OAM Message 0x{:X} while waiting for Set Resp for {}'.format(respType,action))
                # Handle unexpected events/OMCI messages
                check_resp(log, frame)

        # Verify Set Response
        rc = False
        if ack:
            (rc,branch,leaf,status) = check_set_resp(log, frame)
            if (rc is False):
                log.info('Set Response for {} for {}: {} had errors - Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(action, device.model, device.mac_address,branch, leaf, DPoEVariableResponseEnum[status]))
            else:
                log.info('Set Response received for {} for {}: {} had no errors'.format(action, device.model, device.mac_address))
        else:
            log.info('No Set Response received for {} for {}: {}'.format(action, device.model, device.mac_address))

        retcode.append(rc)

    @inlineCallbacks
    def _set_req_rsp(self, device, action, body, rc):
        msg = self._build_dpoe_oam_msg(DPoEOpcodes["Set Request"], body)
        log.info('Send to {} for {}: {}'.format(action, device.model, device.mac_address))
        self.adapter_agent.send_proxied_message(device.proxy_address, msg)

        # Get and process the Set Response
        yield self._handle_set_resp(device, action, rc)
