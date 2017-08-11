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
Asfvolt16 OLT adapter
"""


from scapy.layers.l2 import Ether, Dot1Q
from uuid import uuid4
from common.frameio.frameio import BpfProgramFilter
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, DeferredQueue
from common.frameio.frameio import hexify
from scapy.packet import Packet
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.protos.device_pb2 import Port
from voltha.protos.common_pb2 import AdminState
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, ofp_switch_features, ofp_desc, ofp_port
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.adapters.asfvolt16_olt.bal import Bal
from voltha.adapters.device_handler import OltDeviceHandler
from voltha.protos.bbf_fiber_base_pb2 import ChannelterminationConfig, \
        VOntaniConfig

ASFVOLT_NNI_PORT = 50
# ASFVOLT_NNI_PORT needs to be other than pon port value.
# Edgecore OLT assigns PONport between 0 to 15, hence
# having a value 50 for NNI port to avoid collision.
# TODO: VLAN ID needs to come from some sort of configuration.
PACKET_IN_VLAN = 4091
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))


class Asfvolt16Handler(OltDeviceHandler):
    def __init__(self, adapter, device_id):
        super(Asfvolt16Handler, self).__init__(adapter, device_id)
        self.filter = is_inband_frame
        self.bal = Bal(self, self.log)
        self.host_and_port = None
        self.olt_id = 0

    def __del__(self):
        super(Asfvolt16Handler, self).__del__()

    def __str__(self):
        return "Asfvolt16Handler: {}".format(self.host_and_port)

    def activate(self, device):

        self.log.info('activating-asfvolt16-olt', device=device)

        if self.logical_device_id is None:

            if not device.host_and_port:
                device.oper_status = OperStatus.FAILED
                device.reason = 'No host_and_port field provided'
                self.adapter_agent.update_device(device)
                return

            self.host_and_port = device.host_and_port
            device.root = True
            device.vendor = 'Edgecore'
            device.model = 'ASFvOLT16'
            device.serial_number = device.host_and_port
            self.adapter_agent.update_device(device)

            self.add_port(port_no=ASFVOLT_NNI_PORT,
                          port_type=Port.ETHERNET_NNI,
                          label='NNI facing Ethernet port')
            self.logical_device_id = \
                self.add_logical_device(device_id=device.id)
            self.add_logical_port(port_no=1,
                                  port_type=Port.ETHERNET_NNI,
                                  device_id=device.id,
                                  logical_device_id=self.logical_device_id)

            self.bal.connect_olt(device.host_and_port, self.device_id)

        self.bal.activate_olt()

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = self.logical_device_id
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

    def add_port(self, port_no, port_type, label):
        self.log.info('adding-port', port_no=port_no, port_type=port_type)
        if port_type is Port.ETHERNET_NNI:
            oper_status = OperStatus.ACTIVE
        elif port_type is Port.PON_OLT:
            # To-Do The pon port status should be ACTIVATING.
            # For now make the status as Active.
            oper_status = OperStatus.ACTIVE
        else:
            self.log.erro('invalid-port-type', port_type=port_type)
            return

        port = Port(
            port_no=port_no,
            label=label,
            type=port_type,
            admin_state=AdminState.ENABLED,
            oper_status=oper_status
        )
        self.adapter_agent.add_port(self.device_id, port)

    def add_logical_device(self, device_id):
        self.log.info('adding-logical-device', device_id=device_id)
        ld = LogicalDevice(
            # not setting id and datapth_id will let the adapter
            # agent pick id
            desc=ofp_desc(
                mfr_desc='cord project',
                hw_desc='n/a',
                sw_desc='logical device for Edgecore ASFvOLT16 OLT',
                serial_num=uuid4().hex,
                dp_desc='n/a'
            ),
            switch_features=ofp_switch_features(
                n_buffers=256,  # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    OFPC_FLOW_STATS |
                    OFPC_TABLE_STATS |
                    OFPC_PORT_STATS |
                    OFPC_GROUP_STATS
                )
            ),
            root_device_id=device_id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        return ld_initialized.id

    def add_logical_port(self, port_no, port_type,
                         device_id, logical_device_id):
        self.log.info('adding-logical-port', port_no=port_no,
                      port_type=port_type, device_id=device_id)
        if port_type is Port.ETHERNET_NNI:
            label = 'nni'
            cap = OFPPF_1GB_FD | OFPPF_FIBER
            curr_speed = OFPPF_1GB_FD
            max_speed = OFPPF_1GB_FD
        else:
            self.log.erro('invalid-port-type', port_type=port_type)
            return

        ofp = ofp_port(
            port_no=0,  # is 0 OK?
            hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
            name=label,
            config=0,
            state=OFPPS_LIVE,
            curr=cap,
            advertised=cap,
            peer=cap,
            curr_speed=curr_speed,
            max_speed=max_speed)

        logical_port = LogicalPort(
            id=label,
            ofp_port=ofp,
            device_id=device_id,
            device_port_no=port_no,
            root_port=True
        )

        self.adapter_agent.add_logical_port(logical_device_id, logical_port)

    def handle_access_term_ind(self, ind_info):
        device = self.adapter_agent.get_device(self.device_id)
        if ind_info['activation_successful'] is True:
            self.log.info('successful access terminal Indication',
                          olt_id=self.olt_id)
            device.connect_status = ConnectStatus.REACHABLE
            device.oper_status = OperStatus.ACTIVE
            device.reason = 'OLT activated successfully'
            self.adapter_agent.update_device(device)
            self.log.info('OLT activation complete')
        else:
            device.oper_status = OperStatus.FAILED
            device.reason = 'Failed to Intialize OLT'
            self.adapter_agent.update_device(device)
            reactor.callLater(15, self.activate, device)
        return

    def handle_not_started_onu(self, child_device, ind_info):
        if ind_info['_sub_group_type'] == 'onu_discovery':
            self.log.info('Onu discovered', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)
            # To-Do: Need to handle the ONUs, where the admin state is
            # ENABLED and operation state is in Failed or Unkown
            self.log.info('Not Yet handled', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)
        else:
            self.log.info('Invalid ONU event', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)

    def handle_activating_onu(self, child_device, ind_info):
        pon_id = ind_info['_pon_id']
        self.log.info('Not handled Yet', olt_id=self.olt_id,
                      pon_ni=pon_id, onu_data=ind_info)

    def handle_activated_onu(self, child_device, ind_info):
        pon_id = ind_info['_pon_id']
        self.log.info('Not handled Yet', olt_id=self.olt_id,
                      pon_ni=pon_id, onu_data=ind_info)

    def handle_discovered_onu(self, child_device, ind_info):
        pon_id = ind_info['_pon_id']
        if ind_info['_sub_group_type'] == 'onu_discovery':
            self.log.info('Activation is in progress', olt_id=self.olt_id,
                          pon_ni=pon_id, onu_data=ind_info,
                          onu_id=child_device.proxy_address.onu_id)

        elif ind_info['_sub_group_type'] == 'sub_term_indication':
            self.log.info('ONU activation is completed', olt_id=self.olt_id,
                          pon_ni=pon_id, onu_data=ind_info)

            msg = {'proxy_address': child_device.proxy_address,
                   'event': 'activation-completed', 'event_data': ind_info}

            # Send the event message to the ONU adapter
            self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                             msg)
        else:
            self.log.info('Invalid ONU event', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)

    onu_handlers = {
        OperStatus.UNKNOWN: handle_not_started_onu,
        OperStatus.FAILED: handle_not_started_onu,
        OperStatus.ACTIVATING: handle_activating_onu,
        OperStatus.ACTIVE: handle_activated_onu,
        OperStatus.DISCOVERED: handle_discovered_onu,
    }

    def handle_sub_term_ind(self, ind_info):
        child_device = self.adapter_agent.get_child_device(
            self.device_id,
            serial_number=(ind_info['_vendor_id'] +
                           ind_info['_vendor_specific']))
        if child_device is None:
            self.log.info('Onu is not configured', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)
            return

        handler = self.onu_handlers.get(child_device.oper_status)
        if handler:
            handler(self, child_device, ind_info)

    def send_proxied_message(self, proxy_address, msg):
        if isinstance(msg, Packet):
            msg = str(msg)
        try:
            self.bal.send_omci_request_message(proxy_address, msg)
        except Exception as e:
            self.log.exception('', exc=str(e))
        return

    def handle_omci_ind(self, ind_info):
        child_device = self.adapter_agent.get_child_device(
            self.device_id,
            onu_id=ind_info['onu_id'])
        if child_device is None:
            self.log.info('Onu is not configured', onu_id=ind_info['onu_id'])
            return
        try:
            self.adapter_agent.receive_proxied_message(
                child_device.proxy_address,
                ind_info['packet'])
        except Exception as e:
                self.log.exception('', exc=str(e))
        return

    def create_interface(self, data):
        try:
            if isinstance(data, ChannelterminationConfig):
                self.log.info('Activating PON port at OLT',
                              pon_id=data.data.xgs_ponid)
                self.add_port(port_no=data.data.xgs_ponid,
                              port_type=Port.PON_OLT,
                              label=data.name)
                self.bal.activate_pon_port(self.olt_id, data.data.xgs_ponid)
            if isinstance(data, VOntaniConfig):
                serial_number = data.data.expected_serial_number
                child_device = self.adapter_agent.get_child_device(
                    self.device_id,
                    serial_number=serial_number)
                if child_device is None:
                    self.log.info('Failed to find ONU Info',
                                  serial_number=serial_number)
                elif child_device.admin_state == AdminState.ENABLED:
                    self.log.info('Activating ONU',
                                  serial_number=serial_number,
                                  onu_id=child_device.proxy_address.onu_id,
                                  pon_id=child_device.parent_port_no)
                    onu_info = dict()
                    onu_info['pon_id'] = child_device.parent_port_no
                    onu_info['onu_id'] = child_device.proxy_address.onu_id
                    onu_info['vendor'] = child_device.vendor_id
                    onu_info['vendor_specific'] = serial_number[4:]
                    self.bal.activate_onu(onu_info)
                else:
                    self.log.info('Invalid ONU state to activate',
                                  onu_id=child_device.proxy_address.onu_id,
                                  serial_number=serial_number)
        except Exception as e:
            self.log.exception('', exc=str(e))
        return

    def update_interface(self, data):
        self.log.info('Not Implemented yet')
        return

    def remove_interface(self, data):
        self.log.info('Not Implemented yet')
        return

    def disable(self):
        super(Asfvolt16Handler, self).disable()

    def delete(self):
        super(Asfvolt16Handler, self).delete()

    def handle_packet_in(self, ind_info):
        self.log.info('Received Packet-In', ind_info=ind_info)

        pkt = Ether(ind_info['packet'])
        if pkt.haslayer(Dot1Q):
            outer_shim = pkt.getlayer(Dot1Q)
            if isinstance(outer_shim.payload, Dot1Q):
                inner_shim = outer_shim.payload
                cvid = inner_shim.vlan
                logical_port = cvid
                popped_frame = (
                    Ether(src=pkt.src, dst=pkt.dst, type=inner_shim.type) /
                    inner_shim.payload
                )
                kw = dict(
                    logical_device_id=self.logical_device_id,
                    logical_port_no=logical_port,
                )
                self.log.info('sending-packet-in', **kw)
                self.adapter_agent.send_packet_in(
                    packet=str(popped_frame), **kw)

        reactor.callLater(1, self.process_packet_in)

    def packet_out(self, egress_port, msg):
        self.log.info('sending-packet-out', egress_port=egress_port,
                      msg=hexify(msg))
        pkt = Ether(msg)
        out_pkt = (
            Ether(src=pkt.src, dst=pkt.dst) /
            Dot1Q(vlan=PACKET_IN_VLAN) /
            Dot1Q(vlan=egress_port, type=pkt.type) /
            pkt.payload
        )

        # TODO: Need to retrieve the correct destination onu_id
        self.bal.packet_out(onu_id=1, egress_port, str(out_pkt))
