#
# Copyright 2018 the original author or authors.
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
#

import structlog
import threading
import grpc
import collections

from twisted.internet import reactor
from scapy.layers.l2 import Ether, Dot1Q
import binascii

from voltha.protos.device_pb2 import Port, Device
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, ofp_switch_features, ofp_port
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.registry import registry
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2
import voltha.core.flow_decomposer as fd

import openolt_platform as platform
from openolt_flow_mgr import OpenOltFlowMgr

OnuKey = collections.namedtuple('OnuKey', ['intf_id', 'onu_id'])
OnuRec = collections.namedtuple('OnuRec', ['serial_number', 'state'])

"""
OpenoltDevice represents an OLT.
"""
class OpenoltDevice(object):

    def __init__(self, **kwargs):
        super(OpenoltDevice, self).__init__()

        self.adapter_agent = kwargs['adapter_agent']
        self.device_num = kwargs['device_num']
        device = kwargs['device']
        self.device_id = device.id
        self.host_and_port = device.host_and_port
        self.log = structlog.get_logger(id=self.device_id, ip=self.host_and_port)
        self.nni_oper_state = dict() #intf_id -> oper_state
        self.onus = {} # OnuKey -> OnuRec

        # Update device
        device.root = True
        device.serial_number = self.host_and_port # FIXME
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

        # Initialize gRPC
        self.channel = grpc.insecure_channel(self.host_and_port)
        self.channel_ready_future = grpc.channel_ready_future(self.channel)

        # Start indications thread
        self.indications_thread = threading.Thread(target=self.process_indications)
        self.indications_thread.daemon = True
        self.indications_thread.start()

    def process_indications(self):

        self.channel_ready_future.result() # blocks till gRPC connection is complete

        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)
        self.flow_mgr = OpenOltFlowMgr(self.log, self.stub)
        self.indications = self.stub.EnableIndication(openolt_pb2.Empty())

        while True:
            # get the next indication from olt
            ind = next(self.indications)
            self.log.debug("rx indication", indication=ind)

            # indication handlers run in the main event loop
            if ind.HasField('olt_ind'):
                reactor.callFromThread(self.olt_indication, ind.olt_ind)
            elif ind.HasField('intf_ind'):
                reactor.callFromThread(self.intf_indication, ind.intf_ind)
            elif ind.HasField('intf_oper_ind'):
                reactor.callFromThread(self.intf_oper_indication,
                        ind.intf_oper_ind)
            elif ind.HasField('onu_disc_ind'):
                reactor.callFromThread(self.onu_discovery_indication,
                        ind.onu_disc_ind)
            elif ind.HasField('onu_ind'):
                reactor.callFromThread(self.onu_indication, ind.onu_ind)
            elif ind.HasField('omci_ind'):
                reactor.callFromThread(self.omci_indication, ind.omci_ind)
            elif ind.HasField('pkt_ind'):
                reactor.callFromThread(self.packet_indication, ind.pkt_ind)

    def olt_indication(self, olt_indication):
	self.log.debug("olt indication", olt_ind=olt_indication)

        # FIXME
        if olt_indication.oper_state == "down":
	    self.log.error("ignore olt oper state down", olt_ind=olt_indication)
            return

        if not hasattr(olt_indication, 'mac') or \
                not olt_indication.mac:
            mac = '00:00:00:00:00:' + '{:02x}'.format(self.device_num)
        else:
            mac = olt_indication.mac

        # Create logical OF device
        ld = LogicalDevice(
            root_device_id=self.device_id,
            switch_features=ofp_switch_features(
                n_buffers=256,  # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    OFPC_FLOW_STATS
                    | OFPC_TABLE_STATS
                    | OFPC_PORT_STATS
                    | OFPC_GROUP_STATS
                )
            )
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld, dpid=mac)
        self.logical_device_id = ld_initialized.id

        # Update phys OF device
        device = self.adapter_agent.get_device(self.device_id)
        device.parent_id = self.logical_device_id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)


    def intf_indication(self, intf_indication):
	self.log.debug("intf indication", intf_id=intf_indication.intf_id,
            oper_state=intf_indication.oper_state)

        if intf_indication.oper_state == "up":
            oper_status = OperStatus.ACTIVE
        else:
            oper_status = OperStatus.DISCOVERED

        # FIXME - If port exists, update oper state
        self.add_port(intf_indication.intf_id, Port.PON_OLT, oper_status)

    def intf_oper_indication(self, intf_oper_indication):
	self.log.debug("Received interface oper state change indication",
                intf_id=intf_oper_indication.intf_id,
                type=intf_oper_indication.type,
                oper_state=intf_oper_indication.oper_state)

        if intf_oper_indication.oper_state == "up":
            oper_state = OperStatus.ACTIVE
        else:
            oper_state = OperStatus.DISCOVERED

        if intf_oper_indication.type == "nni":

            # FIXME - creating logical port for 2nd interface throws exception!
            if intf_oper_indication.intf_id != 0:
                return

            if intf_oper_indication.intf_id not in self.nni_oper_state:
                self.nni_oper_state[intf_oper_indication.intf_id] = oper_state
                port_no, label = self.add_port(intf_oper_indication.intf_id, Port.ETHERNET_NNI, oper_state)
	        self.log.debug("int_oper_indication", port_no=port_no, label=label)
                self.add_logical_port(port_no, intf_oper_indication.intf_id) # FIXME - add oper_state
            elif intf_oper_indication.intf_id != self.nni_oper_state:
                # FIXME - handle subsequent NNI oper state change
                pass

        elif intf_oper_indication.type == "pon":
            # FIXME - handle PON oper state change
            pass

    def onu_discovery_indication(self, onu_disc_indication):
        intf_id = onu_disc_indication.intf_id
        serial_number=onu_disc_indication.serial_number

	self.log.debug("onu discovery indication", intf_id=intf_id,
            serial_number=serial_number)

        key = self.lookup_key(serial_number=serial_number)

        if key is None:
            onu_id = self.new_onu_id(intf_id)
            try:
                self.add_onu_device(intf_id,
                        platform.intf_id_to_port_no(intf_id, Port.PON_OLT),
                        onu_id, serial_number)
            except Exception as e:
                self.log.exception('onu activation failed', e=e)
            else:
		self.log.info("activate onu", intf_id=intf_id, onu_id=onu_id,
                        serial_number=serial_number)
                self.onus[OnuKey(intf_id=intf_id, onu_id=onu_id)] \
                        = OnuRec(serial_number=serial_number, state='discovered')
		onu = openolt_pb2.Onu(intf_id=intf_id, onu_id=onu_id,
			serial_number=serial_number)
		self.stub.ActivateOnu(onu)
        else:
            # FIXME - handle onu discover indication for a discovered/activated onu
            onu_id = key.onu_id
            intf_id = key.intf_id
            if self.onus[key].state == 'discovered' or \
                    self.onus[key].state == 'active':
	        self.log.info("ignore onu discovery indication", intf_id=intf_id,
                        onu_id=onu_id, state=self.onus[key].state)

    def onu_indication(self, onu_indication):
        self.log.debug("onu indication", intf_id=onu_indication.intf_id,
                onu_id=onu_indication.onu_id)

        key = self.lookup_key(serial_number=onu_indication.serial_number)

        # FIXME - handle serial_number mismatch
        assert key is not None

        # FIXME - handle intf_id mismatch (ONU move?)
        assert onu_indication.intf_id == key.intf_id

        # FIXME - handle onu id mismatch
        assert onu_indication.onu_id == key.onu_id

        if self.onus[key].state is not 'discovered':
            self.log.debug("ignore onu indication",
                    intf_id=onu_indication.intf_id,
                    onu_id=onu_indication.onu_id,
                    state=self.onus[key].state)
            return

        self.onus[key] = self.onus[key]._replace(state='active')

        onu_device = self.adapter_agent.get_child_device(self.device_id,
                onu_id=onu_indication.onu_id)
        assert onu_device is not None

        msg = {'proxy_address':onu_device.proxy_address,
               'event':'activation-completed',
               'event_data':{'activation_successful':True}}
        self.adapter_agent.publish_inter_adapter_message(onu_device.id, msg)

        #
        # tcont create (onu)
        #
        alloc_id = platform.mk_alloc_id(onu_indication.onu_id)
        msg = {'proxy_address':onu_device.proxy_address,
               'event':'create-tcont',
               'event_data':{'alloc_id':alloc_id}}
        self.adapter_agent.publish_inter_adapter_message(onu_device.id, msg)

        #
        # v_enet create (olt)
        #
        uni_no = platform.mk_uni_port_num(onu_indication.intf_id, onu_indication.onu_id)
        uni_name = self.port_name(uni_no, Port.ETHERNET_UNI,
                serial_number=onu_indication.serial_number)
	self.adapter_agent.add_port(
            self.device_id,
            Port(
                port_no=uni_no,
                label=uni_name,
                type=Port.ETHERNET_UNI,
                admin_state=AdminState.ENABLED,
                oper_status=OperStatus.ACTIVE))

        #
        # v_enet create (onu)
        #
        msg = {'proxy_address':onu_device.proxy_address,
               'event':'create-venet',
               'event_data':{'uni_name':uni_name, 'interface_name':uni_name}}
        self.adapter_agent.publish_inter_adapter_message(onu_device.id, msg)

        #
        # gem port create
        #
        gemport_id = platform.mk_gemport_id(onu_indication.onu_id)
        msg = {'proxy_address':onu_device.proxy_address,
               'event':'create-gemport',
               'event_data':{'gemport_id':gemport_id}}
        self.adapter_agent.publish_inter_adapter_message(onu_device.id, msg)

    def omci_indication(self, omci_indication):

        self.log.debug("omci indication", intf_id=omci_indication.intf_id,
                onu_id=omci_indication.onu_id)

        onu_device = self.adapter_agent.get_child_device(self.device_id,
                onu_id=omci_indication.onu_id)

        self.adapter_agent.receive_proxied_message(onu_device.proxy_address,
                omci_indication.pkt)

    def packet_indication(self, pkt_indication):

        self.log.debug("packet indication", intf_id=pkt_indication.intf_id,
                gemport_id=pkt_indication.gemport_id,
                flow_id=pkt_indication.flow_id)

        onu_id = platform.onu_id_from_gemport_id(pkt_indication.gemport_id)
        logical_port_num = platform.mk_uni_port_num(pkt_indication.intf_id, onu_id)

        pkt = Ether(pkt_indication.pkt)
        kw = dict(logical_device_id=self.logical_device_id,
                logical_port_no=logical_port_num)
        self.adapter_agent.send_packet_in(packet=str(pkt), **kw)

    def packet_out(self, egress_port, msg):
        pkt = Ether(msg)
        self.log.info('packet out', egress_port=egress_port,
                packet=str(pkt).encode("HEX"))

        if pkt.haslayer(Dot1Q):
            outer_shim = pkt.getlayer(Dot1Q)
            if isinstance(outer_shim.payload, Dot1Q):
                payload = (
                    Ether(src=pkt.src, dst=pkt.dst, type=outer_shim.type) /
                    outer_shim.payload
                )
            else:
                payload = pkt
        else:
            payload = pkt

        self.log.info('sending-packet-to-device', egress_port=egress_port,
                packet=str(payload).encode("HEX"))

        send_pkt = binascii.unhexlify(str(payload).encode("HEX"))

        onu_pkt = openolt_pb2.OnuPacket(intf_id=platform.intf_id_from_port_num(egress_port),
                onu_id=platform.onu_id_from_port_num(egress_port), pkt=send_pkt)

        self.stub.OnuPacketOut(onu_pkt)

    def send_proxied_message(self, proxy_address, msg):
        omci = openolt_pb2.OmciMsg(intf_id=proxy_address.channel_id, # intf_id
                onu_id=proxy_address.onu_id, pkt=str(msg))
        self.stub.OmciMsgOut(omci)

    def add_onu_device(self, intf_id, port_no, onu_id, serial_number):
        self.log.info("Adding ONU", port_no=port_no, onu_id=onu_id,
                serial_number=serial_number)

        # NOTE - channel_id of onu is set to intf_id
        proxy_address = Device.ProxyAddress(device_id=self.device_id,
                channel_id=intf_id, onu_id=onu_id, onu_session_id=onu_id)

        self.log.info("Adding ONU", proxy_address=proxy_address)

        serial_number_str = ''.join([serial_number.vendor_id,
                self.stringify_vendor_specific(serial_number.vendor_specific)])

        self.adapter_agent.add_onu_device(parent_device_id=self.device_id,
                parent_port_no=port_no, vendor_id=serial_number.vendor_id,
                proxy_address=proxy_address, root=True,
                serial_number=serial_number_str, admin_state=AdminState.ENABLED)

    def port_name(self, port_no, port_type, intf_id=None, serial_number=None):
        if port_type is Port.ETHERNET_NNI:
            return "nni" "-" + str(port_no)
        elif port_type is Port.PON_OLT:
            return "pon" + str(intf_id)
        elif port_type is Port.ETHERNET_UNI:
            return ''.join([serial_number.vendor_id,
                    self.stringify_vendor_specific(serial_number.vendor_specific)])

    def add_logical_port(self, port_no, intf_id):
        self.log.info('adding-logical-port', port_no=port_no)

        label = self.port_name(port_no, Port.ETHERNET_NNI)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        curr_speed = OFPPF_1GB_FD
        max_speed = OFPPF_1GB_FD

        ofp = ofp_port(port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name=label, config=0, state=OFPPS_LIVE, curr=cap,
                advertised=cap, peer=cap, curr_speed=curr_speed,
                max_speed=max_speed)

        logical_port = LogicalPort(id=label, ofp_port=ofp,
                device_id=self.device_id, device_port_no=port_no,
                root_port=True)

        self.adapter_agent.add_logical_port(self.logical_device_id, logical_port)

    def add_port(self, intf_id, port_type, oper_status):
        port_no = platform.intf_id_to_port_no(intf_id, port_type)

        label = self.port_name(port_no, port_type, intf_id)

        self.log.info('adding-port', port_no=port_no, label=label,
                port_type=port_type)

        port = Port(port_no=port_no, label=label, type=port_type,
            admin_state=AdminState.ENABLED, oper_status=oper_status)

        self.adapter_agent.add_port(self.device_id, port)

        return port_no, label

    def new_onu_id(self, intf_id):
        onu_id = None
        for i in range(1, 512):
            key = OnuKey(intf_id=intf_id, onu_id=i)
            if key not in self.onus:
                onu_id = i
                break
        return onu_id

    def stringify_vendor_specific(self, vendor_specific):
        return ''.join(str(i) for i in [
                hex(ord(vendor_specific[0])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[0]) & 0x0f)[2:],
                hex(ord(vendor_specific[1])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[1]) & 0x0f)[2:],
                hex(ord(vendor_specific[2])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[2]) & 0x0f)[2:],
                hex(ord(vendor_specific[3])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[3]) & 0x0f)[2:]])

    def lookup_key(self, serial_number):
        key = None
        for k, r in self.onus.iteritems():
            if r.serial_number.vendor_id == serial_number.vendor_id:
                str1 = self.stringify_vendor_specific(r.serial_number.vendor_specific)
                str2 = self.stringify_vendor_specific(serial_number.vendor_specific)
                if str1 == str2:
                    key = k
                    break
        return key

    def update_flow_table(self, flows):
        device = self.adapter_agent.get_device(self.device_id)
        self.log.debug('update flow table')
        in_port = None

        for flow in flows:
            is_down_stream = None
            in_port = fd.get_in_port(flow)
            assert in_port is not None
            # Right now there is only one NNI port. Get the NNI PORT and compare
            # with IN_PUT port number. Need to find better way.
            ports = self.adapter_agent.get_ports(device.id, Port.ETHERNET_NNI)

            for port in ports:
                if (port.port_no == in_port):
                    self.log.info('downstream-flow')
                    is_down_stream = True
                    break
            if is_down_stream is None:
                is_down_stream = False
                self.log.info('upstream-flow')

            for flow in flows:
                try:
                    self.flow_mgr.add_flow(flow, is_down_stream)
                except Exception as e:
                    self.log.exception('failed-to-install-flow', e=e, flow=flow)
