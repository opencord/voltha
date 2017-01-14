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
Maple OLT/ONU adapter.
"""
from uuid import uuid4

import grpc
import structlog
from scapy.layers.l2 import Ether, Dot1Q
from twisted.internet import reactor
from twisted.spread import pb
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue
from zope.interface import implementer

from common.frameio.frameio import BpfProgramFilter, hexify

from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Device
from voltha.protos.health_pb2 import HealthStatus
from google.protobuf.empty_pb2 import Empty

from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPF_1GB_FD, \
    OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS, \
    ofp_switch_features, ofp_desc, ofp_port
from voltha.registry import registry
from voltha.extensions.omci.omci import *

_ = third_party
log = structlog.get_logger()

PACKET_IN_VLAN = 4091
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))


class OmciRxProxy(pb.Root):
    def __init__(self):
        self.pb_server_ip = '192.168.24.20'  # registry('main').get_args().external_host_address
        self.pb_server_port = 24497
        self.pb_server_factory = pb.PBServerFactory(self)
        # start PB server
        self.listen_port = reactor.listenTCP(self.pb_server_port, self.pb_server_factory)
        self.omci_rx_queue = DeferredQueue()
        log.info('PB-server-started-on-port', port=self.pb_server_port)

    def get_ip(self):
        return self.pb_server_ip

    def get_port(self):
        return self.pb_server_port

    def get_host(self):
        return self.listen_port.getHost()

    def remote_echo(self, pkt_type, pon, onu, port, crc_ok, msg_size, msg_data):
        log.info('received-omci-msg',
                 pkt_type=pkt_type,
                 pon_id=pon,
                 onu_id=onu,
                 port_id=port,
                 crc_ok=crc_ok,
                 msg_size=msg_size,
                 msg_data=hexify(msg_data))
        self.omci_rx_queue.put((onu, msg_data))

    def receive(self):
        return self.omci_rx_queue.get()


@implementer(IAdapterInterface)
class MapleOltAdapter(object):
    name = 'maple_olt'

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
        self.devices_handlers = dict()  # device_id -> MapleOltHandler()
        self.logical_device_id_to_root_device_id = dict()

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
        self.devices_handlers[device.id] = MapleOltHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device

    def abandon_device(self, device):
        raise NotImplementedError()

    def deactivate_device(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)
        handler = self.devices_handlers[proxy_address.device_id]
        handler.send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        def ldi_to_di(ldi):
            di = self.logical_device_id_to_root_device_id.get(ldi)
            if di is None:
                logical_device = self.adapter_agent.get_logical_device(ldi)
                di = logical_device.root_device_id
                self.logical_device_id_to_root_device_id[ldi] = di
            return di

        device_id = ldi_to_di(logical_device_id)
        handler = self.devices_handlers[device_id]
        handler.packet_out(egress_port_no, msg)


class MapleOltHandler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.channel = None
        self.io_port = None
        self.logical_device_id = None
        self.interface = registry('main').get_args().interface
        self.pbc_factory = pb.PBClientFactory()
        self.pbc_port = 24498
        self.tx_id = 0
        self.omci_rx_proxy = OmciRxProxy()

    def __del__(self):
        if self.io_port is not None:
            registry('frameio').del_interface(self.interface)

    def get_channel(self):
        return self.channel

    def get_vlan_from_onu(self, onu):
        vlan = onu + 1024
        return vlan

    def get_onu_from_vlan(self, vlan):
        onu = vlan - 1024
        return onu

    @inlineCallbacks
    def send_set_remote(self):
        srv_ip = self.omci_rx_proxy.get_ip()
        srv_port = self.omci_rx_proxy.get_port()
        self.log.info('setting-remote-ip-port', ip=srv_ip, port=srv_port)

        try:
            remote = self.get_channel()
            data = yield remote.callRemote('set_remote', srv_ip, srv_port)
            self.log.info('set-remote', data=data, ip=srv_ip, port=srv_port)
        except Exception as e:
            self.log.info('set-remote-exception', exc=str(e))

    @inlineCallbacks
    def send_connect_olt(self, olt_no):
        self.log.info('connecting-to-olt', olt=olt_no)
        try:
            remote = self.get_channel()
            data = yield remote.callRemote('connect_olt', olt_no)
            self.log.info('connected-to-olt', data=data)
        except Exception as e:
            self.log.info('connect-olt-exception', exc=str(e))

    @inlineCallbacks
    def send_activate_olt(self, olt_no):
        self.log.info('activating-olt', olt=olt_no)
        try:
            remote = self.get_channel()
            data = yield remote.callRemote('activate_olt', olt_no)
            self.log.info('activated-olt', data=data)
        except Exception as e:
            self.log.info('activate-olt-exception', exc=str(e))

    @inlineCallbacks
    def send_create_onu(self, olt_no, onu_no, serial_no, vendor_no):
        self.log.info('creating-onu',
                      olt=olt_no,
                      onu=onu_no,
                      serial=serial_no,
                      vendor=vendor_no)
        try:
            remote = self.get_channel()
            data = yield remote.callRemote('create_onu',
                                           olt_no,
                                           onu_no,
                                           serial_no,
                                           vendor_no)
            self.log.info('created-onu', data=data)
        except Exception as e:
            self.log.info('create-onu-exception', exc=str(e))

    @inlineCallbacks
    def send_configure_onu(self, olt_no, onu_no, alloc_id, uni_gem, multi_gem):
        self.log.info('configuring-onu',
                      olt=olt_no,
                      onu=onu_no,
                      alloc_id=alloc_id,
                      unicast_gem_port=uni_gem,
                      multicast_gem_port=multi_gem)
        try:
            remote = self.get_channel()
            data = yield remote.callRemote('configure_onu',
                                           olt_no,
                                           onu_no,
                                           alloc_id,
                                           uni_gem,
                                           multi_gem)
            self.log.info('configured-onu', data=data)
        except Exception as e:
            self.log.info('configure-onu-exception', exc=str(e))

    @inlineCallbacks
    def send_activate_onu(self, olt_no, onu_no):
        self.log.info('activating-onu', olt=olt_no, onu=onu_no)
        try:
            remote = self.get_channel()
            data = yield remote.callRemote('activate_onu', olt_no, onu_no)
            self.log.info('activated-onu', data=data)
        except Exception as e:
            self.log.info('activate-onu-exception', exc=str(e))

    @inlineCallbacks
    def activate(self, device):
        self.log.info('activating')

        if not device.ipv4_address:
            device.oper_status = OperStatus.FAILED
            device.reason = 'No ipv4_address field provided'
            self.adapter_agent.update_device(device)
            return

        self.log.info('initiating-connection-to-olt',
                      device_id=device.id,
                      ipv4=device.ipv4_address,
                      port=self.pbc_port)
        reactor.connectTCP(device.ipv4_address, self.pbc_port, self.pbc_factory)
        try:
            self.channel = yield self.pbc_factory.getRootObject()
            self.log.info('connected-to-olt',
                          device_id=device.id,
                          ipv4=device.ipv4_address,
                          port=self.pbc_port)
        except Exception as e:
            self.log.info('get-channel-exception', exc=str(e))

        self.send_set_remote()
        self.send_connect_olt(0)
        self.send_activate_olt(0)

        device.root = True
        device.vendor = 'Broadcom'
        device.model = 'bcm68620'
        device.serial_number = device.ipv4_address
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        nni_port = Port(
            port_no=2,
            label='NNI facing Ethernet port',
            type=Port.ETHERNET_NNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.adapter_agent.add_port(device.id, nni_port)
        self.adapter_agent.add_port(device.id, Port(
            port_no=1,
            label='PON port',
            type=Port.PON_OLT,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        ))

        ld = LogicalDevice(
            # not setting id and datapth_id will let the adapter agent pick id
            desc=ofp_desc(
                mfr_desc='cord porject',
                hw_desc='n/a',
                sw_desc='logical device for Maple-based PON',
                serial_num=uuid4().hex,
                dp_desc='n/a'
            ),
            switch_features=ofp_switch_features(
                n_buffers=256,  # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    OFPC_FLOW_STATS
                    | OFPC_TABLE_STATS
                    | OFPC_PORT_STATS
                    | OFPC_GROUP_STATS
                )
            ),
            root_device_id=device.id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=0,  # is 0 OK?
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
                name='nni',
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=device.id,
            device_port_no=nni_port.port_no,
            root_port=True
        ))

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)
        self.logical_device_id = ld_initialized.id

        # register ONUS per uni port until done asynchronously
        for onu_no in [1]:
            vlan_id = self.get_vlan_from_onu(onu_no)
            yield self.send_create_onu(0, onu_no, '4252434d', '12345678')
            yield self.send_configure_onu(0, onu_no, vlan_id, vlan_id, 4000)
            yield self.send_activate_onu(0, onu_no)

            self.adapter_agent.child_device_detected(
                parent_device_id=device.id,
                parent_port_no=1,
                child_device_type='broadcom_onu',
                proxy_address=Device.ProxyAddress(
                    device_id=device.id,
                    channel_id=vlan_id
                ),
                vlan=vlan_id
            )

        # finally, open the frameio port to receive in-band packet_in messages
        self.log.info('registering-frameio')
        self.io_port = registry('frameio').add_interface(
            self.interface, self.rcv_io, is_inband_frame)

    def rcv_io(self, port, frame):
        self.log.info('reveived', iface_name=port.iface_name,
                      frame_len=len(frame))
        pkt = Ether(frame)
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

    def update_flow_table(self, flows):
        self.log.info('pushing-olt-flow-table')

    @inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        if isinstance(msg, Packet):
            msg = str(msg)

        self.log.info('send-proxied-message',
                      proxy_address=proxy_address.channel_id,
                      msg=msg)

        try:
            remote = self.get_channel()
            yield remote.callRemote("send_omci",
                                    0,
                                    0,
                                    self.get_onu_from_vlan(proxy_address.channel_id),
                                    msg)
            onu, rmsg = yield self.omci_rx_proxy.receive()
            self.adapter_agent.receive_proxied_message(proxy_address, rmsg)
        except Exception as e:
            self.log.info('send-proxied_message-exception', exc=str(e))

    def packet_out(self, egress_port, msg):
        self.log.info('sending-packet-out',
                      egress_port=egress_port,
                      msg=hexify(msg))

        pkt = Ether(msg)
        out_pkt = (
            Ether(src=pkt.src, dst=pkt.dst) /
            Dot1Q(vlan=4091) /
            Dot1Q(vlan=egress_port, type=pkt.type) /
            pkt.payload
        )
        self.io_port.send(str(out_pkt))
