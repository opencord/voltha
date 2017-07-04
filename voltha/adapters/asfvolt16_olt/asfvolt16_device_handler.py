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

from uuid import uuid4
import structlog
from twisted.internet.defer import inlineCallbacks, DeferredQueue
from twisted.internet import reactor
from scapy.layers.l2 import Packet, Ether, Dot1Q
from common.frameio.frameio import BpfProgramFilter, hexify

from voltha.registry import registry
from voltha.protos.common_pb2 import OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import Port, Device
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, OFPXMC_OPENFLOW_BASIC, \
    ofp_switch_features, ofp_desc, ofp_port
from voltha.core.logical_device_agent import mac_str_to_tuple
import voltha.core.flow_decomposer as fd
from voltha.adapters.asfvolt16_olt.asfvolt16_rx_handler import Asfvolt16RxHandler

log = structlog.get_logger()

PACKET_IN_VLAN = 4091
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))

class Asfvolt16Handler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.io_port = None
        self.logical_device_id = None
        self.interface = registry('main').get_args().interface
        self.onu_discovered_queue = DeferredQueue()
        self.rx_handler = Asfvolt16RxHandler(self.device_id, self.adapter, self.onu_discovered_queue)
        self.heartbeat_count = 0
        self.heartbeat_miss = 0
        self.heartbeat_interval = 1
        self.heartbeat_failed_limit = 3
        self.command_timeout = 5
        self.pm_metrics = None
        self.onus = {}

    def __del__(self):
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)

    def get_channel(self):
        raise NotImplementedError()

    def get_proxy_channel_id_from_onu(self, onu_id):
        return onu_id << 4

    def get_onu_from_channel_id(self, channel_id):
        return channel_id >> 4

    def get_tunnel_tag_from_onu(self, onu):
        return 1024 + (onu * 16)

    def get_onu_from_tunnel_tag(self, tunnel_tag):
        return (tunnel_tag - 1024) / 16

    def get_new_onu_id(self, vendor, vendor_specific):
        onu_id = None
        for i in range(0, 63):
            if i not in self.onus:
                onu_id = i
                break

        if onu_id is not None:
            self.onus[onu_id] = {'onu_id': onu_id,
                                 'vendor': vendor,
                                 'vendor_specific': vendor_specific}
        return onu_id

    def onu_exists(self, onu_id):
        if onu_id in self.onus:
            self.log.info('onu-exists',
                          onu_id=onu_id,
                          vendor=self.onus[onu_id]['vendor'],
                          vendor_specific=self.onus[onu_id]['vendor_specific'])
            return self.onus[onu_id]['vendor'], self.onus[onu_id]['vendor_specific']
        else:
            self.log.info('onu-does-not-exist', onu_id=onu_id)
            return None, None

    def onu_serial_exists(self, sn_vendor, sn_vendor_specific):
        for key, value in self.onus.iteritems():
            if sn_vendor in value.itervalues() and sn_vendor_specific in value.itervalues():
                self.log.info('onu-serial-number-exists',
                              onu_id=value['onu_id'],
                              vendor=sn_vendor,
                              vendor_specific=sn_vendor_specific,
                              onus=self.onus)
                return value['onu_id']

        self.log.info('onu-serial-number-does-not-exist',
                      vendor=sn_vendor,
                      vendor_specific=sn_vendor_specific,
                      onus=self.onus)
        return None

    @inlineCallbacks
    def send_set_remote(self):
        self.log.info('setting-remote-ip-port')
        raise NotImplementedError()

    @inlineCallbacks
    def send_config_classifier(self, olt_no, etype, ip_proto=None,
                               dst_port=None):
        self.log.info('configuring-classifier',
                      olt=olt_no,
                      etype=etype,
                      ip_proto=ip_proto,
                      dst_port=dst_port)
        raise NotImplementedError()

    @inlineCallbacks
    def send_config_acflow(self, olt_no, onu_no, etype, ip_proto=None,
                           dst_port=None):
        self.log.info('configuring-acflow',
                      olt=olt_no,
                      onu=onu_no,
                      etype=etype,
                      ip_proto=ip_proto,
                      dst_port=dst_port)
        raise NotImplementedError()

    @inlineCallbacks
    def send_connect_olt(self, olt_no):
        self.log.info('connecting-to-olt', olt=olt_no)
        raise NotImplementedError()

    @inlineCallbacks
    def send_activate_olt(self, olt_no):
        self.log.info('activating-olt', olt=olt_no)
        raise NotImplementedError()

    @inlineCallbacks
    def send_create_onu(self, olt_no, onu_no, serial_no, vendor_no):
        self.log.info('creating-onu',
                      olt=olt_no,
                      onu=onu_no,
                      serial=serial_no,
                      vendor=vendor_no)
        raise NotImplementedError()

    @inlineCallbacks
    def send_configure_alloc_id(self, olt_no, onu_no, alloc_id):
        self.log.info('configuring-alloc-id',
                      olt=olt_no,
                      onu=onu_no,
                      alloc_id=alloc_id)
        raise NotImplementedError()

    @inlineCallbacks
    def send_configure_unicast_gem(self, olt_no, onu_no, uni_gem):
        self.log.info('configuring-unicast-gem',
                      olt=olt_no,
                      onu=onu_no,
                      unicast_gem_port=uni_gem)
        raise NotImplementedError()

    @inlineCallbacks
    def send_configure_multicast_gem(self, olt_no, onu_no, multi_gem):
        self.log.info('configuring-multicast-gem',
                      olt=olt_no,
                      onu=onu_no,
                      multicast_gem_port=multi_gem)
        raise NotImplementedError()

    @inlineCallbacks
    def send_configure_onu(self, olt_no, onu_no, alloc_id, uni_gem, multi_gem):
        self.log.info('configuring-onu',
                      olt=olt_no,
                      onu=onu_no,
                      alloc_id=alloc_id,
                      unicast_gem_port=uni_gem,
                      multicast_gem_port=multi_gem)
        raise NotImplementedError()

    @inlineCallbacks
    def send_activate_onu(self, olt_no, onu_no):
        self.log.info('activating-onu', olt=olt_no, onu=onu_no)
        raise NotImplementedError()

    @inlineCallbacks
    def heartbeat(self, device_id, state='run'):
        """Heartbeat OLT hardware

        Call remote method 'heartbeat' to verify connectivity to OLT
        hardware. If heartbeat missed self.heartbeat_failed_limit times OLT
        adapter is set FAILED/UNREACHABLE.
        No further action from VOLTHA core is expected as result of heartbeat
        failure. Heartbeat continues following failure and once connectivity is
        restored adapter state will be set to ACTIVE/REACHABLE

        Arguments:
        device_id: adapter device id
        state: desired state (stop, start, run)
        """

        self.log.debug('olt-heartbeat', device=device_id, state=state,
                       count=self.heartbeat_count)
        raise NotImplementedError()

    @inlineCallbacks
    def arrive_onu(self):
        self.log.info('arrive-onu waiting')
        _data = yield self.onu_discovered_queue.get()

        ok_to_arrive = False
        olt_id = _data['_device_id']
        pon_id = _data['_pon_id']
        onu_id = self.onu_serial_exists(_data['_vendor_id'], _data['_vendor_specific'])
        self.log.info('arrive-onu-detected', olt_id=olt_id, pon_ni=pon_id, onu_data=_data, onus=self.onus)

        if _data['onu_id'] == 65535:
            if onu_id is not None:
                self.log.info('onu-activation-already-in-progress',
                              vendor=_data['_vendor_id'],
                              vendor_specific=_data['_vendor_specific'],
                              onus=self.onus)
            else:
                onu_id = self.get_new_onu_id(_data['_vendor_id'],
                                             _data['_vendor_specific'])
                self.log.info('assigned-onu-id',
                              onu_id=onu_id,
                              vendor=_data['_vendor_id'],
                              vendor_specific=_data['_vendor_specific'],
                              onus=self.onus)
                ok_to_arrive = True
        else:
            vendor_id, vendor_specific = self.onu_exists(_data['onu_id'])
            if vendor_id is not None and vendor_id == _data['_vendor_id'] and \
               vendor_specific is not None and vendor_specific == _data['_vendor_specific']:
                onu_id = _data['onu_id']
                self.log.info('re-discovered-existing-onu',
                              onu_id=onu_id,
                              vendor=_data['_vendor_id'],
                              vendor_specific=_data['_vendor_specific'])
                ok_to_arrive = True
            else:
                self.log.info('onu-id-serial-number-mismatch-detected',
                              onu_id=onu_id,
                              vendor_id=vendor_id,
                              new_vendor_id=_data['_vendor_id'],
                              vendor_specific=vendor_specific,
                              new_vendor_specific=_data['_vendor_specific'])

        if onu_id is not None and ok_to_arrive:
            self.log.info('arriving-onu', onu_id=onu_id)
            tunnel_tag = self.get_tunnel_tag_from_onu(onu_id)
            yield self.send_create_onu(pon_id,
                                       onu_id,
                                       _data['_vendor_id'],
                                       _data['_vendor_specific'])
            yield self.send_configure_alloc_id(pon_id, onu_id, tunnel_tag)
            yield self.send_configure_unicast_gem(pon_id, onu_id, tunnel_tag)
            yield self.send_configure_multicast_gem(pon_id, onu_id, 4000)
            yield self.send_activate_onu(pon_id, onu_id)

            self.adapter_agent.child_device_detected(
                parent_device_id=self.device_id,
                parent_port_no=100,
                child_device_type='broadcom_onu',
                proxy_address=Device.ProxyAddress(
                    device_id=self.device_id,
                    channel_id=self.get_proxy_channel_id_from_onu(onu_id),  # c-vid
                    onu_id=onu_id,
                    onu_session_id=tunnel_tag  # tunnel_tag/gem_port, alloc_id
                ),
                vlan=tunnel_tag,
                serial_number=_data['_vendor_specific']
            )

        reactor.callLater(1, self.arrive_onu)

    @inlineCallbacks
    def activate(self):
        device = self.adapter_agent.get_device(self.device_id)
        self.log.info('activating-olt', device=device)

        while self.onu_discovered_queue.pending:
            _ = yield self.onu_discovered_queue.get()

        if self.logical_device_id is None:
            if not device.ipv4_address:
                device.oper_status = OperStatus.FAILED
                device.reason = 'No ipv4_address field provided'
                self.adapter_agent.update_device(device)
                return

            device.root = True
            device.vendor = 'Broadcom'
            device.model = 'bcm68620'
            device.serial_number = device.ipv4_address
            self.adapter_agent.update_device(device)

            nni_port = Port(
                port_no=1,
                label='NNI facing Ethernet port',
                type=Port.ETHERNET_NNI,
                admin_state=AdminState.ENABLED,
                oper_status=OperStatus.ACTIVE
            )
            self.adapter_agent.add_port(self.device_id, nni_port)
            self.adapter_agent.add_port(self.device_id, Port(
                port_no=100,
                label='PON port',
                type=Port.PON_OLT,
                admin_state=AdminState.ENABLED,
                oper_status=OperStatus.ACTIVE
            ))

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
                        OFPC_FLOW_STATS
                        | OFPC_TABLE_STATS
                        | OFPC_PORT_STATS
                        | OFPC_GROUP_STATS
                    )
                ),
                root_device_id=self.device_id
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
                device_id=self.device_id,
                device_port_no=nni_port.port_no,
                root_port=True
            ))

            device.parent_id = ld_initialized.id
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.ACTIVATING
            self.adapter_agent.update_device(device)
            self.logical_device_id = ld_initialized.id

        self.log.info('initiating-connection-to-olt',
                      device_id=self.device_id,
                      ipv4=device.ipv4_address,
                      port=self.pbc_port)
        try:
            reactor.connectTCP(device.ipv4_address, self.pbc_port, self.pbc_factory)
            device.connect_status = ConnectStatus.REACHABLE
            device.oper_status = OperStatus.ACTIVE
            device.reason = ''
            self.adapter_agent.update_device(device)
        except Exception as e:
            self.log.info('get-channel-exception', exc=str(e))
            device.oper_status = OperStatus.FAILED
            device.reason = 'Failed to connect to OLT'
            self.adapter_agent.update_device(device)
            self.pbc_factory.stopTrying()
            reactor.callLater(5, self.activate, device)
            return

        self.log.info('connected-to-olt',
                       device_id=self.device_id,
                       ipv4=device.ipv4_address,
                       port=self.pbc_port)

        reactor.callLater(0, self.heartbeat, self.device_id, state='start')

        yield self.send_set_remote()
        yield self.send_connect_olt(0)
        yield self.send_activate_olt(0)

        # Open the frameio port to receive in-band packet_in messages
        self.log.info('registering-frameio')
        self.io_port = registry('frameio').open_port(
            self.interface, self.rcv_io, is_inband_frame)

        # Finally set the initial PM configuration for this device
        # TODO: if arrive_onu not working, the following PM stuff was commented out during testing
        '''
        self.pm_metrics=Asfvolt16PmMetrics(device)
        pm_config = self.pm_metrics.make_proto()
        log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config,init=True)

        # Apply the PM configuration
        self.update_pm_metrics(device, pm_config)
        '''

        reactor.callLater(1, self.arrive_onu)

        self.log.info('olt-activated', device=device)

    def rcv_io(self, port, frame):
        self.log.info('received', iface_name=port.iface_name,
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

    @inlineCallbacks
    def update_flow_table(self, flows):
        self.log.info('bulk-flow-update', device_id=self.device_id, flows=flows)

        def is_downstream(port):
            return not is_upstream(port)

        def is_upstream(port):
            return port == 100  # Need a better way

        for flow in flows:
            _type = None
            _ip_proto = None
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
                        _ip_proto = field.ip_proto
                        self.log.info('field-type-ip-proto',
                                      ip_proto=_ip_proto)

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
                            self.log.info('set-field-type-vlan-vid',
                                          vlan_vid=_field.vlan_vid & 0xfff)
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type)
                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type, in_port=_in_port)

                if is_upstream(_in_port) and \
                        (_type == 0x888e or
                        (_type == 0x800 and (_ip_proto == 2 or _ip_proto == 17))):
                    yield self.send_config_classifier(0, _type, _ip_proto, _udp_dst)
                    yield self.send_config_acflow(0, _in_port, _type, _ip_proto, _udp_dst)



            except Exception as e:
                log.exception('failed-to-install-flow', e=e, flow=flow)

    @inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        if isinstance(msg, Packet):
            msg = str(msg)

        self.log.info('send-proxied-message',
                      proxy_address=proxy_address.channel_id,
                      msg=msg)
        raise NotImplementedError()

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

    @inlineCallbacks
    def update_pm_metrics(self, device, pm_config):
        self.log.info('update-pm-metrics', device_id=self.device_id,
                      pm_config=pm_config)
        remote = yield self.get_channel()
        self.pm_metrics.update(device, pm_config, remote)
