#
# Copyright 2016 the original author or authors.
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
Simple PON Simulator which would not be needed if openvswitch could do
802.1ad (QinQ), which it cannot (the reason is beyond me), or if CPQD could
handle 0-tagged packets (no comment).
"""
import structlog
import random
import arrow
import json
from scapy.layers.inet import IP, UDP, TCP, Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet

from voltha.protos import third_party
from voltha.protos.ponsim_pb2 import PonSimMetrics, PonSimPortMetrics, \
    PonSimPacketCounter
from voltha.protos.events_pb2 import AlarmEventType, AlarmEventSeverity, \
    AlarmEventState, AlarmEventCategory
from voltha.core.flow_decomposer import *
from twisted.internet.task import LoopingCall
from twisted.internet import reactor

_ = third_party


def ipv4int2str(ipv4int):
    return '{}.{}.{}.{}'.format(
        (ipv4int >> 24) & 0xff,
        (ipv4int >> 16) & 0xff,
        (ipv4int >> 8) & 0xff,
        ipv4int & 0xff
    )


class _FlowMatchMask(object):
    """
    Enum of mask values based on flow match priority. For instance, a port
    match has higher priority when match that a UDP match.
    """
    UDP_DST = 1
    UDP_SRC = 2
    IPV4_DST = 4
    VLAN_PCP = 8
    VLAN_VID = 16
    IP_PROTO = 34
    ETH_TYPE = 64
    IN_PORT = 128


class FrameIOCounter(object):
    class SingleFrameCounter(object):
        def __init__(self, name, min, max):
            # Currently there are 2 values, one for the PON interface (port 1)
            # and one for the Network Interface (port 2). This can be extended if
            # the virtual devices extend the number of ports. 
            self.value = [0, 0]  # {PON,NI}
            self.name = name
            self.min = min
            self.max = max

    def __init__(self, device):
        self.device = device
        self.tx_counters = dict(
            tx_64_pkts=self.SingleFrameCounter("tx_64_pkts", 1, 64),
            tx_65_127_pkts=self.SingleFrameCounter("tx_65_127_pkts", 65, 127),
            tx_128_255_pkts=self.SingleFrameCounter("tx_128_255_pkts", 128, 255),
            tx_256_511_pkts=self.SingleFrameCounter("tx_256_511_pkts", 256, 511),
            tx_512_1023_pkts=self.SingleFrameCounter("tx_512_1023_pkts", 512, 1024),
            tx_1024_1518_pkts=self.SingleFrameCounter("tx_1024_1518_pkts", 1024, 1518),
            tx_1519_9k_pkts=self.SingleFrameCounter("tx_1519_9k_pkts", 1519, 9216),
        )
        self.rx_counters = dict(
            rx_64_pkts=self.SingleFrameCounter("rx_64_pkts", 1, 64),
            rx_65_127_pkts=self.SingleFrameCounter("rx_65_127_pkts", 65, 127),
            rx_128_255_pkts=self.SingleFrameCounter("rx_128_255_pkts", 128, 255),
            rx_256_511_pkts=self.SingleFrameCounter("rx_256_511_pkts", 256, 511),
            rx_512_1023_pkts=self.SingleFrameCounter("rx_512_1023_pkts", 512, 1024),
            rx_1024_1518_pkts=self.SingleFrameCounter("rx_1024_1518_pkts", 1024, 1518),
            rx_1519_9k_pkts=self.SingleFrameCounter("rx_1519_9k_pkts", 1519, 9216)
        )

    def count_rx_frame(self, port, size):
        log.info("counting-rx-frame", size=size, port=port)
        for k, v in self.rx_counters.iteritems():
            if size >= v.min and size <= v.max:
                self.rx_counters[k].value[port - 1] += 1
                return
        log.warn("unsupported-packet-size", size=size)

    def count_tx_frame(self, port, size):
        for k, v in self.tx_counters.iteritems():
            if size >= v.min and size <= v.max:
                self.tx_counters[k].value[port - 1] += 1
                return
        log.warn("unsupported-packet-size", size=size)

    def log_counts(self):
        rx_ct_list = [(v.name, v.value[0], v.value[1]) for v in
                      self.rx_counters.values()]
        tx_ct_list = [(v.name, v.value[0], v.value[1]) for v in
                      self.tx_counters.values()]
        log.info("rx-counts", rx_ct_list=rx_ct_list)
        log.info("tx-counts", tx_ct_list=tx_ct_list)

    def make_proto(self):
        sim_metrics = PonSimMetrics(
            device=self.device
        )
        pon_port_metrics = PonSimPortMetrics(
            port_name="pon"
        )
        ni_port_metrics = PonSimPortMetrics(
            port_name="nni"
        )
        for c in sorted(self.rx_counters):
            ctr = self.rx_counters[c]
            pon_port_metrics.packets.extend([
                PonSimPacketCounter(name=ctr.name, value=ctr.value[0])
            ])
            # Since they're identical keys, save some time and cheat
            ni_port_metrics.packets.extend([
                PonSimPacketCounter(name=ctr.name, value=ctr.value[1])
            ])

        for c in sorted(self.tx_counters):
            ctr = self.tx_counters[c]
            pon_port_metrics.packets.extend([
                PonSimPacketCounter(name=ctr.name, value=ctr.value[0])
            ])
            # Since they're identical keys, save some time and cheat
            ni_port_metrics.packets.extend([
                PonSimPacketCounter(name=ctr.name, value=ctr.value[1])
            ])
        sim_metrics.metrics.extend([pon_port_metrics])
        sim_metrics.metrics.extend([ni_port_metrics])

        return sim_metrics


class SimAlarms:
    def __init__(self):
        self.lc = None

    @staticmethod
    def _prepare_alarm():
        alarm_event = dict()

        try:
            # Randomly choose values for each enum types
            alm_severity = random.choice(list(
                v for k, v in
                AlarmEventSeverity.DESCRIPTOR.enum_values_by_name.items()))

            alm_type = random.choice(list(
                v for k, v in
                AlarmEventType.DESCRIPTOR.enum_values_by_name.items()))

            alm_category = random.choice(list(
                v for k, v in
                AlarmEventCategory.DESCRIPTOR.enum_values_by_name.items()))

            alarm_event['severity'] = alm_severity.number
            alarm_event['type'] = alm_type.number
            alarm_event['category'] = alm_category.number
            alarm_event['state'] = AlarmEventState.RAISED
            alarm_event['ts'] = arrow.utcnow().timestamp
            alarm_event['description'] = "{}.{} alarm".format(alm_type.name, alm_category.name)

            return alarm_event

        except Exception as e:
            log.exception('failed-to-prepare-alarm', e=e)

    @staticmethod
    def _raise_alarm(alarm_event, olt, egress):
        try:
            frame = Ether() / Dot1Q(vlan=4000) / IP() / TCP() / Raw(load=json.dumps(alarm_event))
            egress(0, frame)

        except Exception as e:
            log.exception('failed-to-raise-alarm', e=e)

    @staticmethod
    def _clear_alarm(alarm_event, olt, egress):
        try:
            alarm_event['state'] = AlarmEventState.CLEARED
            frame = Ether() / Dot1Q(vlan=4000) / IP() / TCP() / Raw(load=json.dumps(alarm_event))
            egress(0, frame)

        except Exception as e:
            log.exception('failed-to-clear-alarm', e=e)

    def _generate_alarm(self, olt, egress):
        try:
            alarm = self._prepare_alarm()
            self._raise_alarm(alarm, olt, egress)
            reactor.callLater(random.randint(20, 60), self._clear_alarm, alarm, olt, egress)
        except Exception as e:
            log.exception(e=e)

    def start_simulation(self, olt, egress, config):
        log.info("starting-alarm-simulation")

        """Simulate periodic device alarms"""
        self.lc = LoopingCall(self._generate_alarm, olt, egress)
        self.lc.start(config['frequency'])

    def stop_simulation(self):
        log.info("stopping-alarm-simulation")
        self.lc.stop()


class SimDevice(object):
    def __init__(self, name, logical_port_no):
        self.name = name
        self.logical_port_no = logical_port_no
        self.links = dict()
        self.flows = list()
        self.log = structlog.get_logger(name=name,
                                        logical_port_no=logical_port_no)
        self.counter = FrameIOCounter(name)

    def link(self, port, egress_fun):
        self.links.setdefault(port, []).append(egress_fun)

    def ingress(self, port, frame):
        self.log.debug('ingress', ingress_port=port, name=self.name)
        self.counter.count_rx_frame(port, len(frame["Ether"].payload))
        outcome = self.process_frame(port, frame)
        if outcome is not None:
            egress_port, egress_frame = outcome
            forwarded = 0
            links = self.links.get(egress_port)
            if links is not None:
                self.counter.count_tx_frame(egress_port,
                                            len(egress_frame["Ether"].payload))
                for fun in links:
                    forwarded += 1
                    self.log.debug('forwarding', egress_port=egress_port)
                    fun(egress_port, egress_frame)
            if not forwarded:
                self.log.debug('no-one-to-forward-to', egress_port=egress_port)
        else:
            self.log.debug('dropped')

    def install_flows(self, flows):
        # store flows in precedence order so we can roll down on frame arrival
        self.flows = sorted(flows, key=lambda fm: fm.priority, reverse=True)

    def process_frame(self, ingress_port, ingress_frame):
        matched_mask = 0
        highest_priority = 0
        matched_flow = None
        for flow in self.flows:
            # flows are sorted by highest priority.
            if matched_flow and flow.priority < highest_priority:
                break

            highest_priority = flow.priority
            current_mask = self.is_match(flow, ingress_port, ingress_frame)
            if current_mask > matched_mask:
                matched_mask = current_mask
                matched_flow = flow

        if matched_flow:
            egress_port, egress_frame = self.process_actions(
                matched_flow, ingress_frame)
            return egress_port, egress_frame
        return None

    @staticmethod
    def is_match(flow, ingress_port, frame):
        matched_mask = 0

        def get_non_shim_ether_type(f):
            if f.haslayer(Dot1Q):
                f = f.getlayer(Dot1Q)
            return f.type

        def get_vlan_pcp(f):
            if f.haslayer(Dot1Q):
                return f.getlayer(Dot1Q).prio

        def get_ip_proto(f):
            if f.haslayer(IP):
                return f.getlayer(IP).proto

        def get_ipv4_dst(f):
            if f.haslayer(IP):
                return f.getlayer(IP).dst

        def get_udp_src(f):
            if f.haslayer(UDP):
                return f.getlayer(UDP).sport

        def get_udp_dst(f):
            if f.haslayer(UDP):
                return f.getlayer(UDP).dport

        for field in get_ofb_fields(flow):

            if field.type == IN_PORT:
                if field.port != ingress_port:
                    return 0
                matched_mask |= _FlowMatchMask.IN_PORT

            elif field.type == ETH_TYPE:
                if field.eth_type != get_non_shim_ether_type(frame):
                    return 0
                matched_mask |= _FlowMatchMask.ETH_TYPE

            elif field.type == IP_PROTO:
                if field.ip_proto != get_ip_proto(frame):
                    return 0
                matched_mask |= _FlowMatchMask.IP_PROTO

            elif field.type == VLAN_VID:
                expected_vlan = field.vlan_vid
                tagged = frame.haslayer(Dot1Q)
                if bool(expected_vlan & 4096) != bool(tagged):
                    return 0
                if tagged:
                    actual_vid = frame.getlayer(Dot1Q).vlan
                    if actual_vid != expected_vlan & 4095:
                        return 0
                matched_mask |= _FlowMatchMask.VLAN_VID

            elif field.type == VLAN_PCP:
                if field.vlan_pcp != get_vlan_pcp(frame):
                    return 0
                matched_mask |= _FlowMatchMask.VLAN_PCP

            elif field.type == IPV4_DST:
                if ipv4int2str(field.ipv4_dst) != get_ipv4_dst(frame):
                    return 0
                matched_mask |= _FlowMatchMask.IPV4_DST

            elif field.type == UDP_SRC:
                if field.udp_src != get_udp_src(frame):
                    return 0
                matched_mask |= _FlowMatchMask.UDP_SRC

            elif field.type == UDP_DST:
                if field.udp_dst != get_udp_dst(frame):
                    return 0
                matched_mask |= _FlowMatchMask.UDP_DST

            elif field.type == METADATA:
                pass  # safe to ignore

            else:
                raise NotImplementedError('field.type=%d' % field.type)

        return matched_mask

    @staticmethod
    def process_actions(flow, frame):
        egress_port = None
        for action in get_actions(flow):

            if action.type == OUTPUT:
                egress_port = action.output.port

            elif action.type == POP_VLAN:
                if frame.haslayer(Dot1Q):
                    shim = frame.getlayer(Dot1Q)
                    frame = Ether(
                        src=frame.src,
                        dst=frame.dst,
                        type=shim.type) / shim.payload

            elif action.type == PUSH_VLAN:
                frame = (
                    Ether(src=frame.src, dst=frame.dst,
                          type=action.push.ethertype) /
                    Dot1Q(type=frame.type) /
                    frame.payload
                )

            elif action.type == SET_FIELD:
                assert (action.set_field.field.oxm_class ==
                        ofp.OFPXMC_OPENFLOW_BASIC)
                field = action.set_field.field.ofb_field

                if field.type == VLAN_VID:
                    shim = frame.getlayer(Dot1Q)
                    shim.vlan = field.vlan_vid & 4095

                elif field.type == VLAN_PCP:
                    shim = frame.getlayer(Dot1Q)
                    shim.prio = field.vlan_pcp

                else:
                    raise NotImplementedError('set_field.field.type=%d'
                                              % field.type)

            else:
                raise NotImplementedError('action.type=%d' % action.type)

        return egress_port, frame


class PonSim(object):
    def __init__(self, onus, egress_fun, alarm_config):
        self.egress_fun = egress_fun

        self.log = structlog.get_logger()
        # Create OLT and hook NNI port up for egress
        self.olt = SimDevice('olt', 0)
        self.olt.link(2, lambda _, frame: self.egress_fun(0, frame))
        self.devices = dict()
        self.devices[0] = self.olt
        # TODO: This can be removed, it's for debugging purposes
        self.lc = LoopingCall(self.olt.counter.log_counts)
        self.lc.start(90)  # To correlate with Kafka

        # Create ONUs of the requested number and hook them up with OLT
        # and with egress fun
        def mk_egress_fun(port_no):
            return lambda _, frame: self.egress_fun(port_no, frame)

        def mk_onu_ingress(onu):
            return lambda _, frame: onu.ingress(1, frame)

        for i in range(onus):
            port_no = 128 + i
            onu = SimDevice('onu%d' % i, port_no)
            onu.link(1, lambda _, frame: self.olt.ingress(1,
                                                          frame))  # Send to the OLT
            onu.link(2,
                     mk_egress_fun(port_no))  # Send from the ONU to the world
            self.olt.link(1, mk_onu_ingress(onu))  # Internal send to the ONU
            self.devices[port_no] = onu
        for d in self.devices:
            self.log.info("pon-sim-init", port=d, name=self.devices[d].name,
                          links=self.devices[d].links)

        if alarm_config['simulation']:
            self.alarms = SimAlarms()
            self.alarms.start_simulation(self.olt, self.egress_fun, alarm_config)

    def get_ports(self):
        return sorted(self.devices.keys())

    def get_stats(self):
        return self.olt.counter.make_proto()

    def olt_install_flows(self, flows):
        self.olt.install_flows(flows)

    def onu_install_flows(self, onu_port, flows):
        self.devices[onu_port].install_flows(flows)

    def ingress(self, port, frame):
        if not isinstance(frame, Packet):
            frame = Ether(frame)
        self.devices[port].ingress(2, frame)

class XPonSim(object):
    def __init__(self):
        self.log = structlog.get_logger()

    def CreateInterface(self, request):
        self.log.info("create-interface-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def UpdateInterface(self, request):
        self.log.info("update-interface-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def RemoveInterface(self, request):
        self.log.info("remove-interface-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def CreateTcont(self, request, request2):
        self.log.info("create-tcont-request",
                      tcont_config_data=request,
                      traffic_descriptor_profile_config_data=request2)
        return

    def UpdateTcont(self, request, request2):
        self.log.info("update-tcont-request",
                      tcont_config_data=request,
                      traffic_descriptor_profile_config_data=request2)
        return

    def RemoveTcont(self, request, request2):
        self.log.info("remove-tcont-request",
                      tcont_config_data=request,
                      traffic_descriptor_profile_config_data=request2)
        return

    def CreateGemport(self, request):
        self.log.info("create-gemport-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def UpdateGemport(self, request):
        self.log.info("update-gemport-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def RemoveGemport(self, request):
        self.log.info("remove-gemport-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def CreateMulticastGemport(self, request):
        self.log.info("create-multicast-gemport-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def UpdateMulticastGemport(self, request):
        self.log.info("update-multicast-gemport-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def RemoveMulticastGemport(self, request):
        self.log.info("remove-multicast-gemport-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def CreateMulticastDistributionSet(self, request):
        self.log.info("create-multicast-distribution-set-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def UpdateMulticastDistributionSet(self, request):
        self.log.info("update-multicast-distribution-set-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return

    def RemoveMulticastDistributionSet(self, request):
        self.log.info("remove-multicast-distribution-set-request",
                      interface_type=request.WhichOneof("interface_type"),
                      data=request)
        return
