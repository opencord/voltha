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

from unittest import TestCase, main

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, Dot1Q, EAPOL

from ponsim import PonSim
from voltha.extensions.IGMP import IGMP_TYPE_V3_MEMBERSHIP_REPORT, IGMPv3gr, \
    IGMPv3, IGMP_TYPE_MEMBERSHIP_QUERY
from voltha.extensions.IGMP import IGMP_V3_GR_TYPE_EXCLUDE
from voltha.protos import third_party
from voltha.core.flow_decomposer import *
_ = third_party


class TestPonSim(TestCase):

    def setUp(self):
        self.output = []
        self.pon = PonSim(onus=2, egress_fun=lambda port, frame:
            self.output.append((port, frame)))

    def reset_output(self):
        while self.output:
            self.output.pop()

    def ingress_frame(self, frame, ports=None):
        if ports is None:
            ports = self.pon.get_ports()
        if isinstance(ports, int):
            ports = [ports]
        for port in ports:
            self.pon.ingress(port, frame)

    def assert_dont_pass(self, frame, ports=None):
        self.reset_output()
        self.ingress_frame(frame, ports)
        self.assertEqual(self.output, [])

    def assert_untagged_frames_dont_pass(self, ports=None):
        self.assert_dont_pass(Ether(), ports=ports)

    def test_basics(self):
        self.assertEqual(self.pon.get_ports(), [0, 128, 129])

    def test_by_default_no_traffic_passes(self):
        self.assert_untagged_frames_dont_pass()

    def test_downstream_unicast_forwarding(self):

        self.pon.olt_install_flows([
            mk_flow_stat(
                match_fields=[in_port(2), vlan_vid(4096 + 1000)],
                actions=[pop_vlan(), output(1)]
            )
        ])
        self.pon.onu_install_flows(128, [
            mk_flow_stat(
                match_fields=[in_port(1), vlan_vid(4096 + 128)],
                actions=[set_field(vlan_vid(4096 + 0)), output(2)]
            )
        ])

        # untagged frames shall not get through
        self.assert_untagged_frames_dont_pass()

        # incorrect single- or double-tagged frames don't pass
        self.assert_dont_pass(Ether() / Dot1Q(vlan=1000) / IP())
        self.assert_dont_pass(Ether() / Dot1Q(vlan=128) / IP())
        self.assert_dont_pass(
            Ether() / Dot1Q(vlan=128) / Dot1Q(vlan=1000) / IP())
        self.assert_dont_pass(
            Ether() / Dot1Q(vlan=1000) / Dot1Q(vlan=129) / IP())

        # properly tagged downstream frame gets through and pops up at port 128
        # as untagged
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=1000) / Dot1Q(vlan=128) / IP()
        out_frame = Ether(**kw) / Dot1Q(vlan=0) / IP()

        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(128, out_frame)])

    def test_upstream_unicast_forwarding(self):

        self.pon.onu_install_flows(128, [
            mk_flow_stat(
                match_fields=[in_port(2), vlan_vid(4096 + 0)],
                actions=[set_field(vlan_vid(4096 + 128)), output(1)]
            )
        ])
        self.pon.olt_install_flows([
            mk_flow_stat(
                match_fields=[in_port(1), vlan_vid(4096 + 128)],
                actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + 1000)),
                         output(2)]
            )
        ])

        # untagged frames shall not get through
        self.assert_untagged_frames_dont_pass()

        # incorrect single- or double-tagged frames don't pass
        self.assert_dont_pass(Ether() / Dot1Q(vlan=1000) / IP())
        self.assert_dont_pass(Ether() / Dot1Q(vlan=128) / IP())
        self.assert_dont_pass(
            Ether() / Dot1Q(vlan=1000) / Dot1Q(vlan=128) / IP())
        self.assert_dont_pass(
            Ether() / Dot1Q(vlan=129) / Dot1Q(vlan=1000) / IP())

        # properly tagged downstream frame gets through and pops up at port 128
        # as untagged
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=0) / IP()
        out_frame = Ether(**kw) / Dot1Q(vlan=1000) / Dot1Q(vlan=128) / IP()

        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(0, out_frame)])


    def setup_all_flows(self):

        self.pon.olt_install_flows([
            mk_flow_stat(
                priority=2000,
                match_fields=[in_port(2), vlan_vid(4096 + 4000), vlan_pcp(0)],
                actions=[pop_vlan(), output(1)]
            ),
            mk_flow_stat(
                priority=2000,
                match_fields=[in_port(1), eth_type(0x888e)],
                actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + 4000)),
                         output(2)]
            ),
            mk_flow_stat(
                priority=1000,
                match_fields=[in_port(1), eth_type(0x800), ip_proto(2)],
                actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + 4000)),
                         output(2)]
            ),
            mk_flow_stat(
                priority=1000,
                match_fields=[in_port(1), eth_type(0x800), ip_proto(17),
                              udp_dst(67)],
                actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + 4000)),
                         output(2)]
            ),
            mk_flow_stat(
                priority=1000,
                match_fields=[in_port(2), vlan_vid(4096 + 140)],
                actions=[pop_vlan(), output(1)]
            ),
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(2), vlan_vid(4096 + 1000)],
                actions=[pop_vlan(), output(1)]
            ),
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(1), vlan_vid(4096 + 128)],
                actions=[
                    push_vlan(0x8100), set_field(vlan_vid(4096 + 1000)),
                    output(2)]
            ),
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(1), vlan_vid(4096 + 129)],
                actions=[
                    push_vlan(0x8100), set_field(vlan_vid(4096 + 1000)),
                    output(2)]
            ),
        ])

        self.pon.onu_install_flows(128, [
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(2), vlan_vid(4096 + 0)],
                actions=[
                    set_field(vlan_vid(4096 + 128)), output(1)]
            ),
            mk_flow_stat(
                priority=1000,
                match_fields=[
                    in_port(1), eth_type(0x800), ipv4_dst(0xe4010102)],
                actions=[output(2)]
            ),
            mk_flow_stat(
                priority=1000,
                match_fields=[
                    in_port(1), eth_type(0x800), ipv4_dst(0xe4010104)],
                actions=[output(2)]
            ),
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(1), vlan_vid(4096 + 128)],
                actions=[set_field(vlan_vid(4096 + 0)), output(2)]
            ),
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(2), vlan_vid(0)],
                actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + 128)),
                         output(1)]
            )
        ])

        self.pon.onu_install_flows(129, [
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(2), vlan_vid(4096 + 0)],
                actions=[
                    set_field(vlan_vid(4096 + 129)), output(1)]
            ),
            mk_flow_stat(
                priority=1000,
                match_fields=[
                    in_port(1), eth_type(0x800), ipv4_dst(0xe4010103)],
                actions=[output(2)]
            ),
            mk_flow_stat(
                priority=1000,
                match_fields=[
                    in_port(1), eth_type(0x800), ipv4_dst(0xe4010104)],
                actions=[output(2)]
            ),
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(1), vlan_vid(4096 + 129)],
                actions=[set_field(vlan_vid(4096 + 0)), output(2)]
            ),
            mk_flow_stat(
                priority=500,
                match_fields=[in_port(2), vlan_vid(0)],
                actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + 129)),
                         output(1)]
            )
        ])

    def test_combo_block_untagged_downstream(self):
        self.setup_all_flows()
        self.assert_untagged_frames_dont_pass(ports=0)

    def test_eapol_in(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / EAPOL(type=1)
        out_frame1 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=128) / EAPOL(type=1)
        out_frame2 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=129) / EAPOL(type=1)
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(0, out_frame1), (0, out_frame2)])

    def test_eapol_out(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame1 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=128) / EAPOL(type=1)
        in_frame2 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=129) / EAPOL(type=1)
        out_frame = Ether(**kw) / Dot1Q(vlan=0) / EAPOL(type=1)
        self.ingress_frame(in_frame1)
        self.ingress_frame(in_frame2)
        self.assertEqual(self.output, [(128, out_frame), (129, out_frame)])

    def test_igmp_in(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        mr = IGMPv3(type=IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                    gaddr="224.0.0.1")
        mr.grps = [
            IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr="228.1.1.3")]

        in_frame = Ether(**kw) / IP() / mr
        out_frame1 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=128) /\
                     in_frame.payload.copy()
        out_frame2 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=129) /\
                     in_frame.payload.copy()
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(0, out_frame1), (0, out_frame2)])

    def test_igmp_out(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        mq = IGMPv3(type=IGMP_TYPE_MEMBERSHIP_QUERY, max_resp_code=120)
        in_frame1 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=128) /\
                    IP() / mq.copy()
        in_frame2 = Ether(**kw) / Dot1Q(vlan=4000) / Dot1Q(vlan=129) /\
                    IP() / mq.copy()
        out_frame = Ether(**kw) / Dot1Q(vlan=0) / IP() / mq.copy()
        self.ingress_frame(in_frame1)
        self.ingress_frame(in_frame2)
        self.assertEqual(self.output, [(128, out_frame), (129, out_frame)])

    def test_combo_downstream_unicast_onu1(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=1000) / Dot1Q(vlan=128) / IP()
        out_frame = Ether(**kw) / Dot1Q(vlan=0) / IP()
        self.reset_output()
        self.ingress_frame(in_frame, ports=0)
        self.assertEqual(self.output, [(128, out_frame)])

    def test_combo_downstream_unicast_onu2(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=1000) / Dot1Q(vlan=129) / IP()
        out_frame = Ether(**kw) / Dot1Q(vlan=0) / IP()
        self.reset_output()
        self.ingress_frame(in_frame, ports=0)
        self.assertEqual(self.output, [(129, out_frame)])

    def test_combo_upstream_unicast_onu1(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=1000) / Dot1Q(vlan=128) / IP()
        out_frame = Ether(**kw) / Dot1Q(vlan=0) / IP()
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(128, out_frame)])

    def test_combo_upstream_unicast_onu2(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=1000) / Dot1Q(vlan=129) / IP()
        out_frame = Ether(**kw) / Dot1Q(vlan=0) / IP()
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(129, out_frame)])

    def test_combo_multicast_stream1(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=140) / IP(dst='228.1.1.1')
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [])

    def test_combo_multicast_stream2(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=140) / IP(dst='228.1.1.2')
        out_frame = Ether(**kw) / IP(dst='228.1.1.2')
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(128, out_frame),])

    def test_combo_multicast_stream3(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=140) / IP(dst='228.1.1.3')
        out_frame = Ether(**kw) / IP(dst='228.1.1.3')
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(129, out_frame),])

    def test_combo_multicast_stream4(self):
        self.setup_all_flows()
        kw = dict(src='00:00:00:11:11:11', dst='00:00:00:22:22:22')
        in_frame = Ether(**kw) / Dot1Q(vlan=140) / IP(dst='228.1.1.4')
        out_frame = Ether(**kw) / IP(dst='228.1.1.4')
        self.ingress_frame(in_frame)
        self.assertEqual(self.output, [(128, out_frame), (129, out_frame)])


if __name__ == '__main__':
    main()
