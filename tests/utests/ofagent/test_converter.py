# Copyright 2017-present Open Networking Foundation
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
from unittest import TestCase, main

from loxi import of13
from ofagent.loxi.of13.instruction import clear_actions
from voltha.protos import third_party
from ofagent.converter import to_loxi, to_grpc
from voltha.core.flow_decomposer import *

_ = third_party


class TestConverter(TestCase):

    def gen_pb_flow_stats(self):

        # device level flows

        flow_stats = [
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
                              udp_src(68), udp_dst(67)],
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
                match_fields=[in_port(2), vlan_vid(4096 + 1000), metadata(128)],
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
        ] + [
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

        ]

        # logical device level flows

        # Various controller-bound rules
        for _in_port in (1, 2):
            flow_stats.append(mk_flow_stat(
                priority=2000,
                match_fields=[in_port(_in_port), eth_type(0x888e)],
                actions=[
                    push_vlan(0x8100),
                    set_field(vlan_vid(4096 + 4000)),
                    output(ofp.OFPP_CONTROLLER)
                ]
            ))
        flow_stats.append(mk_flow_stat(
            priority=1000,
            match_fields=[eth_type(0x800), ip_proto(2)],
            actions=[output(ofp.OFPP_CONTROLLER)]
        ))
        flow_stats.append(mk_flow_stat(
            priority=1000,
            match_fields=[eth_type(0x800), ip_proto(17),
                          udp_src(68), udp_dst(67)],
            actions=[output(ofp.OFPP_CONTROLLER)]
        ))

        # Multicast channels
        mcast_setup = (
            (1, 0xe4010101, ()),
            (2, 0xe4010102, (1,)),
            (3, 0xe4010103, (2,)),
            (4, 0xe4010104, (1, 2)),
        )

        group_stats = []
        for group_id, mcast_addr, ports in mcast_setup:
            # self.lda.update_group_table(mk_multicast_group_mod(
            #     group_id=group_id,
            #     buckets=[
            #         ofp.ofp_bucket(actions=[
            #             pop_vlan(),
            #             output(port)
            #         ]) for port in ports
            #     ]))
            flow_stats.append(mk_flow_stat(
                priority=1000,
                match_fields=[
                    in_port(0),
                    eth_type(0x800),
                    vlan_vid(4096 + 140),
                    ipv4_dst(mcast_addr)
                ],
                actions=[
                    group(group_id)
                ]
            ))
            group_stats.append(group_entry_from_group_mod(
                mk_multicast_group_mod(
                 group_id=group_id,
                 buckets=[
                     ofp.ofp_bucket(actions=[
                         pop_vlan(),
                         output(port)
                     ]) for port in ports
                 ])))


        # Unicast channels for each subscriber
        # Downstream flow 1 for both
            flow_stats.append(mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(0),
                vlan_vid(4096 + 1000),
                metadata(128)
            ],
            actions=[pop_vlan()],
            next_table_id=1
        ))
        # Downstream flow 2 and upsrteam flow 1 for each ONU
        for port, c_vid in ((1, 101), (2, 102)):
            flow_stats.append(mk_flow_stat(
                priority=500,
                match_fields=[in_port(0), vlan_vid(4096 + c_vid)],
                actions=[set_field(vlan_vid(4096 + 0)), output(port)]
            ))
            # for the 0-tagged case
            flow_stats.append(mk_flow_stat(
                priority=500,
                match_fields=[in_port(port), vlan_vid(4096 + 0)],
                actions=[set_field(vlan_vid(4096 + c_vid))],
                next_table_id=1
            ))
            # for the untagged case
            flow_stats.append(mk_flow_stat(
                priority=500,
                match_fields=[in_port(port), vlan_vid(0)],
                actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + c_vid))],
                next_table_id=1
            ))
            # Upstream flow 2 for s-tag
            flow_stats.append(mk_flow_stat(
                priority=500,
                match_fields=[in_port(port), vlan_vid(4096 + c_vid)],
                actions=[
                    push_vlan(0x8100),
                    set_field(vlan_vid(4096 + 1000)),
                    output(0)
                ]
            ))

        return (flow_stats, group_stats)

    def test_flow_spec_pb_to_loxi_conversion(self):
        flow_stats, _ = self.gen_pb_flow_stats()
        for flow_stat in flow_stats:
            loxi_flow_stats = to_loxi(flow_stat)

    def test_group_stat_spec_pb_to_loxi_conversion(self):
        _, group_stats = self.gen_pb_flow_stats()
        for group_stat in group_stats:
            loxi_group_stat = to_loxi(group_stat.stats)

    def test_group_desc_spec_pb_to_loxi_conversion(self):
        _, group_stats = self.gen_pb_flow_stats()
        for group_stat in group_stats:
            loxi_group_desc = to_loxi(group_stat.desc)

    def test_clear_actions_instruction(self):
        obj = clear_actions()
        ofp_instruction = to_grpc(obj)
        self.assertEqual(ofp_instruction.type, 5)

if __name__ == '__main__':
    main()
