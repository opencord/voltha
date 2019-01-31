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
from unittest import main
from nose.tools import nottest

from tests.utests.voltha.core.flow_helpers import FlowHelpers
from voltha.core.flow_decomposer import *
from voltha.protos import third_party
from voltha.protos.device_pb2 import Device, Port
from voltha.protos.logical_device_pb2 import LogicalPort


class TestFlowDecomposer(FlowHelpers, FlowDecomposer):

    def setUp(self):
        self.logical_device_id = 'pon'
        self._nni_logical_port_no = None

    # methods needed by FlowDecomposer; faking real lookups

    _devices = {
        'olt':  Device(
            id='olt',
            root=True,
            parent_id='logical_device',
            ports=[
                Port(port_no=1, label='pon'),
                Port(port_no=2, label='nni'),
            ]
        ),
        'onu1': Device(
            id='onu1',
            parent_id='olt',
            ports=[
                Port(port_no=1, label='pon'),
                Port(port_no=2, label='uni'),
            ]
        ),
        'onu2': Device(
            id='onu2',
            parent_id='olt',
            ports=[
                Port(port_no=1, label='pon'),
                Port(port_no=2, label='uni'),
            ]
        ),
        'onu3': Device(
            id='onu3',
            parent_id='olt',
            ports=[
                Port(port_no=1, label='pon'),
                Port(port_no=2, label='uni'),
            ]
        ),
        'onu4': Device(
            id='onu4',
            parent_id='olt',
            ports=[
                Port(port_no=1, label='pon'),
                Port(port_no=2, label='uni'),
            ]
        ),
    }

    _logical_ports = {
        0: LogicalPort(id='0', device_id='olt', device_port_no=2),
        1: LogicalPort(id='1', device_id='onu1', device_port_no=2),
        2: LogicalPort(id='2', device_id='onu2', device_port_no=2),
        3: LogicalPort(id='3', device_id='onu3', device_port_no=2),
        4: LogicalPort(id='4', device_id='onu4', device_port_no=2),
    }

    def get_wildcard_input_ports(self, exclude_port=None):
        logical_ports =  self._logical_ports.iterkeys()
        return [port_no for port_no in logical_ports
                if port_no != exclude_port]

    _routes = {

        # DOWNSTREAM ROUTES

        (0, 1): [
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[1],
                     _devices['olt'].ports[0]),
            RouteHop(_devices['onu1'],
                     _devices['onu1'].ports[0],
                     _devices['onu1'].ports[1]),
        ],
        (0, 2): [
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[1],
                     _devices['olt'].ports[0]),
            RouteHop(_devices['onu2'],
                     _devices['onu2'].ports[0],
                     _devices['onu2'].ports[1]),
        ],
        (0, 3): [
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[1],
                     _devices['olt'].ports[0]),
            RouteHop(_devices['onu3'],
                     _devices['onu3'].ports[0],
                     _devices['onu3'].ports[1]),
        ],
        (0, 4): [
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[1],
                     _devices['olt'].ports[0]),
            RouteHop(_devices['onu4'],
                     _devices['onu4'].ports[0],
                     _devices['onu4'].ports[1]),
        ],

        # UPSTREAM DATA PLANE

        (1, 0): [
            RouteHop(_devices['onu1'],
                     _devices['onu1'].ports[1],
                     _devices['onu1'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],
        (2, 0): [
            RouteHop(_devices['onu2'],
                     _devices['onu2'].ports[1],
                     _devices['onu2'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],
        (3, 0): [
            RouteHop(_devices['onu3'],
                     _devices['onu3'].ports[1],
                     _devices['onu3'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],
        (4, 0): [
            RouteHop(_devices['onu4'],
                     _devices['onu4'].ports[1],
                     _devices['onu4'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],

        # UPSTREAM NEXT TABLE BASED

        (1, None): [
            RouteHop(_devices['onu1'],
                     _devices['onu1'].ports[1],
                     _devices['onu1'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],
        (2, None): [
            RouteHop(_devices['onu2'],
                     _devices['onu2'].ports[1],
                     _devices['onu2'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],
        (3, None): [
            RouteHop(_devices['onu3'],
                     _devices['onu3'].ports[1],
                     _devices['onu3'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],
        (4, None): [
            RouteHop(_devices['onu4'],
                     _devices['onu4'].ports[1],
                     _devices['onu4'].ports[0]),
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]),
        ],

        # DOWNSTREAM NEXT TABLE BASED

        (0, None): [
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[1],
                     _devices['olt'].ports[0]),
            None  # 2nd hop is not known yet
        ],

        # UPSTREAM WILD-CARD
        (None, 0): [
            None,  # 1st hop is wildcard
            RouteHop(_devices['olt'],
                     _devices['olt'].ports[0],
                     _devices['olt'].ports[1]
                     )
        ]
    }

    _default_rules = {
        'onu1': (
            OrderedDict((f.id, f) for f in [
                mk_flow_stat(
                    match_fields=[
                        in_port(2),
                        vlan_vid(ofp.OFPVID_PRESENT | 0)
                    ],
                    actions=[
                        set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
                        output(1)
                    ]
                )
            ]),
            OrderedDict()
        ),
        'onu2': (
            OrderedDict((f.id, f) for f in [
                mk_flow_stat(
                    match_fields=[
                        in_port(2),
                        vlan_vid(ofp.OFPVID_PRESENT | 0)
                    ],
                    actions=[
                        set_field(vlan_vid(ofp.OFPVID_PRESENT | 102)),
                        output(1)
                    ]
                )
            ]),
            OrderedDict()
        ),
        'onu3': (
            OrderedDict((f.id, f) for f in [
                mk_flow_stat(
                    match_fields=[
                        in_port(2),
                        vlan_vid(ofp.OFPVID_PRESENT | 0)
                    ],
                    actions=[
                        set_field(vlan_vid(ofp.OFPVID_PRESENT | 103)),
                        output(1)
                    ]
                )
            ]),
            OrderedDict()
        ),
        'onu4': (
            OrderedDict((f.id, f) for f in [
                mk_flow_stat(
                    match_fields=[
                        in_port(2),
                        vlan_vid(ofp.OFPVID_PRESENT | 0)
                    ],
                    actions=[
                        set_field(vlan_vid(ofp.OFPVID_PRESENT | 104)),
                        output(1)
                    ]
                )
            ]),
            OrderedDict()
        )
    }

    def get_all_default_rules(self):
        return self._default_rules

    def get_default_rules(self, device_id):
        return self._default_rules[device_id]

    def get_route(self, in_port_no, out_port_no):
        if out_port_no is not None and \
                        (out_port_no & 0x7fffffff) == ofp.OFPP_CONTROLLER:
            # treat it as if the output port is the NNI of the OLT
            out_port_no = 0  # OLT NNI port
        return self._routes[(in_port_no, out_port_no)]

    # ~~~~~~~~~~~~~~~~~~~~~~~~ ACTUAL TEST CASES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def test_eapol_reroute_rule_decomposition(self):
        flow = mk_flow_stat(
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                eth_type(0x888e)
            ],
            actions=[
                output(ofp.OFPP_CONTROLLER)
            ],
            priority=1000,
            metadata=4294967296
        )
        device_rules = self.decompose_rules([flow], [])
        onu1_flows, onu1_groups = device_rules['onu1']
        olt_flows, olt_groups = device_rules['olt']
        self.assertEqual(len(onu1_flows), 1)
        self.assertEqual(len(onu1_groups), 0)
        self.assertEqual(len(olt_flows), 1)  # not doing in-band control
        self.assertEqual(len(olt_groups), 0)
        self.assertFlowsEqual(onu1_flows.values()[0], mk_flow_stat(
            match_fields=[
                in_port(2),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
                output(1)
            ]
        ))
        self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
            priority=1000,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                eth_type(0x888e)
            ],
            actions=[
                output(ofp.OFPP_CONTROLLER)
            ],
            metadata=4294967296
        ))
        # Not doing in-band control
        # self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
        #     priority=1000,
        #     match_fields=[
        #         in_port(1),
        #         vlan_vid(ofp.OFPVID_PRESENT | 1),
        #         eth_type(0x888e)
        #     ],
        #     actions=[
        #         push_vlan(0x8100),
        #         set_field(vlan_vid(ofp.OFPVID_PRESENT | 4000)),
        #         output(2)
        #     ],
        #     metadata=4294967296
        # ))
        # self.assertFlowsEqual(olt_flows.values()[1], mk_flow_stat(
        #     priority=1000,
        #     match_fields=[
        #         in_port(2),
        #         vlan_vid(ofp.OFPVID_PRESENT | 4000),
        #         vlan_pcp(0)
        #     ],
        #     actions=[
        #         pop_vlan(),
        #         output(1)
        #     ],
        #     metadata=4294967296
        # ))

    def test_dhcp_reroute_rule_decomposition(self):
        flow = mk_flow_stat(
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                eth_type(0x0800),
                ipv4_dst(0xffffffff),
                ip_proto(17),
                udp_src(68),
                udp_dst(67)
            ],
            actions=[output(ofp.OFPP_CONTROLLER)],
            priority=1000,
            metadata=4294967296
        )
        device_rules = self.decompose_rules([flow], [])
        onu1_flows, onu1_groups = device_rules['onu1']
        olt_flows, olt_groups = device_rules['olt']
        self.assertEqual(len(onu1_flows), 1)
        self.assertEqual(len(onu1_groups), 0)
        self.assertEqual(len(olt_flows), 1)
        self.assertEqual(len(olt_groups), 0)
        self.assertFlowsEqual(onu1_flows.values()[0], mk_flow_stat(
            match_fields=[
                in_port(2),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
                output(1)
            ]
        ))
        self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
            priority=1000,
            match_fields=[
                in_port(1),
                vlan_vid(4096),
                eth_type(0x0800),
                ipv4_dst(0xffffffff),
                ip_proto(17),
                udp_src(68),
                udp_dst(67)
            ],
            actions=[
                output(2147483645)
            ],
            metadata=4294967296
        ))

    @nottest
    def test_igmp_reroute_rule_decomposition(self):
        flow = mk_flow_stat(
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                eth_type(0x0800),
                ip_proto(2)
            ],
            actions=[output(ofp.OFPP_CONTROLLER)],
            priority=1000,
            metadata=4294967296
        )
        device_rules = self.decompose_rules([flow], [])
        onu1_flows, onu1_groups = device_rules['onu1']
        olt_flows, olt_groups = device_rules['olt']
        self.assertEqual(len(onu1_flows), 1)
        self.assertEqual(len(onu1_groups), 0)
        self.assertEqual(len(olt_flows), 1)
        self.assertEqual(len(olt_groups), 0)
        self.assertFlowsEqual(onu1_flows.values()[0], mk_flow_stat(
            match_fields=[
                in_port(2),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
                output(1)
            ]
        ))
        self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
            priority=1000,
            match_fields=[
                in_port(1),
                vlan_vid(4096),
                eth_type(0x0800),
                ip_proto(2)
            ],
            actions=[
                output(2147483645)
            ],
            metadata=4294967296
        ))

    # @nottest
    # def test_wildcarded_igmp_reroute_rule_decomposition(self):
    #     flow = mk_flow_stat(
    #         match_fields=[
    #             eth_type(0x0800),
    #             ip_proto(2)
    #         ],
    #         actions=[output(ofp.OFPP_CONTROLLER)],
    #         priority=2000,
    #         metadata=4294967296,
    #         cookie=140
    #     )
    #     device_rules = self.decompose_rules([flow], [])
    #     onu1_flows, onu1_groups = device_rules['onu1']
    #     olt_flows, olt_groups = device_rules['olt']
    #     self.assertEqual(len(onu1_flows), 1)
    #     self.assertEqual(len(onu1_groups), 0)
    #     self.assertEqual(len(olt_flows), 1)
    #     self.assertEqual(len(olt_groups), 0)
    #     self.assertFlowsEqual(onu1_flows.values()[0], mk_flow_stat(
    #         match_fields=[
    #             in_port(2), vlan_vid(ofp.OFPVID_PRESENT | 0)
    #         ],
    #         actions=[
    #             set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
    #             output(1)
    #         ]
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
    #         priority=2000,
    #         cookie=140,
    #         match_fields=[
    #             in_port(1), vlan_vid(ofp.OFPVID_PRESENT | 0),
    #             eth_type(0x0800), ip_proto(2)
    #         ],
    #         actions=[
    #             push_vlan(0x8100),
    #             set_field(vlan_vid(ofp.OFPVID_PRESENT | 4000)),
    #             output(2)
    #         ],
    #         metadata=4294967296
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[1], mk_flow_stat(
    #         priority=2000,
    #         match_fields=[
    #             in_port(2), vlan_vid(ofp.OFPVID_PRESENT | 4000),
    #             vlan_pcp(0)
    #         ],
    #         actions=[
    #             pop_vlan(), output(1)
    #         ]
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[2], mk_flow_stat(
    #         priority=2000,
    #         cookie=140,
    #         match_fields=[
    #             in_port(1), vlan_vid(ofp.OFPVID_PRESENT | 1),
    #             eth_type(0x0800), ip_proto(2)
    #         ],
    #         actions=[
    #             push_vlan(0x8100),
    #             set_field(vlan_vid(ofp.OFPVID_PRESENT | 4000)),
    #             output(2)
    #         ]
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[3], mk_flow_stat(
    #         priority=2000,
    #         match_fields=[
    #             in_port(2), vlan_vid(ofp.OFPVID_PRESENT | 4000),
    #             vlan_pcp(0)
    #         ],
    #         actions=[
    #             pop_vlan(), output(1)
    #         ]
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[4], mk_flow_stat(
    #         priority=2000,
    #         cookie=140,
    #         match_fields=[
    #             in_port(1), vlan_vid(ofp.OFPVID_PRESENT | 3),
    #             eth_type(0x0800), ip_proto(2)
    #         ],
    #         actions=[
    #             push_vlan(0x8100),
    #             set_field(vlan_vid(ofp.OFPVID_PRESENT | 4000)),
    #             output(2)
    #         ]
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[5], mk_flow_stat(
    #         priority=2000,
    #         match_fields=[
    #             in_port(2), vlan_vid(ofp.OFPVID_PRESENT | 4000),
    #             vlan_pcp(0)
    #         ],
    #         actions=[
    #             pop_vlan(), output(1)
    #         ]
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[6], mk_flow_stat(
    #         priority=2000,
    #         cookie=140,
    #         match_fields=[
    #             in_port(1), vlan_vid(ofp.OFPVID_PRESENT | 4),
    #             eth_type(0x0800), ip_proto(2)
    #         ],
    #         actions=[
    #             push_vlan(0x8100),
    #             set_field(vlan_vid(ofp.OFPVID_PRESENT | 4000)),
    #             output(2)
    #         ]
    #     ))
    #     self.assertFlowsEqual(olt_flows.values()[7], mk_flow_stat(
    #         priority=2000,
    #         match_fields=[
    #             in_port(2), vlan_vid(ofp.OFPVID_PRESENT | 4000),
    #             vlan_pcp(0)
    #         ],
    #         actions=[
    #             pop_vlan(), output(1)
    #         ]
    #     ))

    def test_unicast_upstream_rule_decomposition(self):
        flow1 = mk_flow_stat(
            table_id=0,
            priority=500,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                vlan_pcp(0)
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
            ],
            next_table_id=1
        )
        flow2 = mk_flow_stat(
            table_id=1,
            priority=500,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 101),
                vlan_pcp(0)
            ],
            actions=[
                push_vlan(0x8100),
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 1000)),
                set_field(vlan_pcp(0)),
                output(0)
            ]
        )
        device_rules = self.decompose_rules([flow1, flow2], [])
        onu1_flows, onu1_groups = device_rules['onu1']
        olt_flows, olt_groups = device_rules['olt']
        self.assertEqual(len(onu1_flows), 2)
        self.assertEqual(len(onu1_groups), 0)
        self.assertEqual(len(olt_flows), 1)
        self.assertEqual(len(olt_groups), 0)
        self.assertFlowsEqual(onu1_flows.values()[1], mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(2),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                vlan_pcp(0)
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
                output(1)
            ]
        ))
        self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 101),
                vlan_pcp(0)
            ],
            actions=[
                push_vlan(0x8100),
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 1000)),
                set_field(vlan_pcp(0)),
                output(2)
            ]
        ))

    def test_unicast_upstream_rule_including_meter_band_decomposition(self):
        flow1 = mk_flow_stat(
            table_id=0,
            priority=500,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                vlan_pcp(0)
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
            ],
            next_table_id=1,
        )
        flow2 = mk_flow_stat(
            table_id=1,
            priority=500,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 101),
                vlan_pcp(0)
            ],
            actions=[
                push_vlan(0x8100),
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 1000)),
                set_field(vlan_pcp(0)),
                output(0)
            ],
            meter_id=1
        )
        device_rules = self.decompose_rules([flow1, flow2], [])
        onu1_flows, onu1_groups = device_rules['onu1']
        olt_flows, olt_groups = device_rules['olt']
        self.assertEqual(len(onu1_flows), 2)
        self.assertEqual(len(onu1_groups), 0)
        self.assertEqual(len(olt_flows), 1)
        self.assertEqual(len(olt_groups), 0)
        self.assertFlowsEqual(onu1_flows.values()[1], mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(2),
                vlan_vid(ofp.OFPVID_PRESENT | 0),
                vlan_pcp(0)
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 101)),
                output(1)
            ]
        ))

        check_flow = mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 101),
                vlan_pcp(0)
            ],
            actions=[
                push_vlan(0x8100),
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 1000)),
                set_field(vlan_pcp(0)),
                output(2)
            ],
            meter_id=1
        )

        self.assertFlowsEqual(olt_flows.values()[0], check_flow)


    def test_unicast_downstream_rule_decomposition(self):
        flow1 = mk_flow_stat(
            table_id=0,
            match_fields=[
                in_port(0),
                vlan_pcp(0)
            ],
            actions=[
                pop_vlan(),
            ],
            next_table_id=1,
            meter_id=1,
            metadata=2,
            priority=500
        )
        flow2 = mk_flow_stat(
            table_id=1,
            match_fields=[
                in_port(0),
                vlan_vid(ofp.OFPVID_PRESENT | 101),
                vlan_pcp(0)
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 0)),
                output(1)
            ],
            priority=500,
            meter_id=1,
            metadata=2
        )
        device_rules = self.decompose_rules([flow1, flow2], [])
        onu1_flows, onu1_groups = device_rules['onu1']
        olt_flows, olt_groups = device_rules['olt']
        self.assertEqual(len(onu1_flows), 2)
        self.assertEqual(len(onu1_groups), 0)
        self.assertEqual(len(olt_flows), 1)
        self.assertEqual(len(olt_groups), 0)
        self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(2),
                vlan_pcp(0)
            ],
            actions=[
                pop_vlan(),
                output(1)
            ],
            meter_id=1,
            metadata=2
        ))
        self.assertFlowsEqual(onu1_flows.values()[1], mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(1),
                vlan_vid(ofp.OFPVID_PRESENT | 101),
                vlan_pcp(0)
            ],
            actions=[
                set_field(vlan_vid(ofp.OFPVID_PRESENT | 0)),
                output(2)
            ],
            meter_id=1,
            metadata=2
        ))

    def test_multicast_downstream_rule_decomposition(self):
        flow = mk_flow_stat(
            match_fields=[
                in_port(0),
                vlan_vid(ofp.OFPVID_PRESENT | 170),
                vlan_pcp(0),
                eth_type(0x800),
                ipv4_dst(0xe00a0a0a)
            ],
            actions=[
                group(10)
            ],
            priority=500
        )
        grp = mk_group_stat(
            group_id=10,
            buckets=[
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(1)
                ])
            ]
        )
        device_rules = self.decompose_rules([flow], [grp])
        onu1_flows, onu1_groups = device_rules['onu1']
        olt_flows, olt_groups = device_rules['olt']
        self.assertEqual(len(onu1_flows), 2)
        self.assertEqual(len(onu1_groups), 0)
        self.assertEqual(len(olt_flows), 1)
        self.assertEqual(len(olt_groups), 0)
        self.assertFlowsEqual(olt_flows.values()[0], mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(2),
                vlan_vid(ofp.OFPVID_PRESENT | 170),
                vlan_pcp(0),
                eth_type(0x800),
                ipv4_dst(0xe00a0a0a)
            ],
            actions=[
                pop_vlan(),
                output(1)
            ]
        ))
        self.assertFlowsEqual(onu1_flows.values()[1], mk_flow_stat(
            priority=500,
            match_fields=[
                in_port(1),
                eth_type(0x800),
                ipv4_dst(0xe00a0a0a)
            ],
            actions=[
                output(2)
            ]
        ))


if __name__ == '__main__':
    main()
