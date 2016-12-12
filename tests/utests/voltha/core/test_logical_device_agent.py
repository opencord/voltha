from unittest import main

from mock import Mock

from tests.utests.voltha.core.flow_helpers import FlowHelpers
from voltha.core import logical_device_agent
from voltha.core.flow_decomposer import *
from voltha.core.logical_device_agent import LogicalDeviceAgent
from voltha.protos import third_party
from voltha.protos.device_pb2 import Device, Port
from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import Flows, FlowGroups


class test_logical_device_agent(FlowHelpers):

    def setup_mock_registry(self):
        registry = Mock()
        logical_device_agent.registry = registry

    def setUp(self):
        self.setup_mock_registry()

        self.flows = Flows(items=[])
        self.groups = FlowGroups(items=[])
        self.ld_ports = [
            LogicalPort(
                id='0',
                device_id='olt',
                device_port_no=0,
                root_port=True,
                ofp_port=ofp.ofp_port(
                    port_no=0
                )
            ),
            LogicalPort(
                id='1',
                device_id='onu1',
                device_port_no=0,
                ofp_port=ofp.ofp_port(
                    port_no=1
                )
            ),
            LogicalPort(
                id='2',
                device_id='onu2',
                device_port_no=0,
                ofp_port=ofp.ofp_port(
                    port_no=2
                )
            )
        ]

        self.devices = {
            'olt': Device(id='olt', root=True, parent_id='id'),
            'onu1': Device(id='onu1', parent_id='olt', parent_port_no=1),
            'onu2': Device(id='onu2', parent_id='olt', parent_port_no=1),
        }

        self.ports = {
            'olt': [
                Port(port_no=0, type=Port.ETHERNET_NNI, device_id='olt'),
                Port(port_no=1, type=Port.PON_OLT, device_id='olt',
                     peers=[
                         Port.PeerPort(device_id='onu1', port_no=1),
                         Port.PeerPort(device_id='onu2', port_no=1)
                     ]
                )
            ],
            'onu1': [
                Port(port_no=0, type=Port.ETHERNET_UNI, device_id='onu1'),
                Port(port_no=1, type=Port.PON_ONU, device_id='onu1',
                     peers=[
                         Port.PeerPort(device_id='olt', port_no=1),
                     ]
                )
            ],
            'onu2': [
                Port(port_no=0, type=Port.ETHERNET_UNI, device_id='onu2'),
                Port(port_no=1, type=Port.PON_ONU, device_id='onu2',
                     peers=[
                         Port.PeerPort(device_id='olt', port_no=1),
                     ]
                )
            ],
        }

        self.device_flows = {
            'olt': Flows(),
            'onu1': Flows(),
            'onu2': Flows()
        }

        self.device_groups = {
            'olt': FlowGroups(),
            'onu1': FlowGroups(),
            'onu2': FlowGroups()
        }

        self.ld = LogicalDevice(id='id', root_device_id='olt')

        self.root_proxy = Mock()
        def get_devices(path):
            if path == '':
                return self.devices.values()
            if path.endswith('/ports'):
                return self.ports[path[:-len('/ports')]]
            elif path.find('/') == -1:
                return self.devices[path]
            else:
                raise Exception(
                    'Nothing to yield for path /devices/{}'.format(path))
        def update_devices(path, data):
            if path.endswith('/flows'):
                self.device_flows[path[:-len('/flows')]] = data
            elif path.endswith('/flow_groups'):
                self.device_groups[path[:-len('/flows')]] = data
            else:
                raise NotImplementedError(
                    'not handling path /devices/{}'.format(path))

        self.root_proxy.get = lambda p: \
            get_devices(p[len('/devices/'):]) if p.startswith('/devices') \
                else None
        self.root_proxy.update = lambda p, d: \
            update_devices(p[len('/devices/'):], d) \
                if p.startswith('/devices') \
                else None
        self.ld_proxy = Mock()
        self.ld_proxy.get = lambda p: \
            self.ld_ports if p == '/ports' else (
                self.ld if p == '/' else None
            )

        self.flows_proxy = Mock()
        self.flows_proxy.get = lambda _: self.flows  # always '/' path
        def update_flows(_, flows):  # always '/' path
            self.flows = flows
        self.flows_proxy.update = update_flows

        self.groups_proxy = Mock()
        self.groups_proxy.get = lambda _: self.groups  # always '/' path
        def update_groups(_, groups):  # always '/' path
            self.groups = groups
        self.groups_proxy.update = update_groups

        self.core = Mock()
        self.core.get_proxy = lambda path: \
            self.root_proxy if path == '/' else (
                self.ld_proxy if path.endswith('id') else (
                    self.flows_proxy if path.endswith('flows') else
                    self.groups_proxy
                )
            )

        self.lda = LogicalDeviceAgent(self.core, self.ld)

    def test_init(self):
        pass  # really just tests the setUp method

    # ~~~~~~~~~~~~~~~~~~~ TEST FLOW TABLE MANIPULATION ~~~~~~~~~~~~~~~~~~~~~~~~

    def test_add_flow(self):
        flow_mod = mk_simple_flow_mod(
            match_fields=[],
            actions=[]
        )
        self.lda.update_flow_table(flow_mod)

        expected_flows = Flows(items=[
            flow_stats_entry_from_flow_mod_message(flow_mod)
        ])
        self.assertFlowsEqual(self.flows, expected_flows)

    def test_add_redundant_flows(self):
        flow_mod = mk_simple_flow_mod(
            match_fields=[],
            actions=[]
        )
        self.lda.update_flow_table(flow_mod)
        self.lda.update_flow_table(flow_mod)
        self.lda.update_flow_table(flow_mod)
        self.lda.update_flow_table(flow_mod)

        expected_flows = Flows(items=[
            flow_stats_entry_from_flow_mod_message(flow_mod)
        ])
        self.assertFlowsEqual(self.flows, expected_flows)

    def test_add_different_flows(self):
        flow_mod1 = mk_simple_flow_mod(
            match_fields=[
                in_port(1)
            ],
            actions=[]
        )
        flow_mod2 = mk_simple_flow_mod(
            match_fields=[
                in_port(2)
            ],
            actions=[]
        )
        self.lda.update_flow_table(flow_mod1)
        self.lda.update_flow_table(flow_mod2)

        expected_flows = Flows(items=[
            flow_stats_entry_from_flow_mod_message(flow_mod1),
            flow_stats_entry_from_flow_mod_message(flow_mod2)
        ])
        self.assertFlowsEqual(self.flows, expected_flows)

    def test_delete_all_flows(self):
        for i in range(5):
            flow_mod = mk_simple_flow_mod(
                match_fields=[in_port(i)],
                actions=[output(i + 1)]
            )
            self.lda.update_flow_table(flow_mod)
        self.assertEqual(len(self.flows.items), 5)

        self.lda.update_flow_table(mk_simple_flow_mod(
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match_fields=[],
            actions=[]
        ))
        self.assertEqual(len(self.flows.items), 0)

    def test_delete_specific_flows(self):
        for i in range(5):
            flow_mod = mk_simple_flow_mod(
                match_fields=[in_port(i)],
                actions=[output(i + 1)]
            )
            self.lda.update_flow_table(flow_mod)
        self.assertEqual(len(self.flows.items), 5)

        self.lda.update_flow_table(mk_simple_flow_mod(
            command=ofp.OFPFC_DELETE_STRICT,
            match_fields=[in_port(2)],
            actions=[]
        ))
        self.assertEqual(len(self.flows.items), 4)

    # ~~~~~~~~~~~~~~~~~~~ TEST GROUP TABLE MANIPULATION ~~~~~~~~~~~~~~~~~~~~~~~

    def test_add_group(self):
        group_mod = mk_multicast_group_mod(
            group_id=2,
            buckets=[
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(1)
                ]),
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(2)
                ]),
            ]
        )
        self.lda.update_group_table(group_mod)

        expected_groups = FlowGroups(items=[
            group_entry_from_group_mod(group_mod)
        ])
        self.assertEqual(self.groups, expected_groups)

    def test_add_redundant_groups(self):
        group_mod = mk_multicast_group_mod(
            group_id=2,
            buckets=[
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(1)
                ]),
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(2)
                ]),
            ]
        )
        self.lda.update_group_table(group_mod)
        self.lda.update_group_table(group_mod)
        self.lda.update_group_table(group_mod)
        self.lda.update_group_table(group_mod)
        self.lda.update_group_table(group_mod)

        expected_groups = FlowGroups(items=[
            group_entry_from_group_mod(group_mod)
        ])
        self.assertEqual(self.groups, expected_groups)

    def test_modify_group(self):
        group_mod = mk_multicast_group_mod(
            group_id=2,
            buckets=[
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(1)
                ]),
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(2)
                ]),
            ]
        )
        self.lda.update_group_table(group_mod)

        group_mod = mk_multicast_group_mod(
            command=ofp.OFPGC_MODIFY,
            group_id=2,
            buckets=[
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(i)
                ]) for i in range(1, 4)
            ]
        )
        self.lda.update_group_table(group_mod)

        self.assertEqual(len(self.groups.items), 1)
        self.assertEqual(len(self.groups.items[0].desc.buckets), 3)

    def test_delete_all_groups(self):
        for i in range(10):
            group_mod = mk_multicast_group_mod(
                group_id=i,
                buckets=[
                    ofp.ofp_bucket(actions=[
                        pop_vlan(),
                        output(i)
                    ]) for j in range(1, 4)
                ]
            )
            self.lda.update_group_table(group_mod)
        self.assertEqual(len(self.groups.items), 10)

        # now delete all
        self.lda.update_group_table(mk_multicast_group_mod(
            command=ofp.OFPGC_DELETE,
            group_id=ofp.OFPG_ALL,
            buckets=[]
        ))
        self.assertEqual(len(self.groups.items), 0)

    def test_delete_specific_group(self):
        for i in range(10):
            group_mod = mk_multicast_group_mod(
                group_id=i,
                buckets=[
                    ofp.ofp_bucket(actions=[
                        pop_vlan(),
                        output(i)
                    ]) for j in range(1, 4)
                ]
            )
            self.lda.update_group_table(group_mod)
        self.assertEqual(len(self.groups.items), 10)

        # now delete all
        self.lda.update_group_table(mk_multicast_group_mod(
            command=ofp.OFPGC_DELETE,
            group_id=3,
            buckets=[]
        ))
        self.assertEqual(len(self.groups.items), 9)

    # ~~~~~~~~~~~~~~~~~~~~ DEFAULT RULES AND ROUTES ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def test_default_rules(self):
        rules = self.lda.get_all_default_rules()
        # we assume one default flow and no default group for each of 3 devs
        self.assertEqual(len(rules['olt'][0]), 1)
        self.assertEqual(len(rules['olt'][1]), 0)
        self.assertEqual(len(rules['onu1'][0]), 1)
        self.assertEqual(len(rules['onu1'][1]), 0)
        self.assertEqual(len(rules['onu2'][0]), 1)
        self.assertEqual(len(rules['onu2'][1]), 0)

    def test_routes(self):
        self.lda.get_all_default_rules()  # this will prepare the _routes
        routes = self.lda._routes
        self.assertEqual(len(routes), 4)
        self.assertEqual(set(routes.keys()),
                         set([(0, 1), (0, 2), (1, 0), (2, 0)]))

        # verify all routes
        route = routes[(0, 1)]
        self.assertEqual(len(route), 2)
        self.assertEqual(route[0].device, self.devices['olt'])
        self.assertEqual(route[0].ingress_port, self.ports['olt'][0])
        self.assertEqual(route[0].egress_port, self.ports['olt'][1])
        self.assertEqual(route[1].device, self.devices['onu1'])
        self.assertEqual(route[1].ingress_port, self.ports['onu1'][1])
        self.assertEqual(route[1].egress_port, self.ports['onu1'][0])

        route = routes[(0, 2)]
        self.assertEqual(len(route), 2)
        self.assertEqual(route[0].device, self.devices['olt'])
        self.assertEqual(route[0].ingress_port, self.ports['olt'][0])
        self.assertEqual(route[0].egress_port, self.ports['olt'][1])
        self.assertEqual(route[1].device, self.devices['onu2'])
        self.assertEqual(route[1].ingress_port, self.ports['onu2'][1])
        self.assertEqual(route[1].egress_port, self.ports['onu2'][0])

        route = routes[(1, 0)]
        self.assertEqual(len(route), 2)
        self.assertEqual(route[0].device, self.devices['onu1'])
        self.assertEqual(route[0].ingress_port, self.ports['onu1'][0])
        self.assertEqual(route[0].egress_port, self.ports['onu1'][1])
        self.assertEqual(route[1].device, self.devices['olt'])
        self.assertEqual(route[1].ingress_port, self.ports['olt'][1])
        self.assertEqual(route[1].egress_port, self.ports['olt'][0])

        route = routes[(2, 0)]
        self.assertEqual(len(route), 2)
        self.assertEqual(route[0].device, self.devices['onu2'])
        self.assertEqual(route[0].ingress_port, self.ports['onu2'][0])
        self.assertEqual(route[0].egress_port, self.ports['onu2'][1])
        self.assertEqual(route[1].device, self.devices['olt'])
        self.assertEqual(route[1].ingress_port, self.ports['olt'][1])
        self.assertEqual(route[1].egress_port, self.ports['olt'][0])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~ FLOW DECOMP TESTS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def test_eapol_flow_decomp_case(self):
        self.lda.update_flow_table(mk_simple_flow_mod(
            priority=1000,
            match_fields=[in_port(1), eth_type(0x888e)],
            actions=[output(ofp.OFPP_CONTROLLER)]
        ))
        self.lda._flow_table_updated(self.flows)
        self.assertEqual(len(self.device_flows['olt'].items), 2)
        self.assertEqual(len(self.device_flows['onu1'].items), 1)
        self.assertEqual(len(self.device_flows['onu2'].items), 1)
        self.assertEqual(len(self.device_groups['olt'].items), 0)
        self.assertEqual(len(self.device_groups['onu1'].items), 0)
        self.assertEqual(len(self.device_groups['onu2'].items), 0)

        # the only non-default flow (check without the id field)
        self.assertFlowsEqual(self.device_flows['olt'].items[1], mk_flow_stat(
                priority=1000,
                match_fields=[in_port(1), eth_type(0x888e)],
                actions=[
                    push_vlan(0x8100),
                    set_field(vlan_vid(4096 + 4000)),
                    output(0)
                ]
            ))

    def test_wildcarded_igmp_rule(self):
        self.lda.update_flow_table(mk_simple_flow_mod(
            priority=1000,
            match_fields=[eth_type(0x800), ip_proto(2)],
            actions=[output(ofp.OFPP_CONTROLLER)]
        ))
        self.lda._flow_table_updated(self.flows)
        self.assertEqual(len(self.device_flows['olt'].items), 2)
        self.assertEqual(len(self.device_flows['onu1'].items), 1)
        self.assertEqual(len(self.device_flows['onu2'].items), 1)
        self.assertEqual(len(self.device_groups['olt'].items), 0)
        self.assertEqual(len(self.device_groups['onu1'].items), 0)
        self.assertEqual(len(self.device_groups['onu2'].items), 0)

        # the only non-default flow
        self.assertFlowsEqual(self.device_flows['olt'].items[1], mk_flow_stat(
            priority=1000,
            match_fields=[in_port(1), eth_type(0x800), ip_proto(2)],
            actions=[
                push_vlan(0x8100),
                set_field(vlan_vid(4096 + 4000)),
                output(0)
            ]
        ))

    def test_multicast_group_with_one_subscriber(self):
        self.lda.update_group_table(mk_multicast_group_mod(
            group_id=2,
            buckets=[
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(1)
                ]),
            ]
        ))
        self.lda.update_flow_table(mk_simple_flow_mod(
            priority=1000,
            match_fields=[
                in_port(0),
                eth_type(0x800),
                vlan_vid(4096 + 140),
                ipv4_dst(0xe60a0a0a)
            ],
            actions=[group(2)]
        ))
        self.lda._flow_table_updated(self.flows)
        self.assertEqual(len(self.device_flows['olt'].items), 2)
        self.assertEqual(len(self.device_flows['onu1'].items), 2)
        self.assertEqual(len(self.device_flows['onu2'].items), 1)
        self.assertEqual(len(self.device_groups['olt'].items), 0)
        self.assertEqual(len(self.device_groups['onu1'].items), 0)
        self.assertEqual(len(self.device_groups['onu2'].items), 0)

        self.assertFlowsEqual(self.device_flows['olt'].items[1], mk_flow_stat(
            priority=1000,
            match_fields=[in_port(0), vlan_vid(4096 + 140)],
            actions=[
                pop_vlan(),
                output(1)
            ]
        ))
        self.assertFlowsEqual(self.device_flows['onu1'].items[1], mk_flow_stat(
            priority=1000,
            match_fields=[in_port(1), eth_type(0x800), ipv4_dst(0xe60a0a0a)],
            actions=[
                output(0)
            ]
        ))

    def test_multicast_group_with_two_subscribers(self):
        self.lda.update_group_table(mk_multicast_group_mod(
            group_id=2,
            buckets=[
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(1)
                ]),
                ofp.ofp_bucket(actions=[
                    pop_vlan(),
                    output(2)
                ]),
            ]
        ))
        self.lda.update_flow_table(mk_simple_flow_mod(
            priority=1000,
            match_fields=[
                in_port(0),
                eth_type(0x800),
                vlan_vid(4096 + 140),
                ipv4_dst(0xe60a0a0a)
            ],
            actions=[group(2)]
        ))
        self.lda._flow_table_updated(self.flows)
        self.assertEqual(len(self.device_flows['olt'].items), 2)
        self.assertEqual(len(self.device_flows['onu1'].items), 2)
        self.assertEqual(len(self.device_flows['onu2'].items), 2)
        self.assertEqual(len(self.device_groups['olt'].items), 0)
        self.assertEqual(len(self.device_groups['onu1'].items), 0)
        self.assertEqual(len(self.device_groups['onu2'].items), 0)

        self.assertFlowsEqual(self.device_flows['olt'].items[1], mk_flow_stat(
            priority=1000,
            match_fields=[in_port(0), vlan_vid(4096 + 140)],
            actions=[
                pop_vlan(),
                output(1)
            ]
        ))
        self.assertFlowsEqual(self.device_flows['onu1'].items[1], mk_flow_stat(
            priority=1000,
            match_fields=[in_port(1), eth_type(0x800), ipv4_dst(0xe60a0a0a)],
            actions=[
                output(0)
            ]
        ))
        self.assertFlowsEqual(self.device_flows['onu2'].items[1], mk_flow_stat(
            priority=1000,
            match_fields=[in_port(1), eth_type(0x800), ipv4_dst(0xe60a0a0a)],
            actions=[
                output(0)
            ]
        ))

    def test_multicast_group_with_no_subscribers(self):
        self.lda.update_group_table(mk_multicast_group_mod(
            group_id=2,
            buckets=[]  # No subscribers
        ))
        self.lda.update_flow_table(mk_simple_flow_mod(
            priority=1000,
            match_fields=[
                in_port(0),
                eth_type(0x800),
                vlan_vid(4096 + 140),
                ipv4_dst(0xe60a0a0a)
            ],
            actions=[group(2)]
        ))
        self.lda._flow_table_updated(self.flows)
        self.assertEqual(len(self.device_flows['olt'].items), 2)
        self.assertEqual(len(self.device_flows['onu1'].items), 1)
        self.assertEqual(len(self.device_flows['onu2'].items), 1)
        self.assertEqual(len(self.device_groups['olt'].items), 0)
        self.assertEqual(len(self.device_groups['onu1'].items), 0)
        self.assertEqual(len(self.device_groups['onu2'].items), 0)

        self.assertFlowsEqual(self.device_flows['olt'].items[1], mk_flow_stat(
            priority=1000,
            match_fields=[in_port(0), vlan_vid(4096 + 140)],
            actions=[
                pop_vlan(),
                output(1)
            ]
        ))



if __name__ == '__main__':
    main()
