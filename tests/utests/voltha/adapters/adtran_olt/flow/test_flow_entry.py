# from voltha.adapters.adtran_olt.adtran_device_handler import DEFAULT_MULTICAST_VLAN, DEFAULT_UTILITY_VLAN
# from voltha.adapters.adtran_olt.adtran_olt_handler import *
# from voltha.adapters.adtran_olt.flow.flow_entry import *
# from voltha.core.flow_decomposer import mk_flow_stat
# import mock
#
#
# class TestFlowEntry(object):
#     def setUp(self):
#         def get_pon(pon_id):
#             p = mock.MagicMock()
#             p.gem_ids = lambda a, b, c, d: {
#                 100: ([2048], 1234)
#             }
#             p.pon_id = pon_id
#             return p
#
#         self.handler = mock.MagicMock(spec=AdtranOltHandler)
#         self.handler.device_id = 9876543210
#         self.handler.multicast_vlans = [DEFAULT_MULTICAST_VLAN]
#         self.handler.multicast_vlans = DEFAULT_UTILITY_VLAN
#         self.handler.northbound_ports = {1: None}
#         self.handler.exception_gems = False
#         self.handler.is_nni_port = lambda n: n in self.handler.northbound_ports
#         self.handler.is_pon_port = lambda n: not self.handler.is_nni_port(n)
#         self.handler.get_southbound_port = get_pon
#         self.handler.get_port_name = lambda n: "mock-{} 0/{}".format(
#             "uni" if n not in self.handler.northbound_ports else "nni",
#             n)
#
#     def test_create(self):
#         downstream = mk_flow_stat(priority=40000,
#                                   match_fields=[
#                                       in_port(1),
#                                       vlan_vid(ofp.OFPVID_PRESENT | 4),
#                                       vlan_pcp(7),
#                                       metadata(666)
#                                   ],
#                                   actions=[
#                                       pop_vlan(),
#                                       output(5)
#                                   ])
#         ds_entry, ds_evc = FlowEntry.create(downstream, self.handler)
#         assert ds_entry is not None, "Entry already exists"
#         assert ds_evc is None, "EVC not labeled"
#
#         upstream = mk_flow_stat(priority=40000,
#                                 match_fields=[
#                                     in_port(5),
#                                     vlan_vid(ofp.OFPVID_PRESENT | 666),
#                                     vlan_pcp(7)
#                                 ],
#                                 actions=[
#                                     push_vlan(0x8100),
#                                     set_field(vlan_vid(ofp.OFPVID_PRESENT | 4)),
#                                     set_field(vlan_pcp(7)),
#                                     output(1)
#                                 ])
#         us_entry, us_evc = FlowEntry.create(upstream, self.handler)
#         assert us_entry is not None, "Entry doesn't exist"
#         assert us_evc is not None, "EVC not labeled"
#         us_evc._do_install()
#         assert us_evc._installed, "EVC wasn't installed"
#         edit_configs = self.handler.netconf_client.edit_config.call_args_list
#         assert len(edit_configs) == 3, "EVC, EVC-MAP, and ACL edit config"
#         for call in edit_configs:
#             log.info("Netconf Calls: {}".format(call))
