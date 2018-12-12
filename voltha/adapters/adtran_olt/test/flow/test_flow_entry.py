import pytest
from voltha.adapters.adtran_olt.adtran_device_handler import DEFAULT_MULTICAST_VLAN, DEFAULT_UTILITY_VLAN
from voltha.adapters.adtran_olt.adtran_olt_handler import *
from voltha.adapters.adtran_olt.flow.flow_entry import *
from voltha.adapters.adtran_olt.flow.flow_tables import DownstreamFlows, DeviceFlows
from voltha.core.flow_decomposer import mk_flow_stat
import mock


@pytest.yield_fixture()
def flow_handler():
    handler = mock.MagicMock(spec=AdtranOltHandler)
    handler.device_id = 9876543210
    handler.multicast_vlans = [DEFAULT_MULTICAST_VLAN]
    handler.northbound_ports = {1}
    handler.southbound_ports = {}
    handler.utility_vlan = 0
    handler.downstream_flows = DownstreamFlows()
    handler.upstream_flows = DeviceFlows()
    handler.is_nni_port = lambda n: n in handler.northbound_ports
    handler.is_pon_port = lambda n: not handler.is_nni_port(n)
    handler.get_port_name = lambda n: "mock-{} 0/{}".format(
        "uni" if n not in handler.northbound_ports else "nni",
        n)
    yield handler


def test_create(flow_handler, caplog):
    downstream = mk_flow_stat(priority=40000,
                              match_fields=[
                                  in_port(1),
                                  vlan_vid(ofp.OFPVID_PRESENT | 4),
                                  vlan_pcp(7),
                                  metadata(666)
                              ],
                              actions=[
                                  pop_vlan(),
                                  output(5)
                              ])
    ds_entry, ds_evc = FlowEntry.create(downstream, flow_handler)
    assert ds_entry is not None, "Entry wasn't created"
    assert ds_evc is None, "EVC not labeled"

    upstream = mk_flow_stat(priority=40000,
                            match_fields=[
                                in_port(5),
                                vlan_vid(ofp.OFPVID_PRESENT | 666),
                                vlan_pcp(7)
                            ],
                            actions=[
                                push_vlan(0x8100),
                                set_field(vlan_vid(ofp.OFPVID_PRESENT | 4)),
                                set_field(vlan_pcp(7)),
                                output(1)
                            ])
    us_entry, us_evc = FlowEntry.create(upstream, flow_handler)
    assert us_entry is not None, "Entry wasn't created"
    assert us_evc is not None, "EVC not labeled"
    us_evc._do_install()
    assert us_evc._installed, "EVC wasn't installed"
    edit_configs = flow_handler.netconf_client.edit_config.call_args_list
    assert len(edit_configs) == 1, "EVC-MAP edit config"
    for call in edit_configs:
        log.info("Netconf Calls: {}".format(call))
