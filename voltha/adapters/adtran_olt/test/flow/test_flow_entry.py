# Copyright 2017-present Adtran, Inc.
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

import pytest
from collections import namedtuple
from voltha.adapters.adtran_olt.adtran_device_handler import DEFAULT_MULTICAST_VLAN
from voltha.adapters.adtran_olt.adtran_olt_handler import *
from voltha.adapters.adtran_olt.flow.flow_entry import *
from voltha.adapters.adtran_olt.flow.flow_tables import DownstreamFlows, DeviceFlows
from voltha.core.flow_decomposer import mk_flow_stat
import mock


@pytest.fixture()
def downstream():
    yield mk_flow_stat(
        priority=40000,
        match_fields=[
            in_port(1),
            vlan_vid(ofp.OFPVID_PRESENT | 4),
            vlan_pcp(7),
            metadata(666)
        ],
        actions=[
            pop_vlan(),
            output(5)
        ]
    )


@pytest.fixture()
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


@pytest.mark.parametrize('decoder', [
    '_decode',
    '_decode_flow_direction',
    '_decode_traffic_treatment',
    '_decode_traffic_selector'
])
def test_create_fails_decode(flow_handler, decoder, downstream):
    with mock.patch(
            'voltha.adapters.adtran_olt.flow.flow_entry.FlowEntry.%s' % decoder,
            return_value=False) as mock_decode:
        assert (None, None) == FlowEntry.create(downstream, flow_handler)
    mock_decode.assert_called_once()


def test_empty_flow_signature(flow_handler):
    Flow = namedtuple('Flow', 'id')
    flow = FlowEntry(Flow(1), flow_handler)
    with pytest.raises(AssertionError):
        _ = flow.signature
    flow.in_port, flow.output = 1, 10
    assert flow.signature is None


@pytest.mark.parametrize('direction, expected', [
    ('downstream', '1.*.2048.*'),
    ('upstream', '1.10.2048.2')
])
def test_flow_signature(flow_handler, direction, expected):
    Flow = namedtuple('Flow', 'id')
    flow = FlowEntry(Flow(1), flow_handler)
    flow.in_port, flow.output = 1, 10
    flow.vlan_id, flow.inner_vid = 2048, 2
    if direction == 'downstream':
        flow._flow_direction = FlowEntry.FlowDirection.DOWNSTREAM
    else:
        flow._flow_direction = FlowEntry.FlowDirection.UPSTREAM
    assert expected == flow.signature
    assert expected == flow.signature


@pytest.mark.parametrize('direction', [
    'downstream', 'upstream', 'multicast'
])
def test_create_failures(flow_handler, direction):
    def mock_decode(self, _):
        expected['flow_entry'] = self
        self.in_port, self.output = 1, 2
        self.vlan_id, self.inner_vid = 3, 4
        if direction == 'upstream':
            self._flow_direction = FlowEntry.FlowDirection.UPSTREAM
            flow_handler.upstream_flows.add(self)
        elif direction == 'downstream':
            self._flow_direction = FlowEntry.FlowDirection.DOWNSTREAM
            flow_handler.downstream_flows.add(self.signature).flows.add(self)
        elif direction == 'multicast':
            self._flow_direction = FlowEntry.FlowDirection.DOWNSTREAM
            self._is_multicast = True
            sig_table = flow_handler.downstream_flows.add(self.signature)
            expected['evc'] = sig_table.evc = EVC(self)
        return True

    expected = {'flow_entry': None, 'evc': None}
    Flow = namedtuple('Flow', 'id')
    with mock.patch(
            'voltha.adapters.adtran_olt.flow.flow_entry.FlowEntry._decode',
            mock_decode):
        flow_entry, evc = FlowEntry.create(Flow(5), flow_handler)
    assert flow_entry is expected['flow_entry']
    assert evc is expected['evc']


def test_create(flow_handler, caplog, downstream):
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
