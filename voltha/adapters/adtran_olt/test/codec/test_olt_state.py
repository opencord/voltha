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

from resources.sample_json import olt_state_json
from voltha.adapters.adtran_olt.codec.olt_state import OltState

import pytest


@pytest.fixture()
def olt_state_object():
    return OltState(olt_state_json)


@pytest.fixture()
def pon_object():
    return OltState.Pon(olt_state_json["pon"][0])


@pytest.fixture()
def onu_object():
    return OltState.Pon.Onu(olt_state_json["pon"][0]["onu"][0])


@pytest.fixture()
def gem_object():
    return OltState.Pon.Gem(olt_state_json["pon"][0]["gem"][0])


def test_olt_to_string(olt_state_object):
    assert str(olt_state_object) == "OltState: ngpon2_agent-13.0.32-1.657.815547"


def test_olt_state_software_version(olt_state_object):
    assert olt_state_object.software_version == "ngpon2_agent-13.0.32-1.657.815547"


def test_olt_state_pons(olt_state_object):
    assert str(olt_state_object.pons[0]) == "OltState.Pon: pon-id: 0"


def test_olt_state_len(olt_state_object):
    assert len(olt_state_object) == 16


def test_olt_state_get_item(olt_state_object):
    assert str(olt_state_object[1]) == "OltState.Pon: pon-id: 1"


def test_olt_state_get_item_not_int(olt_state_object):
    with pytest.raises(TypeError):
        olt_state_object["something"]


def test_olt_state_get_item_out_of_bounds(olt_state_object):
    with pytest.raises(KeyError):
        olt_state_object[16]


def test_olt_state_iter(olt_state_object):
    with pytest.raises(NotImplementedError):
        for _ in olt_state_object:
            pass


def test_olt_state_contains(olt_state_object):
    assert 5 in olt_state_object


def test_olt_state_contains_does_not_contain(olt_state_object):
    assert not 16 in olt_state_object


def test_olt_state_contains_not_int(olt_state_object):
    with pytest.raises(TypeError):
        "something" in olt_state_object


def test_pon_to_string(pon_object):
    assert str(pon_object) == "OltState.Pon: pon-id: 0"


def test_pon_properties(pon_object):
    assert pon_object.pon_id == 0
    assert pon_object.downstream_wavelength == 0
    assert pon_object.upstream_wavelength == 0
    assert pon_object.downstream_channel_id == 15
    assert pon_object.rx_packets == 1625773517
    assert pon_object.tx_packets == 761098346
    assert pon_object.rx_bytes == 145149613233620
    assert pon_object.tx_bytes == 141303797318481
    assert pon_object.tx_bip_errors == 0
    assert pon_object.ont_los == []
    assert pon_object.discovered_onu == frozenset()
    assert pon_object.wm_tuned_out_onus == "AAAAAAAAAAAAAAAAAAAAAA=="


def test_pon_gems(pon_object):
    assert str(pon_object.gems[2176]) == "OltState.Pon.Gem: onu-id: 0, gem-id: 2176"


def test_pon_gems_existing(pon_object):
    pon_object._gems = "existing"
    assert pon_object.gems == "existing"


def test_pon_onus(pon_object):
    assert str(pon_object.onus[0]) == "OltState.Pon.Onu: onu-id: 0"


def test_pon_onus_existing(pon_object):
    pon_object._onus = "existing"
    assert pon_object.onus == "existing"


def test_onu_properties(onu_object):
    assert onu_object.onu_id == 0
    assert onu_object.oper_status == "unknown"
    assert onu_object.reported_password == "redacted"
    assert onu_object.rssi == -207
    assert onu_object.equalization_delay == 620952
    assert onu_object.fiber_length == 47


def test_gem_properties(gem_object):
    assert gem_object.onu_id == 0
    assert gem_object.alloc_id == 1024
    assert gem_object.gem_id == 2176
    assert gem_object.tx_packets == 65405
    assert gem_object.tx_bytes == 5420931
    assert gem_object.rx_packets == 13859
    assert gem_object.rx_bytes == 3242784




