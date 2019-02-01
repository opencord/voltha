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

from voltha.adapters.adtran_olt.codec.olt_config import OltConfig

import pytest

real_json = [{
    "pon-id": 0,
    "enabled": True,
    "downstream-fec-enable": True,
    "upstream-fec-enable": True,
    "onus": {
        "onu": [{
            "onu-id": 0,
            "serial-number": "QURUThYmBZk=",
            "enable": True,
            "protection-requested": False,
            "t-conts": {
                "t-cont": [{
                    "alloc-id": 1024,
                    "traffic-descriptor": {
                        "fixed-bandwidth": "0",
                        "assured-bandwidth": "0",
                        "maximum-bandwidth": "8500000000"
                    },
                    # I don't actually see this in the model but I am passing in the expected values.
                    "best-effort": {
                        "bandwidth": 12345,
                        "priority": 0,
                        "weight": 20
                    }
                }]
            },
            "gem-ports": {
                "gem-port": [{
                    "port-id": 2176,
                    "encryption": False,
                    "alloc-id": 1024
                }, {
                    "port-id": 2308,
                    "encryption": False,
                    "alloc-id": 1024
                }, {
                    "port-id": 2309,
                    "encryption": False,
                    "alloc-id": 1024
                }]
            }
        }]
}
}, {
    "pon-id": 1,
    "enabled": False
}, {
    "pon-id": 2,
    "enabled": False
}, {
    "pon-id": 3,
    "enabled": False
}, {
    "pon-id": 4,
    "enabled": False
}, {
    "pon-id": 5,
    "enabled": False
}, {
    "pon-id": 6,
    "enabled": False
}, {
    "pon-id": 7,
    "enabled": False
}, {
    "pon-id": 8,
    "enabled": False
}, {
    "pon-id": 9,
    "enabled": False
}, {
    "pon-id": 10,
    "enabled": False
}, {
    "pon-id": 11,
    "enabled": False
}, {
    "pon-id": 12,
    "enabled": False
}, {
    "pon-id": 13,
    "enabled": False
}, {
    "pon-id": 14,
    "enabled": False
}, {
    "pon-id": 15,
    "enabled": False
}]

tcont_config = real_json[0]["onus"]["onu"][0]["t-conts"]["t-cont"][0]


@pytest.fixture()
def traffic_desc_object():
    traffic_desc_config = tcont_config["traffic-descriptor"]
    return OltConfig.Pon.Onu.TCont.TrafficDescriptor(traffic_desc_config)


@pytest.fixture()
def bad_traffic_desc_object():
    bad_traffic_desc = {
        "fixed-bandwidth": "not-an-int",
        "assured-bandwidth": SyntaxError(),
        "maximum-bandwidth": []
    }
    return OltConfig.Pon.Onu.TCont.TrafficDescriptor(bad_traffic_desc)


@pytest.fixture()
def best_effort_object():
    best_effort_config = tcont_config["best-effort"]
    return OltConfig.Pon.Onu.TCont.BestEffort(best_effort_config)


@pytest.fixture()
def gemport_object():
    gem_port_config = real_json[0]["onus"]["onu"][0]["gem-ports"]["gem-port"][0]
    return OltConfig.Pon.Onu.GemPort(gem_port_config)


@pytest.fixture()
def onu_object():
    onu_config = real_json[0]["onus"]["onu"][0]
    return OltConfig.Pon.Onu(onu_config)


@pytest.fixture()
def pon_object():
    pon_config = real_json[0]
    return OltConfig.Pon(pon_config)


@pytest.fixture()
def olt_object():
    olt_config = {"pon": real_json}
    return OltConfig(olt_config)


def test_tcont_to_string():
    test_config = OltConfig.Pon.Onu.TCont(tcont_config)
    assert str(test_config) == "OltConfig.Pon.Onu.TCont: alloc-id: 1024"


def test_tcont_decode():
    test_config = real_json[0]["onus"]["onu"][0]["t-conts"]
    decoded_output = OltConfig.Pon.Onu.TCont.decode(test_config)
    assert tcont_config == decoded_output[1024]._packet


def test_tcont_decode_no_tcont():
    decoded_output = OltConfig.Pon.Onu.TCont.decode(None)
    assert decoded_output == {}


def test_tcont_traffic_descriptor():
    test_config = real_json[0]["onus"]["onu"][0]["t-conts"]
    decoded_output = OltConfig.Pon.Onu.TCont.decode(test_config)[1024].traffic_descriptor
    assert "OltConfig.Pon.Onu.TCont.TrafficDescriptor: 0/0/8500000000" == str(decoded_output)


def test_tcont_traffic_descriptor_exists():
    test_config = real_json[0]["onus"]["onu"][0]["t-conts"]
    tcont_config = OltConfig.Pon.Onu.TCont.decode(test_config)[1024]
    tcont_config._traffic_descriptor = "exists"
    assert tcont_config.traffic_descriptor == "exists"


def test_traffic_descriptor_fixed_bw(traffic_desc_object):
    assert traffic_desc_object.fixed_bandwidth == 0


def test_traffic_descriptor_fixed_bw_exception(bad_traffic_desc_object):
    assert bad_traffic_desc_object.fixed_bandwidth == 0


def test_traffic_descriptor_assured_bw(traffic_desc_object):
    assert traffic_desc_object.assured_bandwidth == 0


def test_traffic_descriptor_assured_bw_exception(bad_traffic_desc_object):
    assert bad_traffic_desc_object.assured_bandwidth == 0


def test_traffic_descriptor_max_bw(traffic_desc_object):
    assert traffic_desc_object.maximum_bandwidth == 8500000000


def test_traffic_descriptor_max_bw_exception(bad_traffic_desc_object):
    assert bad_traffic_desc_object.maximum_bandwidth == 0


def test_traffic_descriptor_additional_bw_eligibility(traffic_desc_object):
    assert traffic_desc_object.additional_bandwidth_eligibility == "none"


def test_tcont_best_effort():
    test_config = real_json[0]["onus"]["onu"][0]["t-conts"]
    decoded_output = OltConfig.Pon.Onu.TCont.decode(test_config)[1024].best_effort
    assert "OltConfig.Pon.Onu.TCont.BestEffort: 12345" == str(decoded_output)


def test_tcont_best_effort_exists():
    test_config = real_json[0]["onus"]["onu"][0]["t-conts"]
    tcont_config = OltConfig.Pon.Onu.TCont.decode(test_config)[1024]
    tcont_config._best_effort = "exists"
    assert tcont_config.best_effort == "exists"


def test_best_effort_bandwidth(best_effort_object):
    assert best_effort_object.bandwidth == 12345


def test_best_effort_priority(best_effort_object):
    assert best_effort_object.priority == 0


def test_best_effort_weight(best_effort_object):
    assert best_effort_object.weight == 20


def test_gem_port_decode_no_gemport(gemport_object):
    assert gemport_object.decode(None) == {}


def test_gem_port_to_string(gemport_object):
    assert str(gemport_object) == "OltConfig.Pon.Onu.GemPort: port-id: 2176/1024"


def test_gem_port_port_id(gemport_object):
    assert gemport_object.port_id == 2176


def test_gem_port_gem_id(gemport_object):
    assert gemport_object.port_id == 2176


def test_gem_port_alloc_id(gemport_object):
    assert gemport_object.alloc_id == 1024


def test_gem_port_omci_transport(gemport_object):
    assert not gemport_object.omci_transport


def test_gem_port_encryption(gemport_object):
    assert not gemport_object.encryption


def test_onu_to_string(onu_object):
    assert str(onu_object) == "OltConfig.Pon.Onu: onu-id: 0"


def test_onu_onu_id(onu_object):
    assert onu_object.onu_id == 0


def test_onu_serial_number_64(onu_object):
    assert onu_object.serial_number_64 == "QURUThYmBZk="


def test_onu_password(onu_object):
    assert onu_object.password == "0"


def test_onu_enable(onu_object):
    assert onu_object.enable


def test_onu_gem_ports(onu_object):
    assert str(onu_object.gem_ports[2176]) == "OltConfig.Pon.Onu.GemPort: port-id: 2176/1024"


def test_onu_tconts(onu_object):
    assert str(onu_object.tconts[1024]) == "OltConfig.Pon.Onu.TCont: alloc-id: 1024"


def test_onu_gem_ports_dict(onu_object):
    assert str(onu_object.gem_ports_dict[2176]) == "OltConfig.Pon.Onu.GemPort: port-id: 2176/1024"


def test_onu_gem_ports_dict_existing(onu_object):
    onu_object._gem_ports_dict = "existing"
    assert onu_object.gem_ports_dict == "existing"


def test_onu_tconts_dict(onu_object):
    assert str(onu_object.tconts_dict[1024]) == "OltConfig.Pon.Onu.TCont: alloc-id: 1024"


def test_onu_tconts_dict_existing(onu_object):
    onu_object._tconts_dict = "existing"
    assert onu_object.tconts_dict == "existing"


def test_onu_decode_onus():
    assert str(OltConfig.Pon.Onu.decode(real_json[0]["onus"])[0]) == "OltConfig.Pon.Onu: onu-id: 0"


def test_onu_decode_onus_no_onus():
    assert OltConfig.Pon.Onu.decode(None) == {}


def test_onu_decode_onu_list():
    assert str(OltConfig.Pon.Onu.decode(real_json[0]["onus"]["onu"])[0]) == "OltConfig.Pon.Onu: onu-id: 0"


def test_onu_decode_bad_dict():
    test_json = [{}]
    assert OltConfig.Pon.Onu.decode(test_json) == {}


def test_pon_to_string(pon_object):
    assert str(pon_object) == "OltConfig.Pon: pon-id: 0"


def test_pon_pon_id(pon_object):
    assert pon_object.pon_id == 0


def test_pon_enabled(pon_object):
    assert pon_object.enabled


def test_pon_downstream_fec_enable(pon_object):
    assert pon_object.downstream_fec_enable


def test_pon_upstream_fec_enable(pon_object):
    assert pon_object.upstream_fec_enable


def test_pon_deployment_range(pon_object):
    assert pon_object.deployment_range == 25000


def test_pon_onus(pon_object):
    assert str(pon_object.onus[0]) == "OltConfig.Pon.Onu: onu-id: 0"


def test_pon_onus_existing(pon_object):
    pon_object._onus = "existing"
    assert pon_object.onus == "existing"


def test_pon_decode_no_pons(pon_object):
    assert pon_object.decode(None) == {}


def test_olt_to_string(olt_object):
    assert str(olt_object) == "OltConfig: "


def test_olt_olt_id(olt_object):
    assert olt_object.olt_id == ""


def test_olt_debug_output(olt_object):
    assert olt_object.debug_output == "warning"


def test_olt_pons(olt_object):
    assert str(olt_object.pons[0]) == "OltConfig.Pon: pon-id: 0"


def test_olt_existing_pons(olt_object):
    olt_object._pons = "existing"
    assert olt_object.pons == "existing"