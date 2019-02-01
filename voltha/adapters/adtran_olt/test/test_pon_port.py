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
"""
Adtran generic VOLTHA device handler
"""
import pytest
from mock import MagicMock
from voltha.adapters.adtran_olt.pon_port import PonPort
from voltha.adapters.adtran_olt.adtran_olt import AdtranOltHandler


@pytest.fixture()
def simple_pon():
    parent = MagicMock(autospec=AdtranOltHandler)
    parent.__str__.return_value = 'test-olt'
    yield PonPort(parent=parent,
                  port_no=1,
                  **{
                      'pon-id': 2  # TODO: This is a kinda crumby API
                  })


def test_properties(simple_pon):
    assert simple_pon.pon_id == 2
    assert simple_pon.onus == frozenset()
    assert simple_pon.onu_ids == frozenset()
    assert simple_pon.onu(12345) is None
    assert simple_pon.in_service_onus == 0
    assert simple_pon.closest_onu_distance == -1
    assert simple_pon.downstream_fec_enable is True
    assert simple_pon.upstream_fec_enable is True
    assert simple_pon.any_upstream_fec_enabled is False
    assert simple_pon.mcast_aes is False
    assert simple_pon.deployment_range == 25000
    assert simple_pon.discovery_tick == 200.0
    assert simple_pon.activation_method == 'autoactivate'
    assert simple_pon.authentication_method == 'serial-number'
    assert 'PonPort-pon-2: Admin: 3, Oper: 1, OLT: test-olt' == str(simple_pon)


def test_get_port(simple_pon):
    port = simple_pon.get_port()
    assert """port_no: 1
label: "pon-2"
type: PON_OLT
admin_state: ENABLED
oper_status: DISCOVERED
""" == str(port)
