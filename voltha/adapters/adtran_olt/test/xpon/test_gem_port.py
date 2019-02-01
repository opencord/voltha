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


from voltha.adapters.adtran_olt.xpon.gem_port import GemPort
from mock import patch, MagicMock
import pytest

g_in = 11
a_in = 21
u_in = 31
te_in = 41
e_in = 'encryption'
m_in = 'multicast'
tr_in = 'traffic_class'
h_in = 'handler'
i_in = 'ismock'


def test_gem_port_init_values_missing():
    """
    verify __init__ fails when no values are specified
    """

    with pytest.raises(Exception):
        obj = GemPort()


def test_gem_port_init_values():
    """
    verify __init__ values are set properly
    """
    gp = GemPort(g_in, a_in, u_in, te_in, e_in, m_in, tr_in, h_in, i_in)

    assert gp.gem_id == g_in
    assert gp._alloc_id == a_in
    assert gp.uni_id == u_in
    assert gp.tech_profile_id == None           # TODO: code says default may change to a property
    assert gp._encryption == e_in
    assert gp.multicast == m_in
    assert gp.traffic_class == tr_in
    assert gp._handler == h_in
    assert gp._is_mock == i_in

def test_gem_port_init_values_default():
    """
    verify __init__ values are set properly using defaults
    """
    gp = GemPort(g_in, a_in, u_in, te_in)

    assert gp.gem_id == g_in
    assert gp._alloc_id == a_in
    assert gp.uni_id == u_in
    #assert gp.tech_profile_id == te_in
    assert gp.tech_profile_id == None
    assert gp._encryption == False
    assert gp.multicast == False
    assert gp.traffic_class == None
    assert gp._handler == None
    assert gp._is_mock == False


@pytest.fixture(scope="module")
def gp():
    be_obj = GemPort(g_in, a_in, u_in, te_in, e_in, m_in, tr_in, h_in, i_in)
    return be_obj

def test_gem_port_str_values(gp):
    """
    verify __str__ values are set properly
    """

    expected_str_value = "GemPort: alloc-id: {}, gem-id: {}, uni-id: {}".format(a_in, g_in, u_in)

    actual_str_val = str(gp)

    assert expected_str_value == actual_str_val

def test_gem_port_getter_properties(gp):
    """
    verify alloc_id and encryption @property getters
    """

    assert gp.alloc_id == a_in
    assert gp.encryption == e_in

def test_gem_port_dict_values(gp):
    """
    verify dict values are set properly
    """

    expected_dict = {
            'port-id': g_in,
            'alloc-id': a_in,
            'encryption': e_in,
            'omci-transport': False
        }

    actual_dict = gp.to_dict()

    assert expected_dict == actual_dict

# TODO - Exercise the rx and tx statistics

