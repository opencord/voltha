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


from voltha.adapters.adtran_olt.xpon.tcont import TCont
# from mock import patch, MagicMock
import pytest

# Globals
# consider parametrizing these attributes

allo = 12
tech = 22
traf = 32
unii = 42
imck=False


def test_tcont_init_values_missing():
    """
    verify __init__ fails when no values are specified
    """

    with pytest.raises(Exception):
        tc_obj = TCont()


@pytest.fixture(scope="module")
def tc():
    tc_obj = TCont(allo, tech, traf, unii, imck)
    return tc_obj


def test_tcont_init_values(tc):
    """
    verify __init__ values are set properly
    """
    assert allo == tc.alloc_id
    assert traf == tc.traffic_descriptor
    assert imck == tc._is_mock
    assert tech == tc.tech_profile_id
    assert unii == tc.uni_id

def test_tcont_init_values_no_ismock():
    """
    verify __init__ values are set properly
    """

    tc1 = TCont(allo, tech, traf, unii)

    assert allo == tc1.alloc_id
    assert traf == tc1.traffic_descriptor
    assert imck == tc1._is_mock
    assert tech == tc1.tech_profile_id
    assert unii == tc1.uni_id


def test_tcont_init_values_ismock_true():
    """
    verify __init__ values are set properly
    """
    tc2 = TCont(allo, tech, traf, unii, True)

    assert allo == tc2.alloc_id
    assert traf == tc2.traffic_descriptor
    assert True == tc2._is_mock
    assert tech == tc2.tech_profile_id
    assert unii == tc2.uni_id

def test_tcont_str_values(tc):
    """
    verify __str__ values are set properly
    """

    expected_str_value = "TCont: alloc-id: {}, uni-id: {}".format(allo, unii)
    actual_str_val = str(tc)

    assert expected_str_value == actual_str_val
