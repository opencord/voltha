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

from voltha.adapters.adtran_olt.xpon.traffic_descriptor import TrafficDescriptor

import pytest

f_bw = 100000000  # fixed_bandwidth
a_bw = 95000000   # assured_bandwidth
m_bw = 95000000   # maximum_bandwidth
AbE = 1         # Additional Bandwidth Eligibility


@pytest.fixture(scope='module')
def td():
    td = TrafficDescriptor(f_bw, a_bw, m_bw, AbE)
    return td


def test_init(td):
    assert td.fixed_bandwidth == f_bw
    assert td.assured_bandwidth == a_bw
    assert td.maximum_bandwidth == m_bw
    assert td.additional_bandwidth_eligibility == AbE


def test_str(td):
    assert str(td) == "TrafficDescriptor: {}/{}/{}".format(f_bw, a_bw, m_bw)


@pytest.mark.parametrize("input_value, expected_value",
                         [(TrafficDescriptor.AdditionalBwEligibility.NON_ASSURED_SHARING, "non-assured-sharing"),
                          (TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING, "best-effort-sharing"),
                          (TrafficDescriptor.AdditionalBwEligibility.NONE, "none")])
def test_to_string(td, input_value, expected_value):

    test_value = td.AdditionalBwEligibility.to_string(input_value)

    assert test_value == expected_value


@pytest.mark.parametrize("input_value, expected_value",
                         [(0, TrafficDescriptor.AdditionalBwEligibility.NONE),
                          (1, TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING),
                          (2, TrafficDescriptor.AdditionalBwEligibility.NON_ASSURED_SHARING)])
def test_from_value(td, input_value, expected_value):

    test_value = td.AdditionalBwEligibility.from_value(input_value)

    assert test_value == expected_value


def test_to_dict(td):

    dict_val = {
        'fixed-bandwidth': f_bw,
        'assured-bandwidth': a_bw,
        'maximum-bandwidth': m_bw,
        'additional-bandwidth-eligibility': td.AdditionalBwEligibility.to_string(AbE)

    }

    test_dict = td.to_dict()

    assert dict_val == test_dict


