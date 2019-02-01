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
from voltha.adapters.adtran_onu.onu_traffic_descriptor import OnuTrafficDescriptor
from voltha.adapters.adtran_olt.xpon.traffic_descriptor import TrafficDescriptor
from voltha.adapters.adtran_olt.xpon.best_effort import BestEffort


FIXED_BW = 1000000000               # String name of UNI port
ASSURED_BW = 2000000000             # String name of UNI port
MAX_BW = 4000000000                 # String name of UNI port


# Basic test of OnuTrafficDescriptor() object creation
def test_traf_desc_init():
    otd = OnuTrafficDescriptor(FIXED_BW, ASSURED_BW, MAX_BW, TrafficDescriptor.AdditionalBwEligibility.NONE, None)
    assert otd.fixed_bandwidth == FIXED_BW
    assert otd.assured_bandwidth == ASSURED_BW
    assert otd.maximum_bandwidth == MAX_BW
    assert otd.additional_bandwidth_eligibility == TrafficDescriptor.AdditionalBwEligibility.NONE
    assert otd.best_effort is None


@pytest.mark.parametrize("f_bw, a_bw, m_bw, addl_ind", [(FIXED_BW, ASSURED_BW, MAX_BW, 0),
                                                        (FIXED_BW, ASSURED_BW, MAX_BW, 1),
                                                        (FIXED_BW, ASSURED_BW, MAX_BW, 2),
                                                        (FIXED_BW, ASSURED_BW, MAX_BW, 3)])
# Test static method constructor for OnuTrafficDescriptor() for various parametrized combinations
def test_traf_desc_create(f_bw, a_bw, m_bw, addl_ind):
    otd_data = dict()
    otd_data['fixed-bandwidth'] = f_bw
    otd_data['assured-bandwidth'] = a_bw
    otd_data['maximum-bandwidth'] = m_bw
    otd_data['additional-bw-eligibility-indicator'] = addl_ind
    otd_data['priority'] = 0
    otd_data['weight'] = 0
    otd = OnuTrafficDescriptor.create(otd_data)
    assert otd.fixed_bandwidth == f_bw
    assert otd.assured_bandwidth == a_bw
    assert otd.maximum_bandwidth == m_bw

    if addl_ind == 0:
        assert otd.additional_bandwidth_eligibility == TrafficDescriptor.AdditionalBwEligibility.NONE
    elif addl_ind == 1:
        assert otd.additional_bandwidth_eligibility == TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING
    elif addl_ind == 2:
        assert otd.additional_bandwidth_eligibility == TrafficDescriptor.AdditionalBwEligibility.NON_ASSURED_SHARING
    elif addl_ind == 3:
        assert otd.additional_bandwidth_eligibility == TrafficDescriptor.AdditionalBwEligibility.NONE

    if addl_ind == 1:
        assert isinstance(otd.best_effort, BestEffort)
    else:
        assert otd.best_effort is None
