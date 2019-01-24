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


import mock
import pytest
from array import array

from voltha.adapters.adtran_onu.omci.adtn_mib_resync_task import *


@pytest.fixture(autouse="True")
def AMRTInstance():
    new_mock = mock.MagicMock()
    result = AdtnMibResyncTask(new_mock, new_mock)
    return result

#Tests the init function to make sure it calls the init of its parent class and successfully sets omci_fixed
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_resync_task.MibResyncTask.__init__')
def test_AdtnMibResyncTask_init(mock_MibResyncTask_init):
    test_mock = mock.MagicMock()
    test = AdtnMibResyncTask(test_mock, test_mock)
    assert mock_MibResyncTask_init.call_count == 1
    assert test.omci_fixed == False

#Tests what happens if omci_fixed is True
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_resync_task.MibResyncTask.compare_mibs')
def test_compare_mibs_omci_fixed_true(mock_compare_mibs, AMRTInstance):
    AMRTInstance.omci_fixed = True
    mock_compare_mibs.return_value = 1, 2, 3
    test1, test2, test3 = AMRTInstance.compare_mibs('test', 'test')
    assert test1 == 1
    assert test2 == 2
    assert test3 == 3

#Tests compare_mibs for the scenario where omci_fixed is false and on_olt_only is None
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_resync_task.MibResyncTask.compare_mibs')
def test_compare_mibs_omci_fixed_false_on_olt_only_true(mock_compare_mibs, AMRTInstance):
    testarr1 = [272, 'test', 'max_gem_payload_size']
    testarr2 = [272, 'test', 'test']
    testarr3 = ['test', 'test', 'max_gem_payload_size']
    testarr4 = [268, 'test', 'test']
    testarr5 = ['test', 'test', 'test']
    attr_diffs = [testarr1, testarr2, testarr3, testarr4, testarr5]

    mock_compare_mibs.return_value = None, None, attr_diffs

    _, _, attr_diffs = AMRTInstance.compare_mibs('test', 'test')

    assert mock_compare_mibs.call_count == 1
    assert attr_diffs[0] == testarr2
    assert attr_diffs[1] == testarr3
    assert attr_diffs[2] == testarr5

#Tests compare_mibs for the scenario where omci_fixed is false and on_olt_only is not None
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_resync_task.MibResyncTask.compare_mibs')
def test_compare_mibs_omci_fixed_false_on_olt_only_not_none(mock_compare_mibs, AMRTInstance):
    testarr1 = [272, 'test', 'max_gem_payload_size']
    testarr2 = [272, 'test', 'test']
    testarr3 = ['test', 'test', 'max_gem_payload_size']
    testarr4 = [268, 'test', 'test']
    testarr5 = ['test', 'test', 'test']
    attr_diffs = [testarr1, testarr2, testarr3, testarr4, testarr5]

    testtup1 = (130, 1)
    testtup2 = (287, 4)
    testtup3 = (145, 3456)
    testtup4 = (130, -56)
    on_olt_only = [testtup1, testtup2, testtup3, testtup4]

    mock_compare_mibs.return_value = on_olt_only, None, attr_diffs

    on_olt_only, _, attr_diffs = AMRTInstance.compare_mibs('test', 'test')

    assert mock_compare_mibs.call_count == 1

    assert attr_diffs[0] == testarr2
    assert attr_diffs[1] == testarr3
    assert attr_diffs[2] == testarr5

    assert on_olt_only[0] == testtup2
    assert on_olt_only[1] == testtup3


