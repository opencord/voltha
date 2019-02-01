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

from voltha.adapters.adtran_onu.omci.adtn_mib_sync import *

@pytest.fixture(autouse="True")
def AMSInstance():
    new_mock = mock.MagicMock()
    result = AdtnMibSynchronizer(new_mock, new_mock, new_mock, new_mock)
    return result

#Tests the init function to make sure it calls the init of its parent class and successfully sets fields
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.__init__')
def test_AdtnMibSynchronizer_init(mock_AdtnMibSynchronizer_init):
    test_mock = mock.MagicMock()
    test = AdtnMibSynchronizer(test_mock, test_mock, test_mock, test_mock)
    assert mock_AdtnMibSynchronizer_init.call_count == 1
    assert test._first_in_sync == True
    assert test._omci_managed == False

#Tests function when omci managed is True
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.increment_mib_data_sync')
def test_increment_mib_data_sync_omci_managed_true(mock_increment_mib_data_sync, AMSInstance):
    AMSInstance._omci_managed = True
    AMSInstance.increment_mib_data_sync()
    assert mock_increment_mib_data_sync.call_count == 1
    assert AMSInstance._mib_data_sync == 0

#Tests function when omci managed is False
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.increment_mib_data_sync')
def test_increment_mib_data_sync_omci_managed_false(mock_increment_mib_data_sync, AMSInstance):
    AMSInstance.increment_mib_data_sync()
    assert mock_increment_mib_data_sync.call_count == 0
    assert AMSInstance._mib_data_sync == 0

#Tests function when omci managed is true
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.on_enter_in_sync')
def test_on_enter_in_sync_omci_managed_true(mock_on_enter_in_sync, AMSInstance):
    AMSInstance._omci_managed = True
    AMSInstance.on_enter_in_sync()
    assert mock_on_enter_in_sync.call_count == 1

#Tests function when omci managed is false and first in sync is true
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.on_enter_in_sync')
def test_on_enter_in_sync_omci_managed_false_first_in_sync_true(mock_on_enter_in_sync, AMSInstance):
    AMSInstance._first_in_sync = True
    AMSInstance.on_enter_in_sync()
    assert mock_on_enter_in_sync.call_count == 1
    assert AMSInstance._first_in_sync == False

#Tests function when omci managed is false and first in sync is false
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.on_enter_in_sync')
def test_on_enter_in_sync_omci_managed_false_first_in_sync_false(mock_on_enter_in_sync, AMSInstance):
    AMSInstance._first_in_sync = False
    AMSInstance.on_enter_in_sync()
    assert mock_on_enter_in_sync.call_count == 1
    assert AMSInstance._audit_delay == 60
    assert AMSInstance._resync_delay == 120

#Tests function if if statement is triggered (mib data sync is supported)
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.on_enter_auditing')
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.AdtnMibSynchronizer._check_if_mib_data_sync_supported')
def test_on_enter_auditing_attempt_one(mock_check_if_mib_data_sync_supported, mock_on_enter_auditing, AMSInstance):
    mock_check_if_mib_data_sync_supported.return_value = True
    AMSInstance.on_enter_auditing()
    assert AMSInstance._omci_managed == True
    assert AMSInstance._resync_delay == 300
    assert mock_on_enter_auditing.call_count == 1

#Tests function if if statement is false isn't triggered (mib data sync isn't supported)
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.on_enter_auditing')
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.AdtnMibSynchronizer._check_if_mib_data_sync_supported')
def test_on_enter_auditing_attempt_two(mock_check_if_mib_data_sync_supported, mock_on_enter_auditing, AMSInstance):
    mock_check_if_mib_data_sync_supported.return_value = False
    AMSInstance.on_enter_auditing()
    assert mock_on_enter_auditing.call_count == 1

#Tests that function returns false
def test__check_if_mib_data_sync_supported(AMSInstance):
    result = AMSInstance._check_if_mib_data_sync_supported()
    assert result == False

#Tests this function to ensure it changes the right field and calls the right function
@mock.patch('voltha.adapters.adtran_onu.omci.adtn_mib_sync.MibSynchronizer.on_mib_reset_response')
def test_on_mib_reset_response(mock_on_mib_reset_response, AMSInstance):
    test_mock = mock.MagicMock()
    AMSInstance.on_mib_reset_response(test_mock, test_mock)
    assert AMSInstance._first_in_sync == True
    assert mock_on_mib_reset_response.call_count == 1


