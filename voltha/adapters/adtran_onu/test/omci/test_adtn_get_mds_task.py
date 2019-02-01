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


from pytest import fixture
from mock import MagicMock
from mock import patch


from voltha.adapters.adtran_onu.omci.adtn_get_mds_task import AdtnGetMdsTask


@fixture(scope='function')
def mds_task():
    return AdtnGetMdsTask(MagicMock(), "test_id")


def test_properties(mds_task):
    assert mds_task.name == "ADTN: Get MDS Task"
    assert mds_task._omci_managed is False
    assert mds_task._device is not None


def test_perform_get_mds_when_not_managed_via_omci(mds_task):
    test = MagicMock()
    mds_task.deferred.addCallback(test)
    mds_task.perform_get_mds()
    test.assert_called_with(mds_task.omci_agent.get_device().mib_synchronizer.mib_data_sync)


def test_perform_get_mds_when_managed_via_omci(mds_task):
    with patch('voltha.extensions.omci.tasks.get_mds_task.GetMdsTask.perform_get_mds') as get_mds:
        mds_task._omci_managed = True
        get_mds.return_value = 'test'
        res = mds_task.perform_get_mds()
        assert res == 'test'
