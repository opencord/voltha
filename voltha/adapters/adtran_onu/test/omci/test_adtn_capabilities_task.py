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


from voltha.adapters.adtran_onu.omci.adtn_capabilities_task import AdtnCapabilitiesTask
from voltha.extensions.omci.omci_entities import EntityOperations


@fixture(scope='function')
def adtn_capabilities():
    return AdtnCapabilitiesTask(MagicMock(), "test_id")


@fixture(scope='function')
def message_types():
    op_11287800f1 = [
        EntityOperations.Create,
        EntityOperations.CreateComplete]
    return op_11287800f1


def test_properties(adtn_capabilities):
    assert adtn_capabilities.name == "Adtran ONU Capabilities Task"


def test_supported_managed_entities_when_entity_not_managed_via_omci(adtn_capabilities):
    me_1287800f1 = [
        2, 5, 6, 7, 11, 24, 45, 46, 47, 48, 49, 50, 51, 52, 79, 84, 89, 130,
        131, 133, 134, 135, 136, 137, 148, 157, 158, 159, 171, 256, 257, 262,
        263, 264, 266, 268, 272, 273, 274, 277, 278, 279, 280, 281, 297, 298,
        299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312,
        329, 330, 332, 334, 336, 340, 341, 342, 343, 348, 425, 426, 65300,
        65400, 65401, 65402, 65403, 65404, 65406, 65407, 65408, 65409, 65410,
        65411, 65412, 65413, 65414, 65420, 65421, 65422, 65423, 65424
    ]
    expected_result = frozenset(list(me_1287800f1))
    capabilities = adtn_capabilities.supported_managed_entities
    assert expected_result == capabilities


def test_supported_managed_entities_when_entity_managed_via_omci(adtn_capabilities):
    adtn_capabilities._supported_entities = [1, 2]
    adtn_capabilities._omci_managed = True
    capabilities = adtn_capabilities.supported_managed_entities
    assert capabilities == frozenset([1, 2])


def test_supported_message_types_when_entity_not_managed_via_omci(adtn_capabilities):
    from voltha.extensions.omci.omci_entities import EntityOperations
    op_11287800f1 = [
        EntityOperations.Create,
        EntityOperations.CreateComplete,
        EntityOperations.Delete,
        EntityOperations.Set,
        EntityOperations.Get,
        EntityOperations.GetComplete,
        EntityOperations.GetAllAlarms,
        EntityOperations.GetAllAlarmsNext,
        EntityOperations.MibUpload,
        EntityOperations.MibUploadNext,
        EntityOperations.MibReset,
        EntityOperations.AlarmNotification,
        EntityOperations.AttributeValueChange,
        EntityOperations.Test,
        EntityOperations.StartSoftwareDownload,
        EntityOperations.DownloadSection,
        EntityOperations.EndSoftwareDownload,
        EntityOperations.ActivateSoftware,
        EntityOperations.CommitSoftware,
        EntityOperations.SynchronizeTime,
        EntityOperations.Reboot,
        EntityOperations.GetNext,
    ]
    expected_result = frozenset(op_11287800f1)
    message_types = adtn_capabilities.supported_message_types
    assert expected_result == message_types


def test_supported_message_types_when_entity_managed_via_omci(adtn_capabilities, message_types):
    adtn_capabilities._omci_managed = True
    adtn_capabilities._supported_msg_types = set(message_types)
    capabilities = adtn_capabilities.supported_message_types
    assert capabilities == frozenset(message_types)


def test_perform_get_capabilities_when_not_managed_via_omci(adtn_capabilities):
    adtn_capabilities._omci_managed = False
    adtn_capabilities.perform_get_capabilities()
    result = adtn_capabilities.deferred.result
    assert result['supported-managed-entities'] == adtn_capabilities.supported_managed_entities
    assert result['supported-message-types'] == adtn_capabilities.supported_message_types


def test_perform_get_capabilities_when_managed_via_omci(adtn_capabilities, message_types):
    adtn_capabilities._omci_managed = True
    with patch('voltha.adapters.adtran_onu.omci.adtn_capabilities_task.AdtnCapabilitiesTask.get_supported_entities') as supp_ent,\
        patch('voltha.adapters.adtran_onu.omci.adtn_capabilities_task.AdtnCapabilitiesTask.get_supported_message_types') as sup_msg:
        supp_ent.return_value = [1, 2]
        sup_msg.return_value = set(message_types)
        adtn_capabilities.perform_get_capabilities()
        result = adtn_capabilities.deferred.result
        assert result['supported-managed-entities'] == frozenset([1, 2])
        assert result['supported-message-types'] == frozenset(message_types)


