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


from mock import Mock, patch
import pytest
import json
from bitstring import BitArray

from voltha.adapters.adtran_olt.resources.adtran_resource_manager import AdtranPONResourceManager
from voltha.adapters.adtran_olt.test.resources.test_adtran_olt_resource_manager import MockRegistry


@pytest.fixture()
@patch('common.tech_profile.tech_profile.registry', MockRegistry())
def resource_manager():
    rm = AdtranPONResourceManager("xgspon", "--olt_model adtran", "test_id", "etcd", "6.7.8.9", "1245")
    rm.init_default_pon_resource_ranges()
    rm._kv_store = Mock()
    return rm


@pytest.fixture(scope="module")
def resource():
    return {'onu_map': {'1': {'end_idx': 6, 'start_idx': 1, 'pool': '11111'},
                        '2': {'end_idx': 5, 'start_idx': 1, 'pool': '1111'}}, 'pon_intf_id': 1}


@pytest.fixture(scope="module")
def resource_bin():
    return {'onu_map': {'1': {'end_idx': 6, 'start_idx': 1, 'pool': BitArray('0b11000')},
                        '2': {'end_idx': 5, 'start_idx': 1, 'pool': BitArray('0b1100')}}, 'pon_intf_id': 1}


def test_resource_manager_initialization(resource_manager):
    assert resource_manager.ONU_MAP == 'onu_map'


def test__format_resource(resource_manager):
    test_str = resource_manager._format_resource(1, 1, 4)
    resource = json.loads(test_str)
    assert resource[AdtranPONResourceManager.START_IDX] == 1
    assert resource[AdtranPONResourceManager.END_IDX] == 4
    assert resource[AdtranPONResourceManager.PON_INTF_ID] == 1
    assert resource[AdtranPONResourceManager.POOL] == "000"


def test__format_map_resource(resource_manager):
    resource = dict()
    resource[1] = [1, 2, 3, 4, 5]
    resource[2] = [1, 2, 3, 4]
    resource[3] = [1, 2, 3]
    resource[4] = [1, 2]
    test_str = resource_manager._format_map_resource(1, resource)
    pon_map = json.loads(test_str)
    pon_map["onu_map"]['1'][AdtranPONResourceManager.END_IDX] == 6
    pon_map["onu_map"]['2'][AdtranPONResourceManager.END_IDX] == 5
    pon_map["onu_map"]['3'][AdtranPONResourceManager.END_IDX] == 4
    pon_map["onu_map"]['4'][AdtranPONResourceManager.END_IDX] == 3


def test__get_resource_returns_none_when_path_is_not_available_in_kv(resource_manager):
    resource_manager._kv_store.get_from_kv_store.return_value = None
    result = resource_manager._get_resource("test", 1)
    assert result is None


@pytest.mark.parametrize("resource_map, path, onu_id",
                         [(resource(), '1/alloc_id/1', 1),
                          (resource()['onu_map']['2'], '1/onu_id/2', 2)])
def test__get_resource_returns_resources(resource_manager, resource_map, path, onu_id):
    resource_manager._kv_store.get_from_kv_store.return_value = json.dumps(resource_map)
    result = resource_manager._get_resource(path, onu_id)
    if 'alloc_id' in path:
        assert result[AdtranPONResourceManager.ONU_MAP]['1'][AdtranPONResourceManager.POOL] == BitArray('0b11111')
    else:
        assert result[AdtranPONResourceManager.POOL] == BitArray('0b1111')


def test__release_id(resource_manager, resource_bin):
    resource_manager._release_id(resource_bin, 2, 1)
    assert resource_bin['onu_map']['1']['pool'] == BitArray('0b10000')


@pytest.mark.parametrize("onu_id", [None, 1])
def test__generate_next_id(resource_manager, resource_bin, onu_id):
    if onu_id is None:
        result = resource_manager._generate_next_id(resource_bin[AdtranPONResourceManager.ONU_MAP]['2'])
        assert result == 3
    else:
        result = resource_manager._generate_next_id(resource_bin, onu_id)
        assert result == 2


@pytest.mark.parametrize("path, onu_id", [('1/onu_id/2', None)])
def test__update_resource(resource_manager, resource, resource_bin, path, onu_id):
    resource_manager._kv_store.update_to_kv_store = Mock()
    if 'alloc_id' in path:
        resource_manager._update_resource(path, resource, onu_id)
    else:
        resource_manager._update_resource(path, resource_bin['onu_map']['1'], onu_id)
    resource_manager._kv_store.update_to_kv_store.assert_called()


def test_clear_device_resource_pool(resource_manager):
    resource_manager.intf_ids = [1]
    resource_manager.clear_resource_id_pool = Mock()
    resource_manager.clear_device_resource_pool()
    resource_manager.clear_resource_id_pool.assert_any_call(pon_intf_id=1,
                                                            resource_type=AdtranPONResourceManager.ONU_ID)
    resource_manager.clear_resource_id_pool.assert_any_call(pon_intf_id=1,
                                                            resource_type=AdtranPONResourceManager.ALLOC_ID)
    resource_manager.clear_resource_id_pool.assert_any_call(pon_intf_id=1,
                                                            resource_type=AdtranPONResourceManager.GEMPORT_ID)


@pytest.mark.parametrize("resource_map", [None, {}])
def test_init_resource_id_pool(resource_manager, resource_map):
    resource_manager._get_resource = Mock()
    resource_manager._get_resource.return_value = None
    resource_manager._format_resource = Mock()
    resource_manager._format_resource.return_value = {}
    resource_manager._kv_store.update_to_kv_store.return_value = True
    status = resource_manager.init_resource_id_pool(pon_intf_id=1, resource_type=AdtranPONResourceManager.ONU_ID,
                                                    resource_map=resource_map)
    resource_manager._kv_store.update_to_kv_store.assert_called()
    assert status is True


def test_init_resource_id_pool_returns_false_when_get_path_is_none(resource_manager):
    resource_manager._get_path = Mock()
    resource_manager._get_path.return_value = None
    status = resource_manager.init_resource_id_pool(pon_intf_id=1, resource_type=AdtranPONResourceManager.ONU_ID,
                                                    resource_map=None)
    assert status is False


def test_init_resource_id_pool_returns_true_when_get_resources_is_not_none(resource_manager):
    resource_manager._get_path = Mock()
    resource_manager._get_path.return_value = "test"
    resource_manager._get_resource = Mock()
    resource_manager._get_resource.return_value = "test"
    status = resource_manager.init_resource_id_pool(pon_intf_id=1, resource_type=AdtranPONResourceManager.ONU_ID,
                                                    resource_map=None)
    assert status is True


def test_get_resource_id_validates_num_of_ids(resource_manager):
    result = resource_manager.get_resource_id(1, AdtranPONResourceManager.ONU_ID, None, 0)
    assert result is None


def test_get_resource_id_returns_none_when_get_path_returns_none(resource_manager):
    resource_manager._get_path = Mock()
    resource_manager._get_path.return_value = None
    result = resource_manager.get_resource_id(1, "test", None, 2)
    assert result is None


def test_get_resource_id_returns_none_when_resource_not_available(resource_manager):
    resource_manager._get_path = Mock()
    resource_manager._get_path.return_value = "test"
    resource_manager._get_resource = Mock()
    resource_manager._get_resource.return_value = "test"
    result = resource_manager.get_resource_id(1, "test", None, 2)
    assert result is None


@pytest.mark.parametrize("resource_type, next_id, num_of_id, expected_id",
                         [(AdtranPONResourceManager.ONU_ID, 1, 1, 1), (AdtranPONResourceManager.FLOW_ID, 1, 1, 1),
                          (AdtranPONResourceManager.GEMPORT_ID, 1, 2, [1, 1]),
                          (AdtranPONResourceManager.GEMPORT_ID, 1, 1, 1),
                          (AdtranPONResourceManager.ALLOC_ID, 1, 2, [1, 1]),
                          (AdtranPONResourceManager.ALLOC_ID, 1, 1, 1)])
def test_get_resource_id_valid_data(resource_manager, resource_type, next_id, num_of_id, expected_id):
    resource_manager._get_path = Mock()
    resource_manager._get_path.return_value = "test"
    resource_manager._get_resource = Mock()
    resource_manager._get_resource.return_value = "test"
    resource_manager._generate_next_id = Mock()
    resource_manager._generate_next_id.return_value = next_id
    resource_manager._update_resource = Mock()
    result = resource_manager.get_resource_id(1, resource_type, 1, num_of_id)
    assert result == expected_id
    if resource_type is not AdtranPONResourceManager.ALLOC_ID:
        resource_manager._generate_next_id.assert_any_call("test")
    else:
        resource_manager._generate_next_id.assert_any_call("test", 1)


def test_init_resource_id_pool_handles_exception(resource_manager):
    resource_manager._get_resource = Mock()
    resource_manager._get_resource.side_effect = Exception("Test")
    status = resource_manager.init_resource_id_pool(pon_intf_id=1, resource_type=AdtranPONResourceManager.ONU_ID)
    assert status is False


def test_init_device_resource_pool(resource_manager):
    """Need to revisit its tests"""
    resource_manager.intf_ids = [1]
    resource_manager.init_resource_id_pool = Mock()
    resource_manager.init_device_resource_pool()
    resource_manager.init_resource_id_pool.assert_any_call(
                pon_intf_id=1,
                resource_type=AdtranPONResourceManager.ONU_ID,
                start_idx=resource_manager.pon_resource_ranges[AdtranPONResourceManager.ONU_ID_START_IDX],
                end_idx=resource_manager.pon_resource_ranges[AdtranPONResourceManager.ONU_ID_END_IDX])
    resource_manager.init_resource_id_pool.assert_any_call(
                pon_intf_id=1,
                resource_type=AdtranPONResourceManager.GEMPORT_ID,
                start_idx=resource_manager.pon_resource_ranges[AdtranPONResourceManager.GEMPORT_ID_START_IDX],
                end_idx=resource_manager.pon_resource_ranges[AdtranPONResourceManager.GEMPORT_ID_END_IDX])


def test_free_resource_id_invalid_resource_type(resource_manager):
    result = resource_manager.free_resource_id(1, "test", None)
    assert result is False


@pytest.mark.parametrize("resource_type", [AdtranPONResourceManager.ONU_ID,
                                           AdtranPONResourceManager.GEMPORT_ID, AdtranPONResourceManager.ALLOC_ID])
def test_free_resource_id__valid_data(resource_manager, resource_type):
    resource_manager._release_id = Mock()
    resource_manager._update_resource = Mock()
    resource_manager._update_resource.return_value = True
    resource_manager._get_path = Mock()
    resource_manager._get_path.return_value = "test1"
    resource_manager._get_resource = Mock()
    resource_manager._get_resource.return_value = "test2"
    result = resource_manager.free_resource_id(1, resource_type, [1])
    assert result is True

