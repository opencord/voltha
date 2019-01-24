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


from voltha.adapters.adtran_olt.resources.adtranolt_platform import MAX_ONUS_PER_PON,\
    MIN_TCONT_ALLOC_ID, MAX_TCONT_ALLOC_ID, MIN_GEM_PORT_ID, MAX_GEM_PORT_ID, MAX_TCONTS_PER_ONU,\
    MAX_GEM_PORTS_PER_ONU
from voltha.adapters.adtran_olt.resources.adtran_olt_resource_manager import AdtranPONResourceManager
from voltha.adapters.adtran_olt.resources.adtran_olt_resource_manager import AdtranOltResourceMgr


@pytest.fixture(scope="module")
def device_info():
    device_info = mock.MagicMock()
    device_info.technology = "xgspon"
    device_info.onu_id_start = 0
    device_info.onu_id_end = MAX_ONUS_PER_PON
    device_info.alloc_id_start = MIN_TCONT_ALLOC_ID
    device_info.alloc_id_end = MAX_TCONT_ALLOC_ID
    device_info.gemport_id_start = MIN_GEM_PORT_ID
    device_info.gemport_id_end = MAX_GEM_PORT_ID
    device_info.pon_ports = 3
    device_info.max_tconts = MAX_TCONTS_PER_ONU
    device_info.max_gem_ports = MAX_GEM_PORTS_PER_ONU
    device_info.intf_ids = ["1", "2", "3"]
    return device_info


@pytest.fixture(scope="module")
def pon_rm():
    pon_rm = mock.MagicMock(AdtranPONResourceManager)
    return pon_rm


@pytest.fixture(scope="module")
def pon_intf_id_onu_id():
    pon_intf_id_onu_id = (1, 1)
    return pon_intf_id_onu_id


class MockRegistry:
    """ Need to revisit this class"""
    def __init__(self):
        pass

    def __call__(self, name):
        main_mock = mock.MagicMock()

        def get_args():
            args = mock.Mock()
            args.backend = "etcd"
            args.etcd = "6.7.8.9:1245"
            return args
        main_mock.get_args = get_args
        return main_mock


@pytest.fixture(scope="module")
@mock.patch('voltha.adapters.adtran_olt.resources.adtran_olt_resource_manager.registry', MockRegistry())
def olt_rm(device_info, pon_rm):
    with mock.patch('voltha.adapters.adtran_olt.resources.adtran_olt_resource_manager.AdtranPONResourceManager',
                    pon_rm):
        olt_rm = AdtranOltResourceMgr("test_id", "1.2.3.4:830", "--olt_model adtran", device_info)
        olt_rm.resource_managers = mock.MagicMock()
        return olt_rm


def test_properties(olt_rm):
    assert olt_rm.device_id == "test_id"


def test_get_onu_id(olt_rm, pon_intf_id_onu_id):
    olt_rm.resource_mgr.get_resource_id.return_value = 1
    onu_id = olt_rm.get_onu_id(1)
    assert onu_id == 1
    olt_rm.resource_mgr.init_resource_map.assert_called_with(pon_intf_id_onu_id)


def test_free_onu_id(olt_rm, pon_intf_id_onu_id):
    olt_rm.free_onu_id(1, 1)
    olt_rm.resource_mgr.free_resource_id.assert_called_with(1, AdtranPONResourceManager.ONU_ID, 1)
    olt_rm.resource_mgr.remove_resource_map.assert_called_with(pon_intf_id_onu_id)


def test_get_alloc_id_per_onu(olt_rm, pon_intf_id_onu_id):
    olt_rm.resource_mgr.get_current_alloc_ids_for_onu.return_value = [1024]
    alloc_id = olt_rm.get_alloc_id(pon_intf_id_onu_id)
    assert alloc_id == 1024


def test_get_alloc_id_not_available(olt_rm):
    olt_rm.resource_mgr.get_current_alloc_ids_for_onu.return_value = []
    olt_rm.resource_mgr.get_resource_id.return_value = []
    alloc_id = olt_rm.get_alloc_id((1, 1))
    assert alloc_id is None


def test_get_alloc_id_fetch_from_kv(olt_rm, pon_intf_id_onu_id):
    pon_intf = pon_intf_id_onu_id[0]
    onu_id = pon_intf_id_onu_id[1]
    alloc_id_list = [1024]
    olt_rm.resource_mgr.get_current_alloc_ids_for_onu.return_value = []
    olt_rm.resource_mgr.get_resource_id.return_value = alloc_id_list
    alloc_id = olt_rm.get_alloc_id(pon_intf_id_onu_id)
    assert alloc_id == 1024
    olt_rm.resource_mgr.get_resource_id.assert_called_with(pon_intf, AdtranPONResourceManager.ALLOC_ID, num_of_id=1,
                                                           onu_id=onu_id)
    olt_rm.resource_mgr.update_alloc_ids_for_onu.assert_called_with(pon_intf_id_onu_id, alloc_id_list)


def test_free_pon_resources_for_onu(olt_rm, pon_intf_id_onu_id):
    pon_intf_id = pon_intf_id_onu_id[0]
    onu_id = pon_intf_id_onu_id[1]
    alloc_ids = [1024]
    gem_ids = [2176]
    olt_rm.resource_mgr.get_current_alloc_ids_for_onu.return_value = alloc_ids
    olt_rm.resource_mgr.get_current_gemport_ids_for_onu.return_value = gem_ids
    olt_rm.kv_store = mock.MagicMock()
    olt_rm.kv_store[str((pon_intf_id, gem_ids[0]))] = "Dummy Value"
    olt_rm.free_pon_resources_for_onu(pon_intf_id_onu_id)
    olt_rm.resource_mgr.free_resource_id.assert_any_call(pon_intf_id, AdtranPONResourceManager.ALLOC_ID, alloc_ids,
                                                         onu_id=onu_id)
    olt_rm.resource_mgr.free_resource_id.assert_any_call(pon_intf_id, AdtranPONResourceManager.GEMPORT_ID, gem_ids)
    olt_rm.resource_mgr.free_resource_id.assert_any_call(pon_intf_id, AdtranPONResourceManager.ONU_ID, onu_id)
    olt_rm.resource_mgr.remove_resource_map.assert_called_with(pon_intf_id_onu_id)


def test_free_pon_resources_for_onu_handles_exceptions(olt_rm, pon_intf_id_onu_id):
    with pytest.raises(UnboundLocalError):
        olt_rm.resource_mgr.get_current_alloc_ids_for_onu = mock.Mock(side_effect=KeyError('test'))
        olt_rm.resource_mgr.get_current_gemport_ids_for_onu = mock.Mock(side_effect=KeyError('test'))
        olt_rm.resource_mgr.free_resource_id = mock.Mock(side_effect=KeyError('test'))
        olt_rm.kv_store = mock.MagicMock()
        olt_rm.free_pon_resources_for_onu(pon_intf_id_onu_id)


def test_get_current_gemport_ids_for_onu(olt_rm, pon_intf_id_onu_id):
    pon_intf_id = pon_intf_id_onu_id[0]
    olt_rm.resource_managers[pon_intf_id].get_current_gemport_ids_for_onu.return_value = 1024
    gemport_ids = olt_rm.get_current_gemport_ids_for_onu(pon_intf_id_onu_id)
    assert gemport_ids == 1024


@pytest.mark.parametrize("input_value, expected_value", [([1024], 1024), (None, None)])
def test_get_current_alloc_ids_for_onu(olt_rm, pon_intf_id_onu_id, input_value, expected_value):
    pon_intf_id = pon_intf_id_onu_id[0]
    olt_rm.resource_managers[pon_intf_id].get_current_alloc_ids_for_onu.return_value = input_value
    allocation_ids = olt_rm.get_current_alloc_ids_for_onu(pon_intf_id_onu_id)
    assert allocation_ids == expected_value


def test_update_gemports_ponport_to_onu_map_on_kv_store(olt_rm):
    expected_output = {'(1, 2177)': '2 3', '(1, 2176)': '2 3'}
    gemport_list = [2176, 2177]
    pon_port = 1
    onu_id = 2
    uni_id = 3
    olt_rm.kv_store = {}
    olt_rm.update_gemports_ponport_to_onu_map_on_kv_store(gemport_list, pon_port, onu_id, uni_id)
    assert expected_output == olt_rm.kv_store


def test_get_onu_uni_from_ponport_gemport(olt_rm):
    olt_rm.kv_store = {'(1, 2177)': '2 3', '(1, 2176)': '2 3'}
    (onu_id, uni_id) = olt_rm.get_onu_uni_from_ponport_gemport(1,2177)
    assert (onu_id, uni_id) == (2, 3)


@pytest.mark.parametrize("flow_store_cookie, flow_category, expected_flow_id", [("cookie2", None, 4, ), (None, "test", 4)])
def test_get_flow_id(olt_rm, flow_store_cookie, flow_category, expected_flow_id):
    pon_intf_id = 1
    onu_id = 2
    uni_id = 3
    flows = [{"flow_category": "test", "flow_store_cookie": "cookie1"}, {"flow_store_cookie": "cookie2"}]
    olt_rm.resource_managers[pon_intf_id].get_current_flow_ids_for_onu.return_value = [4]
    olt_rm.resource_managers[pon_intf_id].get_flow_id_info.return_value = flows
    returned_flow_id = olt_rm.get_flow_id(pon_intf_id, onu_id, uni_id, flow_store_cookie, flow_category)
    assert returned_flow_id == expected_flow_id


def test_get_flow_id_handles_exception(olt_rm):
    pon_intf_id = 1
    onu_id = 2
    uni_id = 3
    flow_store_cookie = "dummy"
    flow_category = "test"
    olt_rm.resource_managers[pon_intf_id].get_current_flow_ids_for_onu.return_value = None
    olt_rm.resource_managers[pon_intf_id].get_flow_id_info.return_value = [10, 20]
    olt_rm.resource_managers[pon_intf_id].get_flow_id_info.return_value = None
    olt_rm.resource_managers[pon_intf_id].get_resource_id.return_value = 4
    returned_flow_id = olt_rm.get_flow_id(pon_intf_id, onu_id, uni_id, flow_store_cookie, flow_category)
    assert returned_flow_id == 4
    olt_rm.resource_managers[pon_intf_id].update_flow_id_for_onu.assert_called_with((1, 2, 3), 4)


def test_get_current_flow_ids_for_uni(olt_rm):
    pon_intf_id = 1
    onu_id = 2
    uni_id = 3
    olt_rm.resource_managers[pon_intf_id].get_current_flow_ids_for_onu.return_value = 4
    flow_id = olt_rm.get_current_flow_ids_for_uni(pon_intf_id, onu_id, uni_id)
    assert flow_id == 4


def test_update_flow_id_info_for_uni(olt_rm):
    pon_intf_id = 1
    onu_id = 2
    uni_id = 3
    pon_intf_onu_id = (pon_intf_id, onu_id, uni_id)
    flow_id = 4
    flow_data = {"Test": "Dummy"}
    olt_rm.update_flow_id_info_for_uni(pon_intf_id, onu_id, uni_id, flow_id, flow_data)
    olt_rm.resource_managers[pon_intf_id].update_flow_id_info_for_onu.assert_called_with(pon_intf_onu_id, flow_id,
                                                                                         flow_data)
