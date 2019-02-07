# Copyright 2019-present Adtran, Inc.
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
from mock import Mock
from mock import MagicMock
from mock import patch
import json
import ast

from twisted.internet.defer import Deferred

from voltha.adapters.adtran_onu.adtran_onu_handler import AdtranOnuHandler
from voltha.adapters.adtran_onu.adtran_onu import AdtranOnuAdapter
from voltha.adapters.adtran_olt.test.resources.test_adtran_olt_resource_manager import MockRegistry
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from common.tech_profile.tech_profile import DEFAULT_TECH_PROFILE_TABLE_ID
from voltha.protos.voltha_pb2 import SelfTestResponse
from voltha.adapters.adtran_onu.test.resources.technology_profile import tech_profile_json
from voltha.adapters.adtran_onu.pon_port import PonPort
from voltha.adapters.adtran_onu.adtran_onu_handler import _STARTUP_RETRY_WAIT


@pytest.fixture()
def device_info():
    device = MagicMock()
    device.id = "test_1"
    device.parent_id = "test_2"
    device.proxy_address.device_id = "test_3"
    return device


@pytest.fixture()
def adapter_agent():
    aa = MagicMock()
    return aa


@pytest.fixture()
def onu_adapter(adapter_agent):
    adtran_onu = AdtranOnuAdapter(adapter_agent, "test_1")
    return adtran_onu


@pytest.fixture()
@patch('voltha.adapters.adtran_onu.adtran_onu_handler.registry', MockRegistry())
def onu_handler(onu_adapter):
    onu_handler = AdtranOnuHandler(onu_adapter, "test_1")
    return onu_handler


def test_onu_handler_initialization(onu_handler):
    assert str(onu_handler) == "AdtranOnuHandler: test_1"


def test_activate(onu_handler, device_info):
    with patch('voltha.adapters.adtran_onu.adtran_onu_handler.reactor.callLater') as onu_handler_reactor:
        parent_device = Mock()
        parent_device.parent_id = "test_5"
        onu_handler.adapter_agent.get_device.return_value = parent_device
        onu_handler._pon.get_port = Mock()
        onu_handler.activate(device_info)
        onu_handler.adapter_agent.register_for_proxied_messages.assert_called_with(device_info.proxy_address)
        onu_handler.adapter_agent.update_device.assert_called_with(device_info)
        onu_handler_reactor.assert_any_call(30, onu_handler.pm_metrics.start_collector)


def test_activate_handles_exceptions(onu_handler, device_info):
    onu_handler.adapter_agent.register_for_proxied_messages.side_effect = Exception()
    onu_handler.activate(device_info)
    assert device_info.connect_status == ConnectStatus.UNREACHABLE
    assert device_info.oper_status == OperStatus.FAILED
    onu_handler.adapter_agent.update_device.assert_called_with(device_info)


def test_reconcile(onu_handler, device_info):
    parent_device = Mock()
    parent_device.parent_id = "test_5"
    onu_handler.adapter_agent.get_device.return_value = parent_device
    onu_handler.reconcile(device_info)
    onu_handler.adapter_agent.register_for_proxied_messages.assert_called_with(device_info.proxy_address)
    assert parent_device.connect_status == ConnectStatus.REACHABLE
    assert parent_device.oper_status == OperStatus.ACTIVE
    assert onu_handler.enabled is True


@pytest.mark.parametrize("tp_path, expected_res", [('/255/xpon/1024', 255),
                                                   ('test/test/1', DEFAULT_TECH_PROFILE_TABLE_ID),
                                                   ('test', None)])
def test_tp_path_to_tp_id(onu_handler, tp_path, expected_res):
    tp_id = onu_handler._tp_path_to_tp_id(tp_path)
    assert tp_id == expected_res


@pytest.mark.parametrize("q_sched_policy, alloc_id, sc_po", [("STRICTPRIORITY", 1, 1), ("WRR", 2, 2)])
def test__create_tcont(onu_handler, q_sched_policy, alloc_id, sc_po):
    onu_handler._pon.add_tcont = Mock()
    us_scheduler = dict()
    us_scheduler['q_sched_policy'] = q_sched_policy
    us_scheduler['alloc_id'] = alloc_id
    tcont = onu_handler._create_tcont(1, us_scheduler, 1)
    onu_handler._pon.add_tcont.assert_called_with(tcont)
    assert tcont.alloc_id == alloc_id
    assert tcont.sched_policy == sc_po


def test_self_test_device(onu_handler, device_info):
    res = onu_handler.self_test_device(device_info)
    assert res.result == SelfTestResponse.NOT_SUPPORTED


def test_create_gemports(onu_handler):
    onu_handler._pon = PonPort.create(onu_handler, onu_handler._pon_port_number)
    onu_handler._create_gemports(tech_profile_json['upstream_gem_port_attribute_list'],
                                 tech_profile_json['downstream_gem_port_attribute_list'], MagicMock(), 1, '255')
    assert onu_handler._pon.gem_ids == [1024, 1025, 1026, 1027]


def test__do_tech_profile_configuration(onu_handler):
    with patch('voltha.adapters.adtran_onu.adtran_onu_handler.AdtranOnuHandler._create_tcont') as tcont_patch,\
            patch('voltha.adapters.adtran_onu.adtran_onu_handler.AdtranOnuHandler._create_gemports') as gemport_patch:
        tech_profile_id = '255'
        uni_id = 1
        tcont_patch.return_value = tcont_obj = Mock()
        onu_handler._do_tech_profile_configuration(uni_id, tech_profile_json, tech_profile_id)
        upstream = tech_profile_json['upstream_gem_port_attribute_list']
        downstream = tech_profile_json['downstream_gem_port_attribute_list']
        us_scheduler = tech_profile_json['us_scheduler']
        tcont_patch.assert_called_with(uni_id, us_scheduler, tech_profile_id)
        gemport_patch.assert_called_with(upstream, downstream, tcont_obj, uni_id, tech_profile_id)


def test_update_pm_config(onu_handler, device_info):
        onu_handler.pm_metrics = Mock()
        pm_config = Mock()
        onu_handler.update_pm_config(device_info, pm_config)
        onu_handler.pm_metrics.update.assert_called_with(pm_config)


@pytest.mark.parametrize("success_case", [True, False])
def test_load_and_configure_tech_profile(onu_handler, success_case):
    with patch('voltha.adapters.adtran_onu.adtran_onu_handler.AdtnTpServiceSpecificTask'),\
         patch('voltha.adapters.adtran_onu.adtran_onu_handler.AdtranOnuHandler.openomci') as openomci, \
            patch('voltha.adapters.adtran_onu.adtran_onu_handler.reactor.callLater') as onu_handler_reactor:
        uni_id, tp_path = 1, '/255/XPON/1024'
        tp = json.dumps(tech_profile_json)
        onu_handler.kv_client = {tp_path: tp}
        onu_handler._do_tech_profile_configuration = MagicMock()
        d = Deferred()
        openomci.onu_omci_device.task_runner.queue_task.return_value = d
        onu_handler.load_and_configure_tech_profile(uni_id, tp_path)
        if success_case:
            d.callback('success')
            assert onu_handler._tech_profile_download_done[uni_id][tp_path] is True
        else:
            d.errback(Exception('test'))
            onu_handler_reactor.assert_called_with(_STARTUP_RETRY_WAIT,
                                                   onu_handler.load_and_configure_tech_profile, uni_id, tp_path)

        assert len(onu_handler._tp_service_specific_task[uni_id]) == 0
        onu_handler._do_tech_profile_configuration.assert_called_with(uni_id, ast.literal_eval(tp), 255)


def test_load_and_configure_tech_profile_handles_exceptions(onu_handler):
    onu_handler.kv_client = Mock(side_effect=Exception())
    uni_id, tp_path = 1, '/255/XPON/1024'
    onu_handler.load_and_configure_tech_profile(uni_id, tp_path)
    assert onu_handler._tech_profile_download_done[uni_id][tp_path] is False


def test_load_and_configure_tech_profile_where_tech_profile_already_loaded(onu_handler):
    uni_id, tp_path = 1, '/255/XPON/1024'
    onu_handler._tech_profile_download_done[uni_id] = dict()
    onu_handler._tech_profile_download_done[uni_id][tp_path] = True
    onu_handler._do_tech_profile_configuration = MagicMock()
    onu_handler.load_and_configure_tech_profile(uni_id, tp_path)
    onu_handler._do_tech_profile_configuration.assert_not_called()


def test_rx_inter_adapter_message_throws_not_implemented_error(onu_handler):
    with pytest.raises(TypeError):
        onu_handler.rx_inter_adapter_message('test')

