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

import pytest_twisted
from pytest import fixture
from pytest import mark
from pytest import raises
from mock import Mock
from mock import patch


from voltha.adapters.adtran_onu.omci.adtn_install_flow import AdtnInstallFlowTask
from voltha.extensions.omci.tasks.task import Task
from voltha.adapters.adtran_onu.adtran_onu_handler import AdtranOnuHandler
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent
from voltha.adapters.adtran_onu.flow.flow_entry import FlowEntry
from voltha.adapters.adtran_olt.test.resources.test_adtran_olt_resource_manager import MockRegistry
from voltha.adapters.adtran_onu.uni_port import UniPort
from voltha.adapters.adtran_onu.onu_gem_port import GemPort
from voltha.adapters.adtran_onu.onu_tcont import TCont
from voltha.extensions.omci.omci_messages import OmciCreateResponse
from voltha.extensions.omci.omci_defs import ReasonCodes as RC


class MockResponse:

    def __init__(self):
        self.fields = dict()


@fixture(scope='function')
@patch('voltha.adapters.adtran_onu.adtran_onu_handler.registry', MockRegistry())
def handler():
    handler = AdtranOnuHandler(Mock(), "test_id")
    handler.pon_port = Mock()
    handler.start = Mock()
    uni_ports = dict()
    port1 = UniPort(handler, "test1", 1, 1)
    port2 = UniPort(handler, "test2", 2, 2)
    port1.entity_id = 1
    port2.entity_id = 2
    uni_ports['1'] = port1
    uni_ports['2'] = port2
    handler._unis = uni_ports
    handler.uni_port = Mock(return_value=port1)
    gem_port = GemPort(1, 1, 1, None)
    handler._pon.add_gem_port(gem_port)
    tcont = TCont(1, None, Mock(), 1, True)
    handler._pon.add_tcont(tcont)
    handler.enabled = True
    return handler


@fixture()
def omci_agent():
    omci = OpenOMCIAgent(Mock())
    omci.get_device = Mock()
    return omci


@fixture()
def flow_entry():
    flow = FlowEntry(Mock(), Mock())
    return flow


@fixture()
def flow_task(handler, omci_agent, flow_entry):
    ft = AdtnInstallFlowTask(omci_agent, handler, flow_entry)
    ft._pon = handler._pon
    return ft


@fixture()
def mock_res():
    res = MockResponse()
    res.fields['success_code'] = RC.Success
    r = OmciCreateResponse()
    r.fields['omci_message'] = res
    return r


def test_properties(flow_task, omci_agent, handler):
    assert flow_task.task_priority == Task.DEFAULT_PRIORITY + 10
    omci_agent.get_device.assert_called_with(handler.device_id)
    handler.uni_port.assert_called()
    handler.pon_port.assert_called()


def test_start_should_install_flow(flow_task):
    with patch('voltha.adapters.adtran_onu.omci.adtn_install_flow.reactor.callLater') as flow_task_reactor:
        flow_task_reactor.return_value = "test"
        flow_task.start()
        flow_task_reactor.assert_called_with(0, flow_task.perform_flow_install)
        assert flow_task._local_deferred == "test"


@mark.parametrize("called_param", [True, False])
def test_cancel_deferred(flow_task, called_param):
    flow_task._local_deferred = mock_defer = Mock()
    flow_task._local_deferred.called = called_param
    flow_task.cancel_deferred()
    if not called_param:
        mock_defer.cancel.assert_called()
    else:
        mock_defer.cancel.assert_not_called()
    assert flow_task._local_deferred is None


@mark.parametrize("status, operation, expected_result", [(RC.Success, 'create', True),
                                                         (RC.InstanceExists, 'set', False),
                                                         (RC.UnknownInstance, 'delete', True),
                                                         (RC.UnknownEntity, 'test', False)])
def test_check_status_and_state(flow_task, mock_res, status, operation, expected_result):
    flow_task._onu_device.omci_cc = Mock()
    flow_task._onu_device.omci_cc.return_value = True
    flow_task.strobe_watchdog = Mock()
    mock_res.fields['omci_message'].fields['success_code'] = status
    if status == RC.UnknownEntity:
        with raises(Exception):
            flow_task.check_status_and_state(mock_res, operation=operation)
    else:
        result = flow_task.check_status_and_state(mock_res, operation=operation)
        assert result == expected_result


@mark.parametrize("install_by_delete", [True, False])
@pytest_twisted.inlineCallbacks
def test_perform_flow_install(flow_task, install_by_delete, mock_res):
    flow_task.check_status_and_state = Mock()
    flow_task._onu_device.omci_cc.send = Mock()
    flow_task._install_by_delete = install_by_delete
    flow_task._onu_device.omci_cc.send.return_value = 'test'
    yield flow_task.perform_flow_install()
    if install_by_delete:
        flow_task.check_status_and_state.assert_any_call('test', operation='delete')
        flow_task.check_status_and_state.assert_any_call('test', 'flow-recreate-before-set')
    flow_task.check_status_and_state.assert_any_call('test', 'set-extended-vlan-tagging-operation-configuration-data')
    flow_task.check_status_and_state.assert_any_call('test', 'flow-set-ext-vlan-tagging-op-config-data-untagged')


@mark.parametrize("enable_flag", [True, False])
def test_perform_flow_install_handles_exceptions_appropriately(flow_task, enable_flag):

    """This test case verifies negative cases as below
    1: Handler disabled - Should goto else back and make a errCallback
    2. Handler Enabled but exception thrown during OMCI Send req - Exception should be handled."""

    flow_task.check_status_and_state = Mock()
    flow_task._handler.enabled = enable_flag
    flow_task._install_by_delete = not enable_flag
    flow_task._onu_device.omci_cc = Mock()
    flow_task._onu_device.omci_cc.send = Mock(side_effect=Exception("test"))
    error_back = Mock()
    flow_task.deferred.addErrback(error_back)
    flow_task.perform_flow_install()
    error_back.assert_called()


def test_perform_flow_install_returns_if_flow_entry_vlan_vid_is_0(flow_task):
    flow_task.check_status_and_state = Mock()
    flow_task._onu_device.omci_cc = Mock()
    flow_task._flow_entry.vlan_vid = 0
    flow_task.perform_flow_install()
    flow_task._onu_device.omci_cc.assert_not_called()


def test_stop(flow_task):
    flow_task.cancel_deferred = Mock()
    flow_task.stop()
    flow_task.cancel_deferred.assert_called()
