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
from mock import MagicMock
from mock import patch


from voltha.adapters.adtran_onu.adtran_onu import AdtranOnuAdapter


@pytest.fixture(scope='function')
def device_info():
    device = MagicMock()
    device.root = False
    device.vendor = 'Adtran Inc.'
    device.model = 'n/a'
    device.hardware_version = 'n/a'
    device.firmware_version = 'n/a'
    device.reason = ''
    device.id = "test_1"
    return device


@pytest.fixture(scope='function')
def adapter_agent():
    aa = MagicMock()
    return aa


@pytest.fixture(scope='function')
def onu_handler():
    onu_handler = MagicMock()
    return onu_handler


@pytest.fixture(scope='function')
def onu_adapter(adapter_agent, onu_handler):
    adtran_onu = AdtranOnuAdapter(adapter_agent, "test_1")
    adtran_onu.devices_handlers["test_1"] = onu_handler
    return adtran_onu


def test_initialized_properties(onu_adapter):
    assert onu_adapter.name == 'adtran_onu'
    assert onu_adapter.adtran_omci is not None
    assert onu_adapter.omci_agent is not None


@pytest.mark.parametrize('method, args', [
    ('suppress_alarm', (None, )),
    ('unsuppress_alarm', (None, )),
    ('download_image', (None, None)),
    ('activate_image_update', (None, None)),
    ('cancel_image_download', (None, None)),
    ('revert_image_update', (None, None)),
    ('get_image_download_status', (None, None)),
    ('update_flows_incrementally', (None, None, None)),
    ('send_proxied_message', (None, None)),
    ('get_device_details', (None, )),
    ('change_master_state', (None, )),
    ('abandon_device', (None, )),
    ('receive_onu_detect_state', (None, None)),
    ('receive_packet_out', (None, None, None)),
])
def test_method_throws_not_implemented_error(onu_adapter, method, args):
    with pytest.raises(NotImplementedError):
        getattr(onu_adapter, method)(*args)


@pytest.mark.parametrize('method, args', [
    ('create_multicast_gemport', (None, None)),
    ('update_multicast_gemport', (None, None)),
    ('remove_multicast_gemport', (None, None)),
    ('create_multicast_distribution_set', (None, None)),
    ('update_multicast_distribution_set', (None, None)),
    ('remove_multicast_distribution_set', (None, None))
])
def test_method_throws_type_error(onu_adapter, method, args):
    with pytest.raises(TypeError):
        getattr(onu_adapter, method)(*args)


@pytest.mark.parametrize("device", [device_info(), None])
def test_receive_inter_adapter_message(onu_adapter, onu_handler, device):
    msg = dict()
    msg['proxy_address'] = '1.2.3.4'
    onu_adapter.adapter_agent.get_child_device_with_proxy_address.return_value = device
    onu_adapter.receive_inter_adapter_message(msg)
    onu_adapter.adapter_agent.get_child_device_with_proxy_address.assert_called_with('1.2.3.4')
    if device is not None:
        onu_handler.event_messages.put.assert_called_with(msg)


def test_receive_proxied_message(onu_adapter, onu_handler, device_info):
    onu_adapter.adapter_agent.get_child_device_with_proxy_address.return_value = device_info
    onu_adapter.receive_proxied_message(device_info, 'test')
    onu_adapter.adapter_agent.get_child_device_with_proxy_address.assert_called_with(device_info)
    onu_handler.receive_message.assert_called_with('test')


def test_create_interface(onu_adapter, onu_handler, device_info):
    data = {"test": "dummy"}
    with patch('voltha.adapters.adtran_onu.adtran_onu.reactor.callLater') as call_later:
        onu_adapter.create_interface(device_info, data)
    call_later.assert_called_with(0, onu_handler.xpon_create, data)


def test_update_interface(onu_adapter, onu_handler, device_info):
    data = {"test": "dummy"}
    onu_adapter.update_interface(device_info, data)
    onu_handler.xpon_update.assert_called_with(data)


def test_remove_interface(onu_adapter, onu_handler, device_info):
    data = {"test": "dummy"}
    onu_adapter.remove_interface(device_info, data)
    onu_handler.xpon_remove.assert_called_with(data)


def test_create_tcont(onu_adapter, onu_handler, device_info):
    onu_adapter.create_tcont(device_info, "tcont_data", "traffic_desriptor_data")
    onu_handler.create_tcont.assert_called_with("tcont_data", "traffic_desriptor_data")


def test_update_tcont(onu_adapter, onu_handler, device_info):
    onu_adapter.update_tcont(device_info, "tcont_data", "traffic_desriptor_data")
    onu_handler.update_tcont.assert_called_with("tcont_data", "traffic_desriptor_data")


def test_remove_tcont(onu_adapter, onu_handler, device_info):
    onu_adapter.remove_tcont(device_info, "tcont_data", "traffic_desriptor_data")
    onu_handler.remove_tcont.assert_called_with("tcont_data", "traffic_desriptor_data")


def test_create_gemport(onu_adapter, onu_handler, device_info):
    data = {"test": "dummy"}
    onu_adapter.create_gemport(device_info, data)
    onu_handler.xpon_create.assert_called_with(data)


def test_update_gemport(onu_adapter, onu_handler, device_info):
    data = {"test": "dummy"}
    onu_adapter.update_gemport(device_info, data)
    onu_handler.xpon_update.assert_called_with(data)


def test_remove_gemport(onu_adapter, onu_handler, device_info):
    data = {"test": "dummy"}
    onu_adapter.remove_gemport(device_info, data)
    onu_handler.xpon_remove.assert_called_with(data)


def test_adapter_start(onu_adapter):
    onu_adapter._omci_agent.start = MagicMock()
    onu_adapter.start()
    onu_adapter._omci_agent.start.assert_called()


def test_adapter_stop(onu_adapter):
    onu_adapter._omci_agent.stop = MagicMock()
    onu_adapter.stop()
    assert onu_adapter._omci_agent is None

