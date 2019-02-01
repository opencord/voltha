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
"""
Adtran generic VOLTHA device handler
"""
import pytest
import argparse
import pytest_twisted
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, succeed, Deferred
from twisted.internet.error import ConnectError
import mock
from voltha.adapters.adtran_olt.test.net.mock_netconf_client import MockNetconfClient
from voltha.adapters.adtran_olt.adtran_device_handler import (
    AdtranDeviceHandler, AdtranNetconfClient, AdtranRestClient, AdminState,
    AdapterAlarms, OperStatus, ConnectStatus,
    DEFAULT_MULTICAST_VLAN, _DEFAULT_NETCONF_PORT, _DEFAULT_RESTCONF_PORT,
    DEFAULT_PON_AGENT_TCP_PORT, DEFAULT_PIO_TCP_PORT
)


@pytest.fixture()
def device():
    dev = mock.MagicMock()
    dev.ipv4_address = '1.2.3.4'
    dev.extra_args = '-u NCUSER -p NCPASS -U RUSER -P RPASS'
    dev.images.image[0].version = b'test-version'
    dev.hardware_version = 'A'
    dev.serial_number = 'LBADTN123456789'
    dev.id = b'test-id'
    dev.admin_state = AdminState.ENABLED
    yield dev


@pytest.fixture()
def simple_handler(device):
    adapter = mock.MagicMock()
    adapter.adapter_agent.get_device.return_value = device
    adapter.adapter_agent.create_logical_device.return_value = device
    adapter.adapter_agent.get_logical_device.return_value = device
    AdtranDeviceHandler.NC_CLIENT = MockNetconfClient
    yield AdtranDeviceHandler(**{
        "adapter": adapter,
        "device-id": '123'
    })
    AdtranDeviceHandler.NC_CLIENT = AdtranNetconfClient


def test_properties(simple_handler):
    assert simple_handler.netconf_client is None
    assert simple_handler.rest_client is None
    assert str(simple_handler) == "AdtranDeviceHandler: None"

    simple_handler.northbound_ports = {1: '1'}
    simple_handler.southbound_ports = {10: '10'}
    assert ['1', '10'] == list(simple_handler.all_ports)


def test_evcs(simple_handler):
    evc = mock.MagicMock()
    evc.name = "Magical EVC"
    assert simple_handler.evcs == []
    simple_handler.add_evc(evc)
    simple_handler.add_evc(evc)
    assert simple_handler.evcs == [evc]
    simple_handler.remove_evc(evc)
    simple_handler.remove_evc(evc)
    assert simple_handler.evcs == []


@pytest.mark.parametrize('method, args', [
    ('is_uni_port', (1,)),
    ('is_pon_port', (1,)),
    ('get_port_name', (1,)),
    ('initialize_resource_manager', ()),
    ('packet_out', (None, None))
])
def test_abstract_method(simple_handler, method, args):
    with pytest.raises(NotImplementedError):
        getattr(simple_handler, method)(*args)


@pytest.fixture(params=[
    "'device_information', (None,)",
    "'enumerate_northbound_ports', (None,)",
    "'process_northbound_ports', (None, None)",
    "'enumerate_southbound_ports', (None,)",
    "'process_southbound_ports', (None, None)",
    "'complete_device_specific_activation', (None, None)",
    "'ready_network_access', ()",
])
def abstract_inline_callbacks(simple_handler, request):
    method, args = eval(request.param)
    d = getattr(simple_handler, method)(*args)
    assert isinstance(d, Deferred)
    reactor.callLater(0.0, d.callback, "Test Abstract Callback")
    return pytest.blockon(d)


def test_abstract_inline_callbacks(abstract_inline_callbacks):
    assert abstract_inline_callbacks == "Test Abstract Callback"


def test_parser_port_number():
    args = AdtranDeviceHandler.PARSER.parse_args('')
    assert args.nc_port == _DEFAULT_NETCONF_PORT
    assert args.rc_port == _DEFAULT_RESTCONF_PORT
    assert args.zmq_port == DEFAULT_PON_AGENT_TCP_PORT
    assert args.pio_port == DEFAULT_PIO_TCP_PORT

    args = AdtranDeviceHandler.PARSER.parse_args('-t 1'.split())
    assert args.nc_port == 1

    args = AdtranDeviceHandler.PARSER.parse_args('-t 65535'.split())
    assert args.nc_port == 65535

    with pytest.raises(argparse.ArgumentTypeError):
        AdtranDeviceHandler.PARSER.parse_args('-t 0'.split())

    with pytest.raises(argparse.ArgumentTypeError):
        AdtranDeviceHandler.PARSER.parse_args('-t 65536'.split())

    with pytest.raises(argparse.ArgumentTypeError):
        AdtranDeviceHandler.PARSER.parse_args('-t sixty-six'.split())


def test_parser_vlan():
    args = AdtranDeviceHandler.PARSER.parse_args('')
    assert args.multicast_vlan == [DEFAULT_MULTICAST_VLAN]

    args = AdtranDeviceHandler.PARSER.parse_args('-M 1 1028 4094'.split())
    assert args.multicast_vlan == [1, 1028, 4094]

    with pytest.raises(argparse.ArgumentTypeError):
        AdtranDeviceHandler.PARSER.parse_args('-M 4095'.split())

    with pytest.raises(argparse.ArgumentTypeError):
        AdtranDeviceHandler.PARSER.parse_args('-M 0'.split())

    with pytest.raises(argparse.ArgumentTypeError):
        AdtranDeviceHandler.PARSER.parse_args('-M forty-six'.split())


@pytest.mark.parametrize('host_and_port', [None, '1.2.3.4:22'])
def test_parse_provisioning_options(simple_handler, device, host_and_port):
    assert simple_handler.netconf_username == ''
    assert simple_handler.netconf_password == ''
    assert simple_handler.rest_username == ''
    assert simple_handler.rest_password == ''
    if host_and_port:
        device.ipv4_address = None
        device.host_and_port = host_and_port

    simple_handler.parse_provisioning_options(device)
    assert simple_handler.multicast_vlans == [DEFAULT_MULTICAST_VLAN]
    assert simple_handler.netconf_username == 'NCUSER'
    assert simple_handler.netconf_password == 'NCPASS'
    assert simple_handler.rest_username == 'RUSER'
    assert simple_handler.rest_password == 'RPASS'


@pytest_twisted.inlineCallbacks
def test_make_netconf_connection(simple_handler):
    AdtranDeviceHandler.NC_CLIENT = AdtranNetconfClient
    with mock.patch('voltha.adapters.adtran_olt.net.adtran_netconf.AdtranNetconfClient.connect'):
        yield simple_handler.make_netconf_connection()
        assert isinstance(simple_handler.netconf_client, AdtranNetconfClient)
        first_client = simple_handler.netconf_client

        yield simple_handler.make_netconf_connection(close_existing_client=True)
        assert isinstance(simple_handler.netconf_client, AdtranNetconfClient)
        assert first_client is not simple_handler.netconf_client


@pytest_twisted.inlineCallbacks
def test_make_rest_connection(simple_handler):
    with mock.patch('voltha.adapters.adtran_olt.net.adtran_rest.AdtranRestClient.request',
                    return_value={'module-info': {}}) as request:
        yield simple_handler.make_restconf_connection()
        request.assert_called_once_with('GET', simple_handler.HELLO_URI, name='hello', timeout=simple_handler.timeout)
        assert isinstance(simple_handler.rest_client, AdtranRestClient)


@pytest_twisted.inlineCallbacks
def test_make_rest_connection_bad_response(simple_handler):
    with mock.patch('voltha.adapters.adtran_olt.net.adtran_rest.AdtranRestClient.request',
                    return_value={}):
        with pytest.raises(ConnectError):
            yield simple_handler.make_restconf_connection()
        assert simple_handler.rest_client is None


@inlineCallbacks
def mock_restconf_request(method, uri, name, timeout):
    assert method == 'GET'
    assert uri == AdtranDeviceHandler.HELLO_URI
    assert name == 'hello'
    assert timeout in [0, 20]
    yield None
    returnValue({'module-info': []})


def test_check_pulse(simple_handler, device):
    simple_handler.check_pulse()
    assert simple_handler.heartbeat is None
    assert simple_handler.heartbeat_count == 0

    # Prepare for Successful Check Pulse
    simple_handler._rest_client = mock.MagicMock(autospec=AdtranRestClient)
    simple_handler._rest_client.request = mock_restconf_request
    simple_handler.logical_device_id = 1234
    simple_handler.HEARTBEAT_TIMEOUT = 0
    simple_handler.alarms = AdapterAlarms(simple_handler.adapter_agent, device.id, device.id)

    simple_handler.check_pulse()
    assert simple_handler.heartbeat_miss == 0
    assert simple_handler.heartbeat_count == 1
    simple_handler._suspend_heartbeat()

    simple_handler.check_pulse()
    assert simple_handler.heartbeat_miss == 0
    assert simple_handler.heartbeat_count == 2
    simple_handler._suspend_heartbeat()

    simple_handler.heartbeat_miss = 2
    simple_handler._heartbeat_fail(Exception('Boom'))
    assert simple_handler.heartbeat_miss == 3
    assert simple_handler.heartbeat_count == 3
    simple_handler._suspend_heartbeat()


@pytest_twisted.inlineCallbacks
def test_activate(simple_handler, device):
    @inlineCallbacks
    def mock_netconf_ready():
        yield
        returnValue('ready')

    @inlineCallbacks
    def enumerate_ports(_device):
        yield None
        returnValue([])

    simple_handler.ready_network_access = mock_netconf_ready
    simple_handler.enumerate_northbound_ports = enumerate_ports
    simple_handler.process_northbound_ports = lambda dev, results: 'ok'
    simple_handler.enumerate_southbound_ports = enumerate_ports
    simple_handler.process_southbound_ports = lambda dev, results: 'ok'
    simple_handler.initialize_resource_manager = lambda: 'done'
    simple_handler.complete_device_specific_activation = lambda dev, rec: succeed('Done')

    simple_handler._rest_client = mock.MagicMock(autospec=AdtranRestClient)
    simple_handler._rest_client.request = mock_restconf_request

    result = yield simple_handler.activate(None, False)
    assert result == 'activated'

    # Test Side Effects
    assert simple_handler.netconf_client is not None
    assert simple_handler.rest_client is not None
    assert simple_handler.logical_device_id == 'test-id'
    assert device.model == 'unknown'
    assert device.vendor == 'Adtran Inc.'

    # Reconcile
    simple_handler._delete_logical_device()
    result = yield simple_handler.activate(None, True)
    assert result == 'activated'


@pytest_twisted.inlineCallbacks
def test_reenable(simple_handler, device):
    simple_handler._initial_enable_complete = True
    yield simple_handler.reenable()
    assert device.oper_status == OperStatus.ACTIVE


@pytest_twisted.inlineCallbacks
def test_disable(simple_handler, device):
    device.oper_status = OperStatus.ACTIVE
    simple_handler.logical_device_id = 1234
    yield simple_handler.disable()
    assert device.oper_status == OperStatus.UNKNOWN


@pytest_twisted.inlineCallbacks
def test_reboot(simple_handler, device):
    device.oper_status = OperStatus.ACTIVE
    device.connect_status = ConnectStatus.REACHABLE
    simple_handler._initial_enable_complete = True
    yield simple_handler.make_netconf_connection()
    yield simple_handler.reboot()
    simple_handler._cancel_tasks()
    assert device.oper_status == OperStatus.ACTIVATING
    assert device.connect_status == ConnectStatus.UNREACHABLE


@pytest_twisted.inlineCallbacks
def test_finish_reboot(simple_handler, device):
    device.oper_status = OperStatus.ACTIVATING
    device.connect_status = ConnectStatus.UNREACHABLE
    yield simple_handler._finish_reboot(0, OperStatus.ACTIVE, ConnectStatus.REACHABLE)
    simple_handler._cancel_tasks()
    assert device.oper_status == OperStatus.ACTIVE
    assert device.connect_status == ConnectStatus.REACHABLE


@pytest_twisted.inlineCallbacks
def test_delete(simple_handler, device):
    device.oper_status = OperStatus.ACTIVE
    simple_handler.logical_device_id = 1234
    yield simple_handler.delete()
    assert device.reason == 'Deleting'


