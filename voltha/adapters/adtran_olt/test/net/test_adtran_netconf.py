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
import pytest_twisted

from ncclient.transport.errors import SSHError
from ncclient.operations import RPCError
from voltha.adapters.adtran_olt.net import adtran_netconf



@pytest.fixture()
def test_client():
    return adtran_netconf.AdtranNetconfClient("1.2.3.4", 830, "username", "password")


@pytest.fixture(autouse=True)
def mock_manager():
    old_manager = adtran_netconf.manager
    adtran_netconf.manager = mock.MagicMock()
    yield adtran_netconf.manager
    adtran_netconf.manager = old_manager


@pytest.fixture(autouse=True)
def mock_logger():
    with mock.patch("voltha.adapters.adtran_olt.net.adtran_netconf.log") as temp_mock:
        yield temp_mock


def test_adtran_module_url():
    assert adtran_netconf.adtran_module_url("adtran-physical-entities") == "http://www.adtran.com/ns/yang/adtran-physical-entities"


def test_phys_entities_rpc():
    expected_out = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <physical-entities-state xmlns="http://www.adtran.com/ns/yang/adtran-physical-entities">
        <physical-entity/>
      </physical-entities-state>
    </filter>
    """
    assert adtran_netconf.phys_entities_rpc() == expected_out


def test_adtran_netconf_client_to_string(test_client):
    assert str(test_client) == "AdtranNetconfClient username@1.2.3.4:830"


def test_do_connect(test_client, mock_manager):
    mock_manager.connect.return_value = "This is good"
    assert "This is good" == test_client._do_connect(10)
    mock_manager.connect.assert_called_once_with(host="1.2.3.4",
                                                 port=830,
                                                 username="username",
                                                 password="password",
                                                 allow_agent=False,
                                                 look_for_keys=False,
                                                 hostkey_verify=False,
                                                 timeout=10)


def test_capabilities(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.server_capabilities = "Here's what I do...."
    assert "Here's what I do...." == test_client.capabilities


def test_connected(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.connected = True
    assert test_client.connected


def test_do_connect_with_ssh_error(test_client, mock_manager):
    mock_manager.connect.side_effect = SSHError()
    with pytest.raises(SSHError):
        test_client._do_connect(10)


def test_do_connect_with_literally_any_exception(test_client, mock_manager):
    mock_manager.connect.side_effect = SyntaxError()
    with pytest.raises(SyntaxError):
        test_client._do_connect(10)


def test_do_connect_reset_log_level(test_client, mock_manager, mock_logger):
    mock_logger.isEnabledFor.return_value = True
    test_client._do_connect(10)
    mock_logger.setLevel.assert_called_once_with("INFO")


def test_do_connect_dont_reset_log_level(test_client, mock_manager, mock_logger):
    mock_logger.isEnabledFor.return_value = False
    test_client._do_connect(10)
    assert mock_logger.setLevel.call_count == 0


@pytest_twisted.inlineCallbacks
def test_connect(test_client, mock_manager):
    mock_manager.connect.return_value = "This is good"
    output = yield test_client.connect(10)
    assert "This is good" == output


def test_do_close(test_client, mock_manager):
    mock_session = mock.MagicMock()
    test_client._do_close(mock_session)
    mock_session.close_session.assert_called_once_with()


@pytest_twisted.inlineCallbacks
def test_close(test_client):
    mock_session = mock.MagicMock()
    test_client._session = mock_session
    mock_session.connected = True
    yield test_client.close()
    mock_session.close_session.assert_called_once_with()


@pytest_twisted.inlineCallbacks
def test_close_not_connected(test_client):
    mock_session = mock.MagicMock()
    test_client._session = mock_session
    mock_session.connected = False
    output = yield test_client.close()
    assert output


@pytest_twisted.inlineCallbacks
def test_reconnect(test_client):
    with mock.patch.object(test_client, "connect") as mock_connect:
        with mock.patch.object(test_client, "close") as mock_close:
            yield test_client._reconnect()
            mock_connect.assert_called_once()
            mock_close.assert_called_once()


@pytest_twisted.inlineCallbacks
def test_reconnect_ignore_errors(test_client):
    with mock.patch.object(test_client, "connect") as mock_connect:
        with mock.patch.object(test_client, "close") as mock_close:
            mock_connect.side_effect = SyntaxError()
            mock_close.side_effect = SyntaxError()
            yield test_client._reconnect()
            mock_connect.assert_called_once()
            mock_close.assert_called_once()


def test_do_get_config(test_client):
    test_client._session = mock.MagicMock()
    test_client._do_get_config("running")
    test_client._session.get_config.assert_called_once_with("running")


@pytest_twisted.inlineCallbacks
def test_get_config(test_client):
    test_client._session = mock.MagicMock()
    yield test_client.get_config()
    test_client._session.get_config.assert_called_once_with("running")


@pytest_twisted.inlineCallbacks
def test_get_config_with_no_session(test_client):
    test_client._session = None
    with pytest.raises(NotImplementedError):
        yield test_client.get_config()


@pytest_twisted.inlineCallbacks
def test_get_config_session_not_connected(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.connected = False
    with mock.patch.object(test_client, "_reconnect") as mock_reconnect:
        yield test_client.get_config()
        mock_reconnect.assert_called_once()


def test_do_get(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.get.return_value = "<some>xml</some>"
    assert test_client._do_get("<get>xml</get>") == "<some>xml</some>"
    test_client._session.get.assert_called_once_with("<get>xml</get>")


def test_do_get_rpc_error(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.get.side_effect = RPCError(mock.MagicMock())
    with pytest.raises(RPCError):
        test_client._do_get("<get>xml</get>")


@pytest_twisted.inlineCallbacks
def test_get(test_client):
    test_client._session = mock.MagicMock()
    yield test_client.get("<get>xml</get>")
    test_client._session.get.assert_called_once_with("<get>xml</get>")


@pytest_twisted.inlineCallbacks
def test_get_with_no_session(test_client):
    test_client._session = None
    with pytest.raises(NotImplementedError):
        yield test_client.get("<get>xml</get>")


@pytest_twisted.inlineCallbacks
def test_get_session_not_connected(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.connected = False
    with mock.patch.object(test_client, "_reconnect") as mock_reconnect:
        yield test_client.get("<get>xml</get>")
        mock_reconnect.assert_called_once()


def test_do_lock(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.lock.return_value = "<ok>"
    assert test_client._do_lock("running", 10) == "<ok>"
    test_client._session.lock.assert_called_once_with("running", timeout=10)


def test_do_lock_rpc_error(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.lock.side_effect = RPCError(mock.MagicMock())
    with pytest.raises(RPCError):
        test_client._do_lock("running", 10)


@pytest_twisted.inlineCallbacks
def test_lock(test_client):
    test_client._session = mock.MagicMock()
    yield test_client.lock("running", 10)
    test_client._session.lock.assert_called_once_with("running", timeout=10)


@pytest_twisted.inlineCallbacks
def test_lock_with_no_session(test_client):
    test_client._session = None
    with pytest.raises(NotImplementedError):
        yield test_client.lock("running", 10)


def test_do_unlock(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.unlock.return_value = "<ok>"
    assert test_client._do_unlock("running") == "<ok>"
    test_client._session.unlock.assert_called_once_with("running")


def test_do_unlock_rpc_error(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.unlock.side_effect = RPCError(mock.MagicMock())
    with pytest.raises(RPCError):
        test_client._do_unlock("running")


@pytest_twisted.inlineCallbacks
def test_unlock(test_client):
    test_client._session = mock.MagicMock()
    yield test_client.unlock("running")
    test_client._session.unlock.assert_called_once_with("running")


@pytest_twisted.inlineCallbacks
def test_unlock_with_no_session(test_client):
    test_client._session = None
    with pytest.raises(NotImplementedError):
        yield test_client.unlock("running")


def test_do_edit_config(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.edit_config.return_value = "<ok>"
    assert test_client._do_edit_config("running", "<some>config</some>") == "<ok>"
    test_client._session.edit_config.assert_called_once_with(target="running", config="<some>config</some>")


def test_do_edit_config_rpc_error_and_ignore_delete_error(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.edit_config.side_effect = RPCError(mock.MagicMock())
    with pytest.raises(RPCError):
        test_client._do_edit_config("running", 'operation="delete"', ignore_delete_error=True)


def test_do_edit_config_rpc_error(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.edit_config.side_effect = RPCError(mock.MagicMock())
    with pytest.raises(RPCError):
        test_client._do_edit_config("running", "")


@pytest_twisted.inlineCallbacks
def test_edit_config_with_no_session(test_client):
    test_client._session = None
    with pytest.raises(NotImplementedError):
        yield test_client.edit_config("<some>config</some>")


@pytest_twisted.inlineCallbacks
def test_edit_config_session_not_connected(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.connected = False
    with mock.patch.object(test_client, "_reconnect") as mock_reconnect:
        yield test_client.edit_config("<some>config</some>")
        mock_reconnect.assert_called_once()


@pytest_twisted.inlineCallbacks
def test_edit_config_session_reconnect_causes_exception(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.connected = False
    with mock.patch.object(test_client, "_reconnect") as mock_reconnect:
        mock_reconnect.side_effect = SyntaxError()
        yield test_client.edit_config("<some>config</some>")
        mock_reconnect.assert_called_once()


@pytest_twisted.inlineCallbacks
def test_edit_config_with_config_at_start_of_xml(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.edit_config.return_value = "<ok>"
    yield test_client.edit_config("<config")
    test_client._session.edit_config.assert_called_once_with(target="running", config="<config")


@pytest_twisted.inlineCallbacks
def test_edit_config_without_config_at_start_of_xml(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.edit_config.return_value = "<ok>"
    yield test_client.edit_config("")
    test_client._session.edit_config.assert_called_once_with(
        target="running",
        config='<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"></config>')


@pytest_twisted.inlineCallbacks
def test_edit_config_with_any_exception(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.edit_config.side_effect = SyntaxError()
    with pytest.raises(SyntaxError):
        yield test_client.edit_config("<config")


@pytest_twisted.inlineCallbacks
def test_edit_config_with_any_exception_ignore_errors(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.edit_config.side_effect = SyntaxError()
    output = yield test_client.edit_config('operation="delete"', ignore_delete_error=True)
    assert output == 'ignoring-delete-error'


def test_do_rpc(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.dispatch.return_value = "<ok>"
    with mock.patch("voltha.adapters.adtran_olt.net.adtran_netconf.etree") as mock_etree:
        assert test_client._do_rpc("<rpc>xml</rpc>") == "<ok>"
        mock_etree.fromstring.assert_called_once_with("<rpc>xml</rpc>")


def test_do_rpc_with_rpc_error(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.dispatch.side_effect = RPCError(mock.MagicMock())
    with pytest.raises(RPCError):
        test_client._do_rpc("<rpc>xml</rpc>")


@pytest_twisted.inlineCallbacks
def test_rpc(test_client):
    test_client._session = mock.MagicMock()
    with mock.patch("voltha.adapters.adtran_olt.net.adtran_netconf.etree") as mock_etree:
        yield test_client.rpc("<rpc>xml</rpc>")
        mock_etree.fromstring.assert_called_once_with("<rpc>xml</rpc>")


@pytest_twisted.inlineCallbacks
def test_rpc_with_no_session(test_client):
    test_client._session = None
    with pytest.raises(NotImplementedError):
        yield test_client.rpc("<rpc>xml</rpc>")


@pytest_twisted.inlineCallbacks
def test_rpc_session_reconnect(test_client):
    test_client._session = mock.MagicMock()
    test_client._session.connected = False
    with mock.patch.object(test_client, "_reconnect") as mock_reconnect:
        yield test_client.rpc("<rpc>xml</rpc>")
        mock_reconnect.assert_called_once()
