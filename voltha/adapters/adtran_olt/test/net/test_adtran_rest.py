import pytest
import pytest_twisted
import mock

from voltha.adapters.adtran_olt.net.adtran_rest import AdtranRestClient
from twisted.internet.error import ConnectionClosed, ConnectionDone, ConnectionLost

POST_LIKE_ARGS = {
    "data": {"some": "json"},
    "auth": ("user", "password"),
    "timeout": 10,
    "headers": {
       "User-Agent": "Adtran RESTConf",
       "Content-Type": "application/json",
       "Accept": ["application/json"]
    }
}

@pytest.fixture()
def test_client():
    return AdtranRestClient("1.2.3.4", "80", "user", "password")


@pytest.yield_fixture(autouse=True)
def mock_treq():
    with mock.patch("voltha.adapters.adtran_olt.net.adtran_rest.treq") as mock_obj:
        yield mock_obj


@pytest_twisted.inlineCallbacks
def assert_ouput(deffered, expected_value):
    def assert_equals(resolved):
        assert resolved == expected_value
    deffered.addCallback(assert_equals)
    yield deffered


def test_adtran_rest_str(test_client):
    assert str(test_client) == "AdtranRestClient user@1.2.3.4:80"


def test_get_request(test_client, mock_treq):
    test_client.request("GET", "/test/uri")
    mock_treq.get.assert_called_once_with("http://1.2.3.4:80/test/uri",
                                          auth=("user", "password"),
                                          timeout=10,
                                          headers={
                                              'User-Agent': 'Adtran RESTConf',
                                              'Accept': ['application/json']
                                          })


def test_post_request(test_client, mock_treq):
    test_client.request("POST", "/test/uri", {"some": "json"})
    mock_treq.post.assert_called_once_with("http://1.2.3.4:80/test/uri", **POST_LIKE_ARGS)


def test_patch_request(test_client, mock_treq):
    test_client.request("PATCH", "/test/uri", {"some": "json"})
    mock_treq.patch.assert_called_once_with("http://1.2.3.4:80/test/uri", **POST_LIKE_ARGS)


def test_connection_closed(test_client, mock_treq):
    mock_treq.post.side_effect = ConnectionClosed()
    return assert_ouput(test_client.request("POST", "/test/uri", {"some": "json"}), ConnectionClosed)
