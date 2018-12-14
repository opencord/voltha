import pytest
import mock
import time

from voltha.adapters.adtran_olt.net.adtran_rest import AdtranRestClient

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
