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
import pytest_twisted
import json
import mock

from voltha.adapters.adtran_olt.net.adtran_rest import AdtranRestClient, RestInvalidResponseCode
from twisted.internet.error import ConnectionClosed, ConnectionDone, ConnectionLost


GET_LIKE_ARGS = {
    "auth": ("user", "password"),
    "timeout": 10,
    "headers": {
       "User-Agent": "Adtran RESTConf",
       "Accept": ["application/json"]
    }
}

SOME_JSON = json.dumps({"some": "json"})

POST_LIKE_ARGS = {
    "data": SOME_JSON,
    "auth": ("user", "password"),
    "timeout": 10,
    "headers": {
       "User-Agent": "Adtran RESTConf",
       "Content-Type": "application/json",
       "Accept": ["application/json"]
    }
}


class MockResponse(object):
    def __init__(self, code):
        self.code = code
        self.headers = mock.MagicMock()
        self.content = mock.MagicMock()


@pytest.fixture()
def test_client():
    return AdtranRestClient("1.2.3.4", "80", "user", "password")


@pytest.fixture(autouse=True)
def mock_treq():
    with mock.patch("voltha.adapters.adtran_olt.net.adtran_rest.treq") as mock_obj:
        yield mock_obj


def test_adtran_rest_str(test_client):
    assert str(test_client) == "AdtranRestClient user@1.2.3.4:80"


def test_get_request(test_client, mock_treq):
    test_client.request("GET", "/test/uri")
    mock_treq.get.assert_called_once_with("http://1.2.3.4:80/test/uri", **GET_LIKE_ARGS)


def test_post_request(test_client, mock_treq):
    test_client.request("POST", "/test/uri", SOME_JSON)
    mock_treq.post.assert_called_once_with("http://1.2.3.4:80/test/uri", **POST_LIKE_ARGS)


def test_post_json_request(test_client, mock_treq):
    test_client.request("POST", "/test/uri", json={"some": "json"})
    mock_treq.post.assert_called_once_with("http://1.2.3.4:80/test/uri", **POST_LIKE_ARGS)


def test_patch_request(test_client, mock_treq):
    test_client.request("PATCH", "/test/uri", SOME_JSON)
    mock_treq.patch.assert_called_once_with("http://1.2.3.4:80/test/uri", **POST_LIKE_ARGS)


def test_delete_request(test_client, mock_treq):
    test_client.request("DELETE", "/test/uri", SOME_JSON)
    mock_treq.delete.assert_called_once_with("http://1.2.3.4:80/test/uri", **GET_LIKE_ARGS)


@pytest_twisted.inlineCallbacks
def test_bad_http_method(test_client):
    with pytest.raises(NotImplementedError):
        yield test_client.request("UPDATE", "/test/uri", SOME_JSON, is_retry=True)


@pytest_twisted.inlineCallbacks
def test_method_not_implemented(test_client, mock_treq):
    mock_treq.post.side_effect = NotImplementedError()
    with pytest.raises(NotImplementedError):
        yield test_client.request("POST", "/test/uri", SOME_JSON, is_retry=True)


@pytest_twisted.inlineCallbacks
def test_connection_closed(test_client, mock_treq):
    mock_treq.post.side_effect = ConnectionClosed()
    output = yield test_client.request("POST", "/test/uri", SOME_JSON)
    assert output == ConnectionClosed


@pytest_twisted.inlineCallbacks
def test_connection_lost(test_client, mock_treq):
    mock_treq.post.side_effect = ConnectionLost()
    with pytest.raises(ConnectionLost):
        yield test_client.request("POST", "/test/uri", SOME_JSON, is_retry=True)


@pytest_twisted.inlineCallbacks
def test_connection_done(test_client, mock_treq):
    mock_treq.post.side_effect = ConnectionDone()
    with pytest.raises(ConnectionDone):
        yield test_client.request("POST", "/test/uri", SOME_JSON, is_retry=True)


@pytest_twisted.inlineCallbacks
def test_literally_any_other_exception(test_client, mock_treq):
    mock_treq.post.side_effect = SyntaxError()
    with pytest.raises(SyntaxError):
        yield test_client.request("POST", "/test/uri", SOME_JSON, is_retry=True)


@pytest_twisted.inlineCallbacks
def test_204(test_client, mock_treq):
    mock_treq.post.side_effect = [MockResponse(204)]
    output = yield test_client.request("POST", "/test/uri", SOME_JSON)
    assert output is None


@pytest_twisted.inlineCallbacks
def test_404_on_delete(test_client, mock_treq):
    mock_treq.delete.side_effect = [MockResponse(404)]
    output = yield test_client.request("DELETE", "/test/uri", SOME_JSON)
    assert output is None


@pytest_twisted.inlineCallbacks
def test_404_on_post(test_client, mock_treq):
    mock_treq.post.side_effect = [MockResponse(404)]
    with pytest.raises(RestInvalidResponseCode,
                       message="REST POST '' request to 'http://1.2.3.4:80/test/uri' failed with status code 404"):
        yield test_client.request("POST", "/test/uri", SOME_JSON)


@pytest_twisted.inlineCallbacks
def test_no_headers(test_client, mock_treq):
    mock_resp = MockResponse(200)
    mock_treq.post.side_effect = [mock_resp]
    mock_resp.headers.hasHeader.return_value = False
    with pytest.raises(Exception):
        yield test_client.request("POST", "/test/uri", SOME_JSON)


@pytest_twisted.inlineCallbacks
def test_good_request(test_client, mock_treq):
    mock_resp = MockResponse(200)
    mock_treq.post.side_effect = [mock_resp]
    mock_resp.headers.hasHeader.return_value = True
    mock_resp.headers.getRawHeaders.return_value = ['application/json']
    mock_resp.content.return_value = """{"other": "json"}"""
    output = yield test_client.request("POST", "/test/uri", SOME_JSON)
    assert output == {"other": "json"}


@pytest_twisted.inlineCallbacks
def test_bad_json(test_client, mock_treq):
    mock_resp = MockResponse(200)
    mock_treq.post.side_effect = [mock_resp]
    mock_resp.headers.hasHeader.return_value = True
    mock_resp.headers.getRawHeaders.return_value = ['application/json']
    mock_resp.content.return_value = """{"other": "json}"""
    with pytest.raises(ValueError):
        yield test_client.request("POST", "/test/uri", SOME_JSON)
