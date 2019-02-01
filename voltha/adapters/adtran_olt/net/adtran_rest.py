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

import json

import structlog
import treq
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.error import ConnectionClosed, ConnectionDone, ConnectionLost

log = structlog.get_logger()


class RestInvalidResponseCode(Exception):
    def __init__(self, message, url, code):
        super(RestInvalidResponseCode, self).__init__(message)
        self.url = url
        self.code = code


class AdtranRestClient(object):
    """
    Performs Adtran RESTCONF requests
    """
    # HTTP shortcuts
    HELLO_URI = '/restconf/adtran-hello:hello'

    REST_GET_REQUEST_HEADER = {'User-Agent': 'Adtran RESTConf',
                               'Accept': ['application/json']}

    REST_POST_REQUEST_HEADER = {'User-Agent': 'Adtran RESTConf',
                                'Content-Type': 'application/json',
                                'Accept': ['application/json']}

    REST_PATCH_REQUEST_HEADER = REST_POST_REQUEST_HEADER
    REST_PUT_REQUEST_HEADER = REST_POST_REQUEST_HEADER
    REST_DELETE_REQUEST_HEADER = REST_GET_REQUEST_HEADER

    HTTP_OK = 200
    HTTP_CREATED = 201
    HTTP_ACCEPTED = 202
    HTTP_NON_AUTHORITATIVE_INFORMATION = 203
    HTTP_NO_CONTENT = 204
    HTTP_RESET_CONTENT = 205
    HTTP_PARTIAL_CONTENT = 206
    HTTP_NOT_FOUND = 404

    _valid_methods = {'GET', 'POST', 'PATCH', 'DELETE'}
    _valid_results = {'GET': [HTTP_OK, HTTP_NO_CONTENT],
                      'POST': [HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT],
                      'PUT': [HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT],
                      'PATCH': [HTTP_OK],
                      'DELETE': [HTTP_OK, HTTP_ACCEPTED, HTTP_NO_CONTENT, HTTP_NOT_FOUND]
                      }

    for _method in _valid_methods:
        assert _method in _valid_results  # Make sure we have a results entry for each supported method

    def __init__(self, host_ip, port, username='', password='', timeout=10.0):
        """
        REST Client initialization

        :param str host_ip: IP Address of Adtran Device
        :param int port: Port number
        :param str username: Username for credentials
        :param str password: Password for credentials
        :param float timeout: Number of seconds to wait for a response before timing out
        """
        self._ip = host_ip
        self._port = port
        self._username = username
        self._password = password
        self._timeout = timeout

    def __str__(self):
        return "AdtranRestClient {}@{}:{}".format(self._username, self._ip, self._port)

    @inlineCallbacks
    def request(self, method, uri, data=None, name='', timeout=None, is_retry=False,
                suppress_error=False, **kwargs):
        """
        Send a REST request to the Adtran device

        :param str method: HTTP method
        :param str uri: fully URL to perform method on
        :param Optional[str] data: optional data for the request body
        :param str name: optional name of the request, useful for logging purposes
        :param Optional[float] timeout: Number of seconds to wait for a response before timing out
        :param bool is_retry: True if this method called recursively in order to recover
                              from a connection loss. Can happen sometimes in debug sessions
                              and in the real world.
        :param bool suppress_error: If true, do not output ERROR message on REST request failure
        :keyword dict json: json body passed as a dictionary and used in the absence of data

        :return: On success with the proper results
        :rtype dict
        """
        log.debug('request', method=method, uri=uri, data=data, retry=is_retry)

        if method.upper() not in self._valid_methods:
            raise NotImplementedError("REST method '{}' is not supported".format(method))

        url = 'http://{}:{}{}{}'.format(self._ip, self._port,
                                        '/' if uri[0] != '/' else '',
                                        uri)
        response = None
        timeout = timeout or self._timeout

        json_data = kwargs.get('json')
        if data is None and json_data:
            data = json.dumps(json_data)

        try:
            if method.upper() == 'GET':
                response = yield treq.get(url,
                                          auth=(self._username, self._password),
                                          timeout=timeout,
                                          headers=self.REST_GET_REQUEST_HEADER)
            elif method.upper() == 'POST' or method.upper() == 'PUT':
                response = yield treq.post(url,
                                           data=data,
                                           auth=(self._username, self._password),
                                           timeout=timeout,
                                           headers=self.REST_POST_REQUEST_HEADER)
            elif method.upper() == 'PATCH':
                response = yield treq.patch(url,
                                            data=data,
                                            auth=(self._username, self._password),
                                            timeout=timeout,
                                            headers=self.REST_PATCH_REQUEST_HEADER)
            elif method.upper() == 'DELETE':
                response = yield treq.delete(url,
                                             auth=(self._username, self._password),
                                             timeout=timeout,
                                             headers=self.REST_DELETE_REQUEST_HEADER)

        except NotImplementedError:
            raise

        except (ConnectionDone, ConnectionLost):
            if is_retry:
                raise
            returnValue(self.request(method, uri, data=data, name=name,
                                     timeout=timeout, is_retry=True))

        except ConnectionClosed:
            returnValue(ConnectionClosed)

        except Exception as e:
            log.exception("rest-request", method=method, url=url, name=name, e=e)
            raise

        if response.code not in self._valid_results[method.upper()]:
            message = "REST {} '{}' request to '{}' failed with status code {}".format(method, name,
                                                                                       url, response.code)
            if not suppress_error:
                log.error(message)
            raise RestInvalidResponseCode(message, url, response.code)

        if response.code in {self.HTTP_NO_CONTENT, self.HTTP_NOT_FOUND}:
            returnValue(None)

        else:
            # TODO: May want to support multiple body encodings in the future

            headers = response.headers
            type_key = 'content-type'
            type_val = 'application/json'

            if not headers.hasHeader(type_key) or type_val not in headers.getRawHeaders(type_key, []):
                raise Exception("REST {} '{}' request response from '{}' was not JSON",
                                method, name, url)

            content = yield response.content()
            try:
                result = json.loads(content)

            except Exception as e:
                log.exception("json-decode", method=method, url=url, name=name,
                              content=content, e=e)
                raise

            returnValue(result)
