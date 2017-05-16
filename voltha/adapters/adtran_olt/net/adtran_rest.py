#
# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import json

import structlog
import treq
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.error import ConnectionClosed

log = structlog.get_logger()


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

    _valid_methods = {'GET', 'POST', 'PATCH', 'DELETE'}
    _valid_results = {'GET': [HTTP_OK, HTTP_NO_CONTENT],
                      'POST': [HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT],
                      'PUT': [HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT],
                      'PATCH': [HTTP_OK],
                      'DELETE': [HTTP_OK, HTTP_ACCEPTED, HTTP_NO_CONTENT]
                      }

    for _method in _valid_methods:
        assert _method in _valid_results  # Make sure we have a results entry for each supported method

    def __init__(self, host_ip, port, username='', password='', timeout=20):
        """
        REST Client initialization

        :param host_ip: (string) IP Address of Adtran Device
        :param port: (int) Port number
        :param username: (string) Username for credentials
        :param password: (string) Password for credentials
        :param timeout: (int) Number of seconds to wait for a response before timing out
        """
        self.ip = host_ip
        self.rest_port = port
        self.username = username
        self.password = password
        self.timeout = timeout

    @inlineCallbacks
    def request(self, method, uri, data=None, name=''):
        """
        Send a REST request to the Adtran device

        :param method: (string) HTTP method
        :param uri: (string) fully URL to perform method on
        :param data: (string) optional data for the request body
        :param name: (string) optional name of the request, useful for logging purposes
        :return: (deferred)
        """

        if method.upper() not in self._valid_methods:
            raise NotImplementedError("REST method '{}' is not supported".format(method))

        url = 'http://{}:{}{}{}'.format(self.ip, self.rest_port,
                                        '/' if uri[0] != '/' else '',
                                        uri)
        try:
            if method.upper() == 'GET':
                response = yield treq.get(url,
                                          auth=(self.username, self.password),
                                          timeout=self.timeout,
                                          headers=self.REST_GET_REQUEST_HEADER)
            elif method.upper() == 'POST' or method.upper() == 'PUT':
                response = yield treq.post(url,
                                           data=data,
                                           auth=(self.username, self.password),
                                           timeout=self.timeout,
                                           headers=self.REST_POST_REQUEST_HEADER)
            elif method.upper() == 'PATCH':
                response = yield treq.patch(url,
                                            data=data,
                                            auth=(self.username, self.password),
                                            timeout=self.timeout,
                                            headers=self.REST_PATCH_REQUEST_HEADER)
            elif method.upper() == 'DELETE':
                response = yield treq.delete(url,
                                             auth=(self.username, self.password),
                                             timeout=self.timeout,
                                             headers=self.REST_DELETE_REQUEST_HEADER)
            else:
                raise NotImplementedError("REST method '{}' is not supported".format(method))

        except NotImplementedError:
            raise

        except ConnectionClosed:
            returnValue(None)

        except Exception, e:
            log.exception("REST {} '{}' request to '{}' failed: {}".format(method, name, url, str(e)))
            raise

        if response.code not in self._valid_results[method.upper()]:
            message = "REST {} '{}' request to '{}' failed with status code {}".format(method, name,
                                                                                       url, response.code)
            log.error(message)
            raise Exception(message)

        if response.code == self.HTTP_NO_CONTENT:
            returnValue(None)

        else:
            # TODO: May want to support multiple body encodings in the future

            headers = response.headers
            type_key = 'content-type'
            type_val = 'application/json'

            if not headers.hasHeader(type_key) or type_val not in headers.getRawHeaders(type_key, []):
                raise Exception("REST {} '{}' request response from '{} was not JSON",
                                method, name, url)

            content = yield response.content()
            try:
                result = json.loads(content)

            except Exception, e:
                log.exception("REST {} '{}' JSON decode of '{}' failure: {}".format(method, name,
                                                                                    url, str(e)))
                raise

            returnValue(result)
