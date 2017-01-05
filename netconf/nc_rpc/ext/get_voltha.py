#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
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
from lxml import etree
import structlog
from netconf.nc_rpc.rpc import Rpc
import netconf.nc_common.error as ncerror
from twisted.internet.defer import inlineCallbacks, returnValue
import dicttoxml

log = structlog.get_logger()


class GetVoltha(Rpc):
    def __init__(self, request, request_xml, grpc_client, session, capabilities):
        super(GetVoltha, self).__init__(request, request_xml, grpc_client, session)
        self._validate_parameters()


    @inlineCallbacks
    def execute(self):
        log.info('get-voltha-request', session=self.session.session_id,
                 method=self.rpc_method)
        if self.rpc_response.is_error:
            returnValue(self.rpc_response)

        # Invoke voltha via the grpc client
        res_dict = yield self.grpc_client.invoke_voltha_api(self.voltha_method_ref)

        # convert dict to xml
        xml = dicttoxml.dicttoxml(res_dict, attr_type=False)
        log.info('voltha-info', res=res_dict, xml=xml)

        root_elem = self.get_root_element(xml)
        root_elem.tag = 'data'

        self.rpc_method.append(root_elem)
        self.rpc_response.node = self.rpc_method
        self.rpc_response.is_error = False

        returnValue(self.rpc_response)


    def _validate_parameters(self):
        log.info('validate-parameters', session=self.session.session_id)
        self.params = self.rpc_method.getchildren()
        if len(self.params) > 1:
            self.rpc_response.is_error = True
            self.rpc_response.node = ncerror.BadMsg(self.rpc_request)
            return

        if not self.params:
            self.params = [None]
