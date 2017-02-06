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
from netconf.constants import Constants as C
from netconf.nc_common.utils import qmap
from twisted.internet.defer import inlineCallbacks, returnValue

log = structlog.get_logger()

class GetSchema(Rpc):
    def __init__(self, request, request_xml, grpc_client, session, capabilities):
        super(GetSchema, self).__init__(request, request_xml, grpc_client,
                                        session, capabilities)
        # specific schema parsing required
        self.parse_schema_request(request_xml)
        self._validate_parameters()

    @inlineCallbacks
    def execute(self):
        if self.rpc_response.is_error:
            returnValue(self.rpc_response)

        log.info('get-schema-request', session=self.session.session_id,
                 request=self.request)

        # Get the yang schema content
        # TODO: Use version as well
        content = yield self.capabilities.get_schema_content(self.request[
                                                            'identifier'])
        if not content:
            self.rpc_response.is_error = True
            self.rpc_response.node = ncerror.BadMsg(self.request_xml)
            returnValue(self.rpc_response)

        self.rpc_response.node = yield self.create_xml_response(content)

        self.rpc_response.is_error = False

        returnValue(self.rpc_response)

    def _validate_parameters(self):
        log.info('validate-parameters', session=self.session.session_id)
        # Validate the GET-SCHEMA command
        if self.request:
            try:
                if self.request['command'] != 'get-schema' or \
                        not self.request.has_key('identifier') or \
                        not self.request.has_key('format') or \
                        not self.request.has_key('version'):
                    self.rpc_response.is_error = True
                    self.rpc_response.node = ncerror.BadMsg(self.request_xml)
                    return

                if self.request.has_key('filter'):
                    if not self.request.has_key('class'):
                        self.rpc_response.is_error = True
                        self.rpc_response.node = ncerror.BadMsg(
                            self.request_xml)
                        return

                # Verify that the requested schema exists
                if not self.capabilities.is_schema_supported(self.request[
                                                             'identifier']) \
                        or self.request['format'] != 'yang' :
                    self.rpc_response.is_error = True
                    self.rpc_response.node = ncerror.BadMsg(self.request_xml)
                    return

            except Exception as e:
                self.rpc_response.is_error = True
                self.rpc_response.node = ncerror.BadMsg(self.request)
                return

    # Parse context-specific parameters
    def parse_schema_request(self, node):
        if not len(node):
            return
        schema_node = node.find(''.join([qmap(C.NCM), 'get-schema']))
        if schema_node is not None:
            for item in ['identifier', 'version', 'format']:
                elem = schema_node.find(''.join([qmap(C.NCM), item]))
                if elem is not None:
                    self.request[item] = elem.text

    def create_xml_response(self, content):
        ns = {}
        ns['xmlns'] = C.NS_MAP['ncm']

        elem = etree.Element('data', attrib=ns)
        elem.text = unicode(content, "utf-8")
        return elem
