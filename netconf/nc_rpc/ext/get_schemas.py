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


log = structlog.get_logger()


class GetSchemas(Rpc):
    def __init__(self, request, request_xml, grpc_client, session, capabilities):
        super(GetSchemas, self).__init__(request, request_xml, grpc_client,
                                         session, capabilities)
        self._validate_parameters()

    @inlineCallbacks
    def execute(self):
        if self.rpc_response.is_error:
            returnValue(self.rpc_response)

        log.info('get-schemas-request', session=self.session.session_id,
                 request=self.request)

        # Get the schema definitions
        schema_defs = self.capabilities.get_yang_schemas_definitions()
        log.info('schema-defs', definitions=schema_defs)

        # format the schemas in xml
        top = etree.Element('yang')
        for dict in schema_defs:
            schema = etree.SubElement(top, 'schema')
            node = etree.SubElement(schema, 'identifier')
            node.text = dict['id']
            node = etree.SubElement(schema, 'version')
            node.text = dict['version']
            node = etree.SubElement(schema, 'format')
            node.text = dict['format']
            node = etree.SubElement(schema, 'namespace')
            node.text = dict['namespace']
            node = etree.SubElement(schema, 'location')
            node.text = dict['location']

        # Build the yang response
        self.rpc_response.node = yield self.rpc_response.build_xml_response(
            self.request, top)

        self.rpc_response.is_error = False

        returnValue(self.rpc_response)


    def _validate_parameters(self):
        log.info('validate-parameters', session=self.session.session_id)
        # Validate the GET command
        if self.request:
            try:
                if self.request['command'] != 'get-schemas':
                    self.rpc_response.is_error = True
                    self.rpc_response.node = ncerror.BadMsg(self.request_xml)
                    return

                if self.request.has_key('filter'):
                    if not self.request.has_key('class'):
                        self.rpc_response.is_error = True
                        self.rpc_response.node = ncerror.BadMsg(self.request_xml)
                        return

            except Exception as e:
                self.rpc_response.is_error = True
                self.rpc_response.node = ncerror.BadMsg(self.request)
                return

