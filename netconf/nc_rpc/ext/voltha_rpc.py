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
import structlog
from netconf.nc_rpc.rpc import Rpc
import netconf.nc_common.error as ncerror
from twisted.internet.defer import inlineCallbacks, returnValue
import dicttoxml
from netconf.nc_common.utils import qmap, ns
from netconf.constants import Constants as C
from netconf.grpc_client.nc_rpc_mapper import \
    get_nc_rpc_mapper_instance

log = structlog.get_logger()


class VolthaRpc(Rpc):
    def __init__(self, request, request_xml, grpc_client, session,
                 capabilities):
        super(VolthaRpc, self).__init__(request, request_xml, grpc_client,
                                        session, capabilities)
        self.service = None
        self.method = None
        self.metadata = None
        self._extract_parameters()
        if not self.rpc_response.is_error:
            self._validate_parameters()

    @inlineCallbacks
    def execute(self):
        if self.rpc_response.is_error:
            returnValue(self.rpc_response)

        log.info('voltha-rpc-request', session=self.session.session_id,
                 request=self.request)

        # Execute the request
        res_dict, yang_options = yield self.grpc_client.invoke_voltha_rpc(
            service=self.service,
            method=self.method,
            params=self.request['params'],
            metadata=self.metadata)

        # convert dict to xml
        xml = dicttoxml.dicttoxml(res_dict, attr_type=True)
        log.info('voltha-info', res=res_dict, xml=xml)

        root_elem = self.get_root_element(xml)

        # Build the yang response
        self.rpc_response.node = self.rpc_response.build_yang_response(
            root_elem, self.request, yang_options=yang_options, custom_rpc=True)
        self.rpc_response.is_error = False

        returnValue(self.rpc_response)

    def _validate_parameters(self):
        log.info('validate-parameters', session=self.session.session_id)
        # For now just validate that the command is presenf
        if self.request:
            try:
                if self.request['command'] is None:
                    self.rpc_response.is_error = True
                    self.rpc_response.node = ncerror.BadMsg(self.request_xml)
                    return

            except Exception as e:
                self.rpc_response.is_error = True
                self.rpc_response.node = ncerror.ServerException(
                    self.request_xml)
                return

    def _parse_params(self, node):
        params = {}
        if node is not None:
            for r in node:
                children = r.getchildren()
                tag = r.tag.replace(qmap(C.VOLTHA), "")
                if children:
                    if tag in params:
                        if not isinstance(params[tag], list):
                            temp = []
                            temp.append(params[tag])
                            params[tag] = temp
                        params[tag].append(self._parse_params(children))
                    else:
                        params[tag] = self._parse_params(children)
                else:
                    # Convert string boolean to boolean
                    if r.text == 'true':
                        params[tag] = True
                    elif r.text == 'false':
                        params[tag] = False
                    else:
                        params[tag] = r.text
        return params

    def _extract_parameters(self):
        try:
            rpc_node = self.request_xml.find(''.join(
                [qmap(C.VOLTHA),
                 self.request['command']])
            )

            # Parse rpc the parameters
            self.request['params'] = self._parse_params(rpc_node)

            # Remove the subclass element in the request if it is present as
            # it is not required for rpc calls
            if self.request.has_key('subclass'):
                self.request.pop('subclass', None)

            # Extract the service and method from the rpc command
            command = self.request['command'].split('-')
            if len(command) != 2:
                log.debug('invalid-format', command=self.request['command'])
                raise

            self.service = command[0]
            self.method = command[1]
            if self.request.has_key('metadata'):
                self.metadata = self.request['metadata']

        except Exception as e:
            self.rpc_response.is_error = True
            self.rpc_response.node = ncerror.BadMsg(self.request_xml)
            log.exception('params-parsing-error', xml=self.request_xml, e=e)
