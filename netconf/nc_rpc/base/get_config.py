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
from netconf.constants import Constants as C

log = structlog.get_logger()


class GetConfig(Rpc):
    def __init__(self, request, request_xml, grpc_client, session,
                 capabilities):
        super(GetConfig, self).__init__(request, request_xml, grpc_client,
                                        session, capabilities)
        self._validate_parameters()

    def execute(self):
        log.info('get-config-request', session=self.session.session_id)
        if self.rpc_response.is_error:
            return self.rpc_response

    def _validate_parameters(self):
        log.info('validate-parameters', session=self.session.session_id)

        self.params = self.rpc_method.getchildren()
        paramslen = len(self.params)
        # Verify that the source parameter is present
        if paramslen > 2:
            # TODO: need to specify all elements not known
            self.rpc_response.is_error = True
            self.rpc_response.node = ncerror.BadMsg(self.rpc_request)
            return

        self.source_param = self.rpc_method.find(C.NC_SOURCE,
                                                 namespaces=C.NS_MAP)
        # if self.source_param is None:
        # 	self.rpc_response.is_error = True
        # 	self.rpc_response.node = ncerror.MissingElement(
        # 		self.rpc_request, elm(C.NC_SOURCE))
        # 	return

        self.filter_param = None
        if paramslen == 2:
            self.filter_param = self.rpc_method.find(C.NC_FILTER,
                                                     namespaces=C.NS_MAP)
            if self.filter_param is None:
                unknown_elm = self.params[0] if self.params[0] != \
                                                self.source_param else \
                    self.params[1]
                self.rpc_response.is_error = True
                self.rpc_response.node = ncerror.UnknownElement(
                    self.rpc_request, unknown_elm)

        self.params = [self.source_param, self.filter_param]
