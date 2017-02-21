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

log = structlog.get_logger()


class CloseSession(Rpc):
    def __init__(self, request, request_xml, grpc_client, session,
                 capabilities):
        super(CloseSession, self).__init__(request, request_xml, grpc_client,
                                           session, capabilities)
        self._validate_parameters()

    def execute(self):
        log.info('close-session-request', session=self.session.session_id)
        if self.rpc_response.is_error:
            return self.rpc_response

        self.rpc_response.node = etree.Element("ok")

        # Set the close session flag
        self.rpc_response.close_session = True
        return self.rpc_response

    def _validate_parameters(self):

        if self.request:
            try:
                if self.request['command'] != 'close-session':
                    self.rpc_response.is_error = True
                    self.rpc_response.node = ncerror.BadMsg(self.request_xml)
                    return

            except Exception as e:
                self.rpc_response.is_error = True
                self.rpc_response.node = ncerror.ServerException(
                    self.request_xml)
                return
