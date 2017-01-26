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


class Validate(Rpc):
    def __init__(self, request, request_xml, grpc_client, session,
                 capabilities):
        super(Validate, self).__init__(request, grpc_client, session,
                                       capabilities)
        self._validate_parameters()

    def execute(self):
        log.info('Validate-request', session=self.session.session_id)
        if self.rpc_response.is_error:
            return self.rpc_response

    def _validate_parameters(self):
        log.info('validate-parameters', session=self.session.session_id)
