#!/usr/bin/env python
#
# Copyright 2016 the original author or authors.
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
from netconf.utils import filter_tag_match

log = structlog.get_logger()

class Get(Rpc):

	def __init__(self, rpc_request, rpc_method, grpc_client, session):
		super(Get, self).__init__(rpc_request, rpc_method, grpc_client,
								  session)
		self._validate_parameters()

	def execute(self):
		log.info('get-request', session=self.session.session_id)
		if self.rpc_response.is_error:
			return self.rpc_response

	def _validate_parameters(self):
		log.info('validate-parameters', session=self.session.session_id)
		self.params = self.rpc_method.getchildren()
		if len(self.params) > 1:
			self.rpc_response.is_error = True
			self.rpc_response.node = ncerror.BadMsg(self.rpc_request)
			return

		if self.params and not filter_tag_match(self.params[0], C.NC_FILTER):
			self.rpc_response.is_error = True
			self.rpc_response.node = ncerror.UnknownElement(
				self.rpc_request, self.params[0])
			return

		if not self.params:
			self.params = [None]


