#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
#
# Code adapted from https://github.com/choppsv1/netconf
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

from  rpc_response import RpcResponse
from lxml import etree
import io


class Rpc(object):
    def __init__(self, request_dict, request_xml, grpc_client, session,
                 capabilities):
        self.request = request_dict
        self.request_xml = request_xml
        self.rpc_response = RpcResponse(capabilities)
        self.grpc_client = grpc_client
        self.session = session
        self.capabilities = capabilities

    def execute(self):
        """ run the command - returns a OperationResponse """
        pass

    def set_rpc_response(self):
        self.rpc_response = RpcResponse()

    def _validate_parameters(self, rpc_request):
        """Sets and validates the node as well"""
        pass

    def get_root_element(self, xml_msg):
        tree = etree.parse(io.BytesIO(xml_msg))
        return tree.getroot()
