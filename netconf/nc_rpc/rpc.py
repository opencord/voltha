#!/usr/bin/env python
#
# Copyright 2016 the original author or authors.
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

class Rpc(object):
    def __init__(self,rpc_request, rpc_method, session):
        self.rpc_request = rpc_request
        self.rpc_method = rpc_method
        self.rpc_response = RpcResponse()
        self.session = session

    def execute(self):
        """ run the command - returns a OperationResponse """
        pass

    def set_rpc_response(self):
        self.rpc_response = RpcResponse()

    def _validate_parameters(self, rpc_request):
        """Sets and validates the node as well"""
        pass
