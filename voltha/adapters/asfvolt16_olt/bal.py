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

from twisted.internet.defer import inlineCallbacks

from voltha.adapters.asfvolt16_olt.protos import bal_pb2, bal_obj_pb2, \
    bal_model_types_pb2
from voltha.adapters.asfvolt16_olt.grpc_client import GrpcClient

class Bal(object):
    def __init__(self, log):
        self.log = log
        self.grpc_client = GrpcClient(self.log)

    @inlineCallbacks
    def connect_olt(self, host_and_port):
        self.log.info('connecting-olt', host_and_port=host_and_port)
        self.grpc_client.connect(host_and_port)
        self.stub = bal_pb2.BalStub(self.grpc_client.channel)
        init = bal_pb2.BalInit()
        '''
        TODO: Need to determine out what information
        needs to be sent to the OLT at this stage.
        '''
        yield self.stub.BalApiInit(init)

    def activate_olt(self, olt_id):
        self.log.info('activating-olt')
        self.set_access_terminal_admin_state(bal_model_types_pb2.BAL_STATE_UP, olt_id)

    @inlineCallbacks
    def set_access_terminal_admin_state(self, admin_state, olt_id):
        self.log.info('setting-admin-state', admin_state=admin_state, olt_id=olt_id)
        cfg = bal_pb2.BalCfg()
        cfg.hdr.type = bal_obj_pb2.BAL_OBJ_MSG_TYPE_SET
        cfg.cfg.key.access_term_id = olt_id
        cfg.cfg.data.admin_state = admin_state
        yield self.stub.BalCfgSet(cfg)
