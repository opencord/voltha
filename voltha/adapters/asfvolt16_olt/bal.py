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

from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.adapters.asfvolt16_olt.protos import bal_pb2, bal_obj_pb2, \
    bal_model_types_pb2, bal_model_ids_pb2
from voltha.adapters.asfvolt16_olt.grpc_client import GrpcClient

class Bal(object):
    def __init__(self, olt, log):
        self.log = log
        self.grpc_client = GrpcClient(self.log)
        self.stub = None
        self.device_id = None
        self.olt = olt

    @inlineCallbacks
    def connect_olt(self, host_and_port, device_id):
        self.log.info('connecting-olt', host_and_port=host_and_port)
        self.device_id = device_id
        self.grpc_client.connect(host_and_port)
        self.stub = bal_pb2.BalStub(self.grpc_client.channel)
        init = bal_pb2.BalInit()
        '''
        TODO: Need to determine out what information
        needs to be sent to the OLT at this stage.
        '''
        yield self.stub.BalApiInit(init)

    def activate_olt(self):
        self.log.info('activating-olt')
        self.set_access_terminal_admin_state(bal_model_types_pb2.BAL_STATE_UP)

    @inlineCallbacks
    def set_access_terminal_admin_state(self, admin_state):
        #import pdb; pdb.set_trace()
        self.log.info('setting-admin-state', admin_state=admin_state, device_id=self.device_id)
        obj = bal_pb2.BalCfg()
        obj.device_id = self.device_id.encode('ascii', 'ignore')
        obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_ACCESS_TERMINAL
        obj.cfg.key.access_term_id = 0
        obj.cfg.data.admin_state = admin_state
	yield self.stub.BalCfgSet(obj)

    @inlineCallbacks
    def activate_pon_port(self, olt_no, pon_port):
        self.log.info('activating-pon-port in olt', olt=olt_no, pon_port=pon_port)
        try:
            obj = bal_pb2.BalCfg()
            #Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_INTERFACE
            #Fill Access Terminal Details
            obj.interface.key.intf_id = pon_port
            obj.interface.key.intf_type = bal_model_types_pb2.BAL_INTF_TYPE_PON
            obj.interface.data.admin_state = bal_model_types_pb2.BAL_STATE_UP
	    yield self.stub.BalCfgSet(obj)
        except Exception as e:
            self.log.info('activating-pon-port in olt-exception', exc=str(e))
        return

    @inlineCallbacks
    def send_omci_request_message(self, proxy_address, msg):
        if isinstance(msg, Packet):
            msg = str(msg)

        self.log.info('send_omci_request_message',
                      proxy_address=proxy_address.channel_id,
                      msg=msg)
        try:
            obj = bal_pb2.BalCfg()
            #Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_PACKET
            #Fill packet Details
            obj.packet.key.packet_send_dest.type = bal_model_types_pb2.BAL_DEST_TYPE_ITU_OMCI_CHANNEL
            obj.packet.key.packet_send_dest.itu_omci_channel.sub_term_id = proxy_address.channel_id
            obj.packet.key.packet_send_dest.itu_omci_channel.int_id = 0
            obj.packet.data.pkt = msg
	    yield self.stub.BalCfgSet(obj)
        except Exception as e:
            self.log.info('send-proxied_message-exception', exc=str(e))
        return
