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
from voltha.adapters.asfvolt16_olt.protos import bal_pb2, \
    bal_model_types_pb2, bal_model_ids_pb2
from voltha.adapters.asfvolt16_olt.grpc_client import GrpcClient
from common.utils.nethelpers import get_my_primary_interface, \
    get_my_primary_local_ipv4
import os

"""
ASFVOLT Adapter port is 60001
"""
ADAPTER_PORT = 60001

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
        try:
            os.environ["SERVICE_HOST_IP"]
            adapter_ip = os.environ["SERVICE_HOST_IP"]
        except Exception as e:
            self.log.info('voltha is running in non docker container environment')
            adapter_ip = get_my_primary_local_ipv4()

        ip_port = []
        ip_port.append(str(adapter_ip))
        ip_port.append(":")
        ip_port.append(str(ADAPTER_PORT))
        init.voltha_adapter_ip_port ="".join(ip_port)
        self.log.info('Adapter port Ip', init.voltha_adapter_ip_port)

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
        self.log.info('setting-admin-state',
                      admin_state=admin_state, device_id=self.device_id)
        obj = bal_pb2.BalCfg()
        obj.device_id = self.device_id.encode('ascii', 'ignore')
        obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_ACCESS_TERMINAL
        obj.cfg.key.access_term_id = 0
        obj.cfg.data.admin_state = admin_state
        yield self.stub.BalCfgSet(obj)

    @inlineCallbacks
    def activate_pon_port(self, olt_no, pon_port):
        self.log.info('activating-pon-port in olt',
                      olt=olt_no, pon_port=pon_port)
        try:
            obj = bal_pb2.BalCfg()
            #            Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_INTERFACE
            #            Fill Access Terminal Details
            obj.interface.key.intf_id = pon_port
            obj.interface.key.intf_type = bal_model_types_pb2.BAL_INTF_TYPE_PON
            obj.interface.data.admin_state = bal_model_types_pb2.BAL_STATE_UP
            obj.interface.data.transceiver_type = \
                bal_model_types_pb2.BAL_TRX_TYPE_XGPON_LTH_7226_PC
            yield self.stub.BalCfgSet(obj)
        except Exception as e:
            self.log.info('activating-pon-port in olt-exception', exc=str(e))
        return

    @inlineCallbacks
    def send_omci_request_message(self, proxy_address, msg):
        self.log.info('send_omci_request_message',
                      proxy_address=proxy_address.channel_id,
                      msg=msg)
        try:
            obj = bal_pb2.BalCfg()
            #            Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_PACKET
            #            Fill packet Details
            obj.packet.key.packet_send_dest.type = \
                bal_model_types_pb2.BAL_DEST_TYPE_ITU_OMCI_CHANNEL
            obj.packet.key.packet_send_dest.itu_omci_channel.sub_term_id = \
                proxy_address.onu_id
            obj.packet.key.packet_send_dest.itu_omci_channel.intf_id = \
                proxy_address.channel_id
            obj.packet.data.pkt = msg
            yield self.stub.BalCfgSet(obj)
        except Exception as e:
            self.log.info('send-proxied_message-exception', exc=str(e))
        return

    @inlineCallbacks
    def activate_onu(self, onu_info):
        self.log.info('activating-ONU in olt',
                      olt=self.olt.olt_id, onu_id=onu_info['onu_id'])
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL
            # Fill Access Terminal Details
            obj.terminal.key.intf_id = onu_info['pon_id']
            obj.terminal.key.sub_term_id = onu_info['onu_id']
            obj.terminal.data.admin_state = bal_model_types_pb2.BAL_STATE_UP
            obj.terminal.data.serial_number.vendor_id = onu_info['vendor']
            obj.terminal.data.serial_number.vendor_specific = \
                onu_info['vendor_specific']
            obj.terminal.data.registration_id = \
                '202020202020202020202020202020202020202020202020202020202020202020202020'
            yield self.stub.BalCfgSet(obj)
        except Exception as e:
            self.log.info('activating-ONU-exception',
                          onu_info['onu_id'], exc=str(e))
        return

    @inlineCallbacks
    def packet_out(self, onu_id, egress_port, pkt):
        self.log.info('packet-out', onu_id=onu_id, egress_port=egress_port)

        obj = bal_pb2.BalCfg()

        # Set the destination ONU info
        obj.packet.key.dest.packet_send_dest.sub_term.sub_term_id = onu_id
        # TODO: Need to provide correct values for sub_term_uni and int_id
        obj.packet.key.dest.packet_send_dest.sub_term.sub_term_uni = egress_port
        obj.packet.key.dest.packet_send_dest.sub_term.int_id = egress_port

        # Set the Packet-out info
        obj.packet.data.flow_type = BAL_FLOW_TYPE_DOWNSTREAM
        # TODO: Need to provide correct value for intf_id
        obj.packet.data.intf_id = egress_port
        obj.packet.data.pkt = pkt

        yield self.stub.BalCfgSet(obj)
