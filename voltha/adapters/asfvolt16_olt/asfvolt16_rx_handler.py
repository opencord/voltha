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

"""
Asfvolt16 OLT adapter
"""

import structlog
from twisted.internet.defer import DeferredQueue
import arrow
import binascii
from twisted.internet import reactor
from common.utils.grpc_utils import twisted_async
from google.protobuf import empty_pb2
from voltha.adapters.asfvolt16_olt.protos import bal_indications_pb2
from voltha.adapters.asfvolt16_olt.protos import bal_msg_type_pb2, \
     bal_osmsg_pb2, bal_model_ids_pb2, bal_obj_pb2, bal_model_types_pb2, \
     bal_errno_pb2, bal_pb2
from voltha.adapters.device_handler import OltDeviceHandler
from voltha.adapters.asfvolt16_olt.grpc_server import GrpcServer


#log = structlog.get_logger()

class Asfvolt16RxHandler(object):
    def __init__(self, adapter, port, log):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.adapter_name = adapter.name
        self.grpc_server = None
        self.grpc_server_port = port
        self.log = log

    def start(self):
        self.grpc_server = GrpcServer(self.grpc_server_port, self, self.log)
        self.grpc_server.start(bal_indications_pb2.add_BalIndServicer_to_server, self)

    def stop(self):
        self.grpc_server.stop()

    def process_flow_ind(self, bal_indication, device_id):
        self.log.info('Flow indication is not implemented', device_id=device_id)

    def process_group_ind(self, bal_indication, device_id):
        self.log.info('Group indication is not implemented', device_id=device_id)

    def process_interface_ind(self, bal_indication, device_id):
        self.log.info('Inteface Ind received')
        self.log.info('Awaiting ONU discovery')
        return

    def process_packet_ind(self, bal_indication, device_id):
        self.log.info('received omci msg')
        proxy_address=Device.ProxyAddress(
                      device_id=device_id,
                      channel_id=bal_indication.balOmciResp.key.packet_send_dest.itu_omci_channel.sub_term_id,  
                      onu_id=bal_indication.balOmciResp.key.packet_send_dest.itu_omci_channel.sub_term_id,
                      onu_session_id=bal_indication.balOmciResp.key.packet_send_dest.itu_omci_channel.sub_term_id
        )
        self.adapter_agent.receive_proxied_message(proxy_address, bal_indication.balOmciRespInfo.data.pkt.val)

    def process_subscriber_term_ind(self, bal_indication, device_id):
        onu_data = bal_indication.terminal_disc
        self.log.info('Subscriber termination message received')
        #     ind_info: {'object_type': <str>
        #                '_device_id': <str>
        #                '_pon_id' : <int>
        #                'onu_id' : <int>
        #                '_vendor_id' : <str>
        #                '__vendor_specific' : <str>
        #                'activation_successful':[True or False]}

        ind_info = dict()
        ind_info['object_type'] = 'subscriber_terminal'
        ind_info['_device_id'] = device_id
        ind_info['_pon_id'] = onu_data.key.intf_id
        ind_info['onu_id'] = onu_data.key.sub_term_id
        ind_info['_vendor_id'] = '4252434D'
        ind_info['_vendor_specific'] = onu_data.data.serial_number.vendor_specific

        #if(bal_model_types_pb2.BAL_STATE_DOWN == onu_data.data.admin_state):
        #    ind_info['activation_successful']=False
        #elif(bal_model_types_pb2.BAL_STATE_UP == onu_data.data.admin_state):
        #    ind_info['activation_successful']=True
        reactor.callLater(0,
                          self.adapter.devices_handlers[device_id].handle_subscriber_term_ind, 
                          ind_info)

    def process_queue_ind(self, bal_indication, device_id):
        self.log.info('activating-olt', device_id=device_id)

    def process_sched_ind(self, bal_indication, device_id):
        self.log.info('activating-olt', device_id=device_id)

    def process_access_term_ind(self, bal_indication, device_id):
        self.log.info('Received access terminal Indication',
                                  device_id=device_id)
        #     ind_info: {'object_type': <str>
        #                'actv_status': <str>}
        ind_info = dict()
        ind_info['object_type'] = 'access_terminal'
        if bal_indication.access_term_ind.data.admin_state != bal_model_ids_pb2.BAL_ACCESS_TERMINAL_IND_ID_ADMIN_STATE:
            ind_info['actv_status'] = 'failed'
        else:
            ind_info['actv_status'] = 'success'

        reactor.callLater(0,
                          self.adapter.devices_handlers[device_id].handle_access_term_ind,
                          ind_info)

    ind_handlers = {
        bal_model_ids_pb2.BAL_OBJ_ID_ACCESS_TERMINAL : process_access_term_ind,
        bal_model_ids_pb2.BAL_OBJ_ID_FLOW            : process_flow_ind,
        bal_model_ids_pb2.BAL_OBJ_ID_GROUP           : process_group_ind,
        bal_model_ids_pb2.BAL_OBJ_ID_INTERFACE       : process_interface_ind,
        bal_model_ids_pb2.BAL_OBJ_ID_PACKET          : process_packet_ind,
        bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL : process_subscriber_term_ind,
        bal_model_ids_pb2.BAL_OBJ_ID_TM_QUEUE        : process_queue_ind,
        bal_model_ids_pb2.BAL_OBJ_ID_TM_SCHED        : process_sched_ind,
    }

    @twisted_async
    def BalIndInfo(self, request, context):
        self.log.info('get-device-info')
        self.log.info('received indication for object type',obj_type=request.objType)
        device_id = request.device_id.decode('unicode-escape')
        try:
            handler = self.ind_handlers.get(request.objType)
            if handler:
                handler(self, request, device_id)
        except Exception as e:
            self.log.exception('Invalid object type', e=e)

        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err
