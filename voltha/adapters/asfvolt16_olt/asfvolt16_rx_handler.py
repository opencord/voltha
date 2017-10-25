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
from twisted.internet import reactor
from common.utils.grpc_utils import twisted_async
from voltha.adapters.asfvolt16_olt.protos import bal_indications_pb2
from voltha.adapters.asfvolt16_olt.protos import bal_model_types_pb2, \
    bal_errno_pb2, bal_pb2
from voltha.adapters.asfvolt16_olt.grpc_server import GrpcServer
from voltha.adapters.asfvolt16_olt.asfvolt16_ind_handler import Asfvolt16IndHandler


class Asfvolt16RxHandler(object):

    def __init__(self, adapter, port, log):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.adapter_name = adapter.name
        self.grpc_server = None
        self.grpc_server_port = port
        self.log = log
        self.ind_handler = Asfvolt16IndHandler(log)

    def start(self):
        self.grpc_server = GrpcServer(self.grpc_server_port, self, self.log)
        self.grpc_server.start(
            bal_indications_pb2.add_BalIndServicer_to_server, self)

    def stop(self):
        self.grpc_server.stop()

    @twisted_async
    def BalAccTermOperStsCngInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_acc_term_oper_sts_cng_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalAccTermInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Received access terminal Indication',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_acc_term_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalFlowOperStsCng(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_flow_oper_sts_cng(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalFlowInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_flow_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalGroupInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_group_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceOperStsCng(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_iface_oper_sts_cng(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceLos(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Interface Loss Of Signal Alarm',\
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_iface_los(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Interface indication Received',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_iface_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceStat(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_iface_stat(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermOperStsCng(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_subs_term_oper_sts_cng(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermDiscoveryInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Subscriber terminal discovery Indication',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_subs_term_discovery_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermAlarmInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('ONU Alarms for Subscriber Terminal',\
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_subs_term_alarm_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermDgiInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Subscriber terminal dying gasp', \
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_subs_term_dgi_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Subscriber terminal indication received',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_subs_term_ind(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalTmQueueIndInfo(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_tm_queue_ind_info(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalTmSchedIndInfo(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_tm_sched_ind_info(request, device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalPktBearerChannelRxInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Received Packet-In',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_pkt_bearer_channel_rx_ind(request,
                                                       device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalPktOmciChannelRxInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Received OMCI Messages',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_pkt_omci_channel_rx_ind(request,
                                                     device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalPktIeeeOamChannelRxInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        device_handler = self.adapter.devices_handlers[device_id]
        self.ind_handler.bal_pkt_ieee_oam_channel_rx_ind(request,
                                                         device_handler)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err
