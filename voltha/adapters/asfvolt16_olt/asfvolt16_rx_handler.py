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
        self.grpc_server.start(
            bal_indications_pb2.add_BalIndServicer_to_server, self)

    def stop(self):
        self.grpc_server.stop()

    @twisted_async
    def BalAccTermOperStsCngInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'access_terminal_indication'
        ind_info['_sub_group_type'] = 'oper_state_change'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalAccTermInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Received access terminal Indication',
                      device_id=device_id, obj_type=request.objType)
        #     ind_info: {'_object_type': <str>
        #                'actv_status': <str>}
        ind_info = dict()
        ind_info['_object_type'] = 'access_terminal_indication'
        ind_info['_sub_group_type'] = 'access_terminal_indication'
        if request.access_term_ind.data.admin_state == \
                bal_model_types_pb2.BAL_STATE_UP:
            ind_info['activation_successful'] = True
        else:
            ind_info['activation_successful'] = False

        device_handler = self.adapter.devices_handlers[device_id]
        reactor.callLater(0,
                          device_handler.handle_access_term_ind,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalFlowOperStsCng(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'flow_indication'
        ind_info['_sub_group_type'] = 'oper_state_change'
        ind_info['_object_type'] = request.objType
        ind_info['_sub_group_type'] = request.sub_group
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalFlowInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'flow_indication'
        ind_info['_sub_group_type'] = 'flow_indication'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalGroupInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'group_indication'
        ind_info['_sub_group_type'] = 'group_indication'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceOperStsCng(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'interface_indication'
        ind_info['_sub_group_type'] = 'oper_state_change'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceLos(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Interface Loss Of Signal Alarm',\
                      device_id=device_id, obj_type=request.objType)
        los_status = request.interface_los.data.status
        if los_status != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:

           balIfaceLos_dict = { }
           balIfaceLos_dict["los_status"]=los_status.__str__()

           device_handler = self.adapter.devices_handlers[device_id]
           reactor.callLater(0,\
                             device_handler.BalIfaceLosAlarm,\
                             device_id,request.interface_los.key.intf_id,\
                             los_status,balIfaceLos_dict)

        ind_info = dict()
        ind_info['_object_type'] = 'interface_indication'
        ind_info['_sub_group_type'] = 'loss_of_signal'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Interface indication Received',
                      device_id=device_id, obj_type=request.objType)
        self.log.info('Awaiting ONU discovery')
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalIfaceStat(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'interface_indication'
        ind_info['_sub_group_type'] = 'stat_indication'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermOperStsCng(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'sub_term_indication'
        ind_info['_sub_group_type'] = 'oper_state_change'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermDiscoveryInd(self, request, context):
        #     ind_info: {'object_type': <int>
        #                '_sub_group_type': <str>
        #                '_device_id': <str>
        #                '_pon_id' : <int>
        #                'onu_id' : <int>
        #                '_vendor_id' : <str>
        #                '__vendor_specific' : <str>
        #                'activation_successful':[True or False]}

        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Subscriber terminal discovery Indication',
                      device_id=device_id, obj_type=request.objType)
        onu_data = request.terminal_disc
        ind_info = dict()
        ind_info['_object_type'] = 'sub_term_indication'
        ind_info['_sub_group_type'] = 'onu_discovery'
        ind_info['_device_id'] = device_id
        ind_info['_pon_id'] = onu_data.key.intf_id
        ind_info['onu_id'] = onu_data.key.sub_term_id
        ind_info['_vendor_id'] = onu_data.data.serial_number.vendor_id
        ind_info['_vendor_specific'] = \
            onu_data.data.serial_number.vendor_specific
        device_handler = self.adapter.devices_handlers[device_id]
        reactor.callLater(0,
                          device_handler.handle_sub_term_ind,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermAlarmInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('ONU Alarms for Subscriber Terminal',\
                      device_id=device_id, obj_type=request.objType)
        #Loss of signal
        los = request.terminal_alarm.data.alarm.los
        #Loss of busrt
        lob = request.terminal_alarm.data.alarm.lob
        #Loss of PLOAM miss channel
        lopc_miss = request.terminal_alarm.data.alarm.lopc_miss
        #Loss of PLOAM channel
        lopc_mic_error = request.terminal_alarm.data.alarm.lopc_mic_error

        balSubTermAlarm_Dict = { }
        balSubTermAlarm_Dict["LOS Status"]=los.__str__()
        balSubTermAlarm_Dict["LOB Status"]=lob.__str__()
        balSubTermAlarm_Dict["LOPC MISS Status"]=lopc_miss.__str__()
        balSubTermAlarm_Dict["LOPC MIC ERROR Status"]=lopc_mic_error.__str__()

        device_handler = self.adapter.devices_handlers[device_id]

        if los != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
           reactor.callLater(0, device_handler.BalSubsTermLosAlarm,\
                             device_id,request.terminal_alarm.key.intf_id,\
                             los, balSubTermAlarm_Dict)

        if lob != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
           reactor.callLater(0, device_handler.BalSubsTermLobAlarm,\
                             device_id,request.terminal_alarm.key.intf_id,\
                             lob, balSubTermAlarm_Dict)

        if lopc_miss != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
           reactor.callLater(0, device_handler.BalSubsTermLopcMissAlarm,\
                             device_id,request.terminal_alarm.key.intf_id,\
                             lopc_miss, balSubTermAlarm_Dict)

        if lopc_mic_error != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
           reactor.callLater(0, device_handler.BalSubsTermLopcMicErrorAlarm,\
                             device_id,request.terminal_alarm.key.intf_id,\
                             lopc_mic_error, balSubTermAlarm_Dict)

        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermDgiInd(self, request, context):
        self.log.info('Subscriber terminal Indication received')
        #     ind_info: {'_object_type': <str>
        #                '_device_id': <str>
        #                '_pon_id' : <int>
        #                'onu_id' : <int>
        #                '_vendor_id' : <str>
        #                '__vendor_specific' : <str>
        #                'activation_successful':[True or False]}
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Subscriber terminal dying gasp',\
                      device_id=device_id, obj_type=request.objType)

        dgi_status = request.terminal_dgi.data.dgi_status

        if dgi_status != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:

           ind_info = dict()
           ind_info['_object_type'] = 'sub_term_indication'
           ind_info['_sub_group_type'] = 'dgi_indication'

           balSubTermDgi_Dict = { }
           balSubTermDgi_Dict["dgi_status"]=dgi_status.__str__()

           device_handler = self.adapter.devices_handlers[device_id]
           reactor.callLater(0,
                             device_handler.BalSubsTermDgiAlarm,
                             device_id,request.terminal_dgi.key.intf_id,\
                             request.terminal_dgi.key.sub_term_id, \
                             dgi_status,balSubTermDgi_Dict, ind_info)

        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalSubsTermInd(self, request, context):
        #     ind_info: {'_object_type': <str>
        #                '_sub_group_type': <str>
        #                '_device_id': <str>
        #                '_pon_id' : <int>
        #                'onu_id' : <int>
        #                '_vendor_id' : <str>
        #                '__vendor_specific' : <str>
        #                'activation_successful':[True or False]}
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Subscriber terminal indication received',
                      device_id=device_id, obj_type=request.objType)
        onu_data = request.terminal_ind
        ind_info = dict()
        ind_info['_object_type'] = 'sub_term_indication'
        ind_info['_sub_group_type'] = 'sub_term_indication'
        ind_info['_device_id'] = device_id
        ind_info['_pon_id'] = onu_data.key.intf_id
        ind_info['onu_id'] = onu_data.key.sub_term_id
        ind_info['_vendor_id'] = onu_data.data.serial_number.vendor_id
        ind_info['_vendor_specific'] = \
            onu_data.data.serial_number.vendor_specific
        if ((bal_model_types_pb2.BAL_STATE_DOWN == onu_data.data.admin_state)
            or (bal_model_types_pb2.BAL_STATUS_UP != onu_data.data.oper_status)):
            ind_info['activation_successful'] = False
        elif (bal_model_types_pb2.BAL_STATE_UP == onu_data.data.admin_state):
            ind_info['activation_successful'] = True

        device_handler = self.adapter.devices_handlers[device_id]
        reactor.callLater(0,
                          device_handler.handle_sub_term_ind,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalTmQueueIndInfo(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'tm_q_indication'
        ind_info['_sub_group_type'] = 'tm_q_indication'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalTmSchedIndInfo(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'tm_sched_indication'
        ind_info['_sub_group_type'] = 'tm_sched_indication'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalPktBearerChannelRxInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Received Packet-In',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['flow_id'] = request.pktData.data.flow_id
        ind_info['flow_type'] = request.pktData.data.flow_type
        ind_info['intf_id'] = request.pktData.data.intf_id
        ind_info['intf_type'] = request.pktData.data.intf_type
        ind_info['svc_port'] = request.pktData.data.svc_port
        ind_info['flow_cookie'] = request.pktData.data.flow_cookie
        ind_info['packet'] = request.pktData.data.pkt
        device_handler = self.adapter.devices_handlers[device_id]
        reactor.callLater(0,
                          device_handler.handle_packet_in,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalPktOmciChannelRxInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Received OMCI Messages',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'packet_in_indication'
        ind_info['_sub_group_type'] = 'omci_message'
        ind_info['_device_id'] = device_id
        packet_data = request.balOmciResp.key.packet_send_dest
        ind_info['onu_id'] = packet_data.itu_omci_channel.sub_term_id
        ind_info['packet'] = request.balOmciResp.data.pkt
        self.log.info('ONU Id is',
                      onu_id=packet_data.itu_omci_channel.sub_term_id)

        device_handler = self.adapter.devices_handlers[device_id]
        reactor.callLater(0,
                          device_handler.handle_omci_ind,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @twisted_async
    def BalPktIeeeOamChannelRxInd(self, request, context):
        device_id = request.device_id.decode('unicode-escape')
        self.log.info('Not implemented yet',
                      device_id=device_id, obj_type=request.objType)
        ind_info = dict()
        ind_info['_object_type'] = 'packet_in_indication'
        ind_info['_sub_group_type'] = 'ieee_oam_message'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err
