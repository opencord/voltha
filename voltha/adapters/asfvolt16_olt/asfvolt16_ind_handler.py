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
    bal_errno_pb2, bal_pb2, bal_model_ids_pb2
from voltha.adapters.asfvolt16_olt.grpc_server import GrpcServer


class Asfvolt16IndHandler(object):
    def __init__(self, log):
        self.log = log

    def bal_acc_term_oper_sta_cng(self, indication, device_handler):
        self.log.info("access-term-oper-status-change", indication=indication)
        ind_info = dict()
        ind_info['_object_type'] = 'access_term_ind'
        ind_info['_sub_group_type'] = 'oper_state_change'
        ind_info['activation_successful'] = False
        ind_info['deactivation_successful'] = False
        if indication.access_term_ind_op_state.data.admin_state is \
                bal_model_types_pb2.BAL_STATE_UP and \
                indication.access_term_ind_op_state.data.new_oper_status is \
                bal_model_types_pb2.BAL_STATUS_UP:
            ind_info['activation_successful'] = True
        elif indication.access_term_ind_op_state.data.admin_state is \
                bal_model_types_pb2.BAL_STATE_DOWN and \
                indication.access_term_ind_op_state.data.new_oper_status is \
                bal_model_types_pb2.BAL_STATUS_DOWN:
            ind_info['deactivation_successful'] = True

        reactor.callLater(0,
                          device_handler.handle_access_term_oper_status_change,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_acc_term_processing_error(self, indication, device_handler):
        # TODO: No error handling currently.
        self.log.error("access-term-processing-error", indication=indication)
        # return a dummy response
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_flow_oper_sts_cng(self, indication, device_handler):
        self.log.debug("flow-oper-status-change", indication=indication)
        ind_info = dict()
        ind_info['_object_type'] = 'flow_indication'
        ind_info['_sub_group_type'] = 'oper_state_change'
        ind_info['_object_type'] = indication.objType
        ind_info['_sub_group_type'] = indication.sub_group
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_flow_processing_error(self, indication, device_handler):
        # TODO: No error handling.
        self.log.debug("flow-processing-error", indication=indication)
        # dummy response
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_iface_oper_sts_cng(self, indication, device_handler):
        ind_info = dict()
        ind_info['_object_type'] = 'interface_indication'
        ind_info['_sub_group_type'] = 'oper_state_change'
        ind_info['activation_successful'] = False
        if indication.interface_op_state.data.new_oper_status is \
                bal_model_types_pb2.BAL_STATUS_UP and \
                indication.interface_op_state.data.admin_state is \
                bal_model_types_pb2.BAL_STATUS_UP:
            ind_info['activation_successful'] = True
            self.log.info("Awaiting-ONU-discovery")

        reactor.callLater(0,
                          device_handler.BalIfaceOperStatusChange,
                          indication.interface_op_state.key.intf_id,
                          ind_info)

        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_iface_los(self, indication, device_handler):
        los_status = indication.interface_los.data.status
        if los_status != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
            balIfaceLos_dict = dict()
            balIfaceLos_dict["los_status"] = los_status.__str__()
            reactor.callLater(0,
                              device_handler.BalIfaceLosAlarm,
                              indication.device_id,
                              indication,
                              los_status, balIfaceLos_dict)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_oper_sts_cng(self, indication, device_handler):
        onu_data = indication.terminal_op_state
        ind_info = dict()
        ind_info['_object_type'] = 'sub_term_indication'
        ind_info['_sub_group_type'] = 'sub_term_op_state'
        ind_info['_pon_id'] = onu_data.key.intf_id
        ind_info['onu_id'] = onu_data.key.sub_term_id
        ind_info['activation_successful'] = False
        if onu_data.data.admin_state is bal_model_types_pb2.BAL_STATE_DOWN or \
                onu_data.data.new_oper_status is bal_model_types_pb2.BAL_STATUS_DOWN:
            ind_info['activation_successful'] = False
        elif onu_data.data.admin_state is bal_model_types_pb2.BAL_STATE_UP and \
                onu_data.data.new_oper_status is bal_model_types_pb2.BAL_STATUS_UP:
            ind_info['activation_successful'] = True

        reactor.callLater(0,
                          device_handler.handle_sub_term_oper_status_change,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_discovery_ind(self, indication, device_handler):
        #     ind_info: {'object_type': <int>
        #                '_sub_group_type': <str>
        #                '_device_id': <str>
        #                '_pon_id' : <int>
        #                'onu_id' : <int>
        #                '_vendor_id' : <str>
        #                '__vendor_specific' : <str>
        #                'activation_successful':[True or False]}
        onu_data = indication.terminal_disc
        ind_info = dict()
        ind_info['_object_type'] = 'sub_term_indication'
        ind_info['_sub_group_type'] = 'onu_discovery'
        ind_info['_pon_id'] = onu_data.key.intf_id
        ind_info['onu_id'] = onu_data.key.sub_term_id
        ind_info['_vendor_id'] = onu_data.data.serial_number.vendor_id
        ind_info['_vendor_specific'] = \
            onu_data.data.serial_number.vendor_specific
        reactor.callLater(0,
                          device_handler.handle_sub_term_discovery,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_alarm_ind(self, indication, device_handler):
        # Loss of signal
        los = indication.terminal_alarm.data.alarm.los
        # Loss of busrt
        lob = indication.terminal_alarm.data.alarm.lob
        # Loss of PLOAM miss channel
        lopc_miss = indication.terminal_alarm.data.alarm.lopc_miss
        # Loss of PLOAM channel
        lopc_mic_error = indication.terminal_alarm.data.alarm.lopc_mic_error

        balSubTermAlarm_Dict = dict()
        balSubTermAlarm_Dict["LOS Status"] = los.__str__()
        balSubTermAlarm_Dict["LOB Status"] = lob.__str__()
        balSubTermAlarm_Dict["LOPC MISS Status"] = lopc_miss.__str__()
        balSubTermAlarm_Dict["LOPC MIC ERROR Status"] = lopc_mic_error.__str__()

        if los != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
            reactor.callLater(0, device_handler.BalSubsTermLosAlarm,
                              indication.device_id,
                              indication.terminal_alarm.key.intf_id,
                              los, balSubTermAlarm_Dict)

        if lob != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
            reactor.callLater(0, device_handler.BalSubsTermLobAlarm,
                              indication.device_id,
                              indication.terminal_alarm.key.intf_id,
                              lob, balSubTermAlarm_Dict)

        if lopc_miss != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
            reactor.callLater(0, device_handler.BalSubsTermLopcMissAlarm,
                              indication.device_id,
                              indication.terminal_alarm.key.intf_id,
                              lopc_miss, balSubTermAlarm_Dict)

        if lopc_mic_error != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
            reactor.callLater(0, device_handler.BalSubsTermLopcMicErrorAlarm,
                              indication.device_id,
                              indication.terminal_alarm.key.intf_id,
                              lopc_mic_error, balSubTermAlarm_Dict)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_dgi_ind(self, indication, device_handler):
        #     ind_info: {'_object_type': <str>
        #                '_device_id': <str>
        #                '_pon_id' : <int>
        #                'onu_id' : <int>
        #                '_vendor_id' : <str>
        #                '__vendor_specific' : <str>
        #                'activation_successful':[True or False]}
        dgi_status = indication.terminal_dgi.data.dgi_status
        if dgi_status != bal_model_types_pb2.BAL_ALARM_STATUS_NO__CHANGE:
            ind_info = dict()
            ind_info['_object_type'] = 'sub_term_indication'
            ind_info['_sub_group_type'] = 'dgi_indication'

            balSubTermDgi_Dict = dict()
            balSubTermDgi_Dict["dgi_status"] = dgi_status.__str__()
            reactor.callLater(0,
                              device_handler.BalSubsTermDgiAlarm,
                              indication.device_id,
                              indication.terminal_dgi.key.intf_id,
                              indication.terminal_dgi.key.sub_term_id,
                              dgi_status, balSubTermDgi_Dict, ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_dowi_ind(self, indication, device_handler):
        self.log.debug("sub-term-dowi-ind", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_looci_ind(self, indication, device_handler):
        self.log.debug("sub-term-looci-ind", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_processing_error(self, indication, device_handler):
        self.log.debug("sub-term-processing-error", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_sdi_ind(self, indication, device_handler):
        self.log.debug("sub-term-sdi-ind", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_sfi_ind(self, indication, device_handler):
        self.log.debug("sub-term-sfi-ind", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_activation_fail(self, indication, device_handler):
        self.log.debug("sub-term-activation-fail", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_sufi_ind(self, indication, device_handler):
        self.log.debug("sub-term-sufi-ind", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_subs_term_tiwi_ind(self, indication, device_handler):
        self.log.debug("sub-term-tiwi-ind", indication=indication)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_tm_sched_oper_status_change(self, indication, device_handler):
        ind_info = dict()
        ind_info['_object_type'] = 'tm_sched_indication'
        ind_info['_sub_group_type'] = 'tm_sched_indication'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_pkt_bearer_channel_rx_ind(self, indication, device_handler):
        ind_info = dict()
        ind_info['flow_id'] = indication.pktData.data.flow_id
        ind_info['flow_type'] = indication.pktData.data.flow_type
        ind_info['intf_id'] = indication.pktData.data.intf_id
        ind_info['intf_type'] = indication.pktData.data.intf_type
        ind_info['svc_port'] = indication.pktData.data.svc_port
        ind_info['flow_cookie'] = indication.pktData.data.flow_cookie
        ind_info['packet'] = indication.pktData.data.pkt
        reactor.callLater(0,
                          device_handler.handle_packet_in,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def bal_pkt_omci_channel_rx_ind(self, indication, device_handler):
        ind_info = dict()
        ind_info['_object_type'] = 'packet_in_indication'
        ind_info['_sub_group_type'] = 'omci_message'
        ind_info['intf_id'] = \
            indication.balOmciResp.key.packet_send_dest.itu_omci_channel.intf_id
        packet_data = indication.balOmciResp.key.packet_send_dest
        ind_info['onu_id'] = packet_data.itu_omci_channel.sub_term_id
        ind_info['packet'] = indication.balOmciResp.data.pkt
        self.log.info('ONU-Id-is',
                      onu_id=packet_data.itu_omci_channel.sub_term_id)
        reactor.callLater(0,
                          device_handler.handle_omci_ind,
                          ind_info)
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    @staticmethod
    def bal_pkt_ieee_oam_channel_rx_ind(indication, device_handler):
        ind_info = dict()
        ind_info['_object_type'] = 'packet_in_indication'
        ind_info['_sub_group_type'] = 'ieee_oam_message'
        bal_err = bal_pb2.BalErr()
        bal_err.err = bal_errno_pb2.BAL_ERR_OK
        return bal_err

    def handle_indication_from_bal(self, bal_ind, device_handler):
        indication_handler = self.indication_handler_map.get((bal_ind.objType,
                                                              bal_ind.sub_group),
                                                              None)
        if indication_handler is None:
            self.log.debug('No handler', objType=bal_ind.objType,
                           sub_group=bal_ind.sub_group)
            pass  # no-op
        else:
            indication_handler(self, bal_ind, device_handler)

    indication_handler_map = {
        (bal_model_ids_pb2.BAL_OBJ_ID_ACCESS_TERMINAL,
         bal_model_ids_pb2.BAL_ACCESS_TERMINAL_AUTO_ID_OPER_STATUS_CHANGE):
            bal_acc_term_oper_sta_cng,
        (bal_model_ids_pb2.BAL_OBJ_ID_ACCESS_TERMINAL,
         bal_model_ids_pb2.BAL_ACCESS_TERMINAL_AUTO_ID_PROCESSING_ERROR):
            bal_acc_term_processing_error,

        (bal_model_ids_pb2.BAL_OBJ_ID_FLOW,
         bal_model_ids_pb2.BAL_FLOW_AUTO_ID_OPER_STATUS_CHANGE):
            bal_flow_oper_sts_cng,
        (bal_model_ids_pb2.BAL_OBJ_ID_FLOW,
         bal_model_ids_pb2.BAL_FLOW_AUTO_ID_PROCESSING_ERROR):
            bal_flow_processing_error,

        (bal_model_ids_pb2.BAL_OBJ_ID_INTERFACE,
         bal_model_ids_pb2.BAL_INTERFACE_AUTO_ID_LOS):
            bal_iface_los,
        (bal_model_ids_pb2.BAL_OBJ_ID_INTERFACE,
         bal_model_ids_pb2.BAL_INTERFACE_AUTO_ID_OPER_STATUS_CHANGE):
            bal_iface_oper_sts_cng,

        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_OPER_STATUS_CHANGE):
            bal_subs_term_oper_sts_cng,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_SUB_TERM_DISC):
            bal_subs_term_discovery_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_SUB_TERM_ALARM):
            bal_subs_term_alarm_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_DGI):
            bal_subs_term_dgi_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_DOWI):
            bal_subs_term_dowi_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_LOOCI):
            bal_subs_term_looci_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_PROCESSING_ERROR):
            bal_subs_term_processing_error,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_SDI):
            bal_subs_term_sdi_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_SFI):
            bal_subs_term_sfi_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_SUB_TERM_ACT_FAIL):
            bal_subs_term_activation_fail,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_SUFI):
            bal_subs_term_sufi_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL,
         bal_model_ids_pb2.
         BAL_SUBSCRIBER_TERMINAL_AUTO_ID_TIWI):
            bal_subs_term_tiwi_ind,

        (bal_model_ids_pb2.BAL_OBJ_ID_TM_SCHED,
         bal_model_ids_pb2.BAL_TM_SCHED_AUTO_ID_OPER_STATUS_CHANGE):
            bal_tm_sched_oper_status_change,

        (bal_model_ids_pb2.BAL_OBJ_ID_PACKET,
         bal_model_ids_pb2.BAL_PACKET_AUTO_ID_BEARER_CHANNEL_RX):
            bal_pkt_bearer_channel_rx_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_PACKET,
         bal_model_ids_pb2.BAL_PACKET_AUTO_ID_ITU_OMCI_CHANNEL_RX):
            bal_pkt_omci_channel_rx_ind,
        (bal_model_ids_pb2.BAL_OBJ_ID_PACKET,
         bal_model_ids_pb2.BAL_PACKET_AUTO_ID_IEEE_OAM_CHANNEL_RX):
            bal_pkt_ieee_oam_channel_rx_ind,
    }
