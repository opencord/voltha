#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License")
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
Handles sequence of messages that are used to send OMCI to the ONU
"""
import structlog
from scapy.automaton import ATMT

from voltha.adapters.microsemi_olt.BaseOltAutomaton import BaseOltAutomaton
from voltha.adapters.microsemi_olt.PAS5211 import PAS5211MsgSendFrame, PAS5211MsgGetOltVersionResponse, PAS5211MsgSendFrameResponse, \
    PAS5211EventFrameReceived, PAS5211MsgHeader, PAS5211SetVlanGenConfigResponse

from voltha.extensions.omci.omci_frame import OmciFrame

from voltha.adapters.microsemi_olt.PAS5211 import PAS5211GetOnuAllocs, PAS5211GetOnuAllocsResponse, PAS5211GetSnInfo, \
    PAS5211GetSnInfoResponse, PAS5211GetOnusRange, PAS5211GetOnusRangeResponse, PAS5211MsgSetOnuOmciPortId, \
    PAS5211MsgSetOnuOmciPortIdResponse, PAS5211MsgSetOnuAllocId, PAS5211MsgSetOnuAllocIdResponse, \
    PAS5211SetSVlanAtConfig, PAS5211SetSVlanAtConfigResponse, PAS5211SetVlanDownConfig, \
    PAS5211SetVlanDownConfigResponse, PAS5211SetDownVlanHandl, PAS5211SetDownVlanHandlResponse, \
    PAS5211SetUplinkVlanHandl, PAS5211SetDownstreamPolicingConfigResponse, PAS5211SetDownstreamPolicingConfig, \
    PAS5211SetPortIdPolicingConfig, PAS5211UnsetPortIdPolicingConfig, \
    PAS5211MsgSendDbaAlgorithmMsg, PAS5211MsgSendDbaAlgorithmMsgResponse, \
    PAS5211SetUpstreamPolicingConfigResponse, PAS5211SetUpstreamPolicingConfig, \
    PAS5211MsgSetPortIdConfig, PAS5211MsgSetPortIdConfigResponse, \
    PAS5211MsgGetOnuIdByPortId, PAS5211MsgGetOnuIdByPortIdResponse, \
    PAS5211SetVlanUplinkConfiguration, PAS5211SetVlanUplinkConfigurationResponse, PAS5211SetUplinkVlanHandlResponse, PAS5211SetVlanGenConfig, PAS5211SetVlanGenConfigResponse, \
    PAS5211GetPortIdDownstreamPolicingConfig, PAS5211GetPortIdDownstreamPolicingConfigResponse, PAS5211RemoveDownstreamPolicingConfig, \
    PAS5211MsgHeader, PAS5211UnsetPortIdPolicingConfigResponse, PAS5211RemoveDownstreamPolicingConfigResponse, \
    PAS5211SetPortIdPolicingConfigResponse, PAS5211EventAlarmNotification
from voltha.adapters.microsemi_olt.PAS5211_constants import OMCI_GEM_IWTP_IW_OPT_8021P_MAPPER, PON_FALSE, \
    PON_1_TO_1_VLAN_MODE, PON_TRUE, PON_VLAN_UNUSED_TAG, PON_VLAN_UNUSED_PRIORITY, PON_VLAN_REPLACE_PRIORITY, \
    PON_OUTPUT_VLAN_PRIO_HANDLE_INCOMING_VLAN, PON_VLAN_UNCHANGED_PRIORITY, PON_OUTPUT_VLAN_PRIO_HANDLE_DONT_CHANGE, \
    PON_OUTPUT_VLAN_PRIO_HANDLE_DL_VLAN_TABLE, PON_DL_VLAN_SVLAN_REMOVE, PON_DL_VLAN_CVLAN_NO_CHANGE, \
    PON_VLAN_DEST_DATAPATH, GEM_DIR_BIDIRECT, OMCI_MAC_BRIDGE_PCD_LANFCS_FORWARDED, \
    OMCI_MAC_BRIDGE_PCD_ENCAP_METHOD_LLC, OMCI_8021P_MSP_UNMARKED_FRAME_TAG_FRAME, OMCI_8021P_MSP_TP_TYPE_NULL, \
    OMCI_EX_VLAN_TAG_OCD_ASSOCIATION_TYPE_PPTP_ETH_UNI, OMCI_EX_VLAN_TAG_OCD_DS_MODE_US_INVERSE, PMC_UPSTREAM_PORT, \
    PON_DISABLE, PON_VLAN_CHANGE_TAG, PON_VLAN_DONT_CHANGE_TAG, PON_PORT_TYPE_GEM, PON_PORT_DESTINATION_CNI0, PON_ENABLE, SLA_gr_bw_gros, PYTHAGORAS_UPDATE_AID_SLA, \
    SLA_gr_bw_gros, SLA_be_bw_gros, SLA_gr_bw_fine, SLA_be_bw_fine, PYTHAGORAS_DBA_DATA_COS, PYTHAGORAS_DBA_STATUS_REPORT_NSR, \
    PMC_OFAL_NO_POLICY, UPSTREAM, DOWNSTREAM

from struct import pack, unpack

from voltha.adapters.microsemi_olt.OltRemoveFlowStateMachine import OltRemoveFlowStateMachine

log = structlog.get_logger()

MAX_RETRIES = 10
TIMEOUT = 5

class OltInstallFlowStateMachine(BaseOltAutomaton):

    onu_id = None
    channel_id = None
    port_id = None
    onu_session_id = None
    alloc_id = None
    policy_id = None
    retries = 0

    def parse_args(self, debug=0, store=0, **kwargs):

        self.onu_id = kwargs.pop('onu_id')
        self.channel_id = kwargs.pop('channel_id')
        self.port_id = kwargs.pop('port_id')
        self.onu_session_id = kwargs.pop('onu_session_id')
        self.alloc_id = kwargs.pop('alloc_id')
        self.svlan_id = kwargs.pop('svlan_id')
        self.cvlan_id = kwargs.pop('cvlan_id')
        self.uplink_bandwidth = kwargs.pop('uplink_bandwidth')
        self.downlink_bandwidth = kwargs.pop('downlink_bandwidth')

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)

    def master_filter(self, pkt):

        if not super(OltInstallFlowStateMachine, self).master_filter(pkt):
            return False

        if PAS5211MsgHeader in pkt:
            if PAS5211EventAlarmNotification not in pkt:
                if PAS5211MsgGetOltVersionResponse not in pkt:
                    if pkt[PAS5211MsgHeader].channel_id == self.channel_id:
                        if pkt[PAS5211MsgHeader].onu_id == self.onu_id:
                            if OmciFrame not in pkt:
                                if PAS5211MsgSendFrameResponse not in pkt:
                                    return True
        return False

    """
    States
    """

    # Uplink states...
    @ATMT.state(initial=1)
    def send_msg(self):
        log.debug('olt-flow-state-machine-start')

    @ATMT.state()
    def wait_set_gen_vlan_uplink_configuration_response(self):
        pass

    @ATMT.state()
    def wait_set_port_id_configuration_response(self):
        pass

    @ATMT.state()
    def wait_get_onu_id_by_port_id_response(self):
        pass

    @ATMT.state()
    def wait_send_dba_algorithm_msg_response(self):
        pass

    @ATMT.state()
    def wait_set_svlan_at_configuration_response(self):
        pass

    @ATMT.state()
    def wait_set_vlan_uplink_configuration_response(self):
        pass

    @ATMT.state()
    def wait_set_uplink_vlan_handling_response(self):
        pass

    # Downlink states...
    @ATMT.state()
    def wait_set_gen_vlan_downlink_configuration_response(self):
        pass

    @ATMT.state()
    def wait_set_vlan_downlink_configuration_response(self):
        pass

    @ATMT.state()
    def wait_set_downlink_vlan_handling_response(self):
        pass

    @ATMT.state()
    def wait_get_port_id_downlink_policing_response(self):
        pass

    @ATMT.state()
    def wait_unset_port_id_downlink_policing_response(self):
        pass

    @ATMT.state()
    def wait_remove_downlink_policing_response(self):
        pass

    @ATMT.state()
    def wait_set_downlink_policing_response(self):
        pass

    @ATMT.state()
    def wait_set_port_id_policing_response(self):
        pass


    @ATMT.state(error=1)
    def error(self, msg):
        log.error(msg)
        # # If any error, we remove the flow...
        # olt = OltRemoveFlowStateMachine(iface=self.iface, comm=self.comm,
        #         target=self.target, device=self.device, onu_id=self.onu_id,
        #         channel_id=self.channel_id, port_id=self.port_id, onu_session_id=self.onu_session_id,
        #         alloc_id=self.alloc_id)
        # olt.runbg()

        raise self.end()

    @ATMT.state(final=1)
    def end(self):
        log.debug('olt-flow-state-machine-end')
        # pass

    """
    Utils
    """

    def px(self, pkt):
        return self.p(pkt, channel_id=self.channel_id,
                onu_id=self.onu_id,
                onu_session_id=self.onu_session_id)

    """
    Transitions
    """

    @ATMT.condition(send_msg)
    def install_flow(self):
        log.debug("install-flow")
        self.send_set_gen_vlan_uplink_configuration(self.device.device)
        raise self.wait_set_gen_vlan_uplink_configuration_response()

    @ATMT.timeout(wait_set_gen_vlan_uplink_configuration_response, TIMEOUT)
    def timeout_wait_gen_vlan_uplink_configuration_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_gen_vlan_uplink_configuration(self.device.device)
        else:
            raise self.error("Timeout for message PAS5211SetVlanGenConfigResponse")

    @ATMT.receive_condition(wait_set_gen_vlan_uplink_configuration_response)
    def wait_for_set_gen_vlan_uplink_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetVlanGenConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetVlanGenConfigResponse')
            self.send_set_port_id_configuration(self.device.device, PON_ENABLE, self.port_id, self.alloc_id)
            raise self.wait_set_port_id_configuration_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_port_id_configuration_response, TIMEOUT)
    def timeout_wait_set_port_id_configuration_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_port_id_configuration(self.device.device, PON_ENABLE, self.port_id, self.alloc_id)
        else:
            raise self.error("Timeout for message PAS5211MsgSetPortIdConfigResponse")

    @ATMT.receive_condition(wait_set_port_id_configuration_response)
    def wait_for_set_port_id_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211MsgSetPortIdConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211MsgSetPortIdConfigResponse')
            self.send_get_onu_id_by_port_id(self.device.device, self.port_id)
            raise self.wait_get_onu_id_by_port_id_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_get_onu_id_by_port_id_response, TIMEOUT)
    def timeout_wait_get_onu_id_by_port_id_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_get_onu_id_by_port_id(self.device.device, self.port_id)
        else:
            raise self.error("Timeout for message PAS5211MsgGetOnuIdByPortIdResponse")

    @ATMT.receive_condition(wait_get_onu_id_by_port_id_response)
    def wait_for_get_onu_id_by_port_id_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211MsgGetOnuIdByPortIdResponse in pkt:
            log.debug('[RESPONSE] PAS5211MsgGetOnuIdByPortIdResponse')
            self.send_send_dba_algorithm_msg(self.device.device, self.port_id, self.uplink_bandwidth)
            raise self.wait_send_dba_algorithm_msg_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_send_dba_algorithm_msg_response, TIMEOUT)
    def timeout_wait_send_dba_algorithm_msg_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_send_dba_algorithm_msg(self.device.device, self.port_id, self.uplink_bandwidth)
        else:
            raise self.error("Timeout for message PAS5211MsgSendDbaAlgorithmMsgResponse")

    @ATMT.receive_condition(wait_send_dba_algorithm_msg_response)
    def wait_for_send_dba_algorithm_msg_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211MsgSendDbaAlgorithmMsgResponse in pkt:
            log.debug('[RESPONSE] PAS5211MsgSendDbaAlgorithmMsgResponse')
            self.send_set_svlan_at_configuration(self.device.device, self.svlan_id)
            raise self.wait_set_svlan_at_configuration_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_svlan_at_configuration_response, TIMEOUT)
    def timeout_wait_set_svlan_at_configuration_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_svlan_at_configuration(self.device.device, self.svlan_id)
        else:
            raise self.error("Timeout for message PAS5211SetSVlanAtConfigResponse")

    @ATMT.receive_condition(wait_set_svlan_at_configuration_response)
    def wait_for_set_svlan_at_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetSVlanAtConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetSVlanAtConfigResponse')
            self.send_set_vlan_uplink_configuration(self.device.device, self.port_id)
            raise self.wait_set_vlan_uplink_configuration_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_vlan_uplink_configuration_response, TIMEOUT)
    def timeout_wait_set_vlan_uplink_configuration_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_vlan_uplink_configuration(self.device.device, self.port_id)
        else:
            raise self.error("Timeout for message PAS5211SetVlanUplinkConfigurationResponse")

    @ATMT.receive_condition(wait_set_vlan_uplink_configuration_response)
    def wait_for_set_vlan_uplink_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetVlanUplinkConfigurationResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetVlanUplinkConfigurationResponse')
            self.send_set_uplink_vlan_handling(self.device.device, self.port_id, self.cvlan_id, self.svlan_id)
            raise self.wait_set_uplink_vlan_handling_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))


    @ATMT.timeout(wait_set_uplink_vlan_handling_response, TIMEOUT)
    def timeout_wait_set_uplink_vlan_handling_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_uplink_vlan_handling(self.device.device, self.port_id, self.cvlan_id, self.svlan_id)
        else:
            raise self.error("Timeout for message PAS5211SetUplinkVlanHandlResponse")

    @ATMT.receive_condition(wait_set_uplink_vlan_handling_response)
    def wait_for_set_uplink_vlan_handling_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetUplinkVlanHandlResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetUplinkVlanHandlResponse')
            self.send_set_gen_vlan_downlink_configuration(self.device.device)
            raise self.wait_set_gen_vlan_downlink_configuration_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_gen_vlan_downlink_configuration_response, TIMEOUT)
    def timeout_wait_set_gen_vlan_downlink_configuration_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_gen_vlan_downlink_configuration(self.device.device)
        else:
            raise self.error("Timeout for message PAS5211SetVlanGenConfigResponse")

    @ATMT.receive_condition(wait_set_gen_vlan_downlink_configuration_response)
    def wait_for_set_gen_vlan_downlink_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetVlanGenConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetVlanGenConfigResponse')
            self.send_set_vlan_downlink_configuration(self.device.device, self.svlan_id)
            raise self.wait_set_vlan_downlink_configuration_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_vlan_downlink_configuration_response, TIMEOUT)
    def timeout_wait_set_vlan_downlink_configuration_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_vlan_downlink_configuration(self.device.device, self.svlan_id)
        else:
            raise self.error("Timeout for message PAS5211SetVlanDownConfigResponse")

    @ATMT.receive_condition(wait_set_vlan_downlink_configuration_response)
    def wait_for_set_vlan_downlink_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetVlanDownConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetVlanDownConfigResponse')
            self.send_set_downlink_vlan_handling(self.device.device, self.cvlan_id, self.svlan_id, self.port_id)
            raise self.wait_set_downlink_vlan_handling_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_downlink_vlan_handling_response, TIMEOUT)
    def timeout_wait_set_downlink_vlan_handling_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_downlink_vlan_handling(self.device.device, self.cvlan_id, self.svlan_id, self.port_id)
        else:
            raise self.error("Timeout for message PAS5211SetDownVlanHandlResponse")

    @ATMT.receive_condition(wait_set_downlink_vlan_handling_response)
    def wait_for_set_downlink_vlan_handling_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetDownVlanHandlResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetDownVlanHandlResponse')
            self.send_get_port_id_downlink_policing(self.device.device, self.port_id)
            raise self.wait_get_port_id_downlink_policing_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_get_port_id_downlink_policing_response, TIMEOUT)
    def timeout_wait_get_port_id_downlink_policing_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_get_port_id_downlink_policing(self.device.device, self.port_id)
        else:
            raise self.error("Timeout for message PAS5211GetPortIdDownstreamPolicingConfigResponse")

    @ATMT.receive_condition(wait_get_port_id_downlink_policing_response)
    def wait_for_get_port_id_downlink_policing_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211GetPortIdDownstreamPolicingConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211GetPortIdDownstreamPolicingConfigResponse')
            if pkt[PAS5211GetPortIdDownstreamPolicingConfigResponse].ds_policing_config_id != PMC_OFAL_NO_POLICY:
                self.policy_id = pkt[PAS5211GetPortIdDownstreamPolicingConfigResponse].ds_policing_config_id
                log.debug('Policy id got: {}'.format(self.policy_id))
                self.send_unset_port_id_downlink_policing(self.device.device, 1, self.port_id)
                raise self.wait_unset_port_id_downlink_policing_response()
            else:
                self.send_set_downlink_policing(self.device.device,self.downlink_bandwidth)
                raise self.wait_set_downlink_policing_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_unset_port_id_downlink_policing_response, TIMEOUT)
    def timeout_wait_unset_port_id_downlink_policing_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_unset_port_id_downlink_policing(self.device.device, 1, self.port_id)
        else:
            raise self.error("Timeout for message PAS5211UnsetPortIdPolicingConfigResponse")

    @ATMT.receive_condition(wait_unset_port_id_downlink_policing_response)
    def wait_for_unset_port_id_downlink_policing_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211UnsetPortIdPolicingConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211UnsetPortIdPolicingConfigResponse')
            self.send_remove_downlink_policing(self.device.device, self.policy_id)
            raise self.wait_remove_downlink_policing_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_remove_downlink_policing_response, TIMEOUT)
    def timeout_wait_remove_downlink_policing_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_remove_downlink_policing(self.device.device, self.policy_id)
        else:
            raise self.error("Timeout for message PAS5211RemoveDownstreamPolicingConfigResponse")

    @ATMT.receive_condition(wait_remove_downlink_policing_response)
    def wait_for_remove_downlink_policing_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211RemoveDownstreamPolicingConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211RemoveDownstreamPolicingConfigResponse')
            self.send_set_downlink_policing(self.device.device, self.downlink_bandwidth)
            raise self.wait_set_downlink_policing_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_downlink_policing_response, TIMEOUT)
    def timeout_wait_set_downlink_policing_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_downlink_policing(self.device.device, self.downlink_bandwidth)
        else:
            raise self.error("Timeout for message PAS5211SetDownstreamPolicingConfigResponse")

    @ATMT.receive_condition(wait_set_downlink_policing_response)
    def wait_for_set_downlink_policing_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetDownstreamPolicingConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetDownstreamPolicingConfigResponse')
            # if pkt[PAS5211SetDownstreamPolicingConfigResponse].policing_config_id:
            self.policy_id = pkt[PAS5211SetDownstreamPolicingConfigResponse].policing_config_id
            log.debug('Policy id set: {}'.format(self.policy_id))
            self.send_set_port_id_policing(self.device.device, 1, self.port_id, self.policy_id)
            raise self.wait_set_port_id_policing_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_port_id_policing_response, TIMEOUT)
    def timeout_wait_set_port_id_policing_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_port_id_policing(self.device.device, 1, self.port_id, self.policy_id)
        else:
            raise self.error("Timeout for message PAS5211SetPortIdPolicingConfigResponse")

    @ATMT.receive_condition(wait_set_port_id_policing_response)
    def wait_for_set_port_id_policing_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211SetPortIdPolicingConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211SetPortIdPolicingConfigResponse')
            raise self.end()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    def send_set_port_id_configuration(self, device, activate, port_id, alloc_id):
        msg = PAS5211MsgSetPortIdConfig(
            # port_id=1000 + device.proxy_address.onu_id,
            port_id=port_id,
            activate=activate,
            alloc_id=alloc_id,
            type=PON_PORT_TYPE_GEM,
            destination=PON_PORT_DESTINATION_CNI0
        )
        self.send(self.px(msg))
        log.debug("[SENT] PASS_set_port_id_configuration")

    def send_get_onu_id_by_port_id(self, device, port_id):
        msg = PAS5211MsgGetOnuIdByPortId(
                # port_id=1000 + device.proxy_address.onu_id
                port_id=port_id

            )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211MsgGetOnuIdByPortId")

    def send_set_gen_vlan_uplink_configuration(self, device):
        # transmit "vlan uplink configuration port-id 1001 min-cos 0 max-cos 7
        # de-bit disable primary-tag-handling true"

        msg = PAS5211SetVlanGenConfig(
            direction=0,
            extended_svlan_type=33024,
            insertion_svlan_ethertype=33024,
            extended_cvlan_type=33024,
            insertion_cvlan_ethertype=33024,
            pon_pcp_code=3,
            cni_pcp_code=3,
            reserved=0,
        )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetVlanGenConfig")

    def send_set_gen_vlan_downlink_configuration(self, device):
        # transmit "vlan uplink configuration port-id 1001 min-cos 0 max-cos 7
        # de-bit disable primary-tag-handling true"

        msg = PAS5211SetVlanGenConfig(
            direction=1,
            extended_svlan_type=33024,
            insertion_svlan_ethertype=33024,
            extended_cvlan_type=33024,
            insertion_cvlan_ethertype=33024,
            pon_pcp_code=3,
            cni_pcp_code=3,
            reserved=0,
        )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetVlanGenConfig")

    def send_set_vlan_uplink_configuration(self, device, port_id):
        # transmit "vlan uplink configuration port-id 1001 min-cos 0 max-cos 7
        # de-bit disable primary-tag-handling true"

        msg = PAS5211SetVlanUplinkConfiguration(
            # port_id=(1000 + device.proxy_address.onu_id),
            port_id = port_id,
            pvid_config_enabled=PON_TRUE,
            # Enables handling of primary tag in addition to the port-id at
            # uplink frames
            min_cos=0,  # The lower limit of the priority uplink frame from the specific Port Id can get
            max_cos=7,  # The upper limit of the priority uplink frame from the specific Port Id can get
            de_bit=PON_DISABLE  # Discard Eligibility (DE) enabled
        )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetVlanUplinkConfiguration")

    def send_set_uplink_vlan_handling(self, device, port_id, cvlan_id, svlan_id):

        # if (ul_vlan_key->primary_vid == PON_VLAN_UNUSED_TAG)
        #    set_uplink_vlan_handling_msg.pvid_config_enabled = PON_FALSE;
        # else
        # {
        #    set_uplink_vlan_handling_msg.pvid_config_enabled = PON_TRUE;
        #    set_uplink_vlan_handling_msg.primary_vid      = ul_vlan_key->primary_vid;
        # }
        primary_vid = 0  # TODO change
        # self.port_id = (1000 + device.proxy_address.onu_id)  # TODO change
        if cvlan_id == PON_VLAN_UNUSED_TAG:
            pvid_config_enabled = PON_FALSE
        else:
            pvid_config_enabled = PON_TRUE
            primary_vid = cvlan_id

        msg = PAS5211SetUplinkVlanHandl(
            source_port_id=port_id,
            primary_vid=primary_vid,  # The primary VLAN tag of the uplink frame
            pvid_config_enabled=pvid_config_enabled,
            svlan_tag_operation=PON_VLAN_CHANGE_TAG,
            cvlan_tag_operation=PON_VLAN_DONT_CHANGE_TAG,  # Customer tag = new C-VLAN tag
            new_svlan_tag=svlan_id,  # Service tag to be added or replace, not relevant
            new_cvlan_tag=0,  # Customer tag to be added or replace, not relevant
            destination=PON_VLAN_DEST_DATAPATH  # Frames go to the CNI
        )

        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetUplinkVlanHandl")

    def send_set_svlan_at_configuration(self, device, svlan_id):

        msg = PAS5211SetSVlanAtConfig(
            svlan_id=svlan_id,  # 9
            # 1 1:1 VLAN mode is used, no address table
            forwarding_mode=PON_1_TO_1_VLAN_MODE,
            use_svlan=PON_FALSE,  # Use S-VLAN as part of the address table key
            use_cvlan=PON_FALSE,  # Use C-VLAN as part of the address table key
            use_pbits=PON_FALSE,  # Use priority bits as part of the address table key
            discard_unknown=PON_FALSE  # Forward frames
        )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetSVlanAtConfig")

    def send_set_vlan_downlink_configuration(self, device, svlan_id):
        msg = PAS5211SetVlanDownConfig(
            svlan_id=svlan_id,  # 9
            double_tag_handling=PON_TRUE,  # Enable handling according to double tag
            vlan_priority_handling=PON_TRUE  # Use VLAN priority at the downlink VLAN table key
        )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetVlanDownConfig")

    def send_get_port_id_downlink_policing(self, device, port_id):
        msg = PAS5211GetPortIdDownstreamPolicingConfig(port_id=port_id)
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211GetPortIdDownstreamPolicingConfig")

    def send_remove_downlink_policing(self, device, policy_id):
        msg = PAS5211RemoveDownstreamPolicingConfig(
            policing_config_id=policy_id,
            reserved=0)
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211RemoveDownstreamPolicingConfig")

    def send_unset_port_id_downlink_policing(self, device, dir, port_id):
        msg = PAS5211UnsetPortIdPolicingConfig(direction=dir, port_id=port_id)
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211UnsetPortIdPolicingConfig")

    def send_set_downlink_policing(self, device, bandwidth):
        msg = PAS5211SetDownstreamPolicingConfig(
            committed_bandwidth = SLA_gr_bw_gros*1024,
            excessive_bandwidth = (bandwidth - SLA_gr_bw_gros)*1024,
            committed_burst_limit = 256,
            excessive_burst_limit = 256)
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetDownstreamPolicingConfig")

    def send_set_port_id_policing(self, device, dir, port_id, policy_id):
        msg = PAS5211SetPortIdPolicingConfig(
            direction=dir,
            port_id=port_id,
            policing_config_id=policy_id,
            reserved=0)
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetPortIdPolicingConfig")

    def send_send_dba_algorithm_msg(self, device, port_id, bandwidth):
        alloc_id = []
        mx_bw = []
        gr_bw = []

        data = pack('<LLHHBBBB', PYTHAGORAS_UPDATE_AID_SLA,
            port_id, SLA_gr_bw_gros, bandwidth,
            SLA_gr_bw_fine, SLA_be_bw_fine, PYTHAGORAS_DBA_DATA_COS,
            PYTHAGORAS_DBA_STATUS_REPORT_NSR)

        msg = PAS5211MsgSendDbaAlgorithmMsg(data= data)

        self.send(self.px(msg))
        log.debug("[SENT] PAS5211MsgSendDbaAlgorithmMsg")

    def send_set_downlink_vlan_handling(self, device, cvlan_id, svlan_id, port_id):
        cvlan_tag = 0
        svlan_tag = svlan_id
        if cvlan_id == PON_VLAN_UNUSED_TAG:
            double_tag_handling = PON_FALSE
        else:
            double_tag_handling = PON_TRUE
            cvlan_tag = cvlan_id

        input_priority = 0  # TODO: Extract value from somewhere

        if input_priority == PON_VLAN_UNUSED_PRIORITY:
            priority_handling = PON_FALSE
        else:
            priority_handling = PON_TRUE

        output_priority = 0  # TODO: Extract value from somewhere

        if output_priority == PON_VLAN_REPLACE_PRIORITY:
            output_vlan_prio_handle = PON_OUTPUT_VLAN_PRIO_HANDLE_INCOMING_VLAN
            output_priority = 0
        elif output_priority == PON_VLAN_UNCHANGED_PRIORITY:
            output_vlan_prio_handle = PON_OUTPUT_VLAN_PRIO_HANDLE_DONT_CHANGE
            output_priority = 0
        else:
            output_vlan_prio_handle = PON_OUTPUT_VLAN_PRIO_HANDLE_DL_VLAN_TABLE

        msg = PAS5211SetDownVlanHandl(
            svlan_tag=svlan_tag,
            cvlan_tag=cvlan_tag,  # Original downlink frame with this C-tag ID
            double_tag_handling=PON_TRUE,
            priority_handling=PON_FALSE,
            input_priority=1,  # From traces # S-VLAN priority field
            # Don't change original frame service tag
            svlan_tag_operation=PON_DL_VLAN_SVLAN_REMOVE,
            cvlan_tag_operation=PON_DL_VLAN_CVLAN_NO_CHANGE,  # Customer tag = new C-VLAN tag
            # port_id=(1000 + device.proxy_address.onu_id),
            port_id=port_id,
            # GEM port-id destination of the downlink frame. It is used when
            # the MAC destination address (DA) is a broadcast address
            new_cvlan_tag=cvlan_tag,  # Same as cvlan_tag
            # From traces PON_VLAN_DEST_DATAPATH,  # Frames go to the PON
            destination=PON_VLAN_DEST_DATAPATH,
            output_vlan_prio_handle=PON_OUTPUT_VLAN_PRIO_HANDLE_DONT_CHANGE,
            output_priority=1  # New VLAN priority value
        )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211SetDownVlanHandl")
