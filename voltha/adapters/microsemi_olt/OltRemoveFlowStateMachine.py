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

log = structlog.get_logger()

MAX_RETRIES = 10
TIMEOUT = 5

class OltRemoveFlowStateMachine(BaseOltAutomaton):

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

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)


    def master_filter(self, pkt):

        if not super(OltRemoveFlowStateMachine, self).master_filter(pkt):
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
    def wait_set_port_id_configuration_response(self):
        pass

    @ATMT.state()
    def wait_get_onu_id_by_port_id_response(self):
        pass

    @ATMT.state()
    def wait_unset_port_id_downlink_policing_response(self):
        pass


    @ATMT.state(error=1)
    def error(self, msg):
        log.error(msg)
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
    def remove_flow(self):
        self.send_get_onu_id_by_port_id(self.device.device, self.port_id)
        raise self.wait_get_onu_id_by_port_id_response()

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
            self.send_unset_port_id_downlink_policing(self.device.device, 1, self.port_id)
            raise self.wait_unset_port_id_downlink_policing_response()
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
            self.send_set_port_id_configuration(self.device.device, PON_DISABLE, self.port_id, self.alloc_id)
            raise self.wait_set_port_id_configuration_response()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))

    @ATMT.timeout(wait_set_port_id_configuration_response, TIMEOUT)
    def timeout_wait_set_port_id_configuration_response(self):
        #log.debug('api-proxy-timeout')
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_set_port_id_configuration(self.device.device, PON_DISABLE, self.port_id, self.alloc_id)
        else:
            raise self.error("Timeout for message PAS5211MsgSetPortIdConfigResponse")

    @ATMT.receive_condition(wait_set_port_id_configuration_response)
    def wait_for_set_port_id_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211MsgSetPortIdConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211MsgSetPortIdConfigResponse')
            self.end()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))



    """ -   -   -   -   -   -   -   create_double_vlan_flow_olt_config   -   -   -   -   -   -   - """


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
        log.debug("[SENT] PAS5211MsgSetPortIdConfig")

    def send_get_onu_id_by_port_id(self, device, port_id):
        msg = PAS5211MsgGetOnuIdByPortId(
                # port_id=1000 + device.proxy_address.onu_id
                port_id=port_id

            )
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211MsgGetOnuIdByPortId")


    def send_unset_port_id_downlink_policing(self, device, dir, port_id):
        msg = PAS5211UnsetPortIdPolicingConfig(direction=dir, port_id=port_id)
        self.send(self.px(msg))
        log.debug("[SENT] PAS5211UnsetPortIdPolicingConfig")


    """ -   -   -   -   -   -   -  END create_double_vlan_flow_olt_config   -   -   -   -   -   -   - """
