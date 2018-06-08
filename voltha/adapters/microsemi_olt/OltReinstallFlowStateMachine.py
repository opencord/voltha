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

from voltha.adapters.microsemi_olt.OltInstallFlowStateMachine import OltInstallFlowStateMachine
from voltha.adapters.microsemi_olt.OltRemoveFlowStateMachine import OltRemoveFlowStateMachine

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
    PAS5211SetPortIdPolicingConfigResponse
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

TIMEOUT = 5

class OltReinstallFlowStateMachine(OltRemoveFlowStateMachine):

    @ATMT.state()
    def wait_set_port_id_configuration_response(self):
        pass

    @ATMT.receive_condition(wait_set_port_id_configuration_response)
    def wait_for_set_port_id_configuration_response(self, pkt):
        #log.debug('api-proxy-response')
        if PAS5211MsgSetPortIdConfigResponse in pkt:
            log.debug('[RESPONSE] PAS5211MsgSetPortIdConfigResponse')
            olt = OltInstallFlowStateMachine(iface=self.iface, comm=self.comm,
                    target=self.target, device=self.device, onu_id=self.onu_id,
                    channel_id=self.channel_id, port_id=self.port_id, onu_session_id=self.onu_session_id,
                    alloc_id=self.alloc_id, svlan_id= self.svlan_id, cvlan_id=self.cvlan_id)
            olt.runbg()
        else:
            log.debug('Unexpected pkt {}'.format(pkt.summary()))
