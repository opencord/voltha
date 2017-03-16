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
from struct import pack, unpack

from scapy.automaton import ATMT
import structlog
from voltha.adapters.microsemi_olt.BaseOltAutomaton import BaseOltAutomaton
from voltha.adapters.microsemi_olt.PAS5211 import PAS5211EventOnuActivation, PAS5211MsgGetActivationAuthMode, \
    PAS5211MsgGetActivationAuthModeResponse, PAS5211MsgSetOnuOmciPortId, \
    PAS5211MsgSetOnuOmciPortIdResponse, PAS5211MsgSendFrame, PAS5211MsgSendFrameResponse, \
    PAS5211MsgGetLogicalObjectStatus, PAS5211MsgGetLogicalObjectStatusResponse, PAS5211MsgSetOnuAllocId, \
    PAS5211MsgGetDbaMode, PAS5211MsgGetDbaModeResponse, PAS5211MsgSendDbaAlgorithmMsg, \
    PAS5211MsgSendDbaAlgorithmMsgResponse, PAS5211EventDbaAlgorithm, PAS5211MsgSetPortIdConfig, \
    PAS5211MsgSetPortIdConfigResponse, PAS5211MsgGetOnuIdByPortId, PAS5211MsgGetOnuIdByPortIdResponse, \
    PAS5211SetVlanUplinkConfiguration, PAS5211SetVlanUplinkConfigurationResponse, PAS5211MsgSetOnuAllocIdResponse
from voltha.adapters.microsemi_olt.PAS5211_constants import PON_ACTIVATION_AUTH_AUTO, PON_ENABLE, PON_PORT_PON, \
    PON_LOGICAL_OBJECT_TYPE_ALLOC_ID, PON_LOGICAL_OBJECT_TYPE_ONU_ID_BY_ALLOC_ID, PON_TRUE, \
    PMC_OFAL_MAX_BI_DIRECTIONAL_FLOW_PER_ONU, PMC_OFAL_START_FLOW_ID_BASE, PON_DBA_MODE_RUNNING, \
    PYTHAGORAS_UPDATE_AID_SLA, SLA_be_bw_gros, SLA_gr_bw_gros, SLA_gr_bw_fine, SLA_be_bw_fine, PYTHAGORAS_DBA_DATA_COS, \
    PYTHAGORAS_DBA_STATUS_REPORT_NSR, PYTHAGORAS_SET_SLA_RESP_SIZE, PON_PORT_TYPE_GEM, PON_PORT_DESTINATION_CNI0, \
    PON_FALSE, PON_DISABLE
from voltha.extensions.omci.omci_entities import CircuitPack
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciGet, OmciGetResponse

log = structlog.get_logger()
_verbose = False

ALLOC_ID = 1000

def alloc_id(onu_id):
    for i in range(0, PMC_OFAL_MAX_BI_DIRECTIONAL_FLOW_PER_ONU):
        alloc_id = PMC_OFAL_START_FLOW_ID_BASE + \
                   (onu_id * PMC_OFAL_MAX_BI_DIRECTIONAL_FLOW_PER_ONU) + i
        yield alloc_id

def hexstring(string):
    return ":".join("{:02x}".format(ord(c)) for c in string)

class ActivationManager(BaseOltAutomaton):

    onu_id = None
    serial_number = None
    onu_session_id = None
    port_id = None
    channel_id = None
    alloc_id = None
    vendor = None

    def parse_args(self, debug=0, store=0, **kwargs):
        self.onu_id = kwargs.pop('onu_id')
        self.serial_number = kwargs.pop('serial_number')
        self.onu_session_id = kwargs.pop('onu_session_id')
        self.port_id = self.onu_id
        self.channel_id = kwargs.pop('channel_id')
        self.alloc_id = alloc_id(self.onu_id)

        if self.onu_id is None or self.serial_number is None or \
                self.onu_session_id is None or self.channel_id is None:
            raise ValueError('ONU is not well defined')

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)

    """
    States
    """

    @ATMT.state(initial=1)
    def got_activation_event(self):
        pass

    @ATMT.state()
    def wait_get_auth_mode(self):
        pass

    @ATMT.state()
    def got_auth_mode(self):
        pass

    @ATMT.state()
    def wait_omci_port_id(self):
        pass

    @ATMT.state()
    def got_omci_port_id(self):
        pass

    @ATMT.state()
    def wait_send_frame(self):
        pass

    @ATMT.state()
    def wait_omci_get(self):
        pass

    @ATMT.state()
    def wait_logical_object_status(self):
        pass

    @ATMT.state()
    def wait_set_alloc_id(self):
        pass

    @ATMT.state()
    def wait_dba_mode(self):
        pass

    @ATMT.state()
    def wait_send_dba_alg_msg(self):
        pass

    @ATMT.state()
    def wait_dba_alg_event(self):
        pass

    @ATMT.state()
    def wait_set_port_id_config(self):
        pass

    @ATMT.state()
    def wait_get_onu_id_by_port_id(self):
        pass

    @ATMT.state()
    def wait_set_vlan_uplink_config(self):
        pass

    @ATMT.state(final=1)
    def end(self):
        pass

    @ATMT.state(error=1)
    def error(self, msg):
        log.error(msg)

    """
    Utility Methods
    """

    def px(self, pkt):
        return self.p(pkt, channel_id=self.channel_id,
                      onu_id=self.onu_id, onu_session_id=self.onu_session_id)

    def detect_onu(self):
        log.info("Activated {} ONT".format(self.vendor))
        try:
            self.device.onu_detected(
                parent_port_no=self.channel_id,
                child_device_type='%s_onu' % self.vendor.lower(),
                onu_id=self.onu_id,
                serial_number=hexstring(self.serial_number),
                onu_session_id=self.onu_session_id
            )
        except Exception as e:
            print e

    """
    Transitions
    """

    # Transition from got_activation_event
    @ATMT.condition(got_activation_event)
    def send_get_activation_auth_mode(self):
        auth_mode = PAS5211MsgGetActivationAuthMode()
        self.send(self.p(auth_mode))
        raise self.wait_get_auth_mode()

    # Transitions from wait_get_auth_mode
    @ATMT.timeout(wait_get_auth_mode, 3)
    def timeout_get_auth_mode(self):
        raise self.error('Could not get auth mode for OLT {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_get_auth_mode)
    def wait_for_get_auth_mode(self, pkt):
        if PAS5211MsgGetActivationAuthModeResponse in pkt:
            if pkt.mode == PON_ACTIVATION_AUTH_AUTO:
                raise self.got_auth_mode()
            else:
                # TODO There may be something that can be done here.
                # See line 2497 of PAS_onu_mode_change_thread.c
                log.error('Got unknown auth mode {}; dropping activation event'.format(pkt.mode))
                raise self.end()

    # Transitions from got auth_mode
    @ATMT.condition(got_auth_mode)
    def send_omci_port_id(self):
        omci_port_id = PAS5211MsgSetOnuOmciPortId(port_id=self.port_id, activate=PON_ENABLE)
        self.send(self.px(omci_port_id))
        raise self.wait_omci_port_id()

    # Transitions from wait_omci_port_id
    @ATMT.timeout(wait_omci_port_id, 3)
    def timeout_omci_port_id(self):
        raise self.error('Could not set omci port id for OLT {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_omci_port_id)
    def wait_for_omci_port_id(self, pkt):
        if pkt.opcode == PAS5211MsgSetOnuOmciPortIdResponse.opcode and \
                pkt.onu_id == self.onu_id and pkt.onu_session_id == self.onu_session_id and \
                pkt.channel_id == self.channel_id:
            raise self.got_omci_port_id()

    # Transitions from got_omci_port_id
    @ATMT.condition(got_omci_port_id)
    def send_omci_identity_frame(self):
        # attr_mask |= OMCI_ATTR_BIT(OMCI_CIRCUIT_PACK_ATTR_VENDOR_ID);
        #message.attributes_mask = 2048

        # Entity_id
        # equip_ind = OMCI_CIRCUIT_PACK_INTEGRATED_EQUIPMENT;
        # slot_id = 257;
        # entity_instance = ((equip_ind<<8) | slot_id
        message = OmciGet(entity_class=CircuitPack.class_id, entity_id = 257,
                          attributes_mask=2048)
        #TODO fix transaction id
        frame = OmciFrame(transaction_id=0, message_type=OmciGet.message_id,
                          omci_message=message)
        omci_frame = PAS5211MsgSendFrame(port_type=PON_PORT_PON, port_id=self.port_id,
                                         management_frame=PON_ENABLE, frame=frame)


        self.send(self.px(omci_frame))

        raise self.wait_send_frame()

    # Transitions from wait_send_frame
    @ATMT.timeout(wait_send_frame, 3)
    def timeout_send_frame(self):
        raise self.error('Could not send omci to OLT {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_send_frame)
    def wait_for_send_frame(self, pkt):
        if PAS5211MsgSendFrameResponse in pkt:
            raise self.wait_omci_get()

    # Transitions from wait_omci_get
    @ATMT.timeout(wait_omci_get, 3)
    def timeout_send_frame(self):
        raise self.error('Did not receive omci get event from OLT {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_omci_get)
    def wait_for_omci_get(self, pkt):
        if OmciGetResponse in pkt:
            self.allocId = self.alloc_id.next()
            self.vendor = pkt['OmciGetResponse'].data['vendor_id']
            l_obj_status = PAS5211MsgGetLogicalObjectStatus(
                            type=PON_LOGICAL_OBJECT_TYPE_ALLOC_ID,
                            value=self.allocId)
            self.send(self.px(l_obj_status))
            raise self.wait_logical_object_status()

    # Transitions from wait_logical_object_status
    @ATMT.timeout(wait_logical_object_status, 3)
    def timeout_logical_object_status(self):
        raise self.error('Did not receive info about alloc id status for {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_logical_object_status)
    def wait_for_logical_object_status(self, pkt):
        if PAS5211MsgGetLogicalObjectStatusResponse in pkt:
            if pkt.type == PON_LOGICAL_OBJECT_TYPE_ALLOC_ID:
                if pkt.return_value == 0:
                    # alloc-id not set
                    set_alloc_id = PAS5211MsgSetOnuAllocId(
                                    alloc_id=self.allocId,
                                    allocate=PON_ENABLE
                                )
                    self.onu_id = -1
                    self.port_id = self.allocId
                    self.send(self.px(set_alloc_id))
                    raise self.wait_set_alloc_id()
                else:
                    l_obj_status = PAS5211MsgGetLogicalObjectStatus(
                        type=PON_LOGICAL_OBJECT_TYPE_ONU_ID_BY_ALLOC_ID,
                        value=self.allocId)
                    self.send(self.px(l_obj_status))
                    raise self.wait_logical_object_status()
            elif pkt.type == PON_LOGICAL_OBJECT_TYPE_ONU_ID_BY_ALLOC_ID:
                # That's your onu id.
                self.onu_id = pkt.return_value
                # FIXME Need to iterate to get the port id as
                # in PMC_OFAL_flow_db.c line 656
                # UPDATE PORT_ID
                set_alloc_id = PAS5211MsgSetOnuAllocId(
                    alloc_id=self.allocId,
                    allocate=PON_ENABLE
                )
                self.send(self.px(set_alloc_id))
                raise self.wait_for_set_alloc_id() #FIXME are we done? probably not but check

    # Transitions from wait_set_alloc_id
    @ATMT.timeout(wait_set_alloc_id, 3)
    def timeout_set_alloc_id(self):
        raise self.error('Was not able to set alloc id for {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_set_alloc_id)
    def wait_for_set_alloc_id(self, pkt):
        if PAS5211MsgSetOnuAllocIdResponse in pkt:
            self.send(self.px(PAS5211MsgGetDbaMode()))
            raise self.wait_dba_mode()

    # Transitions from wait for dba mode (See Pythagoras_api.c line 344 & PMC_OFAL.c 2062)
    @ATMT.timeout(wait_dba_mode, 3)
    def timeout_wait_dba_mode(self):
        raise self.error('Did not get DBA mode for {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))


    @ATMT.receive_condition(wait_dba_mode)
    def wait_for_dba_mode(self, pkt):
        if PAS5211MsgGetDbaModeResponse in pkt:
            if pkt.dba_mode != PON_DBA_MODE_RUNNING:
                raise self.error('DBA is not running; dropping activation event for {}'
                           .format(hexstring(self.serial_number)))

            data = pack('<LLHHBBBB', PYTHAGORAS_UPDATE_AID_SLA,
                        self.allocId, SLA_gr_bw_gros, SLA_be_bw_gros,
                        SLA_gr_bw_fine, SLA_be_bw_fine, PYTHAGORAS_DBA_DATA_COS,
                        PYTHAGORAS_DBA_STATUS_REPORT_NSR)

            send_dba_alg = PAS5211MsgSendDbaAlgorithmMsg(data=data)
            self.send(self.px(send_dba_alg))
            raise self.wait_send_dba_alg_msg()

    # Transitions from wait_send_dba_alg_msg
    @ATMT.timeout(wait_send_dba_alg_msg, 3)
    def timeout_wait_for_send_dba_alg_msg(self):
        raise self.error('Unable to set dba alg params for {}; dropping activation event for {}'
                         .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_send_dba_alg_msg)
    def wait_for_send_dba_alg_msg(self, pkt):
        if PAS5211MsgSendDbaAlgorithmMsgResponse in pkt:
            raise self.wait_dba_alg_event()

    # Transitions from wait_dba_alg_event
    @ATMT.timeout(wait_dba_alg_event, 3)
    def timeout_wait_for_send_dba_alg_event(self):
        raise self.error('DBA params ont set for {}; dropping activation event for {}'
                         .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_dba_alg_event)
    def wait_for_send_dba_alg_event(self, pkt):
        if PAS5211EventDbaAlgorithm in pkt:
            if pkt.size < PYTHAGORAS_SET_SLA_RESP_SIZE:
                raise self.error('DBA Event message too small for {}, dropping activation event for {}'
                                 .format(self.target, hexstring(self.serial_number)))

            (_, aid, _) = unpack('<LLH',pkt.data)
            if aid == self.allocId:
                # All is well moving on.
                # There is some more shit at PYTHAGORAS.c line 395 but fuck it.
                set_port_id_config = PAS5211MsgSetPortIdConfig(
                    port_id=self.port_id,
                    activate=PON_ENABLE,
                    alloc_id=self.allocId,
                    type=PON_PORT_TYPE_GEM,
                    destination=PON_PORT_DESTINATION_CNI0
                )
                self.send(self.px(set_port_id_config))
                raise self.wait_set_port_id_config()

    # Transitions from wait_set_port_id_config
    @ATMT.timeout(wait_set_port_id_config, 3)
    def timeout_wait_set_port_id_config(self):
        raise self.error('Could not set port id config for {}; dropping activation event for {}'
                         .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_set_port_id_config)
    def wait_for_set_port_id_config(self, pkt):
        if PAS5211MsgSetPortIdConfigResponse in pkt:
            get_onu_id = PAS5211MsgGetOnuIdByPortId(
                port_id=self.port_id
            )
            self.send(self.px(get_onu_id))
            raise self.wait_get_onu_id_by_port_id()

    # Transistions from wait_get_onu_id_by_port_id
    @ATMT.timeout(wait_get_onu_id_by_port_id, 3)
    def timeout_wait_get_onu_id_by_port_id(self):
        raise self.error('Could not get onu id for {}; dropping activation event for {}'
                         .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_get_onu_id_by_port_id)
    def wait_for_get_onu_id_by_port_id(self, pkt):
        if PAS5211MsgGetOnuIdByPortIdResponse in pkt:
            self.onu_id = pkt['PAS5211MsgGetOnuIdByPortIdResponse'].onu_id
            # There may be more things to do here. but traces indicate that no.
            # see PAS.c line 977 and onwards.
            set_vlan_uplink_config = PAS5211SetVlanUplinkConfiguration(
                port_id=self.port_id,
                pvid_config_enabled=PON_FALSE,
                min_cos=0,
                max_cos=7,
                de_bit=PON_DISABLE
            )
            self.send(self.px(set_vlan_uplink_config))
            raise self.wait_set_vlan_uplink_config()

    # Transitions from wait_set_vlan_uplink_config
    @ATMT.timeout(wait_set_vlan_uplink_config, 3)
    def timeout_wait_set_vlan_uplink_config(self):
        raise self.error('Could not set vlan uplink config for {}; dropping activation event for {}'
                                 .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_set_vlan_uplink_config)
    def wait_for_set_vlan_uplink_config(self, pkt):
        if PAS5211SetVlanUplinkConfigurationResponse in pkt:
            # YAY we made it.
            # TODO update OLT with CNI port
            self.detect_onu()
            raise self.end()


class ActivationWatcher(BaseOltAutomaton):

    """
    States
    """

    @ATMT.state(initial=1)
    def wait_onu_activation_event(self):
        pass

    """
    Transitions
    """

    # Transitions from wait_onu_activation_event
    @ATMT.receive_condition(wait_onu_activation_event)
    def wait_for_onu_activation_event(self, pkt):
        if PAS5211EventOnuActivation in pkt:
            log.info('{} activated'.format(hexstring(pkt.serial_number)))
            onu_activation = ActivationManager(iface=self.iface, target=self.target, comm=self.comm,
                                               onu_id=pkt.onu_id, serial_number=pkt.serial_number,
                                               onu_session_id=pkt.onu_session_id,
                                               channel_id=pkt.channel_id, device=self.device)
            onu_activation.runbg()
            raise self.wait_onu_activation_event()
