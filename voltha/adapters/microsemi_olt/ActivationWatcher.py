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

from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue

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
    PAS5211SetVlanUplinkConfiguration, PAS5211SetVlanUplinkConfigurationResponse, PAS5211MsgSetOnuAllocIdResponse, \
    PAS5211MsgHeader, PAS5211MsgGetOltVersionResponse, PAS5211EventOnuDeactivation, PAS5211EventAlarmNotification

    #PAS5211EventAlarmNotification, PAS5211EventOnuDeactivation
from voltha.adapters.microsemi_olt.PAS5211_constants import PON_ACTIVATION_AUTH_AUTO, PON_ENABLE, PON_PORT_PON, \
    PON_LOGICAL_OBJECT_TYPE_ALLOC_ID, PON_LOGICAL_OBJECT_TYPE_ONU_ID_BY_ALLOC_ID, PON_TRUE, \
    PMC_OFAL_MAX_BI_DIRECTIONAL_FLOW_PER_ONU, PMC_OFAL_START_FLOW_ID_BASE, PON_DBA_MODE_RUNNING, \
    PYTHAGORAS_UPDATE_AID_SLA, SLA_be_bw_gros, SLA_gr_bw_gros, SLA_gr_bw_fine, SLA_be_bw_fine, PYTHAGORAS_DBA_DATA_COS, \
    PYTHAGORAS_DBA_STATUS_REPORT_NSR, PYTHAGORAS_SET_SLA_RESP_SIZE, PON_PORT_TYPE_GEM, PON_PORT_DESTINATION_CNI0, \
    PON_FALSE, PON_DISABLE, PON_ALARM_LOS, PASCOMM_RETRIES, \
    PON_ALARM_LOSI, PON_ALARM_DOWI, PON_ALARM_LOFI, PON_ALARM_RDII, PON_ALARM_LOAMI, PON_ALARM_LCDGI, \
    PON_ALARM_LOAI, PON_ALARM_SDI, PON_ALARM_SFI, PON_ALARM_PEE, PON_ALARM_DGI, PON_ALARM_LOKI, PON_ALARM_TIWI, \
    PON_ALARM_TIA, PON_ALARM_AUTH_FAILED_IN_REGISTRATION_ID_MODE, PON_ALARM_SUFI,\
    PON_DOWNSTREAM_PLOAM_MESSAGE_ENCRYPTED_PORT_ID, PON_DOWNSTREAM_PLOAM_MESSAGE_ASSIGN_ALLOC_ID, \
    PON_DOWNSTREAM_PLOAM_MESSAGE_CONFIGURE_PORT_ID, PON_DOWNSTREAM_PLOAM_MESSAGE_BER_INTERVAL, \
    PON_DOWNSTREAM_PLOAM_MESSAGE_KEY_SWITCHING, PON_ALARM_SDI_RAISE, PON_ALARM_SDI_CLEAR, \
    PON_ALARM_RAISE, PON_ALARM_CLEAR

from voltha.extensions.omci.omci_entities import CircuitPack
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciGet, OmciGetResponse, OmciAlarmNotification


from twisted.internet import reactor

from voltha.protos.events_pb2 import AlarmEvent, AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory, AlarmEventCategory

log = structlog.get_logger()
_verbose = False

MAX_RETRIES = 10

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
    olt_adapter = None
    retries = 0

    def parse_args(self, debug=0, store=0,**kwargs):
        self.onu_id = kwargs.pop('onu_id')
        self.serial_number = kwargs.pop('serial_number')
        self.onu_session_id = kwargs.pop('onu_session_id')
        self.port_id = self.onu_id
        self.channel_id = kwargs.pop('channel_id')
        self.alloc_id = alloc_id(self.onu_id)
        self.activation_watcher = kwargs.pop('activation_watcher')
        self.olt_adapter = kwargs.pop('olt_adapter')

        if self.onu_id is None or self.serial_number is None or \
                self.onu_session_id is None or self.channel_id is None:
            raise ValueError('ONU is not well defined')

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)

    """
        Master filter: Do not allow PAS5211MsgGetOltVersionResponse
    """

    def master_filter(self, pkt):

        if not super(ActivationManager, self).master_filter(pkt):
            return False


        if OmciFrame in pkt:
            if pkt[OmciFrame].message_type in (16, 17):
                return False

        if PAS5211MsgGetOltVersionResponse not in pkt:
            if PAS5211MsgHeader in pkt:
                if pkt[PAS5211MsgHeader].channel_id == self.channel_id:
                    return True

        return False

    def create_default_data_flow_olt_config(self):
        # PAS_set_onu_alloc_id
        # PYTHAGORAS_set_SLA
        # PAS_map_port_id_to_alloc_id
        # PAS_set_vlan_uplink_configuration
        pass

    # def register_activation_watcher(self, activation_watcher):
    #     self.activation_watcher = activation_watcher

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

    @ATMT.state(final=1)
    def end(self):
        log.debug("activation-manager-end")
        self.activation_watcher.next_activation()


    @ATMT.state(error=1)
    def error(self, msg):
        log.error(msg)
        raise self.end()

    """
    Utility Methods
    """

    def px(self, pkt):
        return self.p(pkt, channel_id=self.channel_id,
                      onu_id=self.onu_id, onu_session_id=self.onu_session_id)

    def detect_onu(self):
        try:
            log.info("Activated {} ONT, channel_id={}, onu_id={}, session_id={}, serial={} ".format(
                self.vendor, self.channel_id, self.onu_id, self.onu_session_id, hexstring(self.serial_number)))

            parent_port = self.channel_id * 32 + (self.onu_id + 1)
            self.olt_adapter.add_onu_info(parent_port, self.onu_id, self.onu_session_id)

            self.device.onu_detected(
                parent_port_no=parent_port,
                child_device_type='%s_onu' % self.vendor.lower(),
                onu_id=self.onu_id,
                serial_number=hexstring(self.serial_number),
                onu_session_id=self.onu_session_id,
                channel_id=self.channel_id
            )

        except Exception as e:
            log.exception('detect-onu-failed', e=e)
            # raise e

    """
    Transitions
    """

    # Transition from got_activation_event
    @ATMT.condition(got_activation_event)
    def send_get_activation_auth_mode(self):
        log.debug('PAS5211MsgGetActivationAuthMode, channel_id={}'.format(self.channel_id))
        auth_mode = PAS5211MsgGetActivationAuthMode()
        self.send(self.p(auth_mode, channel_id=self.channel_id))
        raise self.wait_get_auth_mode()

    # Transitions from wait_get_auth_mode
    @ATMT.timeout(wait_get_auth_mode, 3)
    def timeout_get_auth_mode(self):
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_get_activation_auth_mode()
        else:
            raise self.error('Could not get auth mode for OLT {}; dropping activation event for {}'
                .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_get_auth_mode)
    def wait_for_get_auth_mode(self, pkt):
        log.debug('wait_for_get_auth_mode')
        if PAS5211MsgGetActivationAuthModeResponse in pkt:
            log.debug('PAS5211MsgGetActivationAuthModeResponse')
            pkt = pkt[PAS5211MsgGetActivationAuthModeResponse]
            if pkt.mode == PON_ACTIVATION_AUTH_AUTO:
                raise self.got_auth_mode()
            else:
                # TODO There may be something that can be done here.
                # See line 2497 of PAS_onu_mode_change_thread.c
                log.error(
                    'Got unknown auth mode {}; dropping activation event'.format(pkt.mode))
                raise self.end()

    # Transitions from got auth_mode
    @ATMT.condition(got_auth_mode)
    def send_omci_port_id(self):
        log.debug('send_omci_port_id')
        omci_port_id = PAS5211MsgSetOnuOmciPortId(
            port_id=self.port_id, activate=PON_ENABLE)
        self.send(self.px(omci_port_id))
        raise self.wait_omci_port_id()

    # Transitions from wait_omci_port_id
    @ATMT.timeout(wait_omci_port_id, 3)
    def timeout_omci_port_id(self):
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_omci_port_id()
        else:
            raise self.error('Could not set omci port id for OLT {}; dropping activation event for {}'
                .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_omci_port_id)
    def wait_for_omci_port_id(self, pkt):
        log.debug('wait_for_omci_port_id')
        if PAS5211MsgSetOnuOmciPortIdResponse in pkt:
            log.debug('PAS5211MsgSetOnuOmciPortIdResponse')
            msg_header = pkt[PAS5211MsgHeader]
            if msg_header.opcode == PAS5211MsgSetOnuOmciPortIdResponse.opcode and \
                    msg_header.onu_id == self.onu_id and msg_header.onu_session_id == self.onu_session_id and \
                    msg_header.channel_id == self.channel_id:
                raise self.got_omci_port_id()

    # Transitions from got_omci_port_id
    @ATMT.condition(got_omci_port_id)
    def send_omci_identity_frame(self):
        log.debug('send_omci_identity_frame')

        message = OmciGet(entity_class=CircuitPack.class_id, entity_id=257,
                          attributes_mask=2048)
        # TODO fix transaction id
        frame = OmciFrame(transaction_id=0, message_type=OmciGet.message_id,
                          omci_message=message)
        omci_frame = PAS5211MsgSendFrame(port_type=PON_PORT_PON, port_id=self.port_id,
                                         management_frame=PON_ENABLE, frame=frame)

        self.send(self.px(omci_frame))

        raise self.wait_send_frame()

    # Transitions from wait_send_frame
    @ATMT.timeout(wait_send_frame, 3)
    def timeout_send_frame(self):
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_omci_identity_frame()
        else:
            raise self.error('Could not send omci to OLT {}; dropping activation event for {}'
                         .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_send_frame)
    def wait_for_send_frame(self, pkt):
        log.debug('wait_for_send_frame')
        if PAS5211MsgSendFrameResponse in pkt:
            log.debug('PAS5211MsgSendFrameResponse')
            raise self.wait_omci_get()

    # Transitions from wait_omci_get
    @ATMT.timeout(wait_omci_get, 3)
    def timeout_omci_get(self):
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send_omci_identity_frame()
        else:
            raise self.error('Did not receive omci get event from OLT {}; dropping activation event for {}'
                .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_omci_get)
    def wait_for_omci_get(self, pkt):
        log.debug('wait_for_omci_get')
        if OmciGetResponse in pkt:
            log.debug('OmciGetResponse')
            self.allocId = self.alloc_id.next()
            #self.vendor = pkt['OmciGetResponse'].data['vendor_id']
            self.vendor = pkt[OmciGetResponse].data['vendor_id']
            log.debug('wait_for_omci_get vendor_id:' + self.vendor)
            l_obj_status = PAS5211MsgGetLogicalObjectStatus(
                type=PON_LOGICAL_OBJECT_TYPE_ALLOC_ID,
                value=self.allocId)
            self.send(self.p(l_obj_status, channel_id=self.channel_id))
            raise self.wait_logical_object_status()

    # Transitions from wait_logical_object_status
    @ATMT.timeout(wait_logical_object_status, 3)
    def timeout_logical_object_status(self):
        if self.retries < MAX_RETRIES:
            self.retries += 1
            l_obj_status = PAS5211MsgGetLogicalObjectStatus(
                type=PON_LOGICAL_OBJECT_TYPE_ALLOC_ID,
                value=self.allocId)
            self.send(self.p(l_obj_status, channel_id=self.channel_id))
        else:
            raise self.error('Did not receive info about alloc id status for {}; dropping activation event for {}'
                .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_logical_object_status)
    def wait_for_logical_object_status(self, pkt):
        log.debug('wait_for_logical_object_status')
        if PAS5211MsgGetLogicalObjectStatusResponse in pkt:
            pkt = pkt[PAS5211MsgGetLogicalObjectStatusResponse]
            log.debug('PAS5211MsgGetLogicalObjectStatusResponse pkt.type=' + str(pkt.type) + ' pkt.return_value=' + str(
                pkt.return_value))
            if pkt.type == PON_LOGICAL_OBJECT_TYPE_ALLOC_ID:  # PASCOMM_GPON_api_parser.c line:11994
                if pkt.return_value == 0:
                    log.debug(
                        'PAS5211MsgGetLogicalObjectStatusResponse (pkt.return_value == 0)')
                    # alloc-id not set
                    set_alloc_id = PAS5211MsgSetOnuAllocId(
                        alloc_id=self.allocId,
                        allocate=PON_ENABLE
                    )
                    # self.onu_id = -1
                    self.port_id = self.allocId
                    self.send(self.px(set_alloc_id))
                    raise self.wait_set_alloc_id()
                else:
                    log.debug(
                        'PAS5211MsgGetLogicalObjectStatusResponse (pkt.return_value != 0)')
                    l_obj_status = PAS5211MsgGetLogicalObjectStatus(
                        type=PON_LOGICAL_OBJECT_TYPE_ONU_ID_BY_ALLOC_ID,
                        value=self.allocId)
                    self.send(self.px(l_obj_status))
                    raise self.wait_logical_object_status()
            elif pkt.type == PON_LOGICAL_OBJECT_TYPE_ONU_ID_BY_ALLOC_ID:
                log.debug(
                    'PAS5211MsgGetLogicalObjectStatusResponse (pkt.type == PON_LOGICAL_OBJECT_TYPE_ALLOC_ID)')
                # That's your onu id.
                self.onu_id = pkt.return_value
                # FIXME Need to iterate to get the port id as
                # in PMC_OFAL_flow_db.c line 656
                set_alloc_id = PAS5211MsgSetOnuAllocId(
                    alloc_id=self.allocId,
                    allocate=PON_ENABLE
                )
                self.send(self.px(set_alloc_id))
                raise self.wait_set_alloc_id()  #  are we done? probably not but check

    # Transitions from wait_set_alloc_id
    @ATMT.timeout(wait_set_alloc_id, 3)
    def timeout_set_alloc_id(self):
        if self.retries < MAX_RETRIES:
            self.retries += 1
            set_alloc_id = PAS5211MsgSetOnuAllocId(
                    alloc_id=self.allocId,
                    allocate=PON_ENABLE
                )
            self.send(self.px(set_alloc_id))
        else:
            raise self.error('Was not able to set alloc id for {}; dropping activation event for {}'
                         .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_set_alloc_id)
    def wait_for_set_alloc_id(self, pkt):
        log.debug('wait_for_set_alloc_id')
        if PAS5211MsgSetOnuAllocIdResponse in pkt:
            self.send(self.p(PAS5211MsgGetDbaMode(),
                             channel_id=self.channel_id))
            raise self.wait_dba_mode()

    # Transitions from wait for dba mode (See Pythagoras_api.c line 344 &
    # PMC_OFAL.c 2062)
    @ATMT.timeout(wait_dba_mode, 3)
    def timeout_wait_dba_mode(self):
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send(self.p(PAS5211MsgGetDbaMode(),
                             channel_id=self.channel_id))
        else:
            raise self.error('Did not get DBA mode for {}; dropping activation event for {}'
                         .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_dba_mode)
    def wait_for_dba_mode(self, pkt):
        if PAS5211MsgGetDbaModeResponse in pkt:
            pkt = pkt[PAS5211MsgGetDbaModeResponse]
            if pkt.dba_mode != PON_DBA_MODE_RUNNING:
                raise self.error('DBA is not running; dropping activation event for {}'
                                 .format(hexstring(self.serial_number)))
            self.detect_onu()
            raise self.end()


class ActivationWatcher(BaseOltAutomaton):
    """
        Master filter: Do not allow PAS5211MsgGetOltVersionResponse
    """

    pending_activation_events = []
    activation_lock = False
    olt_adapter = None

    def master_filter(self, pkt):
        if not super(ActivationWatcher, self).master_filter(pkt):
            return False

        if PAS5211EventOnuActivation in pkt:
            return True

        elif PAS5211EventOnuDeactivation in pkt:
            return True

        elif PAS5211EventAlarmNotification in pkt:
            return True

        elif OmciAlarmNotification in pkt:
            return True

        return False


    # Callback from activation manager
    def next_activation(self):
        log.debug("next-activation")
        if self.pending_activation_events:
            self.activation_lock=True
            # Retrieve last element from list
            pkt = self.pending_activation_events.pop()
            self.activate_onu(pkt)
        else:
            self.activation_lock = False

    def parse_args(self, debug=0, store=0,**kwargs):
        self.olt_adapter = kwargs.pop('olt_adapter')
        BaseOltAutomaton.parse_args(self, **kwargs)

    def activate_onu(self, pkt):
        log.debug("activate-onu")
        msg_header = pkt[PAS5211MsgHeader]
        msg = pkt[PAS5211EventOnuActivation]
        log.debug('{} activated'.format(hexstring(msg.serial_number)))
        onu_activation = ActivationManager(iface=self.iface, target=self.target, comm=self.comm,
                                           onu_id=msg_header.onu_id, serial_number=msg.serial_number,
                                           onu_session_id=msg_header.onu_session_id,
                                           channel_id=msg_header.channel_id, device=self.device, activation_watcher=self, olt_adapter=self.olt_adapter)

        onu_activation.runbg()

    def deactivate_onu(self, pkt):
        log.debug("deactivate-onu")
        msg_header = pkt[PAS5211MsgHeader]
        try:
            log.debug("Deactivating ONT, channel_id={}, onu_id={}, session_id={}".format(
                msg_header.channel_id, msg_header.onu_id, msg_header.onu_session_id))

            self.device.deactivate_onu(channel_id=msg_header.channel_id,
                                       onu_id=msg_header.onu_id,
                                       onu_session_id=msg_header.onu_session_id)

            log.debug("Deactivated ONT, channel_id={}, onu_id={}, session_id={}".format(
                msg_header.channel_id, msg_header.onu_id, msg_header.onu_session_id))
        except Exception as e:
            log.exception('deactivate-onu failed', e=e)

    """
    States
    """

    @ATMT.state(initial=1)
    def wait_onu_activation_event(self):
        log.debug('activation-watcher-start')

    @ATMT.state(final=1)
    def end(self):
        log.debug('activation-watcher-end')

    """
    Transitions
    """

    # Transitions from wait_onu_activation_event
    @ATMT.receive_condition(wait_onu_activation_event)
    def wait_for_onu_activation_event(self, pkt):
        if PAS5211EventOnuActivation in pkt:
            log.debug('PAS5211EventOnuActivation Received')

            self.pending_activation_events.append(pkt)

            if not self.activation_lock:
                self.next_activation()

        elif PAS5211EventOnuDeactivation in pkt:
            log.debug('PAS5211EventOnuDeactivation Received')
            self.deactivate_onu(pkt)

        elif PAS5211EventAlarmNotification in pkt:
            msg = pkt[PAS5211EventAlarmNotification]
            log.debug('PAS5211EventAlarmNotification Received', code=msg.code, parameter1= msg.parameter1, parameter2= msg.parameter2,
                parameter3= msg.parameter3, parameter4= msg.parameter4)
            try:
                self.process_alarm(pkt)
            except Exception as e:
                log.exception('wait-for-onu-activation-alarm-event-error', e=e)

        elif OmciAlarmNotification in pkt:
            log.debug('OmciAlarmNotification Received')
            try:
                self.process_omci_alarm(pkt)
            except Exception as e:
                log.exception('wait-for-onu-activation-omci-alarm-event-error', e=e)

        else:
            pass

        raise self.wait_onu_activation_event()


    #Method to parse alarm and send it to DeviceManager
    def process_alarm(self, pkt):
        log.debug('proccess-alarm-start')
        msg_header = pkt[PAS5211MsgHeader]
        msg = pkt[PAS5211EventAlarmNotification]
        code = msg.code

        ctx = {
            'alarm_code': str(code),
        }

        alarm = dict(
            id='voltha.{}.{}.olt'.format(self.device.adapter_agent.adapter_name, self.device.device.id),
            resource_id=self.device.device.id,
            type=AlarmEventType.EQUIPMENT,
            category=AlarmEventCategory.OLT,
            severity=AlarmEventSeverity.MAJOR,
            context=ctx
        )

        if msg_header.onu_id >= 0:
            ctx['onu_id'] = str(msg_header.onu_id)
        if msg_header.channel_id >= 0:
            ctx['channel_id'] = str(msg_header.channel_id)
        if msg_header.onu_session_id >= 0:
            ctx['onu_session_id'] = str(msg_header.onu_session_id)

        if code == PON_ALARM_LOS:
            alarm['description'] = 'Loss of signal: OLT does not receive transmissions in the upstream'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_LOSI:
            alarm['description'] = 'Loss of signal for ONUi: no signal from the ONU when expected'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_DOWI:
            alarm['description'] = 'Loss of signal for ONUi: no signal from the ONU when expected'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_LOFI:
            alarm['description'] = 'Loss of frame of ONUi: no valid optical signal is received from the ONU'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_RDII:
            alarm['description'] = 'Remote Defect Indication of ONUi: OLT transmissions is received with defect at the ONUi'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_LOAMI:
            alarm['description'] = 'Loss of PLOAM for ONUi: 3 messages of ONU are missing after OLT sends PLOAMu request'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_LCDGI:
            alarm['description'] = 'Loss of GEM channel delineation: GEM fragment delineation of ONUi is lost'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_LOAI:
            alarm['description'] = 'Loss of acknowledge with ONUi: OLT does not receive ack from ONUi'
            if msg.parameter1 in (PON_DOWNSTREAM_PLOAM_MESSAGE_ENCRYPTED_PORT_ID, PON_DOWNSTREAM_PLOAM_MESSAGE_ASSIGN_ALLOC_ID,
                        PON_DOWNSTREAM_PLOAM_MESSAGE_CONFIGURE_PORT_ID, PON_DOWNSTREAM_PLOAM_MESSAGE_BER_INTERVAL,
                        PON_DOWNSTREAM_PLOAM_MESSAGE_KEY_SWITCHING):
                ctx['downstream_ploam_message_id'] = str(msg.parameter1)
                alarm['state'] = PON_ALARM_RAISE
            else:
                log.error('Error, ignored OLT Alarm {} from OLT device {} because Invalid PLOAM message id in OLT device'.format(code, self.device))
                return
        elif code == PON_ALARM_SDI:
            alarm['description'] = 'Signal Degraded of ONUi: raised when the upstream BER of ONUi goes below certain level'
            if msg.parameter1 in (PON_ALARM_SDI_RAISE, PON_ALARM_SDI_CLEAR):
                ctx['onu_id'] = str(msg_header.onu_id)
                ctx['parameter'] = str(msg.parameter1)
                alarm['state'] = PON_ALARM_RAISE
            else:
                log.error('Error, ignored OLT Alarm {} from OLT device {} because Invalid parameter of alarm SDI'.format(code, self.device))
                return
        elif code == PON_ALARM_SFI:
            alarm['description'] = 'Signal Fail of ONUi: raised when the upstream of ONUi becomes greater than some level'
            alarm['state'] = msg.parameter1
        elif code == PON_ALARM_PEE:
            alarm['description'] = 'Physical Equipment Error of ONUi: raised when the OLT receives a PEE message from the ONU'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_DGI:
            alarm['description'] = 'Dying Gasp of ONUi: raised when the OLT receives DG message from ONUi'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_LOKI:
            alarm['description'] = 'Loss of key synch with ONUi: Key transmission from ONU fails 3 times'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_TIWI:
            alarm['description'] = 'Transmission interference warning: raised when the drift of ONU transmissions exceeds specified threshold'
            alarm['state'] = msg.parameter2
        elif code == PON_ALARM_TIA:
            alarm['description'] = 'Transmission Interference Alarm: an ONU turns on its laser at another ONUs time'
            alarm['state'] = msg.parameter2
        else:
            log.error('Error, unsupported OLT Alarm {} received from OLT device {}'.format(code, self.device))
            return

        log.warn('Alarm', alarm=alarm)
        self.device.publish_alarm(alarm)
        log.debug('proccess-alarm-stop')


    def process_omci_alarm(self, pkt):

        log.debug('proccess-omci-alarm-start')
        msg_header = pkt[PAS5211MsgHeader]
        msg_omci_alarm = pkt[OmciAlarmNotification]

        ctx = {
            'entity_class': str(msg_omci_alarm.entity_class),
            'entity_id': str(msg_omci_alarm.entity_id),
            'alarm_bit_map': str(msg_omci_alarm.alarm_bit_map),
            'alarm_sequence_number': str(msg_omci_alarm.alarm_sequence_number)
        }

        if msg_header.onu_id >= 0:
            ctx['onu_id'] = str(msg_header.onu_id)
        if msg_header.channel_id >= 0:
            ctx['channel_id'] = str(msg_header.channel_id)
        if msg_header.onu_session_id >= 0:
            ctx['onu_session_id'] = str(msg_header.onu_session_id)

        alarm = dict(
            id='voltha.{}.{}.ont'.format(self.device.adapter_agent.adapter_name, self.device.device.id),
            resource_id=self.device.device.id,
            type=AlarmEventType.EQUIPMENT,
            category=AlarmEventCategory.OLT,
            context=ctx
        )

        self.device.publish_alarm(alarm)
        log.warn('Alarm', alarm=alarm)
        log.debug('proccess-alarm-stop')
