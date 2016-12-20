#
# Copyright 2016 the original author or authors.
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
from scapy.automaton import ATMT
from twisted.internet import reactor
import structlog
from voltha.adapters.microsemi.BaseOltAutomaton import BaseOltAutomaton
from voltha.adapters.microsemi.PAS5211 import PAS5211EventOnuActivation, PAS5211MsgGetActivationAuthMode, \
    PAS5211MsgGetActivationAuthModeResponse, PON_ACTIVATION_AUTH_AUTO, PON_ENABLE, PAS5211MsgSetOnuOmciPortId, \
    PAS5211MsgSetOnuOmciPortIdResponse, PAS5211MsgSendFrame, PON_PORT_PON, PAS5211MsgSendFrameResponse
from voltha.extensions.omci.omci_entities import CircuitPack
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciGet, OmciGetResponse
from voltha.protos.common_pb2 import AdminState
from voltha.protos.common_pb2 import OperStatus
from voltha.protos.device_pb2 import Port

log = structlog.get_logger()
_verbose = False

def hexstring(string):
    return ":".join("{:02x}".format(ord(c)) for c in string)

class ActivationManager(BaseOltAutomaton):

    onu_id = None
    serial_number = None
    onu_session_id = None
    port_id = None
    channel_id = None

    def parse_args(self, debug=0, store=0, **kwargs):
        self.onu_id = kwargs.pop('onu_id')
        self.serial_number = kwargs.pop('serial_number')
        self.onu_session_id = kwargs.pop('onu_session_id')
        self.port_id = self.onu_id
        self.channel_id = kwargs.pop('channel_id')

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

    @ATMT.state(final=1)
    def end(self):
        pass

    @ATMT.state(error=1)
    def error(self):
        pass

    """
    Utility Methods
    """

    def create_port(self, pkt):
        vendor = pkt['OmciGetResponse'].data['vendor_id']
        port = Port(port_no=self.port_id,
                    label="{} ONU".format(vendor),
                    type=Port.ETHERNET_UNI,
                    admin_state=AdminState.ENABLED,
                    oper_status=OperStatus.ACTIVE
        )
        self.device.add_port(port)

    def px(self, pkt):
        return self.p(pkt, channel_id=self.channel_id,
                      onu_id=self.onu_id, onu_session_id=self.onu_session_id)

    def error(self, msg):
        log.error(msg)
        raise self.error()

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
        self.error('Could not get auth mode for OLT {}; dropping activation event for {}'
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
        self.error('Could not set omci port id for OLT {}; dropping activation event for {}'
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
        self.error('Could not send omci to OLT {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_send_frame)
    def wait_for_send_frame(self, pkt):
        if pkt.opcode == PAS5211MsgSendFrameResponse.opcode:
            raise self.wait_omci_get()

    # Transitions from wait_omci_get
    @ATMT.timeout(wait_omci_get, 3)
    def timeout_send_frame(self):
        self.error('Did not receive omci get event from OLT {}; dropping activation event for {}'
                   .format(self.target, hexstring(self.serial_number)))

    @ATMT.receive_condition(wait_omci_get)
    def wait_for_omci_get(self, pkt):
        if OmciGetResponse in pkt:
            log.info("Activated {} ONT".format(pkt['OmciGetResponse'].data['vendor_id']))
            self.create_port(pkt)
            # TODO: create onu proxy device
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
