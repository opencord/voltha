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

log = structlog.get_logger()


class APIProxy(BaseOltAutomaton):

    proxy_address = None
    msg = None
    opcode = None

    def parse_args(self, debug=0, store=0, **kwargs):
        self.adaptor_agent = kwargs.pop('adapter_agent')
        self.proxy_address = kwargs.pop('proxy_address')
        self.msg = kwargs.pop('msg')

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)

    def restart(self, *args, **kargs):
        self.msg = kargs.pop('msg')
        super(APIProxy, self).restart()

    def master_filter(self, pkt):

        if not super(APIProxy, self).master_filter(pkt):
            return False

        if not self.proxy_address.channel_id:
            self.proxy_address.channel_id = 0

        if not self.proxy_address.onu_id:
            self.proxy_address.onu_id = 0

        # if OmciFrame in pkt:
        #     # if pkt[OmciFrame].message_type in (16, 17):
        #     return False


        if PAS5211MsgHeader in pkt:
            if PAS5211MsgGetOltVersionResponse not in pkt:
                if pkt[PAS5211MsgHeader].channel_id == self.proxy_address.channel_id:
                    if pkt[PAS5211MsgHeader].onu_id == self.proxy_address.onu_id:
                        if OmciFrame not in pkt:
                            rcv_opcode = pkt[PAS5211MsgHeader].opcode & 0xFF
                            if rcv_opcode == self.opcode:
                                return True

        return False

    """
    States
    """

    @ATMT.state(initial=1)
    def send_msg(self):
        pass

    @ATMT.state()
    def wait_response(self):
        pass

    @ATMT.state(error=1)
    def error(self, msg):
        log.error(msg)
        raise self.end()


    @ATMT.state(final=1)
    def end(self):
        log.debug('api-msg-end')
        # pass

    """
    Utils
    """

    def px(self, pkt):

        if not self.proxy_address.channel_id:
            self.proxy_address.channel_id = 0

        return self.p(pkt, channel_id=self.proxy_address.channel_id,
            onu_id=self.proxy_address.onu_id,
            onu_session_id=self.proxy_address.onu_session_id)

    """
    Transitions
    """

    @ATMT.condition(send_msg)
    def send_api_msg(self):
        log.debug('send-api-msg')
        self.opcode = self.msg.opcode & 0xFF
        self.send(self.px(self.msg))
        raise self.wait_response()

    # Transitions from wait_event
    @ATMT.timeout(wait_response, 10)
    def timeout_wait_response(self):
        log.debug('api-proxy-timeout')
        # Send empty packet...
        self.adaptor_agent.receive_proxied_message(self.proxy_address, dict());
        raise self.error("No API event for {}".format(self.proxy_address))

    @ATMT.receive_condition(wait_response)
    def wait_for_response(self, pkt):
        if PAS5211MsgHeader in pkt: # and not isinstance(pkt, OmciFrame):
            log.debug("adaptor-rcv", adaptor=self.adaptor_agent)
            self.adaptor_agent.receive_proxied_message(self.proxy_address, pkt['PAS5211MsgHeader'])
            raise self.end()

    def __del__(self):
        log.debug("APIProxy deleted")
        super(APIProxy, self).__del__()