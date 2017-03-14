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
from voltha.adapters.microsemi_olt.PAS5211 import PAS5211MsgSendFrame, PAS5211MsgSendFrameResponse, \
    PAS5211EventFrameReceived

log = structlog.get_logger()

class Proxy(BaseOltAutomaton):

    proxy_address = None
    msg = None
    opcode = None

    def parse_args(self, debug=0, store=0, **kwargs):
        self.adaptor_agent = kwargs.pop('adapter_agent')
        self.proxy_address = kwargs.pop('proxy_address')
        self.msg = kwargs.pop('msg')

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)

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

    @ATMT.state(final=1)
    def end(self):
        pass

    """
    Utils
    """

    def px(self, pkt):
        return self.p(pkt, channel_id=self.proxy_address.channel_id,
                      onu_id=self.proxy_address.onu_id,
                      onu_session_id=self.proxy_address.onu_session_id)

    """
    Transitions
    """

    @ATMT.condition(send_msg)
    def send_msg(self):
        pkt = PAS5211MsgSendFrame(frame=self.msg, port_id=self.proxy_address.onu_id)
        opcode = packet.opcode & 0xFFFF
        self.send(self.px(pkt))
        raise self.wait_response()

    # Transitions from wait_event
    @ATMT.timeout(wait_response, 3)
    def timeout_wait_response(self):
        raise self.error("No OMCI event for {}".format(self.proxy_address))

    @ATMT.receive_condition(wait_response)
    def wait_response(self, pkt):
        if PAS5211EventFrameReceived in pkt:
            rcv_opcode = pkt.opcode & 0xFF
            if rcv_opcode==opcode:
                # FIXME we may need to verify the transaction id
                #  to make sure we have the right packet
                self.adaptor_agent.recieve_proxied_message(self.proxy_address,pkt)
                raise self.end()
                
            else:
                raise self.error("Received opcode "+pkt.opcode+" does not match")