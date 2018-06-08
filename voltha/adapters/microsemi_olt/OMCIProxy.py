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
from voltha.adapters.microsemi_olt.PAS5211_constants import PON_ENABLE, PON_TRUE
from voltha.adapters.microsemi_olt.PAS5211_constants import PON_PORT_PON

from voltha.adapters.microsemi_olt.PAS5211 import PAS5211MsgHeader, PAS5211MsgGetOltVersionResponse, PAS5211MsgGetOltVersionResponse

from voltha.extensions.omci.omci_messages import OmciMibResetResponse

from voltha.extensions.omci.omci_frame import OmciFrame

import sys, gc

log = structlog.get_logger()

MAX_RETRIES = 10


class OMCIProxy(BaseOltAutomaton):

    proxy_address = None
    msg = None
    retries = 0
    to_send = None

    def parse_args(self, debug=0, store=0, **kwargs):
        self.adaptor_agent = kwargs.pop('adapter_agent')
        self.proxy_address = kwargs.pop('proxy_address')
        self.msg = kwargs.pop('msg')

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)

    def restart(self, *args, **kargs):
        self.msg = kargs.pop('msg')
        super(OMCIProxy, self).restart()


    def master_filter(self, pkt):
        if not super(OMCIProxy, self).master_filter(pkt):
            return False

        if not self.proxy_address.channel_id:
            self.proxy_address.channel_id = 0

        if not self.proxy_address.onu_id:
            self.proxy_address.onu_id = 0

        if PAS5211MsgHeader in pkt:
            if PAS5211MsgGetOltVersionResponse not in pkt:
                if pkt[PAS5211MsgHeader].channel_id == self.proxy_address.channel_id:
                    if pkt[PAS5211MsgHeader].onu_id == self.proxy_address.onu_id:
                        # OMCI response
                        if OmciFrame in pkt:
                            if pkt[OmciFrame].message_type not in (16, 17):
                                return True
                            else:
                                log.debug('OmciAlarmNotification Received')
                        # # SendFrameResponse corresponding to OMCI PAS request
                        elif PAS5211MsgSendFrameResponse in pkt:
                            return True
        return False

    """
    States
    """

    @ATMT.state(initial=1)
    def got_omci_msg(self):
        pass

    @ATMT.state()
    def wait_send_response(self):
        pass

    @ATMT.state()
    def wait_event(self):
        pass

    @ATMT.state(error=1)
    def error(self, msg):
        log.error(msg)
        raise self.end()

    @ATMT.state(final=1)
    def end(self):
        log.debug('omci-msg-end')
        # pass

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

    @ATMT.condition(got_omci_msg)
    def send_omci_msg(self):
        log.debug('send-omci-msg', proxy_address=self.proxy_address)
        send_frame = PAS5211MsgSendFrame(port_type=PON_PORT_PON, port_id=self.proxy_address.onu_id,
                                         management_frame=PON_TRUE, frame=self.msg)
        self.to_send = self.px(send_frame)
        self.send(self.to_send)
        raise self.wait_send_response()

    # Transitions from wait_send_response
    @ATMT.timeout(wait_send_response, 10)
    def timeout_wait_send_response(self):
        log.debug('omci-proxy-timeout')
        # Send back empty packet...
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send(self.to_send)
            raise self.wait_send_response()
        else:
            self.adaptor_agent.receive_proxied_message(self.proxy_address, dict())
            raise self.error("No ack for OMCI for {}".format(self.proxy_address))

    @ATMT.receive_condition(wait_send_response)
    def wait_for_send_response(self, pkt):
        if PAS5211MsgSendFrameResponse in pkt:
            raise self.wait_event()

    # Transitions from wait_event
    @ATMT.timeout(wait_event, 20)
    def timeout_wait_event(self):
        log.debug('omci-proxy-timeout')
        # Send back empty packet...
        if self.retries < MAX_RETRIES:
            self.retries += 1
            self.send(self.to_send)
            raise self.wait_send_response()
        else:
            self.adaptor_agent.receive_proxied_message(self.proxy_address, dict())
            raise self.error("No ack for OMCI for {}".format(self.proxy_address))

    @ATMT.receive_condition(wait_event)
    def wait_for_event(self, pkt):
        if PAS5211EventFrameReceived in pkt:
            log.debug("PAS5211EventFrameReceived")
            # FIXME we may need to verify the transaction id
            #  to make sure we have the right packet
            # pkt.show()
            # pkt['PAS5211EventFrameReceived'].show()
            log.debug("rcv-omci-msg", proxy_address=self.proxy_address)
            self.adaptor_agent.receive_proxied_message(self.proxy_address, pkt)
            raise self.end()

    def __del__(self):
        log.debug("OMCIProxy deleted")
        super(OMCIProxy, self).__del__()
