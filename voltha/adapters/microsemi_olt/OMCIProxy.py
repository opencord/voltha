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

log = structlog.get_logger()

class OMCIProxy(BaseOltAutomaton):


    proxy_address = None
    msg = None

    def parse_args(self, debug=0, store=0, **kwargs):
        self.proxy_address = kwargs.pop('proxy_address')
        self.msg = kwargs.pop('msg')

        BaseOltAutomaton.parse_args(self, debug=debug, store=store, **kwargs)

    """
    States
    """

    @ATMT.state(initial=1)
    def got_omci_msg(self):
        pass

    @ATMT.state(error=1)
    def error(self, msg):
        log.error(msg)

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
