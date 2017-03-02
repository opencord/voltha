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
from scapy.automaton import Automaton
from scapy.sendrecv import sendp
import structlog

log = structlog.get_logger()
_verbose = False

class BaseOltAutomaton(Automaton):

    comm = None
    retry = 3
    iface = None
    target = None
    verbose = None
    adaptor_agent = None
    device = None

    def parse_args(self, debug=0, store=0, **kwargs):
        self.comm = kwargs.pop('comm', None)
        self.target = kwargs.pop('target', None)
        self.device = kwargs.pop('device', None)
        Automaton.parse_args(self, debug=debug, store=store, **kwargs)
        self.verbose = kwargs.get('verbose', _verbose)
        self.iface = kwargs.get('iface', "eth0")

        if self.comm is None or self.target is None:
            raise ValueError("Missing comm or target")

    def my_send(self, pkt):
        sendp(pkt, iface=self.iface, verbose=self.verbose)

    def master_filter(self, pkt):
        """
        Anything coming from the OLT is for us
        :param pkt: incoming packet
        :return: True if it came from the olt
        """
        return pkt.src == self.target

    def debug(self, lvl, msg):
        if self.debug_level >= lvl:
            log.info(msg)

    def p(self, pkt, channel_id=-1, onu_id=-1, onu_session_id=-1):
        return self.comm.frame(pkt, channel_id=channel_id,
                               onu_id=onu_id, onu_session_id=onu_session_id)
