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
import netifaces
from scapy.layers.l2 import Dot3
import structlog
from voltha.adapters.microsemi_olt.PAS5211 import PAS5211Msg, PAS5211MsgHeader, PAS5211FrameHeader

log = structlog.get_logger()

def constructPAS5211Frames(msg, seq, src_mac, dst_mac, channel_id=-1,
                           onu_id=-1, onu_session_id=-1):

    assert isinstance(msg, PAS5211Msg)
    opcode = 0x3000 | msg.opcode

    inner_msg = PAS5211MsgHeader(
        sequence_number=seq,
        opcode=opcode,
        channel_id=channel_id,
        onu_id=onu_id,
        onu_session_id=onu_session_id
    ) / msg

    size = len(inner_msg)
    frame_body = PAS5211FrameHeader(size=size) / inner_msg
    frame = Dot3(src=src_mac, dst=dst_mac) / frame_body

    return frame

def sequence_generator(init):
    num = init
    while True:
        yield num
        num += 1

def determine_src_mac(iface):
    if iface in netifaces.interfaces():
        return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
    return None

class PAS5211Communication(object):
    def __init__(self, dst_mac, init=0, iface = None):
        self.iface = iface
        self.dst_mac = dst_mac
        self.src_mac = determine_src_mac(self.iface)
        self.seqgen = sequence_generator(init)

    def frame(self, msg, channel_id=-1, onu_id=-1, onu_session_id=-1):
        return constructPAS5211Frames(msg, self.seqgen.next(), self.src_mac,
                                      self.dst_mac, channel_id=channel_id,
                                      onu_id=onu_id, onu_session_id=onu_session_id)

