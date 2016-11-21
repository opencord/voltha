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


"""
PAS5211 scapy structs used for interaction with Ruby
"""
from scapy.fields import LEShortField, Field, LEIntField, LESignedIntField, FieldLenField, FieldListField
from scapy.layers.l2 import Dot3, LLC
from scapy.packet import Packet, bind_layers, split_layers
from scapy.utils import lhex
from scapy.volatile import RandSInt
from scapy.layers.ntp import XLEShortField

"""
Extra field structs
"""

class LESignedShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<h")

class XLESignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<i")
    def randval(self):
        return RandSInt()
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

"""
PAS5211 Message structs
"""

class PAS5211Msg(Packet):
    opcode = "Must be filled by subclass"
    pass

class PAS5211FrameHeader(Packet):
    name = "PAS5211FrameHeader"
    fields_desc = [
        LEShortField("part", 1),
        LEShortField("total_parts", 1),
        LEShortField("size", 0),
        XLESignedIntField("magic_number", 0x1234ABCD)
    ]

class PAS5211MsgHeader(Packet):
    name = "PAS5211MsgHeader"
    fields_desc = [
        LEIntField("sequence_number", 0),
        XLEShortField("opcode", 0),
        LEShortField("event_type", 0),
        LESignedShortField("channel_id", -1),
        LESignedShortField("onu_id", -1),
        LESignedIntField("onu_session_id", -1)
    ]


class PAS5211MsgGetOltVersion(PAS5211Msg):
    opcode = 3
    name = "PAS5211MsgGetOltVersion"
    fields_desc = [ ]

    def answers(self, other):
        return other.name == "PAS5211MsgGetOltVersionResponse"


class PAS5211MsgGetProtocolVersion(PAS5211Msg):
    opcode = 2
    name = "PAS5211MsgGetProtocolVersion"
    fields_desc = [ ]


class PAS5211MsgGetProtocolVersionResponse(PAS5211Msg):
    name = "PAS5211MsgGetProtocolVersionResponse"
    fields_desc = [
        LEShortField("major_hardware_version", 0),
        LEShortField("minor_hardware_version", 0),
        LEShortField("major_pfi_version", 0),
        LEShortField("minor_pfi_version", 0)
    ]

    def answers(self, other):
        return other.name == 'PAS5211MsgGetProtocolVersion'


class PAS5211MsgGetOltVersionResponse(PAS5211Msg):
    name = "PAS5211MsgGetOltVersionResponse"
    fields_desc = [
        LEShortField("major_firmware_version", 0),
        LEShortField("minor_firmware_version", 0),
        LEShortField("build_firmware_version", 0),
        LEShortField("maintenance_firmware_version", 0),
        LEShortField("major_hardware_version", 0),
        LEShortField("minor_hardware_version", 0),
        LEIntField("system_port_mac_type", 0),
        FieldLenField("channels_supported", 0, fmt="<H"),
        LEShortField("onus_supported_per_channel", 0),
        LEShortField("ports_supported_per_channel", 0),
        LEShortField("alloc_ids_supported_per_channel", 0),
        FieldListField("critical_events_counter", [0, 0, 0, 0],
                       LEIntField("entry", 0),
                       count_from=lambda pkt: pkt.channels_supported),
        FieldListField("non_critical_events_counter", [0, 0, 0, 0],
                       LEIntField("entry", 0),
                       count_from=lambda pkt: pkt.channels_supported)
    ]

    # FIXME: find a better way to pair messages together.
    def answers(self, other):
        return other.name == "PAS5211MsgGetOltVersion"

"""
Bindings used for message processing
"""

split_layers(Dot3, LLC)
bind_layers(Dot3,PAS5211FrameHeader)
bind_layers(PAS5211FrameHeader, PAS5211MsgHeader)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetOltVersionResponse, opcode=0x3800 | 3)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetProtocolVersionResponse, opcode=0x2800 | 2)