from scapy.all import *
from scapy.layers.l2 import Dot3

MIN_FRAME_SIZE = 60

src_mac = "68:05:ca:05:f2:ef"
dst_mac = "00:0c:d5:00:01:00"


class PAS5211Dot3(Dot3):
    name = "PAS5211Dot3"

    def post_build(self, pkt, payload):
        pkt += payload
        size = ord(payload[4]) + (ord(payload[5]) << 8)
        length = size + 6  # this is a idiosyncracy of the PASCOMM protocol
        pkt = pkt[:12] + chr(length >> 8) + chr(length & 0xff) + pkt[14:]
        padding = MIN_FRAME_SIZE - len(pkt)
        if padding > 0:
            pkt = pkt + ("\x00" * padding)
        return pkt
    
    
class PAS5211FrameHeader(Packet):
    name = "PAS5211FrameHeader"
    fields_desc = [ LEShortField("part", 1),
                    LEShortField("total_parts", 1),
                    LEShortField("size", 0),
                    LEIntField("magic_number", 0x1234ABCD) ]

        
conf.neighbor.register_l3(Dot3, PAS5211FrameHeader, lambda l2,l3: conf.neighbor.resolve(l2,l3.payload))


class PAS5211MsgHeader(Packet):
    name = "PAS5211MsgHeader"
    fields_desc = [ LEIntField("sequence_number", 0),
                    LEShortField("opcode", 0) ]
    

class PAS5211MsgEntityHeader(Packet): # PASCOMM_GPON_msg_entity_hdr
    name = "PAS5211MsgEntityHeader"
    fields_desc = [ LEShortField("reserved", 0),
                    LEShortField("channel_id", 0xffff),
                    LEShortField("onu_id", 0xffff),
                    LESignedIntField("onu_session_id", -1) ]


class PAS5211Msg(Packet):
    opcode = "Must be filled by subclass"
    pass


class PAS5211MsgGetProtocolVersion(PAS5211Msg):
    opcode = 2
    name = "PAS5211MsgGetProtocolVersion"
    fields_desc = [ ]


class PAS5211MsgGetOltVersion(PAS5211Msg):
    opcode = 3
    name = "PAS5211MsgGetOltVersion"
    fields_desc = [ ]

    
def constructPAS5211Frames(msg, seq):

    assert isinstance(msg, PAS5211Msg)
    opcode = 0x3000 | msg.opcode

    entity_hdr = PAS5211MsgEntityHeader() # we may need non-def values later

    inner_msg = PAS5211MsgHeader(sequence_number=seq, opcode=opcode) \
        / msg \
        / entity_hdr
    size = len(inner_msg)
    hexdump(inner_msg)
    
    frame_body = PAS5211FrameHeader(size=size) / inner_msg
    
    frame = PAS5211Dot3(src=src_mac, dst=dst_mac) / frame_body

    return frame

frame = constructPAS5211Frames(PAS5211MsgGetProtocolVersion(), 1) [0]
hexdump(frame)
