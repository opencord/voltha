from scapy.fields import ShortEnumField, XShortField, ShortField
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet, bind_layers


class EoamPayload(Packet):
    name = "EOAM Payload"
    fields_desc = [
        ShortField("junk1", 12),
        XShortField("junk2", None),
    ]

bind_layers(Ether, EoamPayload, type=0xbeef)





f1 = Ether() / EoamPayload()
print '0x%X' % f1.type


f2 = Ether() / EoamPayload()
print '0x%X' % f2.type

f3 = Ether() / Dot1Q() / EoamPayload()

print '0x%X' % f3.type
print '0x%X' % f3.payload.type

f4 = Ether() / Dot1Q() / Dot1Q() / EoamPayload()

print '0x%X' % f4.type
print '0x%X' % f4.payload.type
print '0x%X' % f4.payload.payload.type
