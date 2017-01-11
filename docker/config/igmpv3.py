# Copyright 2016-present Ciena Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from socket import *
from struct import *
from scapy.all import *
from itertools import *

IGMP_TYPE_MEMBERSHIP_QUERY     = 0x11
IGMP_TYPE_V3_MEMBERSHIP_REPORT = 0x22
IGMP_TYPE_V3_MEMBERSHIP_REPORT_NEGATIVE = 0xdd
IGMP_TYPE_V1_MEMBERSHIP_REPORT = 0x12
IGMP_TYPE_V2_MEMBERSHIP_REPORT = 0x16
IGMP_TYPE_V2_LEAVE_GROUP       = 0x17

IGMP_V3_GR_TYPE_INCLUDE           = 0x01
IGMP_V3_GR_TYPE_INCLUDE_NEGATIVE  = 0xaa
IGMP_V3_GR_TYPE_EXCLUDE           = 0x02
IGMP_V3_GR_TYPE_CHANGE_TO_INCLUDE = 0x03
IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE = 0x04
IGMP_V3_GR_TYPE_ALLOW_NEW         = 0x05
IGMP_V3_GR_TYPE_BLOCK_OLD         = 0x06

"""
IGMPV3_ALL_ROUTERS = '224.0.0.22'
IGMPv3 = 3
IP_SRC = '1.2.3.4'
ETHERTYPE_IP = 0x0800
IGMP_DST_MAC = "01:00:5e:00:01:01"
IGMP_SRC_MAC = "5a:e1:ac:ec:4d:a1"
"""


class IGMPv3gr(Packet):
    """IGMPv3 Group Record, used in membership report"""

    name = "IGMPv3gr"

    igmp_v3_gr_types = {
        IGMP_V3_GR_TYPE_INCLUDE: "Include Mode",
        IGMP_V3_GR_TYPE_INCLUDE_NEGATIVE: "Include Mode in negative scenario",
        IGMP_V3_GR_TYPE_EXCLUDE: "Exclude Mode",
        IGMP_V3_GR_TYPE_CHANGE_TO_INCLUDE: "Change to Include Mode",
        IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE: "Change to Exclude Mode",
        IGMP_V3_GR_TYPE_ALLOW_NEW: "Allow New Sources",
        IGMP_V3_GR_TYPE_BLOCK_OLD: "Block Old Sources"
    }

    fields_desc = [
        ByteEnumField("rtype", IGMP_V3_GR_TYPE_INCLUDE, igmp_v3_gr_types),
        ByteField("aux_data_len", 0),
        FieldLenField("numsrc", None, count_of="sources"),
        IPField("mcaddr", "0.0.0.0"),
        FieldListField("sources", None, IPField("src", "0.0.0.0"), "numsrc")
    ]

    def post_build(self, pkt, payload):
        pkt += payload
        if self.aux_data_len != 0:
            print "WARNING: Auxiliary Data Length must be zero (0)"
        return pkt


class IGMPv3(Packet):

    name = "IGMPv3"

    igmp_v3_types = {
        IGMP_TYPE_MEMBERSHIP_QUERY: "Membership Query",
        IGMP_TYPE_V3_MEMBERSHIP_REPORT: " Version 3 Mebership Report",
        IGMP_TYPE_V2_MEMBERSHIP_REPORT: " Version 2 Mebership Report",
        IGMP_TYPE_V1_MEMBERSHIP_REPORT: " Version 1 Mebership Report",
        IGMP_TYPE_V2_LEAVE_GROUP: "Version 2 Leave Group"
    }

    fields_desc = [
        ByteEnumField("type", IGMP_TYPE_MEMBERSHIP_QUERY, igmp_v3_types),
        ByteField("max_resp_code", 0),
        XShortField("checksum", None),
        #IPField("group_address", "0.0.0.0"),

        # membership query fields
        ConditionalField(IPField("gaddr", "0.0.0.0"), lambda pkt: pkt.type == IGMP_TYPE_MEMBERSHIP_QUERY),
        ConditionalField(BitField("resv", 0, 4), lambda pkt: pkt.type == IGMP_TYPE_MEMBERSHIP_QUERY),
        ConditionalField(BitField("s", 0, 1), lambda pkt: pkt.type == IGMP_TYPE_MEMBERSHIP_QUERY),
        ConditionalField(BitField("qrv", 0, 3), lambda pkt: pkt.type == IGMP_TYPE_MEMBERSHIP_QUERY),
        ConditionalField(ByteField("qqic", 0), lambda pkt: pkt.type == IGMP_TYPE_MEMBERSHIP_QUERY),
        ConditionalField(FieldLenField("numsrc", None, count_of="srcs"), lambda pkt: pkt.type == IGMP_TYPE_MEMBERSHIP_QUERY),
        ConditionalField(FieldListField("srcs", None, IPField("src", "0.0.0.0"), "numsrc"), lambda pkt: pkt.type == IGMP_TYPE_MEMBERSHIP_QUERY),

        # membership report fields
        ConditionalField(ShortField("resv2", 0), lambda pkt: pkt.type == IGMP_TYPE_V3_MEMBERSHIP_REPORT),
        ConditionalField(FieldLenField("numgrp", None, count_of="grps"), lambda pkt: pkt.type == IGMP_TYPE_V3_MEMBERSHIP_REPORT),
        ConditionalField(PacketListField("grps", [], IGMPv3gr), lambda pkt: pkt.type == IGMP_TYPE_V3_MEMBERSHIP_REPORT)

        # TODO: v2 and v3 membership reports?

    ]

    def post_build(self, pkt, payload):

        pkt += payload

        if self.type in [IGMP_TYPE_V3_MEMBERSHIP_REPORT,]: # max_resp_code field is reserved (0)
            mrc = 0
        else:
            mrc = self.encode_float(self.max_resp_code)
        pkt = pkt[:1] + chr(mrc) + pkt[2:]

        if self.checksum is None:
            chksum = checksum(pkt)
            pkt = pkt[:2] + chr(chksum >> 8) + chr(chksum & 0xff) + pkt[4:]

        return pkt

    def encode_float(self, value):
        """Encode max response time value per RFC 3376."""
        if value < 128:
            return value
        if value > 31743:
            return 255
        exp = 0
        value >>= 3
        while value > 31:
            exp += 1
            value >>= 1
        return 0x80 | (exp << 4) | (value & 0xf)


    def decode_float(self, code):
        if code < 128:
            return code
        mant = code & 0xf
        exp = (code >> 4) & 0x7
        return (mant | 0x10) << (exp + 3)

    @staticmethod
    def is_valid_mcaddr(ip):
        byte1 = atol(ip) >> 24 & 0xff
        return (byte1 & 0xf0) == 0xe0

    @staticmethod
    def fixup(pkt, invalid_ttl = None):
        """Fixes up the underlying IP() and Ether() headers."""
        assert pkt.haslayer(IGMPv3), "This packet is not an IGMPv4 packet; cannot fix it up"

        igmp = pkt.getlayer(IGMPv3)

        if pkt.haslayer(IP):
            ip = pkt.getlayer(IP)
            if invalid_ttl is None:
               ip.ttl = 1
            else:
               ip.ttl = 20
            ip.proto = 2
            ip.tos = 0xc0
            ip.options = [IPOption_Router_Alert()]

            if igmp.type == IGMP_TYPE_MEMBERSHIP_QUERY:
                if igmp.gaddr == "0.0.0.0":
                    ip.dst = "224.0.0.1"
                else:
                    assert IGMPv3.is_valid_mcaddr(igmp.gaddr), "IGMP membership query with invalid mcast address"
                    ip.dst = igmp.gaddr

            elif igmp.type == IGMP_TYPE_V2_LEAVE_GROUP and IGMPv3.is_valid_mcaddr(igmp.gaddr):
                ip.dst = "224.0.0.2"

            elif (igmp.type in (IGMP_TYPE_V1_MEMBERSHIP_REPORT, IGMP_TYPE_V2_MEMBERSHIP_REPORT) and
                  IGMPv3.is_valid_mcaddr(igmp.gaddr)):
                ip.dst = igmp.gaddr

           # We do not need to fixup the ether layer, it is done by scapy
           #
           # if pkt.haslayer(Ether):
           #     eth = pkt.getlayer(Ether)
           #     ip_long = atol(ip.dst)
           #     ether.dst = '01:00:5e:%02x:%02x:%02x' % ( (ip_long >> 16) & 0x7f, (ip_long >> 8) & 0xff, ip_long & 0xff )


        return pkt


bind_layers(IP,       IGMPv3,   frag=0, proto=2, ttl=1, tos=0xc0)
bind_layers(IGMPv3,   IGMPv3gr, frag=0, proto=2)
bind_layers(IGMPv3gr, IGMPv3gr, frag=0, proto=2)


if __name__ == "__main__":

    print "test float encoding"
    from math import log
    max_expected_error = 1.0 / (2<<3) # four bit precision
    p = IGMPv3()
    for v in range(0, 31745):
        c = p.encode_float(v)
        d = p.decode_float(c)
        rel_err = float(v-d)/v if v!=0 else 0.0
        assert rel_err <= max_expected_error

    print "construct membership query - general query"
    mq = IGMPv3(type=IGMP_TYPE_MEMBERSHIP_QUERY, max_resp_code=120)
    hexdump(str(mq))

    print "construct membership query - group-specific query"
    mq = IGMPv3(type=IGMP_TYPE_MEMBERSHIP_QUERY, max_resp_code=120, gaddr="224.0.0.1")
    hexdump(str(mq))

    print "construct membership query - group-and-source-specific query"
    mq = IGMPv3(type=IGMP_TYPE_MEMBERSHIP_QUERY, max_resp_code=120, gaddr="224.0.0.1")
    mq.srcs = ['1.2.3.4', '5.6.7.8']
    hexdump(str(mq))

    print "fixup"
    mq = IGMPv3(type=IGMP_TYPE_MEMBERSHIP_QUERY)
    mq.srcs = ['1.2.3.4', '5.6.7.8']
    pkt = Ether() / IP() / mq
    print "before fixup:"
    hexdump(str(pkt))

    print "after fixup:"

    IGMPv3.fixup(pkt,'no')
    hexdump(str(pkt))

    print "construct v3 membership report - join a single group"
    mr = IGMPv3(type=IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30, gaddr="224.0.0.1")
    mr.grps = [IGMPv3gr( rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr="229.10.20.30")]
    hexdump(mr)

    print "construct v3 membership report - join two groups"
    mr = IGMPv3(type=IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30, gaddr="224.0.0.1")
    mr.grps = [
        IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr="229.10.20.30"),
        IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr="229.10.20.31")
    ]
    hexdump(mr)

    print "construct v3 membership report - leave a group"
    mr = IGMPv3(type=IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30, gaddr="224.0.0.1")
    mr.grps = [IGMPv3gr(rtype=IGMP_V3_GR_TYPE_INCLUDE, mcaddr="229.10.20.30")]
    hexdump(mr)

    print "all ok"
