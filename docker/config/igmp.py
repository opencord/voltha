#!/usr/bin/env python
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

from igmpv3 import IGMPv3, IGMP_TYPE_V3_MEMBERSHIP_REPORT, IGMP_V3_GR_TYPE_EXCLUDE, IGMPv3gr, IGMP_V3_GR_TYPE_INCLUDE
from scapy.data import ETH_P_IP
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
import argparse

"""
Send an igmp join
"""

IGMP_ETH = Ether(type=ETH_P_IP)
IGMP_IP = IP(dst='224.0.0.22')

def parse_args():
    parser = argparse.ArgumentParser()

    _help = ('Emit a join message')
    parser.add_argument('-j', '--join',
                        dest='join',
                        action='store_true',
                        default=False,
                        help=_help)

    _help = ('Emit a leave message')
    parser.add_argument('-l', '--leave',
                        dest='join',
                        action='store_false',
                        default=False,
                        help=_help)

    _help = ('Group address to use')
    parser.add_argument('-m', '--mcaddr',
                        dest='mcaddr',
                        action='store',
                        default='229.10.20.30',
                        help = _help)

    _help = ('Interface to use')
    parser.add_argument('-i', '--iface',
                        dest='iface',
                        action='store',
                        default='eth0',
                        help = _help)

    return parser.parse_args()


def send(igmp):
    ip_pkt = IGMP_ETH/IGMP_IP
    pkt = ip_pkt/igmp
    IGMPv3.fixup(pkt)

    sendp(pkt, iface=args.iface)

def send_join(args):
    igmp = IGMPv3(type=IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30, gaddr="224.0.0.22")
    igmp.grps = [IGMPv3gr( rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr=args.mcaddr)]

    send(igmp)


def send_leave(args):

    igmp = IGMPv3(type=IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30, gaddr="224.0.0.22")
    igmp.grps = [IGMPv3gr(rtype=IGMP_V3_GR_TYPE_INCLUDE, mcaddr=args.mcaddr)]

    send(igmp)


if __name__ == '__main__':
    args = parse_args()

    if args.join:
        send_join(args)
    else:
        send_leave(args)
