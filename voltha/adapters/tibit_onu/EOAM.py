#!/usr/bin/env python
#--------------------------------------------------------------------------#
# Copyright (C) 2015 - 2016 by Tibit Communications, Inc.                  #
# All rights reserved.                                                     #
#                                                                          #
#    _______ ____  _ ______                                                #
#   /_  __(_) __ )(_)_  __/                                                #
#    / / / / __  / / / /                                                   #
#   / / / / /_/ / / / /                                                    #
#  /_/ /_/_____/_/ /_/                                                     #
#                                                                          #
#--------------------------------------------------------------------------#
""" EOAM protocol implementation in scapy """
from scapy.layers.inet import IP

TIBIT_VERSION_NUMBER = '1.1.2'

import argparse
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.l2 import Ether, Dot1Q
from scapy.sendrecv import sendp

import fcntl  # for get hw address

# TODO should remove import *
from EOAM_TLV import *

EOAM_MULTICAST_ADDRESS = '01:80:c2:00:00:02'
IGMP_MULTICAST_ADDRESS = '01:00:5e:00:00:01'   # for test

class EOAM():
    """ EOAM frame layer """
    def __init__(self, ctag=None, dryrun=False, stag=None,
                 verbose=False, etype='8809',
                 dst=EOAM_MULTICAST_ADDRESS,
                 hexdump=False, interface='eth0',
                 sleep=2.0):
        self.verbose = verbose
        self.dst = dst
        self.dryrun = dryrun
        self.hexdump = hexdump
        self.interface = interface
        self.etype = int(etype, 16)
        self.stag = stag
        self.ctag = ctag
        self.sleep = sleep
        if (self.verbose == True):
            print("=== Settings ================")
            print("ctag      = %s" % self.ctag)
            print("stag      = %s" % self.stag)
            print("dst       = %s" % self.dst)
            print("dryrun    = %s" % self.dryrun)
            print("hexdump   = %s" % self.hexdump)
            print("interface = %s" % self.interface)
            print("etype     = 0x%04x" % self.etype)
            print("verbose   = %s" % self.verbose)
            print("sleep     = %d" % self.sleep)
            print("=== END Settings ============")

    def send_frame(self, frame_body):
        PACKET = Ether()
        PACKET.dst = self.dst
        PACKET.src = self.getHwAddr(self.interface)
        if self.stag:
            # WARNING: September/2016: This should be 0x88a8, but the Intel 10G
            # hardware I am currently using does not support receiving a TPID of
            # 0x88a8. So, I send double CTAGs, and I usually set this to 0x8100.
            # (NOTE: The Intel hardware can send a TPID of 0x88a8)
            PACKET.type = 0x8100
            if self.ctag:
                PACKET/=Dot1Q(type=0x8100,vlan=int(self.stag))
                PACKET/=Dot1Q(type=self.etype,vlan=int(self.ctag))
            else:
                PACKET/=Dot1Q(type=self.etype,vlan=int(self.stag))
        else:
            if self.ctag:
                PACKET.type = 0x8100
                PACKET/=Dot1Q(type=self.etype,vlan=int(self.ctag))
            else:
                PACKET.type = self.etype
#            PACKET/=Dot1Q(type=self.etype, vlan=int(self.ctag))
        PACKET/=SlowProtocolsSubtype()/FlagsBytes()/OAMPDU()
        PACKET/=frame_body
        PACKET/=EndOfPDU()
        if (self.verbose == True):
            PACKET.show()
            print '###[ Frame Length %d (before padding) ]###' % len(PACKET)
        if (self.hexdump == True):
            print hexdump(PACKET)
        if (self.dryrun != True):
            sendp(PACKET, iface=self.interface)
            time.sleep(self.sleep)
        return PACKET

    def get_request(self, TLV):
        return self.send_frame(CablelabsOUI()/DPoEOpcode_GetRequest()/TLV)

    def set_request(self, TLV):
        return self.send_frame(CablelabsOUI()/DPoEOpcode_SetRequest()/TLV)

    def send_multicast_register(self, TLV):
        '''
        Note, for mulicast, the standard specifies a register message
        with ActionFlags of either Register or Deregister
        '''
        return self.send_frame(CablelabsOUI()/DPoEOpcode_MulticastRegister()/TLV)

    def set_request_broadcom(self, TLV):
        return self.send_frame(BroadcomOUI()/DPoEOpcode_SetRequest()/TLV)

    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])


class EoamPayload(Packet):
    name = 'EOAM Payload'
    fields_desc = [
        ByteEnumField("subtype", 0x03, SlowProtocolsSubtypeEnum),
        XShortField("flags", 0x0050),
        XByteField("opcode", 0xfe),
        PacketField("body", None, Packet),
        BitEnumField("type", 0x00, 7, TLV_dictionary),
        BitField("length", 0x00, 9)
    ]

#    def get_request(self, TLV):
#        return self.payload(CablelabsOUI()/DPoEOpcode_GetRequest()/TLV)

#    def set_request(self, TLV):
#        return self.payload(CablelabsOUI()/DPoEOpcode_SetRequest()/TLV)

bind_layers(Ether, EoamPayload, type=0x8809)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dst', dest='dst', action='store', default=EOAM_MULTICAST_ADDRESS,
                        help='MAC destination (default: %s)' % EOAM_MULTICAST_ADDRESS)
    parser.add_argument('-e', '--etype', dest='etype', action='store', default='8809',
                        help='EtherType value (default: 0x8809)')
    parser.add_argument('-i', '--interface', dest='interface', action='store', default='eth0',
                        help='ETH interface to send (default: eth0)')
    parser.add_argument('-s', '--stag', dest='stag', action='store', default=None,
                        help='STAG value (default: None)')
    parser.add_argument('-c', '--ctag', dest='ctag', action='store', default=None,
                        help='CTAG value (default: None)')
    parser.add_argument('-p', '--sleep', dest='sleep', action='store', default='1.0', type=float,
                        help='SLEEP time after frame (default: 1.0 secs)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='verbose frame print out')
    parser.add_argument('-x', '--hexdump', dest='hexdump', action='store_true', default=False,
                        help='Hexdump the frame')
    parser.add_argument('-y', '--dryrun', dest='dryrun', action='store_true', default=False,
                        help='Dry run test, dont send - just print')

    parser.add_argument('-t', '--test', dest='test', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-r', '--critical', dest='critical', action='store_true', default=False,
                        help='Send the critical OAM set of set_request()')
    parser.add_argument('-ta', '--test_add', dest='test_add', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-td', '--test_del', dest='test_del', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-tc', '--test_clr', dest='test_clr', action='store_true', default=False,
                        help='Run commands under test')

    args = parser.parse_args()

    if (args.dryrun == True):
        args.sleep = 0.0

    eoam = EOAM(
        dryrun=args.dryrun,
        dst=args.dst,
        etype=args.etype,
        hexdump=args.hexdump,
        interface=args.interface,
        stag=args.stag,
        ctag=args.ctag,
        verbose=args.verbose,
        sleep=args.sleep
        )

    if (not args.critical
        and not args.test
        and not args.test_add
        and not args.test_del
        and not args.test_clr):
        print 'WARNING: *** No frames sent, please specify \'test\' or \'critical\', etc.  See --help'


    if (args.test == True):
        print 'SET - Multicast Register Message 01'
        eoam.send_multicast_register(MulticastRegisterSet(MulticastLink=0x3fe0, UnicastLink=0x1008))

        print 'SET - Multicast Deregister Message 02'
        eoam.send_multicast_register(MulticastRegisterSet(ActionFlags="Deregister",MulticastLink=0x3fe0, UnicastLink=0x1008))

    if (args.test_clr == True):
        print 'SET Clear Static MAC Table -- User Port Object'
        eoam.set_request(ClearStaticMacTable())

    elif (args.test_add == True):
        print 'SET Add Static MAC Address -- User Port Object'
        eoam.set_request(AddStaticMacAddress(mac=IGMP_MULTICAST_ADDRESS))

    elif (args.test_del == True):
        print 'SET Delete Static MAC Address -- User Port Object'
        eoam.set_request(DeleteStaticMacAddress(mac=IGMP_MULTICAST_ADDRESS))
