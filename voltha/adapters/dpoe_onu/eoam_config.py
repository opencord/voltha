#!/usr/bin/env python
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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

TIBIT_VERSION_NUMBER = '1.1.2'

import time
import logging
import argparse
import sys
import inspect

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot1Q
from scapy.all import sniff
from scapy.all import IP, UDP
from scapy.packet import Packet, bind_layers
from scapy.fields import StrField
from scapy.layers.l2 import Ether
from scapy.main import interact
from scapy.sendrecv import sendp
from scapy.sendrecv import srp1
from scapy.config import conf
conf.verb = None

import fcntl, socket, struct # for get hw address

# TODO should remove import *
from EOAM_TLV import *
from EOAM_Layers import EOAM_MULTICAST_ADDRESS, IGMP_MULTICAST_ADDRESS


class EOAM():
    """ EOAM frame layer """
    def __init__(self, ctag=None, dryrun=False, stag=None,
                 verbose=False, etype='8809',
                 dst=EOAM_MULTICAST_ADDRESS,
                 hexdump=False, interface='eth0',
                 sleep=1.0):
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
            print("=== END Settings ============")

    def send_frame(self, frame_body):
        PACKET = Ether()
        PACKET.length = 64
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
            sendp(PACKET, iface=self.interface, verbose=self.verbose)
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
        if (not self.dryrun):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        else:
            info = range(1, 24)
            info[18:24] = ['0','1','2','3','4','5']

        return ':'.join(['%02x' % ord(char) for char in info[18:24]])


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
                        help='SLEEP time after frame (default: 0.5 secs)')
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
        )

    if (not args.critical
        and not args.test
        and not args.test_add
        and not args.test_del
        and not args.test_clr):
        print 'WARNING: *** No frames sent, please specify \'test\' or \'critical\', etc.  See --help'

    # Critical OAM Messages
    if (args.critical == True):

        # OAM GET Requests
        print 'GET DeviceId and MAX Logical Links Message'
        eoam.get_request(DeviceId()/MaxLogicalLinks())

        print 'SET Report Thresholds Message'
        eoam.set_request(ReportThresholdsSet())

        print 'SET OAM Frame Rate Message'
        eoam.set_request(OamFrameRateSet())

        print 'GET multiple - Device and Manufacturing Info'
        eoam.get_request(DONUObject()/DeviceId()/MaxLogicalLinks()/
                              FirmwareInfo()/ChipsetInfo()/NumberOfNetworkPorts()/NumberOfS1Interfaces())

        print 'GET - LLID Queue Configuration'
        eoam.get_request(DONUObject()/LLIDQueueConfiguration())

        print 'GET - ONU Manufacturer Organization Name'
        eoam.get_request(DONUObject()/OnuManufacturerOrganizationName())

        print 'GET - ONU Firmware Mfg Time Varying Controls'
        eoam.get_request(DONUObject()/FirmwareMfgTimeVaryingControls())

        print 'GET - ONU Vendor Name'
        eoam.get_request(DONUObject()/VendorName())

        print 'GET - ONU Model Number'
        eoam.get_request(DONUObject()/ModelNumber())

        print 'GET - ONU Hardware Version'
        eoam.get_request(DONUObject()/HardwareVersion())

        print 'SET - Clear Port Ingress Rules -- Network Port Object'
        eoam.set_request(NetworkPortObject()/ClearPortIngressRules())

        print 'SET - Clear Port Ingress Rules -- User Port Object'
        eoam.set_request(UserPortObject()/ClearPortIngressRules())

        print 'SET - Broadcom Specific TLVs'
        eoam.set_request_broadcom(Broadcom07_7F_F1_Set01()/Broadcom07_7F_F1_Set02()/
                                       Broadcom07_7F_F1_Set03()/Broadcom07_7F_F1_Set04())

        print 'SET - Multicast Register Message 01'
        eoam.send_multicast_register(MulticastRegisterSetSumitomo01())

        print 'SET - Multicast Register Message 02'
        eoam.send_multicast_register(MulticastRegisterSetSumitomo02())

        print 'SET - Custom Field EtherType'
        eoam.set_request(UserPortObject()/CustomFieldEtherType())

        print 'SET - Custom Field Generic L3'
        eoam.set_request(UserPortObject()/CustomFieldGenericL3())

        print 'SET - MAC Learning MIN/MAX/Age Limit -- User Port Object'
        eoam.set_request(UserPortObject()/MacLearningMaxAllowedSet()/DynamicAddressAgeLimitSet()/
                              SourceAddressAdmissionControlSet()/MacLearningMinGuaranteeSet())

        print 'SET - MAC Learning/Flooding/Local Switching -- D-ONU Port Object'
        eoam.set_request(DONUObject()/MacLearningAggregateLimitSet()/FloodUnknownSet()/LocalSwitchingSet())

        print 'SET - Report Thresholds -- Unicast Logical Link'
        eoam.set_request(UnicastLogicalLink()/UnicastLogicalLinkReportThresholdsSet())

        print 'SET - Port Ingress Rule -- Network Port Object -- Precedence 12'
        eoam.set_request(NetworkPortObject()/
                              PortIngressRuleHeader(precedence=12)/
                              PortIngressRuleClauseMatchLength01(operator=1)/
                              PortIngressRuleResultForward()/
                              PortIngressRuleResultQueue(objecttype=0x0003)/
                              PortIngressRuleTerminator()/
                              AddPortIngressRule())

        print 'SET - Port Ingress Rule -- User Port Object -- Precedence 13'
        eoam.set_request(UserPortObject()/
                              PortIngressRuleHeader(precedence=13)/
                              PortIngressRuleClauseMatchLength00(fieldcode=1, operator=7)/
                              PortIngressRuleResultQueue(objecttype=0x0002)/
                              PortIngressRuleTerminator()/
                              AddPortIngressRule())

        print 'SET - Port Ingress Rule -- User Port Object -- Precedence 7 Discard 01'
        eoam.set_request(UserPortObject()/
                              PortIngressRuleHeader(precedence=7)/
                              PortIngressRuleClauseMatchLength06(fieldcode=1, operator=1)/
                              PortIngressRuleResultDiscard()/
                              PortIngressRuleTerminator()/
                              AddPortIngressRule())


        print 'SET - Port Ingress Rule -- User Port Object -- Precedence 7 Discard 02'
        eoam.set_request(UserPortObject()/
                              PortIngressRuleHeader(precedence=7)/
                              PortIngressRuleClauseMatchLength06(fieldcode=1, operator=1, match5=0x02)/
                              PortIngressRuleClauseMatchLength02(fieldcode=0x19, operator=1, match=0x8889)/
                              PortIngressRuleClauseMatchLength01(fieldcode=0x1a, operator=1, match=0x03)/
                              PortIngressRuleResultDiscard()/
                              PortIngressRuleTerminator()/
                              AddPortIngressRule())

        print 'GET - D-ONU Object -- Firmware Filename'
        eoam.set_request(DONUObject()/FirmwareFilename())

        print 'SET - User Port Object 0 -- Broadcom Specific TLVs'
        eoam.set_request_broadcom(UserPortObject(number=0)/Broadcom07_7F_F6_Set())

        print 'SET - User Port Object 1 -- Broadcom Specific TLVs'
        eoam.set_request_broadcom(UserPortObject(number=1)/Broadcom07_7F_F6_Set())

        print 'SET - User Port Object 0 -- Clause 30 Attributes -- MAC Enable'
        eoam.set_request(UserPortObject()/Clause30AttributesMacEnable())

        print 'SET - IPMC Forwarding Rule Configuration'
        eoam.set_request(IpmcForwardingRuleConfiguration())

        print 'SET - Enable User Traffic -- Unicast Logical Link'
        eoam.set_request(UnicastLogicalLink()/EnableUserTraffic())

    if (args.test == True):
        print 'SET - Multicast Register Message 01'
        eoam.send_multicast_register(MulticastRegisterSet(MulticastLink=0x3ff0, UnicastLink=0x120f))

        #print 'SET - Multicast Deregister Message 02'
        eoam.send_multicast_register(MulticastRegisterSet(ActionFlags="Deregister",MulticastLink=0x3ff0, UnicastLink=0x120f))

    if (args.test_clr == True):
        print 'SET Clear Static MAC Table -- User Port Object'
        eoam.set_request(ClearStaticMacTable())

    elif (args.test_add == True):
        print 'SET Add Static MAC Address -- User Port Object'
        eoam.set_request(AddStaticMacAddress(mac=IGMP_MULTICAST_ADDRESS))

    elif (args.test_del == True):
        print 'SET Delete Static MAC Address -- User Port Object'
        eoam.set_request(DeleteStaticMacAddress(mac=IGMP_MULTICAST_ADDRESS))



    # EXTERNAL OAM LIB TESTING
    #import tboam
    #tboam.get_request(f.branch, f.leaf)
    #print 'SET - User Port Object 1 -- Broadcom Specific TLVs'
    #f = eoam.set_request_broadcom(UserPortObject(number=1)/Broadcom07_7F_F6_Set())
    #print("=== receive frame ===========")
    #Now, pretend I just received this frame.
    #f.show()
    #tboam.set_request(f.branch, f.leaf)

    # Examples
    #oam_frame = eoam.get_request(UserPortObject()/LoopbackEnable())
    #oam_frame = eoam.get_reqeust(UserPortObject()/LoopbackDisable())
    #oam_frame = eoam.set_request(UserPortObject()/LoopbackEnable())
    #oam_frame = eoam.set_request(UnicastLogicalLink()/AlarmReportingSet())
    #oam_frame = eoam.get_request(UserPortObject()/BytesDropped())
    #oam_frame = eoam.get_request(UserPortObject()/TxBytesUnused())
    #print 'GET -- User Port Object -- Rx Frame 512-1023'
    #oam_frame = eoam.get_request(UserPortObject()/RxFrame_512_1023())
    #print 'GET -- User Port Object -- Tx Frame 512-1023'
    #oam_frame = eoam.get_request(UserPortObject()/TxFrame_512_1023())
    #oam_frame = eoam.get_request(NetworkPortObject()/BytesDropped())
    #oam_frame = eoam.get_request(NetworkPortObject()/TxBytesUnused())
    #print 'GET -- Network Port Object -- Rx Frame 512-1023'
    #oam_frame = eoam.get_request(NetworkPortObject()/RxFrame_512_1023())
    #print 'GET -- Network Port Object -- Tx Frame 512-1023'
    #oam_frame = eoam.get_request(NetworkPortObject()/TxFrame_512_1023())
