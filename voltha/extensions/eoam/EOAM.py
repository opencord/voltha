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

TIBIT_VERSION_NUMBER = '1.1.4'

import argparse
import logging
import time
from hexdump import hexdump

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.l2 import Ether, Dot1Q
from scapy.sendrecv import sendp
from scapy.fields import PacketField
from scapy.packet import bind_layers
from scapy.fields import StrField, X3BytesField
from scapy.packet import Packet
from scapy.fields import ByteEnumField, XShortField, XByteField, MACField, \
    ByteField, BitEnumField, BitField, ShortField
from scapy.fields import XLongField, StrFixedLenField, XIntField, \
    FieldLenField, StrLenField, IntField

import fcntl, socket, struct # for get hw address

# TODO should remove import *
from EOAM_TLV import *

OAM_ETHERTYPE = 0xA8C8
CableLabs_OUI = 0x001000
Tibit_OUI = 0x2AEA15
IEEE_OUI = 0x0019A7

EOAM_MULTICAST_ADDRESS = '01:80:c2:00:00:02'
IGMP_MULTICAST_ADDRESS = '01:00:5e:00:00:01'   # for test




### Received OAM Message Types
RxedOamMsgTypeEnum = {
    "Unknown": 0x00,
    # Info PDU - not currently used
    "Info": 0x01,
    # Event Notification - Tibit or DPoE Event
    "Event Notification": 0x02,
    "DPoE Get Response": 0x03,
    "DPoE Set Response": 0x04,
    # Specifically - a File Transfer ACK
    "DPoE File Transfer": 0x05,
    # Contains an embedded OMCI message
    "OMCI Message": 0x06,
    }

Dpoe_Opcodes = {v: k for k, v in DPoEOpcodeEnum.iteritems()}

def get_oam_msg_type(log, frame):

    respType = RxedOamMsgTypeEnum["Unknown"]
    recv_frame = frame

    if recv_frame.haslayer(EOAMPayload):
        if recv_frame.haslayer(EOAMEvent):
            recv_frame = RxedOamMsgTypeEnum["Event Notification"]
        elif recv_frame.haslayer(EOAM_OmciMsg):
            respType = RxedOamMsgTypeEnum["OMCI Message"]
        else:
            dpoeOpcode = 0x00
            if recv_frame.haslayer(EOAM_TibitMsg):
                dpoeOpcode = recv_frame.getlayer(EOAM_TibitMsg).dpoe_opcode;
            elif recv_frame.haslayer(EOAM_DpoeMsg):
                dpoeOpcode = recv_frame.getlayer(EOAM_DpoeMsg).dpoe_opcode;

            # Get Response
            if (dpoeOpcode == 0x02):
                respType = RxedOamMsgTypeEnum["DPoE Get Response"]

            # Set Response
            elif (dpoeOpcode == 0x04):
                respType = RxedOamMsgTypeEnum["DPoE Set Response"]

            # File Transfer ACK
            elif (dpoeOpcode == 0x09):
                respType = RxedOamMsgTypeEnum["DPoE File Transfer"]
            else:
                log.info('Unsupported DPoE Opcode {:0>2X}'.format(dpoeOpcode))
    else:
        log.info('Invalid OAM Header')

    log.info('Received OAM Message 0x %s' % str(respType))

    return respType

def handle_get_value(log, loadstr, startOfTlvs, queryBranch, queryLeaf):
    retVal = False;
    value = 0
    branch = 0
    leaf = 0
    bytesRead = startOfTlvs
    loadstrlen    = len(loadstr)

    while (bytesRead <= loadstrlen):
        (branch, leaf) = struct.unpack_from('>BH', loadstr, bytesRead)

        if (branch != 0):
            bytesRead += 3
            length = struct.unpack_from('>B', loadstr, bytesRead)[0]
            bytesRead += 1

            if (length == 1):
                value = struct.unpack_from(">B", loadstr, bytesRead)[0]
            elif (length == 2):
                value = struct.unpack_from(">H", loadstr, bytesRead)[0]
            elif (length == 4):
                value = struct.unpack_from(">I", loadstr, bytesRead)[0]
            elif (length == 8):
                value = struct.unpack_from(">Q", loadstr, bytesRead)[0]
            else:
                if (length >= 0x80):
                    log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[length]))
                    # Set length to zero so bytesRead doesn't get mistakenly incremented below
                    length = 0
                else:
                    # Attributes with a length of zero are actually 128 bytes long
                    if (length == 0):
                        length = 128;
                    valStr = ">{}s".format(length)
                    value = struct.unpack_from(valStr, loadstr, bytesRead)[0]

            if (length > 0):
                bytesRead += length

            if (branch != 0xD6):
                if ( ((queryBranch == 0) and (queryLeaf == 0)) or
                     ((queryBranch == branch) and (queryLeaf == leaf)) ):
                    # Prevent zero-lengthed values from returning success
                    if (length > 0):
                        retVal = True;
                    break
        else:
            break

    if (retVal == False):
        value = 0

    return retVal,bytesRead,value,branch,leaf


def get_value_from_msg(log, frame, branch, leaf):
    retVal = False
    value = 0
    recv_frame = frame

    if recv_frame.haslayer(EOAMPayload):
        payload = recv_frame.payload
        if hasattr(payload, 'body'):
            loadstr = payload.body.load
            # Get a specific TLV value
            (retVal,bytesRead,value,retbranch,retleaf) = handle_get_value(log, loadstr, 0, branch, leaf)
        else:
            log.info('received frame has no payload')
    else:
        log.info('Invalid OAM Header')
    return retVal,value,

def check_set_resp_attrs(log, loadstr, startOfTlvs):
    retVal = True;
    branch = 0
    leaf = 0
    length = 0
    bytesRead = startOfTlvs
    loadstrlen    = len(loadstr)

    while (bytesRead <= loadstrlen):
        (branch, leaf) = struct.unpack_from('>BH', loadstr, bytesRead)
#            print "Branch/Leaf        0x{:0>2X}/0x{:0>4X}".format(branch, leaf)

        if (branch != 0):
            bytesRead += 3
            length = struct.unpack_from('>B', loadstr, bytesRead)[0]
#                print "Length:            0x{:0>2X} ({})".format(length,length)
            bytesRead += 1

            if (length >= 0x80):
                log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[length]))
                if (length > 0x80):
                    retVal = False;
                    break;
            else:
                bytesRead += length

        else:
            break

    return retVal,branch,leaf,length

def check_set_resp(log, frame):
    rc = False
    branch = 0
    leaf = 0
    status = 0
    recv_frame = frame
    if recv_frame.haslayer(EOAMPayload):
        payload = recv_frame.payload
        if hasattr(payload, 'body'):
            loadstr = payload.body.load
            # Get a specific TLV value
            (rc,branch,leaf,status) = check_set_resp_attrs(log, loadstr, 0)
        else:
            log.info('received frame has no payload')
    else:
        log.info('Invalid OAM Header')
    return rc,branch,leaf,status



def check_resp(log, frame):
    respType = RxedOamMsgTypeEnum["Unknown"]
    recv_frame = frame
    if recv_frame.haslayer(EOAMPayload):

        if recv_frame.haslayer(EOAMEvent):
#            handle_oam_event(recv_frame)
            pass
        elif recv_frame.haslayer(EOAM_OmciMsg):
#            handle_omci(recv_frame)
            pass
        else:
            dpoeOpcode = 0x00
            if recv_frame.haslayer(EOAM_TibitMsg):
                dpoeOpcode = recv_frame.getlayer(EOAM_TibitMsg).dpoe_opcode;
            elif recv_frame.haslayer(EOAM_DpoeMsg):
                dpoeOpcode = recv_frame.getlayer(EOAM_DpoeMsg).dpoe_opcode;

            if hasattr(recv_frame, 'body'):
                payload = recv_frame.payload
                loadstr = payload.body.load

            # Get Response
            if (dpoeOpcode == 0x02):
                bytesRead = 0
                rc = True
                while(rc == True):
                    branch = 0
                    leaf = 0
                    (rc,bytesRead,value,branch,leaf) = handle_get_value(log, loadstr, bytesRead, branch, leaf)
                    if (rc == True):
                        log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X}  value = {}'.format(branch, leaf, value))
                    elif (branch != 0):
                        log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X}  no value'.format(branch, leaf))

            # Set Response
            elif (dpoeOpcode == 0x04):
                (rc,branch,leaf,status) = check_set_resp_attrs(loadstr, 0)
                if (rc == True):
                    log.info('Set Response had no errors')
                else:
                    log.info('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[status]))

            # File Transfer ACK
            elif (dpoeOpcode == 0x09):
                rc = handle_fx_ack(log, loadstr, bytesRead, block_number)
            else:
                log.info('Unsupported DPoE Opcode {:0>2X}'.format(dpoeOpcode))
    else:
        log.info('Invalid OAM Header')

    return respType    


    
def handle_fx_ack(log, loadstr, startOfXfer, block_number):
    retVal = False
    (fx_opcode, acked_block, response_code) = struct.unpack_from('>BHB', loadstr, startOfXfer)

    #print "fx_opcode:      0x%x" % fx_opcode
    #print "acked_block:    0x%x" % acked_block
    #print "response_code:  0x%x" % response_code

    if (fx_opcode != 0x03):
        log.info('unexpected fx_opcode 0x%x (expected 0x03)' % fx_opcode)
    elif (acked_block != block_number):
        log.info('unexpected acked_block 0x%x (expected 0x%x)' % (acked_block, block_number))
    elif (response_code != 0):
        log.info('unexpected response_code 0x%x (expected 0x00)' % response_code)
    else:
        retVal = True;




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

    def send_frame(self, frame_body, slow_protocol=True):
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
                PACKET/=Dot1Q(prio=7,type=self.etype,vlan=int(self.stag))
        else:
            if self.ctag:
                PACKET.type = 0x8100
                PACKET/=Dot1Q(type=self.etype,vlan=int(self.ctag))
            else:
                PACKET.type = self.etype
#            PACKET/=Dot1Q(type=self.etype, vlan=int(self.ctag))
        if slow_protocol:
            PACKET /= SlowProtocolsSubtype()/FlagsBytes()/OAMPDU()
            PACKET /= frame_body
            PACKET /= EndOfPDU()
        else:
            PACKET.lastlayer().type = 0xA8C8
            PACKET /= frame_body

        if (self.verbose == True):
            PACKET.show()
            print '###[ Frame Length %d (before padding) ]###' % len(PACKET)
        if (self.hexdump == True):
            print hexdump(str(PACKET))
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


#TODO - This is duplicated from eoam_messages.py and renamed to EOAMRespPayload
class EOAMPayload(Packet):
    name = 'EOAM Payload'
    fields_desc = [
        ByteEnumField("subtype", 0x03, SlowProtocolsSubtypeEnum),
        XShortField("flags", 0x0050),
        XByteField("opcode", 0xfe),
#        PacketField("body", None, Packet),
    ]

bind_layers(Ether, EOAMPayload, type=OAM_ETHERTYPE)


#TODO - This is duplicated from eoam_messages.py
class EOAMEvent(Packet):
    name = 'EOAM Event'
    fields_desc = [
        XShortField("sequence", 0x0001),
        XByteField("tlv_type", 0xfe),
        XByteField("length", 0x01),
        X3BytesField("oui", 0x001000),
        PacketField("body", None, Packet),
    ]

bind_layers(EOAMPayload, EOAMEvent, opcode=0x01)

#TODO - This is duplicated from eoam_messages.py
class EOAM_VendSpecificMsg(Packet):
    name = "Vendor-Specific OAM"
    fields_desc  = [
        X3BytesField("oui", 0x001000),
    ]

bind_layers(EOAMPayload, EOAM_VendSpecificMsg, opcode=0xFE)

#TODO - This is duplicated from eoam_messages.py
class EOAM_OmciMsg(Packet):
    name = "OAM-encapsulated OMCI Message"
    fields_desc  = [
        PacketField("body", None, Packet),
    ]

bind_layers(EOAM_VendSpecificMsg, EOAM_OmciMsg, oui=0x0019A7)

#TODO - This is duplicated from eoam_messages.py
class EOAM_TibitMsg(Packet):
    name = "Tibit OAM Message"
    fields_desc  = [
        ByteEnumField("dpoe_opcode", 0x01, DPoEOpcodeEnum),
        PacketField("body", None, Packet),
    ]

bind_layers(EOAM_VendSpecificMsg, EOAM_TibitMsg, oui=0x2AEA15)

#TODO - This is duplicated from eoam_messages.py
class EOAM_DpoeMsg(Packet):
    name = "DPoE OAM Message"
    fields_desc  = [
        ByteEnumField("dpoe_opcode", 0x01, DPoEOpcodeEnum),
        PacketField("body", None, Packet),
    ]

bind_layers(EOAM_VendSpecificMsg, EOAM_DpoeMsg, oui=0x001000)

def mcastIp2McastMac(ip):
    """ Convert a dot-notated IPv4 multicast address string into an multicast MAC address"""
    digits = [int(d) for d in ip.split('.')]
    return '01:00:5e:%02x:%02x:%02x' % (digits[1] & 0x7f, digits[2] & 0xff, digits[3] & 0xff)


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
    parser.add_argument('-tc', '--test_clr', dest='test_clr', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-te', '--test_eapol', dest='test_eapol', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-ti', '--test_igmp', dest='test_igmp', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-th', '--test_dhcp', dest='test_dhcp', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-tu', '--test_upstream', dest='test_upstream', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-td', '--test_downstream', dest='test_downstream', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-tm', '--test_multicast', dest='test_multicast', action='store_true', default=False,
                        help='Run commands under test')
    parser.add_argument('-tp', '--test_ping', dest='test_ping', action='store_true', default=False,
                        help='Issue a test ping to get JSON data on device version')

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
        and not args.test_clr
        and not args.test_eapol
        and not args.test_igmp
        and not args.test_dhcp
        and not args.test_upstream
        and not args.test_downstream
        and not args.test_multicast
        and not args.test_ping):
        print 'WARNING: *** No frames sent, please specify \'test\' or \'critical\', etc.  See --help'


    if (args.test == True):
        print 'SET - Multicast Register Message 01'
        eoam.send_multicast_register(MulticastRegisterSet(MulticastLink=0x3fe0, UnicastLink=0x1008))

        print 'SET - Multicast Deregister Message 02'
        eoam.send_multicast_register(MulticastRegisterSet(ActionFlags="Deregister",MulticastLink=0x3fe0, UnicastLink=0x1008))

    if (args.test_clr == True):
        print 'Set - Clear Static MAC Table -- User Port Object'
        eoam.set_request(ClearStaticMacTable())

    if (args.test_add == True):
        print 'SET Add Static MAC Address -- User Port Object'
        eoam.set_request(AddStaticMacAddress(mac=mcastIp2McastMac('230.10.10.10')))
        time.sleep(1)
        eoam.set_request(AddStaticMacAddress(mac=mcastIp2McastMac('231.11.11.11')))

#        print 'SET Delete Static MAC Address -- User Port Object'
#        eoam.set_request(DeleteStaticMacAddress(mac=IGMP_MULTICAST_ADDRESS))

    if (args.test_eapol == True):
        #################################################################################
        ## EAPOL
        #################################################################################
        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

        print 'SET - Port Ingress Rule -- PON Port Object -- EAPOL'
        eoam.set_request(PonPortObject()/
                         PortIngressRuleHeader(precedence=32)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['L2 Type/Len'],
                                                            operator=Operator['=='], match=0x888e)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=4090)/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())

        time.sleep(3)

        print 'Delete - Port Ingress Rule -- PON Port Object -- EAPOL'
        eoam.set_request(PonPortObject()/
                         PortIngressRuleHeader(precedence=32)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['L2 Type/Len'],
                                                            operator=Operator['=='], match=0x888e)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=4090)/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         DeletePortIngressRule())

    if (args.test_igmp == True):
        #################################################################################
        ## IGMP
        #################################################################################
        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

        print 'SET - Port Ingress Rule -- PON Port Object -- IGMP'
        eoam.set_request(PonPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['L2 Type/Len'],
                                                            operator=Operator['=='], match=0x0800)/
                         PortIngressRuleClauseMatchLength01(fieldcode=Clause['IPv4/IPv6 Protocol Type'],
                                                            operator=Operator['=='], match=0x02)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=4000)/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())

        time.sleep(3)

        print 'Delete - Port Ingress Rule -- PON Port Object -- IGMP'
        eoam.set_request(PonPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['L2 Type/Len'],
                                                            operator=Operator['=='], match=0x0800)/
                         PortIngressRuleClauseMatchLength01(fieldcode=Clause['IPv4/IPv6 Protocol Type'],
                                                            operator=Operator['=='], match=0x02)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=4000)/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         DeletePortIngressRule())

    if (args.test_dhcp == True):
        #################################################################################
        ## DHCP
        #################################################################################
        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

        print 'SET - Port Ingress Rule -- PON Port Object -- DHCP'
        eoam.set_request(PonPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['L2 Type/Len'],
                                                            operator=Operator['=='], match=0x0800)/
                         PortIngressRuleClauseMatchLength01(fieldcode=Clause['IPv4/IPv6 Protocol Type'],
                                                            operator=Operator['=='], match=0x11)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['TCP/UDP source port'],
                                                            operator=Operator['=='], match=0x0044)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['TCP/UDP destination port'],
                                                            operator=Operator['=='], match=0x0043)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=4000)/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())

        time.sleep(3)

        print 'Delete - Port Ingress Rule -- PON Port Object -- DHCP'
        eoam.set_request(PonPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['L2 Type/Len'],
                                                            operator=Operator['=='], match=0x0800)/
                         PortIngressRuleClauseMatchLength01(fieldcode=Clause['IPv4/IPv6 Protocol Type'],
                                                            operator=Operator['=='], match=0x11)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['TCP/UDP source port'],
                                                            operator=Operator['=='], match=0x0044)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['TCP/UDP destination port'],
                                                            operator=Operator['=='], match=0x0043)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=4000)/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         DeletePortIngressRule())

    if (args.test_upstream == True):
        #################################################################################
        ## UPSTREAM
        #################################################################################
        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

        print 'SET - Port Ingress Rule -- OLT Unicast Logical Link -- Upstream Traffic'
        eoam.set_request(PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x00f1)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultCopy(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1)/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=1000)/
                         PortIngressRuleResultReplace(fieldcode=Clause['C-VLAN Tag'])/
                         OLTUnicastLogicalLink(unicastvssn="TBIT", unicastlink=0xe2222900)/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())


        time.sleep(3)

        print 'DELETE - Port Ingress Rule -- OLT Unicast Logical Link -- Upstream Traffic'
        eoam.set_request(OLTUnicastLogicalLink(unicastvssn="TBIT", unicastlink=0xe2222900)/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x00f1)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultCopy(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1)/
                         PortIngressRuleResultSet(fieldcode=Clause['C-VLAN Tag'], value=1000)/
                         PortIngressRuleResultReplace(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         DeletePortIngressRule())

    if (args.test_downstream == True):
        #################################################################################
        ## DOWNSTREAM
        #################################################################################
        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

        print 'SET - Port Ingress Rule -- NNI Port Object -- Downstream Traffic -- 4000/241'
        eoam.set_request(NetworkToNetworkPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x0fa0)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                            operator=Operator['=='], match=0x00f1)/
                         PortIngressRuleResultOLTQueue(unicastvssn="TBIT", unicastlink=0xe2222900)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())

        time.sleep(1)

        print 'SET - Port Ingress Rule -- NNI Port Object -- Downstream Traffic -- 1000/241'
        eoam.set_request(NetworkToNetworkPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x03e8)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                            operator=Operator['=='], match=0x00f1)/
                         PortIngressRuleResultOLTQueue(unicastvssn="TBIT", unicastlink=0xe2222900)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())


        time.sleep(1)

        print 'SET - Port Ingress Rule -- NNI Port Object -- Downstream Traffic -- 4000/203'
        eoam.set_request(NetworkToNetworkPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x0fa0)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                            operator=Operator['=='], match=0x00CB)/
                         PortIngressRuleResultOLTQueue(unicastvssn="TBIT", unicastlink=0xe2220300)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())

        time.sleep(1)

        print 'SET - Port Ingress Rule -- NNI Port Object -- Downstream Traffic -- 1000/203'
        eoam.set_request(NetworkToNetworkPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x03e8)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                            operator=Operator['=='], match=0x00cb)/
                         PortIngressRuleResultOLTQueue(unicastvssn="TBIT", unicastlink=0xe2220300)/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())

    if (args.test_multicast == True):
        #################################################################################
        ## MULTICAST
        #################################################################################
        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

        print 'SET - Port Ingress Rule -- NNI Port Object -- Downstream Multicast Traffic'
        eoam.set_request(NetworkToNetworkPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x008c)/
                         PortIngressRuleResultOLTBroadcastQueue()/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         AddPortIngressRule())


        time.sleep(3)

        print 'DELETE - Port Ingress Rule -- NNI Port Object -- Downstream Multicast Traffic'
        eoam.set_request(NetworkToNetworkPortObject()/
                         PortIngressRuleHeader(precedence=13)/
                         PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                            operator=Operator['=='], match=0x008c)/
                         PortIngressRuleResultOLTBroadcastQueue()/
                         PortIngressRuleResultForward()/
                         PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                         PortIngressRuleTerminator()/
                         DeletePortIngressRule())


    if (args.test_ping == True):
        json_operation_str = '{\"operation\":\"version\"}'
        for i in range(10000):
            eoam.send_frame(TBJSON(data='json %s' % json_operation_str), False)

