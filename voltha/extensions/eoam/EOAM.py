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

TIBIT_VERSION_NUMBER = '1.1.4'

import argparse
import logging
import time
from hexdump import hexdump
from datetime import datetime


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

from EOAM_Layers import EOAM_MULTICAST_ADDRESS, IGMP_MULTICAST_ADDRESS, OAM_ETHERTYPE
from EOAM_Layers import VENDOR_SPECIFIC_OPCODE, CABLELABS_OUI, TIBIT_OUI
from EOAM_Layers import RxedOamMsgTypeEnum, RxedOamMsgTypes
from EOAM_Layers import EOAMPayload, EOAM_EventMsg, EOAM_VendSpecificMsg, EOAM_TibitMsg, EOAM_DpoeMsg, EOAM_OmciMsg

# TODO should remove import *
from EOAM_TLV import *

ADTRAN_SHORTENED_VSSN = u'4144'  # 'AD'
TIBIT_SHORTENED_VSSN  = u'5442'  # 'TB'

def get_oam_msg_type(log, frame):

    respType = RxedOamMsgTypeEnum["Unknown"]
    recv_frame = frame

    if recv_frame.haslayer(EOAMPayload):
        if recv_frame.haslayer(EOAM_EventMsg):
            respType = RxedOamMsgTypeEnum["Event Notification"]
        elif recv_frame.haslayer(EOAM_OmciMsg):
            respType = RxedOamMsgTypeEnum["OMCI Message"]
        else:
            dpoeOpcode = 0x00
            if recv_frame.haslayer(EOAM_TibitMsg):
                dpoeOpcode = recv_frame.getlayer(EOAM_TibitMsg).dpoe_opcode;
            elif recv_frame.haslayer(EOAM_DpoeMsg):
                dpoeOpcode = recv_frame.getlayer(EOAM_DpoeMsg).dpoe_opcode;

            # Get Response
            if (dpoeOpcode == DPoEOpcodes["Get Response"]):
                respType = RxedOamMsgTypeEnum["DPoE Get Response"]

            # Set Response
            elif (dpoeOpcode == DPoEOpcodes["Set Response"]):
                respType = RxedOamMsgTypeEnum["DPoE Set Response"]

            # File Transfer ACK
            elif (dpoeOpcode == DPoEOpcodes["File Transfer"]):
                respType = RxedOamMsgTypeEnum["DPoE File Transfer"]
            else:
                log.info("Unsupported DPoE Opcode {:0>2X}".format(dpoeOpcode))
    else:
        log.info("Invalid OAM Header")

    log.info('Received OAM Message - %s' % RxedOamMsgTypes[respType])

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
                    log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseEnum[length]))
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

            if (branch != OamBranches["DPoE Object"]):
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
                log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseEnum[length]))
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


def handle_get_event_context(log, loadstr, startOfTlvs, queryType):
    retVal = False;
    value = 0
    objType = 0
    bytesRead = startOfTlvs
    loadstrlen    = len(loadstr)

    while (bytesRead <= loadstrlen):
        objType = struct.unpack_from('>H', loadstr, bytesRead)[0]
#            print "Branch/Leaf        0x{:0>2X}/0x{:0>4X}".format(branch, leaf)

        if (objType != 0):
            bytesRead += 2
            length = struct.unpack_from('>B', loadstr, bytesRead)[0]
#                print "Length:            0x{:0>2X} ({})".format(length,length)
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
                valStr = ">{}s".format(length)
                value = struct.unpack_from(valStr, loadstr, bytesRead)[0]

#                print "Value:             {}".format(value)

            if (length > 0):
                bytesRead += length

            if ( (queryType == 0) or (queryType == objType) ):
                # Prevent zero-lengthed values from returning success
                if (length > 0):
                    retVal = True;
                break
        else:
            break

    if (retVal == False):
        value = 0

    return retVal,bytesRead,value,objType


def handle_tibit_oam_event(log, loadstr):
    bytesRead = 0
    loadstrlen = len(loadstr)
    if loadstrlen > 0:
        rc = True
        num_iters = 0
        bytesRead = 0
        link_mac = ""
        msg = ""
        # Theare are two contexts in a Tibit-specific event - Source & Reference Contexts
        while(rc == True and num_iters < 2):
            objType = 0
            (rc,bytesRead,value,objType) = handle_get_event_context(log, loadstr, bytesRead, objType)
            if (rc == True):
                if objType == 0x0001:
#                        print "PON Object 0x{:0>4X}  Value = {}".format(objType, value)
                    pass
                elif objType == 0x000A:
                    # This is a Unicast Logical Link context. Determine if this a GPON or EPON link
                    if value[1:5] == "TBIT":
                        #
                        link_mac = ''.join(s.encode('hex') for s in value[1:3])
                        link_mac += ''.join(s.encode('hex') for s in value[5:9])
                    else:
                        link_mac = ''.join(s.encode('hex') for s in value[1:7])

#                        print "Unicast Logical Link Object 0x{:0>4X}  Value = {}".format(objType, link_mac)
                else:
                    log.info("Object Type 0x{:0>4X}  value = {}".format(objType, value))
            elif (branch != 0):
                log.error("Object Type 0x{:0>4X}  no value".format(objType))
            num_iters += 1

        # Pull the Event Code and Event Length out of the event
        (evtCode, evtLen) = struct.unpack_from('>HB', loadstr, bytesRead)
        bytesRead += 3

#            print "Event Code  : 0x{:0>4X}".format(evtCode)
#            print "Event Len   : 0x{:0>4X}".format(evtLen)

        # Tibit Registration Event
        if (evtCode == 0x0001):
            # Handle Registration Status attribute
            regStatus = struct.unpack_from('>B', loadstr, bytesRead)[0]
            if regStatus == 1:
                msg = "Link {} Registered".format(link_mac)
            else:
                msg = "Link {} Deregistered".format(link_mac)

    return objType,evtCode,msg


def handle_dpoe_oam_event(log, loadstr):
    bytesRead = 0
    loadstrlen = len(loadstr)
    if loadstrlen > 0:

        (evtCode, raised, objType) = struct.unpack_from('>BBH', loadstr, bytesRead)
        bytesRead += 4

#            print "Event Code  : 0x{:0>4X}".format(evtCode)
#            print "Event Len   : 0x{:0>4X}".format(evtLen)

        if ((loadstrlen - bytesRead) == 2):
            objInst = struct.unpack_from(">H", loadstr, bytesRead)[0]
        elif ((loadstrlen - bytesRead) == 4):
            objInst = struct.unpack_from(">I", loadstr, bytesRead)[0]

        objTypeStr = ObjectContextEnum[objType]
        evtCodeStr = DPoEEventCodeEnum[evtCode]

        raisedStr = "Raised"
        if (raised):
            rasiedStr = "Cleared"

        #print "{} : {} - {} {}".format(objTypeStr, objInst, evtCodeStr, raisedStr)
        return objType,evtCode,objTypeStr+":"+evtCodeStr


def handle_oam_event(log, frame):
    recv_frame = frame
    if recv_frame.haslayer(EOAM_EventMsg):
        now = datetime.now().strftime('%Y-%m-%f %H:%M:%S.%f')
        event = recv_frame.getlayer(EOAM_EventMsg)
        if hasattr(event, 'body'):
            loadstr = event.body.load

            if (event.tlv_type != VENDOR_SPECIFIC_OPCODE):
                log.error("unexpected tlv_type 0x%x (expected 0xFE)" % event.tlv_type)
            elif (event.oui == CABLELABS_OUI):
                log.info("DPoE Event")
                objType,eventCode,msg = handle_dpoe_oam_event(log, loadstr)
            elif (event.oui == TIBIT_OUI):
                log.info("Tibit-specific Event")
                objType,eventCode,msg = handle_tibit_oam_event(log, loadstr)

            log.info("Description:    %s" % msg)
            log.info("sequence:       0x%04x" % event.sequence)
            log.info("tlv_type:       0x%x" % event.tlv_type)
            log.info("length:         0x%x" % event.length)
            log.info("oui:            0x%06x" % event.oui)
            log.info("time_stamp:     %s" % now)
            log.info("obj_type:       "+hex(objType))
            log.info("event_code:     "+hex(eventCode))

    # TODO - Store the event for future use or generate alarm
    #event_data = [msg, event.sequence, objType, eventCode, now]

def handle_omci(log, frame):
    recv_frame = frame
    if recv_frame.haslayer(EOAM_OmciMsg):
        omci = recv_frame.getlayer(EOAM_OmciMsg)
        if hasattr(omci, 'body'):
            loadstr = omci.body.load

            #log.info("trans_id:  0x%04x" % omci.trans_id)
            #log.info("msg_type:  0x%x" % omci.msg_type)
            #log.info("dev_id:    0x%x" % omci.dev_id)
            #log.info("me_class:  0x%04x" % omci.me_class)
            #log.info("me_inst:   0x%04x" % omci.me_inst)

            bytesRead = 0

    # TODO - Handle OMCI message

def handle_fx_ack(log, loadstr):
    response_code = Dpoe_FileAckRspOpcodes["OK"]

    (fx_opcode, acked_block, response_code) = struct.unpack('>BHB', loadstr[0:4])

    if (fx_opcode == Dpoe_FileXferOpcodes["File Transfer Ack"]):
        pass
        #log.info("   Acked_block: {} Code: {}".format(acked_block, DPoEFileAckRespCodeEnum[response_code]))
    else:
        log.error("Unexpected File Transfer Opcode {} when expecting ACK".format(DPoEFileXferOpcodeEnum[fx_opcode]))

    return response_code,acked_block


def check_resp(log, frame):
    respType = RxedOamMsgTypeEnum["Unknown"]
    recv_frame = frame
    if recv_frame.haslayer(EOAMPayload):

        if recv_frame.haslayer(EOAM_EventMsg):
            handle_oam_event(log, recv_frame)
        elif recv_frame.haslayer(EOAM_OmciMsg):
            handle_omci(log, recv_frame)
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
            if (dpoeOpcode == DPoEOpcodes["Get Response"]):
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
            elif (dpoeOpcode == DPoEOpcodes["Set Response"]):
                (rc,branch,leaf,status) = check_set_resp_attrs(loadstr, 0)
                if (rc == True):
                    log.info('Set Response had no errors')
                else:
                    log.info('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseEnum[status]))

            # File Transfer ACK
            elif (dpoeOpcode == DPoEOpcodes["File Transfer"]):
                (rc,block) = handle_fx_ack(log, loadstr)
            else:
                log.info('Unsupported DPoE Opcode {:0>2X}'.format(dpoeOpcode))
    else:
        log.info('Invalid OAM Header')

    return respType


def mcastIp2McastMac(ip):
    """ Convert a dot-notated IPv4 multicast address string into an multicast MAC address"""
    digits = [int(d) for d in ip.split('.')]
    return '01:00:5e:%02x:%02x:%02x' % (digits[1] & 0x7f, digits[2] & 0xff, digits[3] & 0xff)

def get_olt_queue(mac, mode = None):
    resultOltQueue = ""
    if mode:
        # If the MAC is the Multicast LLID, then use EPON encoding regardless of the actual
        # mode we are in.
        if (mac == "FFFFFFFFFFFF"):
            mode = "EPON"

        if mode.upper()[0] == "G":  #GPON
            if mac[:4].upper() == ADTRAN_SHORTENED_VSSN:
                vssn = "ADTN"
            else:
                vssn = "TBIT"
            link = int(mac[4:12], 16)
            resultOltQueue = "PortIngressRuleResultOLTQueue(unicastvssn=\"" + vssn + "\", unicastlink=" + str(link) + ")"
        else:                       #EPON
            vssn = int(mac[0:8].rjust(8,"0"), 16)
            link = int((mac[8:12]).ljust(8,"0"), 16)
            resultOltQueue = "PortIngressRuleResultOLTEPONQueue(unicastvssn=" + str(vssn) + ", unicastlink=" + str(link) + ")"
    return resultOltQueue


def get_unicast_logical_link(mac, mode = None):
    unicastLogicalLink = ""
    if mode:
        if mode.upper()[0] == "G":  #GPON
            if mac[:4].upper() == ADTRAN_SHORTENED_VSSN:
                vssn = "ADTN"
            else:
                vssn = "TBIT"
            link = int(mac[4:12], 16)
            unicastLogicalLink = "OLTUnicastLogicalLink(unicastvssn=\"" + vssn + "\", unicastlink=" + str(link) + ")"
        else:                       #EPON
            vssn = int(mac[0:8].rjust(8,"0"), 16)
            link = int((mac[8:12]).ljust(8,"0"), 16)
            unicastLogicalLink = "OLTEPONUnicastLogicalLink(unicastvssn=" + str(vssn) + ", unicastlink=" + str(link) +")"
    return unicastLogicalLink


if __name__ == "__main__":
    pass
