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

import sys
import inspect

# SCAPY-specific imports
from scapy.packet import Packet, bind_layers
from scapy.fields import StrField, PacketField, X3BytesField
from scapy.layers.l2 import Ether

from EOAM_TLV import *

# Layer 2 definitions
EOAM_MULTICAST_ADDRESS = '01:80:c2:00:00:02'   # Well-known OAM Multicast address
UNUSED_SOURCE_ADDRESS  = '12:34:56:78:9a:bc'   # for OAM frames sent over the CLI
IGMP_MULTICAST_ADDRESS = '01:00:5e:00:00:01'   # IGMP Multicast address
OAM_ETHERTYPE          = 0xA8C8                # Ethertype value used to identify a 1904.2 message

VENDOR_SPECIFIC_OPCODE = 0xFE
CABLELABS_OUI          = 0x001000              # CableLabs OUI (used for DPoE OAM messages)
TIBIT_OUI              = 0x2AEA15              # Tibit OUI
ITU_OUI                = 0x0019A7              # ITU OUI - used to encapsulate OMCI messages

# Message Types which can be received from the Tibit OLT, Tibit ONU, DPoE ONU, or GPON ONT
# ove the 1904.2 transport
RxedOamMsgTypeEnum = {
    "Unknown"            : 0x00,
    "Info"               : 0x01,    # Info PDU
    "Event Notification" : 0x02,    # Event Notification - Tibit or DPoE Event
    "DPoE Get Response"  : 0x03,    # DPoE Get Response
    "DPoE Set Response"  : 0x04,    # DPoE Set Rewponse
    "DPoE File Transfer" : 0x05,    # Specifically - a File Transfer ACK
    "OMCI Message"       : 0x06,    # Contains an embedded OMCI message
    }

RxedOamMsgTypes = {v: k for k, v in RxedOamMsgTypeEnum.iteritems()}


###############################################################
# SCAPY Layer definitions used to parse 1904.2 messages
###############################################################

# OAM fields after the L2 addressing/VLAN tags
# when the Ethertype is set to 0xA8C8
class EOAMPayload(Packet):
    name = 'EOAM Payload'
    fields_desc = [
        ByteEnumField("subtype", 0x03, SlowProtocolsSubtypeEnum),
        XShortField("flags", 0x0050),
        XByteField("opcode", VENDOR_SPECIFIC_OPCODE),
    ]

bind_layers(Ether, EOAMPayload, type=OAM_ETHERTYPE)


# 1904.1 OAM Event
class EOAM_EventMsg(Packet):
    name = 'EOAM Event'
    fields_desc = [
        XShortField("sequence", 0x0001),
        XByteField("tlv_type", VENDOR_SPECIFIC_OPCODE),
        XByteField("length", 0x01),
        X3BytesField("oui", CABLELABS_OUI),
        PacketField("body", None, Packet),
    ]

bind_layers(EOAMPayload, EOAM_EventMsg, opcode=0x01)

# Vendor-specific OAM message
# indicated by an Opcode field set to 0xFE
class EOAM_VendSpecificMsg(Packet):
    name = "Vendor-Specific OAM"
    fields_desc  = [
        X3BytesField("oui", CABLELABS_OUI),
    ]

bind_layers(EOAMPayload, EOAM_VendSpecificMsg, opcode=VENDOR_SPECIFIC_OPCODE)

# Tibit-specific OAM message
# indicated by an OUI set to 0x2AEA15
class EOAM_TibitMsg(Packet):
    name = "Tibit OAM Message"
    fields_desc  = [
        ByteEnumField("dpoe_opcode", 0x01, DPoEOpcodeEnum),
        PacketField("body", None, Packet),
    ]

bind_layers(EOAM_VendSpecificMsg, EOAM_TibitMsg, oui=TIBIT_OUI)

# DPoE-specific OAM message
# indicated by an OUI set to 0x001000
class EOAM_DpoeMsg(Packet):
    name = "DPoE OAM Message"
    fields_desc  = [
        ByteEnumField("dpoe_opcode", 0x01, DPoEOpcodeEnum),
        PacketField("body", None, Packet),
    ]

bind_layers(EOAM_VendSpecificMsg, EOAM_DpoeMsg, oui=CABLELABS_OUI)

# Embedded OMCI message
# indicated by an OUI set to ITU OUI (0x0019A7)

#class EOAM_OmciMsg(Packet):
#    name = "OAM-encapsulated OMCI Message"
#    fields_desc  = [
#        XShortField("trans_id", 1),
#        XByteField("msg_type", 0x49),
#        XByteField("dev_id", 0x0A),
#        XShortField("me_class", 0x0000),
#        XShortField("me_inst", 0x0000),
#        PacketField("body", None, Packet),
#    ]

class EOAM_OmciMsg(Packet):
    name = "OAM-encapsulated OMCI Message"
    fields_desc  = [
        PacketField("body", None, Packet),
    ]

bind_layers(EOAM_VendSpecificMsg, EOAM_OmciMsg, oui=ITU_OUI)

###############################################################
# End of SCAPY Layers
###############################################################



