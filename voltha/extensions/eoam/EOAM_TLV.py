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
##--------------------------------------------------------------------------#
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

from scapy.packet import Packet
from scapy.fields import ByteEnumField, XShortField, XByteField, MACField, \
    ByteField, BitEnumField, BitField, ShortField
from scapy.fields import XLongField, StrField, StrFixedLenField, XIntField, \
    FieldLenField, StrLenField, IntField, ShortEnumField

# This library strives to be an implementation of the following standard:

# DPoE-SP-OAMv1.0-IO8-140807 - DPoE OAM Extensions Specifications

# This library may be used with PON devices for
# configuration and provisioning.

## Note on Deviations:

## Tibit endeavors to use DPoE OAM for not only communicating with DpOE ONUs,
## but also to communicate with the Tibit OLT Microplug.  In places where this
## document deviates from the DPoE standard for ONUs, Tibit has added a comment
## __TIBIT_OLT_OAM__

TIBIT_VERSION_NUMBER = '1.1.4'

TLV_dictionary = {
    0x00: "End EOAMPDU",
    }

SlowProtocolsSubtypeEnum = {0x03: "OAM"}

### OAM Branch Enumerations
OamBranchEnum = {
    0x00: "End",
    0x06: "Clause 30 Object",
    0x07: "Clause 30 Attr",
    0x09: "Clause 30 Action",
    0xB7: "Tibit Attr",
    0xB9: "Tibit Action",
    0xC7: "DPoG Attr",
    0xC9: "DPoG Action",
    0xD6: "DPoE Object",
    0xD7: "DPoE Attr",
    0xD9: "DPoE Action",
    }

OamBranches = {v: k for k, v in OamBranchEnum.iteritems()}


### Multicast Action Flags
MulticastActionFlagsEnum = {
    0x02: "Deregister",
    0x03: "Register"
    }

### Table 17 - DPoE Opcodes
DPoEOpcodeEnum = {
    0x01: "Get Request",
    0x02: "Get Response",
    0x03: "Set Request",
    0x04: "Set Response",
    0x05: "Dynamic IP Multicast Control",
    0x06: "Multicast Register",
    0x07: "Multicast Register Response",
    0x09: "File Transfer",
    }

DPoEOpcodes = {v: k for k, v in DPoEOpcodeEnum.iteritems()}


### Table 20 - DPoE Variable Response Codes
DPoEVariableResponseEnum = {
    0x80: "No Error",
    0x81: "Too Long",
    0x86: "Bad Parameters",
    0x87: "No Resources",
    0x88: "System Busy",
    0xa0: "Undetermined Error",
    0xa1: "Unsupported",
    0xa2: "May Be Corrupted",
    0xa3: "Hardware Failure",
    0xa4: "Overflow",
    }

DPoEVariableResponseCodes = {v: k for k, v in DPoEVariableResponseEnum.iteritems()}


### Table 14 - DPoE Event Codes
DPoEEventCodeEnum = {
    0x11: "Loss of Signal",
    0x12: "Key Exchange Failure",
    0x21: "Port Disabled",
    0x41: "Power Failure",
    0x81: "Statistics Alarm",
    0x82: "D-ONU Busy",
    0x83: "MAC Table Overflow",
    0x84: "PON Interface Switch",
    }

DPoEEventCodes = {v: k for k, v in DPoEEventCodeEnum.iteritems()}


class SlowProtocolsSubtype(Packet):
    """ Slow Protocols subtype"""
    name = "Slow Protocols subtype"
    fields_desc  = [ByteEnumField("subtype", 0x03, SlowProtocolsSubtypeEnum)]

class FlagsBytes(Packet):
    """ Two Bytes Reserved for 802.3 Flags"""
    name = "FlagsBytes"
    fields_desc  = [XShortField("flags", 0x0050)]

class OAMPDU(Packet):
    """ OAMPDU code: Organization Specific"""
    name = "OAMPDU code: Organization Specific"
    fields_desc  = [XByteField("opcode", 0xfe)]

class CablelabsOUI(Packet):
    """ Organizationally Unique Identifier (Cablelabs)"""
    name = "Organizationally Unique Identifier (Cablelabs)"
    fields_desc  = [XByteField("oui0", 0x00),
                    XByteField("oui1", 0x10),
                    XByteField("oui2", 0x00)]

class BroadcomOUI(Packet):
    """ Organizationally Unique Identifier (Broadcom)"""
    name = "Organizationally Unique Identifier (Broadcom)"
    fields_desc  = [XByteField("oui0", 0x00),
                    XByteField("oui1", 0x0D),
                    XByteField("oui2", 0xB6)]

class TibitOUI(Packet):
    """ Organizationally Unique Identifier (Tibit)"""
    name = "Organizationally Unique Identifier (Tibit)"
    fields_desc  = [XByteField("oui0", 0x2A),
                    XByteField("oui1", 0xEA),
                    XByteField("oui2", 0x15)]

class ItuOUI(Packet):
    """ Organizationally Unique Identifier (Tibit)"""
    name = "Organizationally Unique Identifier (ITU)"
    fields_desc  = [XByteField("oui0", 0x00),
                    XByteField("oui1", 0x19),
                    XByteField("oui2", 0xA7)]

class DPoEOpcode_GetRequest(Packet):
    """ DPoE Opcode"""
    name = "DPoE Opcode"
    fields_desc  = [ByteEnumField("opcode", 0x01, DPoEOpcodeEnum)]

class DPoEOpcode_SetRequest(Packet):
    """ DPoE Opcode"""
    name = "DPoE Opcode"
    fields_desc  = [ByteEnumField("opcode", 0x03, DPoEOpcodeEnum)]

class DPoEOpcode_MulticastRegister(Packet):
    """ DPoE Opcode"""
    name = "DPoE Opcode"
    fields_desc  = [ByteEnumField("opcode", 0x06, DPoEOpcodeEnum)]

class DPoEOpcode_MulticastRegisterResponse(Packet):
    """ DPoE Opcode"""
    name = "DPoE Opcode"
    fields_desc  = [ByteEnumField("opcode", 0x07, DPoEOpcodeEnum)]

class DPoEOpcode_FileTransfer(Packet):
    """ DPoE Opcode"""
    name = "DPoE Opcode"
    fields_desc  = [ByteEnumField("opcode", 0x09, DPoEOpcodeEnum)]

class MulticastRegisterSetSumitomo01(Packet):
    """ Multicast Register: Multicast Register Set Sumitomo 01 """
    name = "Multicast Register: Multicast Register Set Sumitomo 01"
    fields_desc = [ByteEnumField("ActionFlags", 0x02, MulticastActionFlagsEnum),
                   XShortField("MulticastLink", 0xfffe),
                   XShortField("UnicastLink", 0x43dc),
                   ]

class MulticastRegisterSetSumitomo02(Packet):
    """ Multicast Register: Multicast Register Set Sumitomo 02 """
    name = "Multicast Register: Multicast Register Set Sumitomo 02"
    fields_desc = [ByteEnumField("ActionFlags", 0x03, MulticastActionFlagsEnum),
                   XShortField("MulticastLink", 0x43dd),
                   XShortField("UnicastLink", 0x43dc),
                   ]

class MulticastRegisterSet(Packet):
    """ Multicast Register: Multicast Register Set """
    name = "Multicast Register: Multicast Register Set"
    fields_desc = [ByteEnumField("ActionFlags", 0x03, MulticastActionFlagsEnum),
                   XShortField("MulticastLink", 0x0000),
                   XShortField("UnicastLink", 0x0000),
                   ]

####
#### OAM Context OBJECTS
####

### Object Context Enumerations
ObjectContextEnum = {
    0x0000: "Device",
    0x0001: "PON Port",
    0x0002: "Unicast Logical Link",
    0x0003: "Enet Port",
    0x0004: "Queue",
    0x0005: "SOAM MEP",
    0x0006: "Multicast Link",
    0x0007: "T-CONT",
# __TIBIT_OLT_OAM__: Defined by Tibit
    0x0009: "ONU",
    0x000A: "OLT Unicast Link",
    0x000B: "GPIO",
    }

ObjectContexts = {v: k for k, v in ObjectContextEnum.iteritems()}


class DONUObject(Packet):
    """ Object Context: D-ONU Object """
    name = "Object Context: D-ONU Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0000, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

# __TIBIT_OLT_OAM__: Defined by Tibit
class DOLTObject(Packet):
    """ Object Context: D-OLT Object """
    name = "Object Context: D-OLT Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0000, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

class NetworkPortObject(Packet):
    """ Object Context: Network Port Object """
    name = "Object Context: Network Port Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0001, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

# __TIBIT_OLT_OAM__: Defined by Tibit
class PonPortObject(Packet):
    """ Object Context: PON Port Object """
    name = "Object Context: PON Port Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0001, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

class UnicastLogicalLink(Packet):
    """ Object Context: Unicast Logical Link """
    name = "Object Context: Unicast Logical Link"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0002, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

# __TIBIT_OLT_OAM__: Defined by Tibit
class OLTUnicastLogicalLink(Packet):
    """ Object Context: OLT Unicast Logical Link """
    name = "Object Context: OLT Unicast Logical Link"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x000A, ObjectContextEnum),
                   XByteField("length", 10),
                   XByteField("pon", 0),
                   StrField("unicastvssn", "TBIT"),
                   XIntField("unicastlink", 0x00000000),
                   XByteField("pad", 0),
                   ]

class OLTEPONUnicastLogicalLink(Packet):
    """ Object Context: OLT Unicast Logical Link """
    name = "Object Context: OLT Unicast Logical Link"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x000A, ObjectContextEnum),
                   XByteField("length", 10),
                   XByteField("pon", 0),
                   XIntField("unicastvssn", 0x00000000),
                   XIntField("unicastlink", 0x00000000),
                   XByteField("pad", 0),
                   ]


# __TIBIT_OLT_OAM__: Defined by Tibit
class NetworkToNetworkPortObject(Packet):
    """ Object Context: Network-to-Network (NNI) Port Object """
    name = "Object Context: Network-to-Network (NNI) Port Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0003, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

class UserPortObject(Packet):
    """ Object Context: User Port Object """
    name = "Object Context: User Port Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0003, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

class QueueObject(Packet):
    """ Object Context: Queue Object """
    name = "Object Context: Queue Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0004, ObjectContextEnum),
                   XByteField("length", 2),
                   XByteField("instance", 0),
                   XByteField("number", 0)
                   ]

class ONUObject(Packet):
    """ Object Context: ONU Object """
    name = "Object Context: ONU Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x0009, ObjectContextEnum),
                   XByteField("length", 6),
                   MACField("mac", "54:42:e2:22:11:00")
                   ]

class GpioObject(Packet):
    """ Object Context: GPIO Object """
    name = "Object Context: GPIO Object"
    fields_desc = [ByteEnumField("branch", 0xD6, OamBranchEnum),
                   ShortEnumField("leaf", 0x000B, ObjectContextEnum),
                   XByteField("length", 1),
                   XByteField("condition", 1)
                   ]

####
#### 0x09 - BRANCH ATTRIBUTES
####
class PhyAdminControl(Packet):
    """ Variable Descriptor: Phy Admin Control """
    name = "Phy Admin Control"
    fields_desc = [ByteEnumField("branch", 0x09, OamBranchEnum),
                   XShortField("leaf", 0x0005),
                   ]

class PhyAdminControlEnableSet(Packet):
    """ Variable Descriptor: Phy Admin Control Enable """
    name = "Phy Admin Control Enable"
    fields_desc = [ByteEnumField("branch", 0x09, OamBranchEnum),
                   XShortField("leaf", 0x0005),
                   XByteField("length", 1),
                   XByteField("value", 2)
                   ]

class PhyAdminControlDisableSet(Packet):
    """ Variable Descriptor: Phy Admin Control Disable """
    name = "Phy Admin Control Disable"
    fields_desc = [ByteEnumField("branch", 0x09, OamBranchEnum),
                   XShortField("leaf", 0x0005),
                   XByteField("length", 1),
                   XByteField("value", 1)
                   ]

####
#### 0xd7 - BRANCH ATTRIBUTES
####
class DeviceId(Packet):
    """ Variable Descriptor: Device ID """
    name = "Device ID"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0002)]

class FirmwareInfo(Packet):
    """ Variable Descriptor: Firmware Info """
    name = "Firmware Info"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0003)]

class ChipsetInfo(Packet):
    """ Variable Descriptor: Chipset Info """
    name = "Chipset Info"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0004)]

class DateOfManufacture(Packet):
    """ Variable Descriptor: Date of Manufacture """
    name = "Date of Manufacture"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0005)]

class ManufacturerInfo(Packet):
    """ Variable Descriptor: ManufacturerInfo """
    name = "ManufacturerInfo"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0006)]

class MaxLogicalLinks(Packet):
    """ Variable Descriptor: Max Logical Links """
    name = "Max Logical Links"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0007)]

class NumberOfNetworkPorts(Packet):
    """ Variable Descriptor: Number of Network Ports """
    name = "Number of Network Ports"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0008)]

class NumberOfS1Interfaces(Packet):
    """ Variable Descriptor: Number of S1 Interfaces """
    name = "Number of S1 Interfaces"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0009)]

class DONUPacketBuffer(Packet):
    """ Variable Descriptor: D-ONU Packet Buffer """
    name = "D-ONU Packet Buffer"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000a)]

class ReportThresholds(Packet):
    """ Variable Descriptor: Report Thresholds """
    name = "Report Thresholds"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000b),
                   ]

DFLT_NUM_QUEUE_SETS  = 4
DFLT_NUM_REPORT_VALS = 1

class ReportThresholdsSet(Packet):
    """ Variable Descriptor: Report Thresholds Set """
    name = "Report Thresholds Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000b),
                   XByteField("length", 0x0a),
                   XByteField("num_queue_sets", 4),
                   XByteField("values", 1),
                   XShortField("threshold0", 0x800),
                   XShortField("threshold1", 0x1000),
                   XShortField("threshold2", 0x1800),
                   XShortField("threshold3", 0x2000),
                   ]

class UnicastLogicalLinkReportThresholdsSet(Packet):
    """ Variable Descriptor: Report Thresholds Unicast Logical Link Set"""
    name = "Report Thresholds Unicast Logical Link Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000b),
                   XByteField("length", 0x0a),
                   XByteField("num_queue_sets", 4),
                   XByteField("values", 1),
                   XShortField("threshold0", 0x2800),
                   XShortField("threshold1", 0x5000),
                   XShortField("threshold2", 0x7800),
                   XShortField("threshold3", 0xa000),
                   ]

class LogicalLinkForwarding(Packet):
    """ Variable Descriptor: Logical Link Forwarding """
    name = "Logical Link Forwarding"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000c),
                   ]

class OamFrameRate(Packet):
    """ Variable Descriptor: OAM Frame Rate """
    name = "OAM Frame Rate"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000d),
                   ]

class OamFrameRateSet(Packet):
    """ Variable Descriptor: OAM Frame Rate """
    name = "OAM Frame Rate"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000d),
                   XByteField("length", 2),
                   XByteField("max", 12),
                   XByteField("min", 10),
                   ]

class OnuManufacturerOrganizationName(Packet):
    """ Variable Descriptor: ONU Manufacturer Organization Name """
    name = "ONU Manufacturer Organization Name"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000e),
                   ]

class FirmwareMfgTimeVaryingControls(Packet):
    """ Variable Descriptor: Firmware Mfg Time Varying Controls """
    name = "Firmware Mfg Time Varying Controls"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x000f),
                   ]

class VendorName(Packet):
    """ Variable Descriptor: Vendor Name """
    name = "Vendor Name"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0011),
                   ]

class ModelNumber(Packet):
    """ Variable Descriptor: Model Number """
    name = "Model Number"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0012),
                   ]

class HardwareVersion(Packet):
    """ Variable Descriptor: Hardware Version """
    name = "Hardware Version"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0013),
                   ]

class EponMode(Packet):
    """ Variable Descriptor: EPON Mode """
    name = "EPON Mode"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0014),
                   ]

class DynamicAddressAgeLimit(Packet):
    """ Variable Descriptor: Dynamic Address Age Limit """
    name = "Dynamic Address Age Limit"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0102),
                   ]

class DynamicAddressAgeLimitSet(Packet):
    """ Variable Descriptor: Dynamic Address Age Limit Set """
    name = "Dynamic Address Age Limit Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0102),
                   XByteField("length", 2),
                   XShortField("value", 0x0000),
                   ]

class DynamicMacTable(Packet):
    """ Variable Descriptor: Dynamic MAC Table """
    name = "Dynamic MAC Table"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0103),
                   ]

class StaticMacTable(Packet):
    """ Variable Descriptor: Static MAC Table """
    name = "Static MAC Table"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0104),
                   ]

class SourceAddressAdmissionControl(Packet):
    """ Variable Descriptor: Source Address Admission Control """
    name = "Source Address Admission Control"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0106),
                   ]

class SourceAddressAdmissionControlSet(Packet):
    """ Variable Descriptor: Source Address Admission Control Set """
    name = "Source Address Admission Control Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0106),
                   XByteField("length", 1),
                   XByteField("value", 1),
                   ]

class MacLearningMinGuarantee(Packet):
    """ Variable Descriptor: MAC Learning MIN Guarantee """
    name = "MAC Learning MIN Guarantee"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0107),
                   ]

class MacLearningMinGuaranteeSet(Packet):
    """ Variable Descriptor: MAC Learning MIN Guarantee Set """
    name = "MAC Learning MIN Guarantee Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0107),
                   XByteField("length", 2),
                   XShortField("value", 0),
                   ]

class MacLearningMaxAllowed(Packet):
    """ Variable Descriptor: MAC Learning MAX Allowed """
    name = "MAC Learning MAX Allowed"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0108),
                   ]

class MacLearningMaxAllowedSet(Packet):
    """ Variable Descriptor: MAC Learning MAX Allowed Set """
    name = "MAC Learning MAX Allowed Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0108),
                   XByteField("length", 2),
                   XShortField("value", 0x0010),
                   ]

class MacLearningAggregateLimit(Packet):
    """ Variable Descriptor: MAC Learning Aggregate Limit """
    name = "MAC Learning Aggregate Limit"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0109),
                   ]

class MacLearningAggregateLimitSet(Packet):
    """ Variable Descriptor: MAC Learning Aggregate Limit Set """
    name = "MAC Learning Aggregate Limit Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0109),
                   XByteField("length", 2),
                   XShortField("value", 0x0040),
                   ]

class FloodUnknown(Packet):
    """ Variable Descriptor: Flood Unknown """
    name = "Flood Unknown"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010b),
                   ]

class FloodUnknownSet(Packet):
    """ Variable Descriptor: Flood Unknown Set """
    name = "Flood Unknown Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010b),
                   XByteField("length", 1),
                   XByteField("value", 1),
                   ]

class LocalSwitching(Packet):
    """ Variable Descriptor: Local Switching """
    name = "Local Switching"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010c),
                   ]

class LocalSwitchingSet(Packet):
    """ Variable Descriptor: Local Switching Set """
    name = "Local Switching Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010c),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class LLIDQueueConfiguration(Packet):
    """ Variable Descriptor: LLID Queue Configuration """
    name = "LLID Queue Configuration"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010d),
                   ]

DFLT_NUM_ONU_LLIDS   = 1
DFLT_NUM_LLID_QUEUES = 1
DFLT_NUM_UNI_PORTS   = 1
DFLT_NUM_PORT_QUEUES = 1
DFLT_LLID_QUEUE_SIZE = 0xA0

class LLIDQueueConfigurationSet(Packet):
    """ Variable Descriptor: LLID Queue Configuration """
    name = "LLID Queue Configuration"

    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010d),
                   XByteField("length", 6),
                   XByteField("numLLID",    DFLT_NUM_ONU_LLIDS),
                   XByteField("LLID0-numq", DFLT_NUM_LLID_QUEUES),
                   XByteField("l0Q0-size",  DFLT_LLID_QUEUE_SIZE),
                   XByteField("numPort",    DFLT_NUM_UNI_PORTS),
                   XByteField("Port0-numq", DFLT_NUM_PORT_QUEUES),
                   XByteField("p0Q0-size",  DFLT_LLID_QUEUE_SIZE),
                   ]



class LLIDQueueConfiguration16Set(Packet):
    """ Variable Descriptor: LLID Queue Configuration """
    name = "LLID Queue Configuration"

    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010d),
                   XByteField("length", 36),
                   XByteField("numLLID",    16),
                   XByteField("LLID0-numq", 1),
                   XByteField("l0Q0-size",  32),
                   XByteField("LLID1-numq", 1),
                   XByteField("l1Q0-size",  32),
                   XByteField("LLID2-numq", 1),
                   XByteField("l2Q0-size",  32),
                   XByteField("LLID3-numq", 1),
                   XByteField("l3Q0-size",  32),
                   XByteField("LLID4-numq", 1),
                   XByteField("l4Q0-size",  32),
                   XByteField("LLID5-numq", 1),
                   XByteField("l5Q0-size",  32),
                   XByteField("LLID6-numq", 1),
                   XByteField("l6Q0-size",  32),
                   XByteField("LLID7-numq", 1),
                   XByteField("l7Q0-size",  32),
                   XByteField("LLID8-numq", 1),
                   XByteField("l8Q0-size",  32),
                   XByteField("LLID9-numq", 1),
                   XByteField("l9Q0-size",  32),
                   XByteField("LLID10-numq", 1),
                   XByteField("l10Q0-size",  32),
                   XByteField("LLID11-numq", 1),
                   XByteField("l11Q0-size",  32),
                   XByteField("LLID12-numq", 1),
                   XByteField("l12Q0-size",  32),
                   XByteField("LLID13-numq", 1),
                   XByteField("l13Q0-size",  32),
                   XByteField("LLID14-numq", 1),
                   XByteField("l14Q0-size",  32),
                   XByteField("LLID15-numq", 1),
                   XByteField("l15Q0-size",  16),
                   XByteField("numPort",    DFLT_NUM_UNI_PORTS),
                   XByteField("Port0-numq", DFLT_NUM_PORT_QUEUES),
                   XByteField("p0Q0-size",  DFLT_LLID_QUEUE_SIZE),
                   ]



class LLIDQueueConfigurationSetData(Packet):
    """ Variable Descriptor: LLID Queue Configuration """
    name = "LLID Queue Configuration"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010d),
                   FieldLenField("length", None, length_of="data", fmt="B"),
                   StrLenField("data", "", length_from=lambda x:x.length),
                  ]


class FirmwareFilename(Packet):
    """ Variable Descriptor: Firmware Filename """
    name = "Firmware Filename"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x010e),
                   ]


####
#### 0xD9 - MAC Table Operations - Dynamic and Static
####

class ClearDynamicMacTable(Packet):
    """ Variable Descriptor: Clear Dynamic MAC Table """
    name = "Clear Dynamic MAC Table"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0101),
                   ]

class AddDynamicMacAddress(Packet):
    """ Variable Descriptor: Add Dynamic MAC Address """
    name = "Add Dynamic MAC Address"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0102),
                   ]

class DeleteDynamicMacAddress(Packet):
    """ Variable Descriptor: Delete Dynamic MAC Address """
    name = "Delete Dynamic MAC Address"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0103),
                   ]

class ClearStaticMacTable(Packet):
    """ Variable Descriptor: Clear Static MAC Table """
    name = "Clear Static MAC Table"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0104),
                   ]

class AddStaticMacAddress(Packet):
    """ Variable Descriptor: Add Static MAC Address """
    name = "Add Static MAC Address"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0105),
                   ByteField("length", 6),
                   MACField("mac", "01:00:5e:00:00:00"),
                   ]

class DeleteStaticMacAddress(Packet):
    """ Variable Descriptor: Delete Static MAC Address """
    name = "Delete Static MAC Address"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0106),
                   ByteField("length", 6),
                   MACField("mac", "01:00:5e:00:00:00"),
                   ]

####
#### 0xd7 - STATISTICS
####

class RxFramesGreen(Packet):
    """ Variable Descriptor: RxFramesGreen """
    name = "RxFramesGreen"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0201),
                   ]

class TxFramesGreen(Packet):
    """ Variable Descriptor: TxFramesGreen """
    name = "TxFramesGreen"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0202),
                   ]

class RxFrame_64(Packet):
    """ Variable Descriptor: RxFrame_64 """
    name = "RxFrame_64"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0204),
                   ]

class RxFrame_65_127(Packet):
    """ Variable Descriptor: RxFrame_65_127 """
    name = "RxFrame_65_127"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0205),
                   ]

class RxFrame_128_255(Packet):
    """ Variable Descriptor: RxFrame_128_255 """
    name = "RxFrame_128_255"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0206),
                   ]

class RxFrame_256_511(Packet):
    """ Variable Descriptor: RxFrame_256_511 """
    name = "RxFrame_256_511"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0207),
                   ]

class RxFrame_512_1023(Packet):
    """ Variable Descriptor: RxFrame_512_1023 """
    name = "RxFrame_512_1023"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0208),
                   ]

class RxFrame_1024_1518(Packet):
    """ Variable Descriptor: RxFrame_1024_1518 """
    name = "RxFrame_1024_1518"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0209),
                   ]

class RxFrame_1519Plus(Packet):
    """ Variable Descriptor: RxFrame_1024_1518 """
    name = "RxFrame_1519_Plus"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x020A),
                   ]

class TxFrame_64(Packet):
    """ Variable Descriptor: TxFrame_64 """
    name = "TxFrame_64"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x020B),
                   ]

class TxFrame_65_127(Packet):
    """ Variable Descriptor: TxFrame_65_127 """
    name = "TxFrame_65_127"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x020C),
                   ]

class TxFrame_128_255(Packet):
    """ Variable Descriptor: TxFrame_128_255 """
    name = "TxFrame_128_255"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x020D),
                   ]

class TxFrame_256_511(Packet):
    """ Variable Descriptor: TxFrame_256_511 """
    name = "TxFrame_256_511"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x020E),
                   ]

class TxFrame_512_1023(Packet):
    """ Variable Descriptor: TxFrame_512_1023 """
    name = "TxFrame_512_1023"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x020F),
                   ]

class TxFrame_1024_1518(Packet):
    """ Variable Descriptor: TxFrame_1024_1518 """
    name = "TxFrame_1024_1518"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0210),
                   ]

class TxFrame_1519Plus(Packet):
    """ Variable Descriptor: TxFrame_1024_1518 """
    name = "TxFrame_1519_Plus"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0211),
                   ]

class FramesDropped(Packet):
    """ Variable Descriptor: Frames Dropped """
    name = "Frames Dropped"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0214),
                   ]

class BytesDropped(Packet):
    """ Variable Descriptor: Bytes Dropped """
    name = "Bytes Dropped"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0215),
                   ]

class TxBytesUnused(Packet):
    """ Variable Descriptor: Tx Bytes Unused """
    name = "Tx Bytes Unused"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0217),
                   ]

class TxL2Errors(Packet):
    """ Variable Descriptor: TxL2Errors """
    name = "TxL2Errors"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0235),
                   ]

class RxL2Errors(Packet):
    """ Variable Descriptor: RxL2Errors """
    name = "RxL2Errors"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0236),
                   ]

####
#### 0xD7 - Alarm Reporting
####

class AlarmReporting(Packet):
    """ Variable Descriptor: Alarm Reporting """
    name = "Alarm Reporting"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0303),
                   ]

class AlarmReportingSet(Packet):
    """ Variable Descriptor: Alarm Reporting Set """
    name = "Alarm Reporting Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0303),
                   XByteField("length", 6),
                   XShortField("LOS", 0x1101),
                   XShortField("KeyExchange", 0x1201),
                   XShortField("PortDisbled", 0x2101),
                   ]

####
#### 0xD7 - Encryption/ FEC/ and Queue CIR/EIR
####
class EncryptionMode(Packet):
    """ Variable Descriptor: Encryption Mode """
    name = "Encryption Mode"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0402),
                   ]

class EncryptionModeSet(Packet):
    """ Variable Descriptor: Encryption Mode Set """
    name = "Encryption Mode Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0402),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class IpmcForwardingRuleConfiguration(Packet):
    """ Variable Descriptor: IPMC Forwarding Rule Configuration """
    name = "IPMC Forwarding Rule Configuration"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0505),
                   XByteField("length", 2),
                   XShortField("value", 0x0000),
                   ]

class QueueCommittedInformationRate(Packet):
    """ Variable Descriptor: Queue Committed Information Rate """
    name = "Queue Committed Information Rate"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0604),
                   ]

class QueueCommittedInformationRateSet(Packet):
    """ Variable Descriptor: Queue Committed Information Rate Set """
    name = "Queue Committed Information Rate Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0604),
                   XByteField("length", 6),
                   XShortField("burst", 0x0fff),
                   XShortField("CIR_UPPER", 0x0000),
                   XShortField("CIR_LOWER", 0xffff),
                   ]

class FECMode(Packet):
    """ Variable Descriptor: FEC Mode """
    name = "FEC Mode"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0605),
                   ]

class FECModeSet(Packet):
    """ Variable Descriptor: FEC Mode """
    name = "FEC Mode"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0605),
                   XByteField("length", 2),
                   XByteField("downstream", 0x01),
                   XByteField("upstream", 0x01),
                   ]

class MediaType(Packet):
    """ Variable Descriptor: Media Type """
    name = "Media Type"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0822),
                   ]


####
#### 0xD7 - Port Ingress Rules
####
RuleSubtypeEnum = {  0x00: "Terminator",
                     0x01: "Header",
                     0x02: "Clause",
                     0x03: "Result",
                     }

ClauseSubtypeEnum = {0x00: "LLID Index",
                     0x01: "L2 Destination MAC address",
                     0x02: "L2 Source MAC address",
                     0x03: "L2 Type/Len",
                     0x04: "B-DA",
                     0x05: "B-SA",
                     0x06: "I-Tag",
                     0x07: "S-VLAN Tag",
                     0x08: "C-VLAN Tag",
                     0x09: "MPLS Label Stack Entry",
                     0x0a: "IPv4 TOS/IPv6 Traffic Class",
                     0x0b: "IPv4 TTL/IPv6 Hop Limit",
                     0x0c: "IPv4/IPv6 Protocol Type",
                     0x0d: "IPv4 Source Address",
                     0x0e: "IPv6 Source Address",
                     0x0f: "IPv4 Destination Address",
                     0x10: "IPv6 Destination Address",
                     0x11: "IPv6 Next Header",
                     0x12: "IPv6 Flow Header",
                     0x13: "TCP/UDP source port",
                     0x14: "TCP/UDP destination port",
                     0x15: "B-Tag",
                     0x16: "Reserved",
                     0x17: "Reserved",
                     0x18: "Custom field 0",
                     0x19: "Custom field 1",
                     0x1a: "Custom field 2",
                     0x1b: "Custom field 3",
                     0x1c: "Custom field 4",
                     0x1d: "Custom field 5",
                     0x1e: "Custom field 6",
                     0x1f: "Custom field 7",
                     }

RuleOperatorEnum = { 0x00: "F",           #False
                     0x01: "==",
                     0x02: "!=",
                     0x03: "<=",
                     0x04: ">=",
                     0x05: "exists",
                     0x06: "!exist",
                     0x07: "T",           #True
                     }

RuleResultsEnum =  { 0x00: "NOP",
                     0x01: "Discard",
                     0x02: "Forward",
                     0x03: "Queue",
                     0x04: "Set",
                     0x05: "Copy",
                     0x06: "Delete",
                     0x07: "Insert",
                     0x08: "Replace",
                     0x09: "Clear Delete",
                     0x0a: "Clear Insert",
                     0x0b: "Increment Counter",
                     # Tibit-specific values
                     0x13: "OLT Queue",
                     0x14: "Learning Group"
                     }

RuleClauses = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
RuleOperators = {v: k for k, v in RuleOperatorEnum.iteritems()}
RuleResults = {v: k for k, v in RuleResultsEnum.iteritems()}

class PortIngressRule(Packet):
    """ Variable Descriptor: Port Ingress Rule """
    name = "Port Ingress Rule"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ]

class PortIngressRuleHeader(Packet):
    """ Variable Descriptor: Port Ingress Rule Header """
    name = "Port Ingress Rule Header"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 2),
                   XByteField("subtype", 0x01), # Header
                   ByteField("precedence", 12),
                   ]

class PortIngressRuleClause(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Port Ingress Rule Clause"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   FieldLenField("length", None, length_of="match", fmt="B", adjust=lambda pkt,x: x+7),
                   XByteField("subtype", 0x02), #Clause
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   XByteField("operator", 0x7), # T
                   XByteField("matchlength", 0),
                   StrLenField("match", "", length_from=lambda x:x.matchlength),
                   ]

class PortIngressRuleResultNoData(Packet):
    """ Variable Descriptor: Port Ingress Rule Result NOP """
    name = "Rule Result NOP"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 2),
                   XByteField("subtype", 0x03), # Result
                   ByteField("resulttype", 0x00),
                   ]

class PortIngressRuleClauseMatchLength00(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Port Ingress Rule Clause"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 7),
                   XByteField("clause", 2),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   XByteField("operator", 0),
                   XByteField("matchlength", 0),
                   ]

class PortIngressRuleClauseAlwaysMatch(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Port Ingress Rule Clause"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 7),
                   XByteField("clause", 2),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   XByteField("operator", 7),
                   XByteField("matchlength", 0),
                   ]

class PortIngressRuleClauseMatchLength01(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Port Ingress Rule Clause"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 8),
                   XByteField("clause", 2),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   XByteField("operator", 0),
                   XByteField("matchlength", 1),
                   XByteField("match", 0),
                   ]

class PortIngressRuleClauseMatchLength02(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Port Ingress Rule Clause"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 9),
                   XByteField("clause", 2),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   XByteField("operator", 0),
                   XByteField("matchlength", 2),
                   XShortField("match", 0)
                   ]


class PortIngressRuleClauseMatchLength06(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Port Ingress Rule Clause"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 13),
                   XByteField("clause", 2),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   XByteField("operator", 0),
                   XByteField("matchlength", 6),
                   XByteField("match0", 0x01),
                   XByteField("match1", 0x80),
                   XByteField("match2", 0xc2),
                   XByteField("match3", 0x00),
                   XByteField("match4", 0x00),
                   XByteField("match5", 0x00),
                   ]

class PortIngressRuleResultForward(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Forward """
    name = "Port Ingress Rule Result Forward"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 2),
                   XByteField("result", 3),
                   XByteField("forward", 2),
                   ]

class PortIngressRuleResultDiscard(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Discard """
    name = "Port Ingress Rule Result Discard"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 2),
                   XByteField("result", 3),
                   XByteField("discard", 1),
                   ]

class PortIngressRuleResultQueue(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Queue """
    name = "Port Ingress Rule Result Queue"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 6),
                   XByteField("result", 3),
                   XByteField("queuerule", 3),
                   XShortField("objecttype", 0x0000),
                   XByteField("instance", 0),
                   XByteField("queuenum", 0),
                   ]

# __TIBIT_OLT_OAM__: Defined by Tibit
class PortIngressRuleResultOLTQueue(Packet):
    """ Variable Descriptor: Port Ingress Rule Result OLT Queue """
    name = "Port Ingress Rule Result OLT Queue"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 15),
                   XByteField("result", 3),
                   XByteField("oltqueuerule", 0x13),
                   XShortField("objecttype", 0x0001),
                   XByteField("instance", 0),
                   XByteField("pon", 0),
                   StrField("unicastvssn", "TBIT"),
                   XIntField("unicastlink", 0x00000000),
                   XByteField("pad", 0),
                   ]

class PortIngressRuleResultOLTEPONQueue(Packet):
    """ Variable Descriptor: Port Ingress Rule Result OLT Queue """
    name = "Port Ingress Rule Result OLT Queue"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 15),
                   XByteField("result", 3),
                   XByteField("oltqueuerule", 0x13),
                   XShortField("objecttype", 0x0001),
                   XByteField("instance", 0),
                   XByteField("pon", 0),
                   XIntField("unicastvssn", 0x00000000),
                   XIntField("unicastlink", 0x00000000),
                   XByteField("pad", 0),
                   ]



# __TIBIT_OLT_OAM__: Defined by Tibit
class PortIngressRuleResultOLTBroadcastQueue(Packet):
    """ Variable Descriptor: Port Ingress Rule Result OLT Broadcast Queue """
    name = "Port Ingress Rule Result OLT Broadcast Queue"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 15),
                   XByteField("result", 3),
                   XByteField("oltqueuerule", 0x13),
                   XShortField("objecttype", 0x0001),
                   XByteField("instance", 0),
                   XByteField("pon", 0),
                   XLongField("broadcast", 0xffffffffffff0000),
                   XByteField("pad", 0),
                   ]

class PortIngressRuleResultLearningGroup(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Learning Group """
    name = "Port Ingress Rule Result Learning Group "
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 6),
                   XByteField("result", 3),
                   XByteField("grouprule", 0x14),
                   XShortField("objecttype", 0x0000),
                   XByteField("instance", 0),
                   XByteField("num", 0),
                   ]

class PortIngressRuleResultSet(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Set """
    name = "Port Ingress Rule Result Set"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   FieldLenField("length", None, length_of="value", fmt="B", adjust=lambda pkt,x: x+6),
                   XByteField("result", 3),
                   XByteField("set", 4),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   StrLenField("value", "", length_from=lambda x:x.length-6),
                   ]

class PortIngressRuleResultCopy(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Copy """
    name = "Port Ingress Rule Result Copy"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 6),
                   XByteField("result", 3),
                   XByteField("copy", 5),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   XByteField("msbmask", 0),
                   XByteField("lsbmask", 0),
                   ]

class PortIngressRuleResultDelete(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Delete """
    name = "Port Ingress Rule Result Delete"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 4),
                   XByteField("result", 3),
                   XByteField("delete", 6),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   ]

class PortIngressRuleResultInsert(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Insert """
    name = "Port Ingress Rule Result Insert"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 4),
                   XByteField("result", 3),
                   XByteField("insert", 7),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   ]

class PortIngressRuleResultReplace(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Replace """
    name = "Port Ingress Rule Result Replace"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 4),
                   XByteField("result", 3),
                   XByteField("replace", 8),
                   XByteField("fieldcode", 0),
                   XByteField("fieldinstance", 0),
                   ]

class PortIngressRuleTerminator(Packet):
    """ Variable Descriptor: Port Ingress Rule Terminator """
    name = "Port Ingress Rule Terminator"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ByteField("length", 1),
                   XByteField("terminator", 0),
                   ]

class CustomField(Packet):
    """ Variable Descriptor: Custom Field """
    name = "Custom Field"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0502),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class CustomFieldEtherType(Packet):
    """ Variable Descriptor: Custom Field EtherType """
    name = "Custom Field EtherType"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0502),
                   XByteField("length", 6),
                   XByteField("fieldcode", 0x19),
                   XByteField("layerselect", 2),
                   XByteField("dwordoffset", 0),
                   XByteField("lsb", 0),
                   XByteField("width", 0x10),
                   XByteField("numclauses", 0),
                   ]

class CustomFieldGenericL3(Packet):
    """ Variable Descriptor: Custom Field Generic L3 """
    name = "Custom Field Generic L3"
    fields_desc = [ByteEnumField("branch", 0xD7, OamBranchEnum),
                   XShortField("leaf", 0x0502),
                   XByteField("length", 6),
                   XByteField("fieldcode", 0x1a),
                   XByteField("layerselect", 8),
                   XByteField("dwordoffset", 0),
                   XByteField("lsb", 0x18),
                   XByteField("width", 0x8),
                   XByteField("numclauses", 0),
                   ]

####
#### 0xD9 - Port Ingress Rules
####

class ClearPortIngressRules(Packet):
    """ Variable Descriptor: Clear Port Ingress Rule """
    name = "Clear Port Ingress Rule"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0501),
                   ]

class AddPortIngressRule(Packet):
    """ Variable Descriptor: Add Port Ingress Rule """
    name = "Add Port Ingress Rule"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0502),
                   ]


class DeletePortIngressRule(Packet):
    """ Variable Descriptor: Delete Port Ingress Rule """
    name = "Delete Port Ingress Rule"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0503),
                   ]

####
#### 0xb7 - TIBIT ATTRIBUTES
####
class OltMode(Packet):
    """ Variable Descriptor: OLT Mode """
    name = "OLT Mode"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0101),
                   ]

class OltModeSet(Packet):
    """ Variable Descriptor: OLT Mode """
    name = "OLT Mode"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0101),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class OltPonAdminState(Packet):
    """ Variable Descriptor: OLT PON Admin State """
    name = "PON Admin State"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0102),
                   ]

class OltPonAdminStateSet(Packet):
    """ Variable Container: OLT PON Admin State """
    name = "PON Admin State"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0102),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class TibitLinkMacTable(Packet):
    """ Variable Descriptor: Link MAC Table """
    name = "Link MAC Table"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0103),
                   ]

class TibitKeyExchange(Packet):
    """ Variable Descriptor: Key Exchange """
    name = "Key Exchange Period"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0104),
                   ]

class TibitKeyExchangeSet(Packet):
    """ Variable Descriptor: Key Exchange Set"""
    name = "Key Exchange Period"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0104),
                   XByteField("length", 2),
                   XShortField("value", 0x1234),
                  ]

class OnuMode(Packet):
    """ Variable Descriptor: ONU Mode """
    name = "ONU Mode"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0105),
                   ]

class OnuModeSet(Packet):
    """ Variable Descriptor: ONU Mode """
    name = "ONU Mode"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0105),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class TibitGrantSpacing(Packet):
    """ Variable Descriptor: Grant Spacing """
    name = "Grant Spacing"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0106),
                   ]

class TibitGrantSpacingSet(Packet):
    """ Variable Descriptor: Grant Spacing """
    name = "Grant Spacing"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0106),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class TibitBurstOverheadProfiles(Packet):
    """ Variable Descriptor: Burst Overhead Profiles """
    name = "Burst Overhead Profiles"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0107),
                   ]

class TibitBurstOverheadProfilesSet(Packet):
    """ Variable Descriptor: Burst Overhead Profiles """
    name = "Burst Overhead Profiles"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0107),
                   # Length is one + 5 for each entry
                   XByteField("length", 6),
                   XByteField("num_profiles", 1),
                   ]

class TibitBurstOverheadProfilesEntry(Packet):
    """ Variable Descriptor: Burst Overhead Profile Entry """
    name = "Burst Profile Entry:"
    fields_desc = [XByteField("laser_on_time", 0x28),
                   XByteField("laser_off_time", 0x28),
                   XShortField("sync_time", 0x0040),
                   XByteField("us_fec", 1),
                   ]

class TibitGpioConditionSet(Packet):
    """ Variable Descriptor: GPIO condition Set """
    name = "GPIO Condition"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0108),
                   XByteField("length", 1),
                   XByteField("state", 0),
                   ]

class TibitDiscoveryPeriod(Packet):
    """ Variable Descriptor: Discovery Period """
    name = "Discovery Period"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0109),
                   ]

class TibitDiscoveryPeriodSet(Packet):
    """ Variable Descriptor: Discovery Period Set """
    name = "Discovery Period"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0109),
                   XByteField("length", 2),
                   XShortField("period", 3000),
                   ]
class TibitLldpPeriod(Packet):
    """ Variable Descriptor: LLDP Period """
    name = "LLDP Period"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010A),
                   ]

class TibitLldpPeriodSet(Packet):
    """ Variable Descriptor: LLDP Period Set """
    name = "LLDP Period"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010A),
                   XByteField("length", 2),
                   XShortField("period", 60),
                   ]

class TibitLldpDestAddress(Packet):
    """ Variable Descriptor: LLDP Destination MAC Address """
    name = "LLDP Dest Address"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010B),
                   ]

class TibitLldpDestAddressSet(Packet):
    """ Variable Descriptor: LLDP Destination MAC Address Set """
    name = "LLDP Dest Address"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010B),
                   XByteField("length", 6),
                   MACField("addr", "01:80:c2:00:00:0e"),
                   ]

class TibitLldpTpid(Packet):
    """ Variable Descriptor: LLDP TPID """
    name = "LLDP TPID"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010C),
                   ]

class TibitLldpTpidSet(Packet):
    """ Variable Descriptor: LLDP TPID Set """
    name = "LLDP TPID"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010C),
                   XByteField("length", 2),
                   XShortField("tpid", 0),
                   ]

class TibitLldpVid(Packet):
    """ Variable Descriptor: LLDP TPID """
    name = "LLDP VID"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010D),
                   ]

class TibitLldpVidSet(Packet):
    """ Variable Descriptor: LLDP TPID Set """
    name = "LLDP VID"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010D),
                   XByteField("length", 2),
                   XShortField("vid", 0),
                   ]

class TibitFailsafeTimer(Packet):
    """ Variable Descriptor: Failsafe Timer """
    name = "Failsafe Timer"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010E),
                   ]

class TibitFailsafeTimerSet(Packet):
    """ Variable Descriptor: Failsafe Timer Set """
    name = "Failsafe Timer"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010E),
                   XByteField("length", 1),
                   XByteField("timer", 0),
                   ]

class TibitMtu(Packet):
    """ Variable Descriptor: MTU """
    name = "MTU"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010F),
                   ]

class TibitMtuSet(Packet):
    """ Variable Descriptor: MTU Set """
    name = "MTU"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x010F),
                   XByteField("length", 4),
                   XIntField("mtu", 0),
                   ]

class TibitCtagCtagMode(Packet):
    """ Variable Descriptor: CTAG CTAG Mode """
    name = "CTAG-CTAG Mode"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0110),
                   ]

class TibitCtagCtagModeSet(Packet):
    """ Variable Descriptor: CTAG CTAG Mode Set """
    name = "CTAG-CTAG Mode"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0110),
                   XByteField("length", 1),
                   XByteField("enable", 0),
                   ]

class TibitStatsOptions(Packet):
    """ Variable Descriptor: Tibit Stats Options """
    name = "Tibit Stats Options"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0111),
                   ]

class TibitStatsOptionsSet(Packet):
    """ Variable Descriptor: Tibit Stats Options Set"""
    name = "Tibit Stats Options Set"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0111),
                   ByteField("length", 5),
                   ByteField("enable", 0),
                   IntField("period", 0),
                   ]


UpstreamSlaSubtypeEnum = { 0x00: "Terminator",
                           0x01: "Header",
                           0x02: "Max Grant Period",
                           0x03: "Min Grant Period",
                           0x04: "Service Limit",
                           0x05: "Fixed Rate",
                           0x06: "Guaranteed Rate",
                           0x07: "Best Effort Rate",
                           0x08: "Max Burst Size",
                           0x09: "Priority",
                         }

class UpstreamSla(Packet):
    """ Variable Descriptor: Upstream SLA """
    name = "Upstream SLA"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0621),
                   ]

class UpstreamSlaHeader(Packet):
    """ Variable Descriptor: Upstream SLA Header """
    name = "Upstream SLA Header"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0621),
                   ByteField("length", 1),
                   XByteField("subtype", 1),
                   ]

class UpstreamSlaTerminator(Packet):
    """ Variable Descriptor: Upstream SLA Terminator """
    name = "Upstream SLA Terminator"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0621),
                   ByteField("length", 1),
                   XByteField("subtype", 0),
                   ]

class UpstreamSlaSettingLength01(Packet):
    """ Variable Descriptor: Upstream SLA Setting """
    name = "Upstream SLA Setting"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0621),
                   ByteField("length", 3),
                   XByteField("subtype", 0),
                   XByteField("setting_len", 1),
                   ByteField("setting_val", 0),
                   ]

class UpstreamSlaSettingLength02(Packet):
    """ Variable Descriptor: Upstream SLA Setting """
    name = "Upstream SLA Setting"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0621),
                   ByteField("length", 4),
                   XByteField("subtype", 0),
                   XByteField("setting_len", 2),
                   ShortField("setting_val", 0),
                   ]

class UpstreamSlaSettingLength04(Packet):
    """ Variable Descriptor: Upstream SLA Setting """
    name = "Upstream SLA Setting"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0621),
                   ByteField("length", 6),
                   XByteField("subtype", 0),
                   XByteField("setting_len", 4),
                   IntField("setting_val", 0),
                   ]

class SlaPriorityType(Packet):
    """ Variable Descriptor: SLA Priority Type """
    name = "SLA Priority Type"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0622),
                   ]

class SlaPriorityTypeSet(Packet):
    """ Variable Container: SLA Priority Type """
    name = "SLA Priority Type"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0622),
                   XByteField("length", 1),
                   XByteField("value", 1),
                   ]

class DsGuarRate(Packet):
    """ Variable Descriptor: Downstream Guaranteed Rate """
    name = "Downstream Guaranteed Rate"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0623),
                   ]

class DsGuarRateSet(Packet):
    """ Variable Descriptor: Downstream Guaranteed Rate Set"""
    name = "Downstream Guaranteed Rate Set"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0623),
                   ByteField("length", 6),
                   ShortField("mbs", 0),
                   IntField("rate", 0),                  ]


class DsBestEffortRate(Packet):
    """ Variable Descriptor: Downstream Best Effort Rate """
    name = "Downstream Best Effort Rate"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0624),
                   ]

class DsBestEffortRateSet(Packet):
    """ Variable Descriptor: Downstream Best Effort Rate Set"""
    name = "Downstream Best Effort Rate Set"
    fields_desc = [ByteEnumField("branch", 0xB7, OamBranchEnum),
                   XShortField("leaf", 0x0624),
                   ByteField("length", 6),
                   ShortField("mbs", 0),
                   IntField("rate", 0),                  ]


####
#### 0xd9 - BRANCH ATTRIBUTES
####

class EnableUserTraffic(Packet):
    """ Variable Descriptor: Enable User Traffic """
    name = "Enable User Traffic"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0601),
                   ]

class DisableUserTraffic(Packet):
    """ Variable Descriptor: Disable User Traffic """
    name = "Disable User Traffic"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0602),
                   ]

class LoopbackEnable(Packet):
    """ Variable Descriptor: Loopback Enable """
    name = "Loopback Enable"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0603),
                   XByteField("length", 1),
                   XByteField("location", 0),
                   ]

class LoopbackDisable(Packet):
    """ Variable Descriptor: Loopback Disable """
    name = "Loopback Disable"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0604),
                   XByteField("length", 1),
                   XByteField("location", 0),
                   ]

class CurrentAlarmSummary(Packet):
    """ Variable Descriptor: Current Alarm Summary """
    name = "Current Alarm Summary"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0301)]

class DeviceReset(Packet):
    """ Variable Descriptor: Device Reset """
    name = "Device Reset"
    fields_desc = [ByteEnumField("branch", 0xD9, OamBranchEnum),
                   XShortField("leaf", 0x0001),
                   ]

class TibitDeviceReset(Packet):
    """ Variable Descriptor: Tibit Device Reset """
    name = "Tibit Device Reset"
    fields_desc = [XByteField("branch", 0xB9),
                   XShortField("leaf", 0x0001),
                   ]

class TibitPreprovisionLink(Packet):
    """ Variable Descriptor: Tibit Preprovision Link """
    name = "Tibit Preprovision Link"
    fields_desc = [XByteField("branch", 0xB9),
                   XShortField("leaf", 0x0002),
                   ]

class TibitApplySla(Packet):
    """ Variable Descriptor: Apply SLA """
    name = "Apply Sla"
    fields_desc = [XByteField("branch", 0xB9),
                   XShortField("leaf", 0x0601),
                   ]


##
## DPoE File Transfer
##

### Table 156 - DPoE File Transfer Opcodes
DPoEFileXferOpcodeEnum = {
    0x00: "Reserved",
    0x01: "Write Request",
    0x02: "File Transfer Data",
    0x03: "File Transfer Ack",
    }

Dpoe_FileXferOpcodes = {v: k for k, v in DPoEFileXferOpcodeEnum.iteritems()}


### Table 160 - DPoE File Acknowledgement Response Codes
DPoEFileAckRespCodeEnum = {
    0x00: "OK",
    0x01: "Undefined",
    0x02: "Not Found",
    0x03: "No Access",
    0x04: "Full",
    0x05: "Illegal Operation",
    0x06: "Unknown ID",
    0x07: "Bad Block",
    0x08: "Timeout",
    0x09: "Busy",
    0x0A: "Incompatible File",
    0x0B: "Corrupted File",
    }

Dpoe_FileAckRspOpcodes = {v: k for k, v in DPoEFileAckRespCodeEnum.iteritems()}

class DpoeFileTransferWrite(Packet):
    name = "DPoE File Transfer Write "
    fields_desc = [ByteEnumField("opcode", 0x01, DPoEFileXferOpcodeEnum),
                   StrField("filename", ""),
                  ]

class DpoeFileTransferData(Packet):
    name = "DPoE File Transfer Data "
    fields_desc = [ByteEnumField("opcode", 0x02, DPoEFileXferOpcodeEnum),
                   ShortField("block_num", 0),
                   FieldLenField("block_width", None, length_of="block", fmt="H"),
                   StrLenField("block", "", length_from=lambda x:x.length),
                  ]

class DpoeFileTransferAck(Packet):
    name = "DPoE File Transfer Data "
    fields_desc = [ByteEnumField("opcode", 0x03, DPoEFileXferOpcodeEnum),
                   ShortField("block_num", 0),
                   ByteEnumField("response_code", 0x00, DPoEFileAckRespCodeEnum),
                  ]


##
## Broadcom TLVs
##
class Broadcom07_7F_F1_Set01(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Broadcom 0x07/0x7ff1"
    fields_desc = [ByteEnumField("branch", 0x07, OamBranchEnum),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 2),
                   XShortField("value0", 0x0101),
                   ]

class Broadcom07_7F_F1_Set02(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Broadcom 0x07/0x7ff1"
    fields_desc = [ByteEnumField("branch", 0x07, OamBranchEnum),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 7),
                   XShortField("value0", 0x0201),
                   XShortField("value1", 0x0000),
                   XShortField("value2", 0x0107),
                   XByteField("value3", 0xd0),
                   ]

class Broadcom07_7F_F1_Set03(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Broadcom 0x07/0x7ff1"
    fields_desc = [ByteEnumField("branch", 0x07, OamBranchEnum),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 7),
                   XShortField("value0", 0x0301),
                   XShortField("value1", 0x0000),
                   XShortField("value2", 0x0100),
                   XByteField("value3", 0xb8),
                   ]

class Broadcom07_7F_F1_Set04(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Broadcom 0x07/0x7ff1"
    fields_desc = [ByteEnumField("branch", 0x07, OamBranchEnum),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 1),
                   XByteField("value0", 0x00),
                   ]

class Broadcom07_7F_F6_Set(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff6 """
    name = "Broadcom 0x07/0x7ff6"
    fields_desc = [ByteEnumField("branch", 0x07, OamBranchEnum),
                   XShortField("leaf", 0x7ff6),
                   XByteField("length", 2),
                   XShortField("value0", 0x07d0),
                   ]

###
### Clause 30 Attributes (0x07)
###
class Clause30AttributesMacEnable(Packet):
    """ Variable Descriptor: Clause 30 Attributes MAC Enable """
    name = "Clause 30 Attributes MAC Enable"
    fields_desc = [ByteEnumField("branch", 0x07, OamBranchEnum),
                   XShortField("leaf", 0x001a),
                   XByteField("length", 1),
                   XByteField("value", 1),
                   ]

class GenericTLV(Packet):
    """ Variable Descriptor: Generic TLV """
    name = "Generic TLV"
    fields_desc = [ByteEnumField("branch", 0x00, OamBranchEnum),
                   XShortField("leaf", 0x0000),
                   FieldLenField("length", None, length_of="value", fmt="B"),
                   StrLenField("value", "", length_from=lambda x:x.length),
                   ]

class EndOfPDU(Packet):
    name = "End of EOAM PDU"
    fields_desc = [BitEnumField("type", 0x00, 7, TLV_dictionary),
                   BitField("length", 0x00, 9)]
