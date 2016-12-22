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

from scapy.packet import Packet
from scapy.fields import ByteEnumField, XShortField, XByteField, MACField, \
    ByteField, BitEnumField, BitField

# This library strives to be an implementation of the following standard:

# DPoE-SP-OAMv1.0-IO8-140807 - DPoE OAM Extensions Specifications

# This library may be used with PON devices for
# configuration and provisioning.

TIBIT_VERSION_NUMBER = '1.1.4'

TLV_dictionary = {
    0x00: "End EOAMPDU",
    }

SlowProtocolsSubtypeEnum = {0x03: "OAM"}

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
    }

### Table 20 - DPoE Variable Response Codes
DPoEVariableResponseCodes = {
    0x80, "No Error",
    0x81, "Too Long",
    0x86, "Bad Parameters",
    0x87, "No Resources",
    0x88, "System Busy",
    0xa0, "Undetermined Error",
    0xa1, "Unsupported",
    0xa2, "May Be Corrupted",
    0xa3, "Hardware Failure",
    0xa4, "Overflow",
    }

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
#### PORT OBJECTS
####
class DONUObject(Packet):
    """ Object Context: D-ONU Object """
    name = "Object Context: D-ONU Object"
    fields_desc = [XByteField("branch", 0xD6),
                   XShortField("leaf", 0x0000),
                   XByteField("length", 1),
                   XByteField("num", 0)
                   ]

class DOLTObject(Packet):
    """ Object Context: D-OLT Object """
    name = "Object Context: D-OLT Object"
    fields_desc = [XByteField("branch", 0xD6),
                   XShortField("leaf", 0x0000),
                   XByteField("length", 1),
                   XByteField("num", 0)
                   ]

class NetworkPortObject(Packet):
    """ Object Context: Network Port Object """
    name = "Object Context: Network Port Object"
    fields_desc = [XByteField("branch", 0xD6),
                   XShortField("leaf", 0x0001),
                   XByteField("length", 1),
                   XByteField("num", 0)
                   ]

class UnicastLogicalLink(Packet):
    """ Object Context: Unicast Logical Link """
    name = "Object Context: Unicast Logical Link"
    fields_desc = [XByteField("branch", 0xD6),
                   XShortField("leaf", 0x0002),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

class UserPortObject(Packet):
    """ Object Context: User Port Object """
    name = "Object Context: User Port Object"
    fields_desc = [XByteField("branch", 0xD6),
                   XShortField("leaf", 0x0003),
                   XByteField("length", 1),
                   XByteField("number", 0)
                   ]

class QueueObject(Packet):
    """ Object Context: Queue Object """
    name = "Object Context: Queue Object"
    fields_desc = [XByteField("branch", 0xD6),
                   XShortField("leaf", 0x0004),
                   XByteField("length", 2),
                   XByteField("instance", 0),
                   XByteField("number", 0)
                   ]


####
#### 0x09 - BRANCH ATTRIBUTES
####
class PhyAdminControl(Packet):
    """ Variable Descriptor: Phy Admin Control """
    name = "Variable Descriptor: Phy Admin Control"
    fields_desc = [XByteField("branch", 0x09),
                   XShortField("leaf", 0x0005),
                   ]

class PhyAdminControlEnableSet(Packet):
    """ Variable Descriptor: Phy Admin Control Enable """
    name = "Variable Descriptor: Phy Admin Control Enable"
    fields_desc = [XByteField("branch", 0x09),
                   XShortField("leaf", 0x0005),
                   XByteField("length", 1),
                   XByteField("value", 2)
                   ]

class PhyAdminControlDisableSet(Packet):
    """ Variable Descriptor: Phy Admin Control Disable """
    name = "Variable Descriptor: Phy Admin Control Disable"
    fields_desc = [XByteField("branch", 0x09),
                   XShortField("leaf", 0x0005),
                   XByteField("length", 1),
                   XByteField("value", 1)
                   ]

####
#### 0xd7 - BRANCH ATTRIBUTES
####
class DeviceId(Packet):
    """ Variable Descriptor: Device ID """
    name = "Variable Descriptor: Device ID"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0002)]

class FirmwareInfo(Packet):
    """ Variable Descriptor: Firmware Info """
    name = "Variable Descriptor: Firmware Info"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0003)]

class ChipsetInfo(Packet):
    """ Variable Descriptor: Chipset Info """
    name = "Variable Descriptor: Chipset Info"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0004)]

class DateOfManufacture(Packet):
    """ Variable Descriptor: Date of Manufacture """
    name = "Variable Descriptor: Date of Manufacture"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0005)]

class MaxLogicalLinks(Packet):
    """ Variable Descriptor: Max Logical Links """
    name = "Variable Descriptor: Max Logical Links"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0007)]

class NumberOfNetworkPorts(Packet):
    """ Variable Descriptor: Number of Network Ports """
    name = "Variable Descriptor: Number of Network Ports"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0008)]

class NumberOfS1Interfaces(Packet):
    """ Variable Descriptor: Number of S1 Interfaces """
    name = "Variable Descriptor: Number of S1 Interfaces"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0009)]

class DONUPacketBuffer(Packet):
    """ Variable Descriptor: D-ONU Packet Buffer """
    name = "Variable Descriptor: D-ONU Packet Buffer"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x000a)]

class ReportThresholds(Packet):
    """ Variable Descriptor: Report Thresholds """
    name = "Variable Descriptor: Report Thresholds"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x000b),
                   ]

class ReportThresholdsSet(Packet):
    """ Variable Descriptor: Report Thresholds Set """
    name = "Variable Descriptor: Report Thresholds Set"
    fields_desc = [XByteField("branch", 0xD7),
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
    name = "Variable Descriptor: Report Thresholds Unicast Logical Link Set"
    fields_desc = [XByteField("branch", 0xD7),
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
    name = "Variable Descriptor: Logical Link Forwarding"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x000c),
                   ]

class OamFrameRate(Packet):
    """ Variable Descriptor: OAM Frame Rate """
    name = "Variable Descriptor: OAM Frame Rate"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x000d),
                   ]

class OamFrameRateSet(Packet):
    """ Variable Descriptor: OAM Frame Rate """
    name = "Variable Descriptor: OAM Frame Rate"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x000d),
                   XByteField("length", 2),
                   XByteField("max", 12),
                   XByteField("min", 10),
                   ]

class OnuManufacturerOrganizationName(Packet):
    """ Variable Descriptor: ONU Manufacturer Organization Name """
    name = "Variable Descriptor: ONU Manufacturer Organization Name"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x000e),
                   ]

class FirmwareMfgTimeVaryingControls(Packet):
    """ Variable Descriptor: Firmware Mfg Time Varying Controls """
    name = "Variable Descriptor: Firmware Mfg Time Varying Controls"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x000f),
                   ]

class VendorName(Packet):
    """ Variable Descriptor: Vendor Name """
    name = "Variable Descriptor: Vendor Name"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0011),
                   ]

class ModelNumber(Packet):
    """ Variable Descriptor: Model Number """
    name = "Variable Descriptor: Model Number"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0012),
                   ]

class HardwareVersion(Packet):
    """ Variable Descriptor: Hardware Version """
    name = "Variable Descriptor: Hardware Version"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0013),
                   ]

class EponMode(Packet):
    """ Variable Descriptor: EPON Mode """
    name = "Variable Descriptor: EPON Mode"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0014),
                   ]

class DynamicAddressAgeLimit(Packet):
    """ Variable Descriptor: Dynamic Address Age Limit """
    name = "Variable Descriptor: Dynamic Address Age Limit"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0102),
                   ]

class DynamicAddressAgeLimitSet(Packet):
    """ Variable Descriptor: Dynamic Address Age Limit Set """
    name = "Variable Descriptor: Dynamic Address Age Limit Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0102),
                   XByteField("length", 2),
                   XShortField("value", 0x0000),
                   ]

class DynamicMacTable(Packet):
    """ Variable Descriptor: Dynamic MAC Table """
    name = "Variable Descriptor: Dynamic MAC Table"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0103),
                   ]

class StaticMacTable(Packet):
    """ Variable Descriptor: Static MAC Table """
    name = "Variable Descriptor: Static MAC Table"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0104),
                   ]

class SourceAddressAdmissionControl(Packet):
    """ Variable Descriptor: Source Address Admission Control """
    name = "Variable Descriptor: Source Address Admission Control"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0106),
                   ]

class SourceAddressAdmissionControlSet(Packet):
    """ Variable Descriptor: Source Address Admission Control Set """
    name = "Variable Descriptor: Source Address Admission Control Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0106),
                   XByteField("length", 1),
                   XByteField("value", 1),
                   ]

class MacLearningMinGuarantee(Packet):
    """ Variable Descriptor: MAC Learning MIN Guarantee """
    name = "Variable Descriptor: MAC Learning MIN Guarantee"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0107),
                   ]

class MacLearningMinGuaranteeSet(Packet):
    """ Variable Descriptor: MAC Learning MIN Guarantee Set """
    name = "Variable Descriptor: MAC Learning MIN Guarantee Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0107),
                   XByteField("length", 2),
                   XShortField("value", 0),
                   ]

class MacLearningMaxAllowed(Packet):
    """ Variable Descriptor: MAC Learning MAX Allowed """
    name = "Variable Descriptor: MAC Learning MAX Allowed"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0108),
                   ]

class MacLearningMaxAllowedSet(Packet):
    """ Variable Descriptor: MAC Learning MAX Allowed Set """
    name = "Variable Descriptor: MAC Learning MAX Allowed Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0108),
                   XByteField("length", 2),
                   XShortField("value", 0x0010),
                   ]

class MacLearningAggregateLimit(Packet):
    """ Variable Descriptor: MAC Learning Aggregate Limit """
    name = "Variable Descriptor: MAC Learning Aggregate Limit"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0109),
                   ]

class MacLearningAggregateLimitSet(Packet):
    """ Variable Descriptor: MAC Learning Aggregate Limit Set """
    name = "Variable Descriptor: MAC Learning Aggregate Limit Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0109),
                   XByteField("length", 2),
                   XShortField("value", 0x0040),
                   ]

class FloodUnknown(Packet):
    """ Variable Descriptor: Flood Unknown """
    name = "Variable Descriptor: Flood Unknown"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x010b),
                   ]

class FloodUnknownSet(Packet):
    """ Variable Descriptor: Flood Unknown Set """
    name = "Variable Descriptor: Flood Unknown Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x010b),
                   XByteField("length", 1),
                   XByteField("value", 1),
                   ]

class LocalSwitching(Packet):
    """ Variable Descriptor: Local Switching """
    name = "Variable Descriptor: Local Switching"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x010c),
                   ]

class LocalSwitchingSet(Packet):
    """ Variable Descriptor: Local Switching Set """
    name = "Variable Descriptor: Local Switching Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x010c),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class LLIDQueueConfiguration(Packet):
    """ Variable Descriptor: LLID Queue Configuration """
    name = "Variable Descriptor: LLID Queue Configuration"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x010d),
                   ]

class LLIDQueueConfigurationSet(Packet):
    """ Variable Descriptor: LLID Queue Configuration """
    name = "Variable Descriptor: LLID Queue Configuration"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x010d),
                   XByteField("length", 6),
                   XByteField("numLLID", 1),
                   XByteField("LLID0-numq", 1),
                   XByteField("l0Q0-size",0xa0),
                   XByteField("numPort", 1),
                   XByteField("Port0-numq", 1),
                   XByteField("p0Q0-size",0xa0),
                   ]

class FirmwareFilename(Packet):
    """ Variable Descriptor: Firmware Filename """
    name = "Variable Descriptor: Firmware Filename"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x010e),
                   ]
####
#### 0xD9 - MAC Table Operations - Dynamic and Static
####

class ClearDynamicMacTable(Packet):
    """ Variable Descriptor: Clear Dynamic MAC Table """
    name = "Variable Descriptor: Clear Dynamic MAC Table"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0101),
                   ]

class AddDynamicMacAddress(Packet):
    """ Variable Descriptor: Add Dynamic MAC Address """
    name = "Variable Descriptor: Add Dynamic MAC Address"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0102),
                   ]

class DeleteDynamicMacAddress(Packet):
    """ Variable Descriptor: Delete Dynamic MAC Address """
    name = "Variable Descriptor: Delete Dynamic MAC Address"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0103),
                   ]

class ClearStaticMacTable(Packet):
    """ Variable Descriptor: Clear Static MAC Table """
    name = "Variable Descriptor: Clear Static MAC Table"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0104),
                   ]

class AddStaticMacAddress(Packet):
    """ Variable Descriptor: Add Static MAC Address """
    name = "Variable Descriptor: Add Static MAC Address"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0105),
                   ByteField("length", 6),
                   MACField("mac", "01:00:5e:00:00:00"),
                   ]

class DeleteStaticMacAddress(Packet):
    """ Variable Descriptor: Delete Static MAC Address """
    name = "Variable Descriptor: Delete Static MAC Address"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0106),
                   ByteField("length", 6),
                   MACField("mac", "01:00:5e:00:00:00"),
                   ]

####
#### 0xd7 - STATISTICS
####

class RxFrame_512_1023(Packet):
    """ Variable Descriptor: RxFrame_512_1023 """
    name = "Variable Descriptor: RxFrame_512_1023"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0208),
                   ]

class TxFrame_512_1023(Packet):
    """ Variable Descriptor: TxFrame_512_1023 """
    name = "Variable Descriptor: TxFrame_512_1023"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x020f),
                   ]

class FramesDropped(Packet):
    """ Variable Descriptor: Frames Dropped """
    name = "Variable Descriptor: Frames Dropped"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0214),
                   ]

class BytesDropped(Packet):
    """ Variable Descriptor: Bytes Dropped """
    name = "Variable Descriptor: Bytes Dropped"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0215),
                   ]

class TxBytesUnused(Packet):
    """ Variable Descriptor: Tx Bytes Unused """
    name = "Variable Descriptor: Tx Bytes Unused"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0217),
                   ]

class TxL2Errors(Packet):
    """ Variable Descriptor: TxL2Errors """
    name = "Variable Descriptor: TxL2Errors"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0235),
                   ]

class RxL2Errors(Packet):
    """ Variable Descriptor: RxL2Errors """
    name = "Variable Descriptor: RxL2Errors"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0236),
                   ]

####
#### 0xD7 - Alarm Reporting
####

class AlarmReporting(Packet):
    """ Variable Descriptor: Alarm Reporting """
    name = "Variable Descriptor: Alarm Reporting"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0303),
                   ]

class AlarmReportingSet(Packet):
    """ Variable Descriptor: Alarm Reporting Set """
    name = "Variable Descriptor: Alarm Reporting Set"
    fields_desc = [XByteField("branch", 0xD7),
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
    name = "Variable Descriptor: Encryption Mode"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0402),
                   ]

class EncryptionModeSet(Packet):
    """ Variable Descriptor: Encryption Mode Set """
    name = "Variable Descriptor: Encryption Mode Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0402),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class IpmcForwardingRuleConfiguration(Packet):
    """ Variable Descriptor: IPMC Forwarding Rule Configuration """
    name = "Variable Descriptor: IPMC Forwarding Rule Configuration"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0505),
                   XByteField("length", 2),
                   XShortField("value", 0x0000),
                   ]

class QueueCommittedInformationRate(Packet):
    """ Variable Descriptor: Queue Committed Information Rate """
    name = "Variable Descriptor: Queue Committed Information Rate"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0604),
                   ]

class QueueCommittedInformationRateSet(Packet):
    """ Variable Descriptor: Queue Committed Information Rate Set """
    name = "Variable Descriptor: Queue Committed Information Rate Set"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0604),
                   XByteField("length", 6),
                   XShortField("burst", 0x0fff),
                   XShortField("CIR_UPPER", 0x0000),
                   XShortField("CIR_LOWER", 0xffff),
                   ]

class FECMode(Packet):
    """ Variable Descriptor: FEC Mode """
    name = "Variable Descriptor: FEC Mode"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0605),
                   ]

class FECModeSet(Packet):
    """ Variable Descriptor: FEC Mode """
    name = "Variable Descriptor: FEC Mode"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0605),
                   ]

class MediaType(Packet):
    """ Variable Descriptor: Media Type """
    name = "Variable Descriptor: Media Type"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0822),
                   ]


####
#### 0xD7 - Port Ingress Rules
####
class PortIngressRule(Packet):
    """ Variable Descriptor: Port Ingress Rule """
    name = "Variable Descriptor: Port Ingress Rule"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0501),
                   ]

class PortIngressRuleHeader(Packet):
    """ Variable Descriptor: Port Ingress Rule Header """
    name = "Variable Descriptor: Port Ingress Rule Header"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 2),
        XByteField("header", 1),
        XByteField("precedence", 00),
        ]

class PortIngressRuleClauseMatchLength00(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Variable Descriptor: Port Ingress Rule Clause"
    fields_desc = [
        XByteField("branch", 0xD7),
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

class PortIngressRuleClauseMatchLength01(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Variable Descriptor: Port Ingress Rule Clause"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 8),
        XByteField("clause", 2),
        XByteField("fieldcode", 0),
        XByteField("fieldinstance", 0),
        XByteField("msbmask", 0),
        XByteField("lsbmask", 0),
        XByteField("operator", 0),
        XByteField("matchlength", 1),
        XByteField("match0", 0),
        ]

class PortIngressRuleClauseMatchLength02(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Variable Descriptor: Port Ingress Rule Clause"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 9),
        XByteField("clause", 2),
        XByteField("fieldcode", 0),
        XByteField("fieldinstance", 0),
        XByteField("msbmask", 0),
        XByteField("lsbmask", 0),
        XByteField("operator", 0),
        XByteField("matchlength", 2),
        XByteField("match0", 0),
        XByteField("match1", 0),
        ]


class PortIngressRuleClauseMatchLength06(Packet):
    """ Variable Descriptor: Port Ingress Rule Clause """
    name = "Variable Descriptor: Port Ingress Rule Clause"
    fields_desc = [
        XByteField("branch", 0xD7),
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
    name = "Variable Descriptor: Port Ingress Rule Result Forward"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 2),
        XByteField("result", 3),
        XByteField("forward", 2),
        ]

class PortIngressRuleResultDiscard(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Discard """
    name = "Variable Descriptor: Port Ingress Rule Result Discard"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 2),
        XByteField("result", 3),
        XByteField("discard", 1),
        ]

class PortIngressRuleResultQueue(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Queue """
    name = "Variable Descriptor: Port Ingress Rule Result Queue"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 6),
        XByteField("result", 3),
        XByteField("queuerule", 3),
        XShortField("objecttype", 0x0000),
        XByteField("instance", 0),
        XByteField("queuenum", 0),
        ]

class PortIngressRuleResultSet(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Set """
    name = "Variable Descriptor: Port Ingress Rule Result Set"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 8),
        XByteField("result", 3),
        XByteField("set", 4),
        XByteField("fieldcode", 0),
        XByteField("fieldinstance", 0),
        XByteField("msbmask", 0),
        XByteField("lsbmask", 0),
        XShortField("value", 0),
        ]

class PortIngressRuleResultInsert(Packet):
    """ Variable Descriptor: Port Ingress Rule Result Insert """
    name = "Variable Descriptor: Port Ingress Rule Result Insert"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 4),
        XByteField("result", 3),
        XByteField("insert", 7),
        XByteField("fieldcode", 0),
        XByteField("fieldinstance", 0),
        ]

class PortIngressRuleTerminator(Packet):
    """ Variable Descriptor: Port Ingress Rule Terminator """
    name = "Variable Descriptor: Port Ingress Rule Terminator"
    fields_desc = [
        XByteField("branch", 0xD7),
        XShortField("leaf", 0x0501),
        ByteField("length", 1),
        XByteField("terminator", 0),
        ]

class CustomField(Packet):
    """ Variable Descriptor: Custom Field """
    name = "Variable Descriptor: Custom Field"
    fields_desc = [XByteField("branch", 0xD7),
                   XShortField("leaf", 0x0502),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class CustomFieldEtherType(Packet):
    """ Variable Descriptor: Custom Field EtherType """
    name = "Variable Descriptor: Custom Field EtherType"
    fields_desc = [XByteField("branch", 0xD7),
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
    name = "Variable Descriptor: Custom Field Generic L3"
    fields_desc = [XByteField("branch", 0xD7),
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
    name = "Variable Descriptor: Clear Port Ingress Rule"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0501),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class AddPortIngressRule(Packet):
    """ Variable Descriptor: Add Port Ingress Rule """
    name = "Variable Descriptor: Add Port Ingress Rule"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0502),
                   XByteField("length", 0x80),
                   XByteField("value", 0),
                   ]


class DeletePortIngressRule(Packet):
    """ Variable Descriptor: Delete Port Ingress Rule """
    name = "Variable Descriptor: Delete Port Ingress Rule"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0503),
                   XByteField("length", 0x80),
                   XByteField("value", 0),
                   ]

####
#### 0xd9 - BRANCH ATTRIBUTES
####

class EnableUserTraffic(Packet):
    """ Variable Descriptor: Enable User Traffic """
    name = "Variable Descriptor: Enable User Traffic"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0601),
                   XByteField("length", 1),
                   XByteField("value", 0),
                   ]

class DisableUserTraffic(Packet):
    """ Variable Descriptor: Disable User Traffic """
    name = "Variable Descriptor: Disable User Traffic"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0602)]

class LoopbackEnable(Packet):
    """ Variable Descriptor: Loopback Enable """
    name = "Variable Descriptor: Loopback Enable"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0603),
                   XByteField("length", 1),
                   XByteField("location", 0),
                   ]

class LoopbackDisable(Packet):
    """ Variable Descriptor: Loopback Disable """
    name = "Variable Descriptor: Loopback Disable"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0604),
                   XByteField("length", 1),
                   XByteField("location", 0),
                   ]

class CurrentAlarmSummary(Packet):
    """ Variable Descriptor: Current Alarm Summary """
    name = "Variable Descriptor: Current Alarm Summary"
    fields_desc = [XByteField("branch", 0xD9),
                   XShortField("leaf", 0x0301)]


##
## Broadcom TLVs
##
class Broadcom07_7F_F1_Set01(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Variable Descriptor: Broadcom 0x07/0x7ff1"
    fields_desc = [XByteField("branch", 0x07),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 2),
                   XShortField("value0", 0x0101),
                   ]

class Broadcom07_7F_F1_Set02(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Variable Descriptor: Broadcom 0x07/0x7ff1"
    fields_desc = [XByteField("branch", 0x07),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 7),
                   XShortField("value0", 0x0201),
                   XShortField("value1", 0x0000),
                   XShortField("value2", 0x0107),
                   XByteField("value3", 0xd0),
                   ]

class Broadcom07_7F_F1_Set03(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Variable Descriptor: Broadcom 0x07/0x7ff1"
    fields_desc = [XByteField("branch", 0x07),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 7),
                   XShortField("value0", 0x0301),
                   XShortField("value1", 0x0000),
                   XShortField("value2", 0x0100),
                   XByteField("value3", 0xb8),
                   ]

class Broadcom07_7F_F1_Set04(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff1 """
    name = "Variable Descriptor: Broadcom 0x07/0x7ff1"
    fields_desc = [XByteField("branch", 0x07),
                   XShortField("leaf", 0x7ff1),
                   XByteField("length", 1),
                   XByteField("value0", 0x00),
                   ]

class Broadcom07_7F_F6_Set(Packet):
    """ Variable Descriptor: Broadcom 0x07/0x7ff6 """
    name = "Variable Descriptor: Broadcom 0x07/0x7ff6"
    fields_desc = [XByteField("branch", 0x07),
                   XShortField("leaf", 0x7ff6),
                   XByteField("length", 2),
                   XShortField("value0", 0x07d0),
                   ]

###
### Clause 30 Attributes (0x07)
###
class Clause30AttributesMacEnable(Packet):
    """ Variable Descriptor: Clause 30 Attributes MAC Enable """
    name = "Variable Descriptor: Clause 30 Attributes MAC Enable"
    fields_desc = [XByteField("branch", 0x07),
                   XShortField("leaf", 0x001a),
                   XByteField("length", 1),
                   XByteField("value", 1),
                   ]

class EndOfPDU(Packet):
    name = "End of EOAM PDU"
    fields_desc = [BitEnumField("type", 0x00, 7, TLV_dictionary),
                   BitField("length", 0x00, 9)]
