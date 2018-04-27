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


"""
PAS5211 scapy structs used for interaction with Ruby
"""
import struct

from scapy.fields import LEShortField, Field, LEIntField, LESignedIntField, FieldLenField, FieldListField, PacketField, \
    ByteField, StrFixedLenField, ConditionalField, StrField, MACField, LELongField, LenField, StrLenField
from scapy.layers.l2 import DestMACField, ETHER_ANY, Ether
from scapy.packet import Packet, bind_layers
from scapy.utils import lhex
from scapy.volatile import RandSInt
from scapy.layers.ntp import XLEShortField

from voltha.adapters.microsemi_olt.PAS5211_constants import PON_ENABLE, PON_PORT_PON, PON_FALSE, PON_TRUE
from voltha.extensions.omci.omci_frame import OmciFrame

"""
PAS5211 Constants
"""
# TODO get range from olt_version message
CHANNELS = range(0, 4)
PORTS = range(1, 129)


class XLESignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<i")

    def randval(self):
        return RandSInt()

    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class LESignedShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<h")


class PAS5211FrameHeader(Packet):
    name = "PAS5211FrameHeader"
    fields_desc = [
        LEShortField("part", 1),
        LEShortField("total_parts", 1),
        LEShortField("size", 0),
        XLESignedIntField("magic_number", 0x1234ABCD)
    ]


class PAS5211MsgHeader(Packet):
    name = "PAS5211MsgHeader"
    fields_desc = [
        LEIntField("sequence_number", 0),
        XLEShortField("opcode", 0),
        LEShortField("event_type", 0),
        LESignedShortField("channel_id", -1),
        LESignedShortField("onu_id", -1),
        LESignedIntField("onu_session_id", -1)
    ]


class PAS5211Msg(Packet):
    opcode = "Must be filled by subclass"
    pass


class PAS5211MsgGetProtocolVersion(PAS5211Msg):
    opcode = 2
    name = "PAS5211MsgGetProtocolVersion"
    fields_desc = []


class PAS5211MsgGetProtocolVersionResponse(PAS5211Msg):
    name = "PAS5211MsgGetProtocolVersionResponse"
    fields_desc = [
        LEShortField("major_hardware_version", 0),
        LEShortField("minor_hardware_version", 0),
        LEShortField("major_pfi_version", 0),
        LEShortField("minor_pfi_version", 0)
    ]


class PAS5211MsgGetOltVersion(PAS5211Msg):
    opcode = 3
    name = "PAS5211MsgGetOltVersion"
    fields_desc = []


class PAS5211MsgGetOltVersionResponse(PAS5211Msg):
    name = "PAS5211MsgGetOltVersionResponse"
    fields_desc = [
        LEShortField("major_firmware_version", 0),
        LEShortField("minor_firmware_version", 0),
        LEShortField("build_firmware_version", 0),
        LEShortField("maintenance_firmware_version", 0),
        LEShortField("major_hardware_version", 0),
        LEShortField("minor_hardware_version", 0),
        LEIntField("system_port_mac_type", 0),
        FieldLenField("channels_supported", 0, fmt="<H"),
        LEShortField("onus_supported_per_channel", 0),
        LEShortField("ports_supported_per_channel", 0),
        LEShortField("alloc_ids_supported_per_channel", 0),
        FieldListField("critical_events_counter", [0, 0, 0, 0],
                       LEIntField("entry", 0),
                       count_from=lambda pkt: pkt.channels_supported),
        FieldListField("non_critical_events_counter", [0, 0, 0, 0],
                       LEIntField("entry", 0),
                       count_from=lambda pkt: pkt.channels_supported)
    ]


class SnrBurstDelay(Packet):
    name = "SnrBurstDelay"
    fields_desc = [
        LEShortField("timer_delay", None),
        LEShortField("preamble_delay", None),
        LEShortField("delimiter_delay", None),
        LEShortField("burst_delay", None)
    ]

    def extract_padding(self, p):
        return "", p


class RngBurstDelay(Packet):
    name = "SnrBurstDelay"
    fields_desc = [
        LEShortField("timer_delay", None),
        LEShortField("preamble_delay", None),
        LEShortField("delimiter_delay", None)
    ]

    def extract_padding(self, p):
        return "", p


class BurstTimingCtrl(Packet):
    name = "BurstTimingCtrl"
    fields_desc = [
        PacketField("snr_burst_delay", None, SnrBurstDelay),
        PacketField("rng_burst_delay", None, RngBurstDelay),
        LEShortField("burst_delay_single", None),
        LEShortField("burst_delay_double", None)

    ]

    def extract_padding(self, p):
        return "", p


class GeneralOpticsParams(Packet):
    name = "GeneralOpticsParams"
    fields_desc = [
        ByteField("laser_reset_polarity", None),
        ByteField("laser_sd_polarity", None),
        ByteField("sd_source", None),
        ByteField("sd_hold_snr_ranging", None),
        ByteField("sd_hold_normal", None),
        ByteField("reset_type_snr_ranging", None),
        ByteField("reset_type_normal", None),
        ByteField("laser_reset_enable", None),
    ]

    def extract_padding(self, p):
        return "", p


class ResetValues(Packet):
    name = "ResetDataBurst"
    fields_desc = [
        ByteField("bcdr_reset_d2", None),
        ByteField("bcdr_reset_d1", None),
        ByteField("laser_reset_d2", None),
        ByteField("laser_reset_d1", None)
    ]

    def extract_padding(self, p):
        return "", p


class DoubleResetValues(Packet):
    name = "ResetDataBurst"
    fields_desc = [
        ByteField("bcdr_reset_d4", None),
        ByteField("bcdr_reset_d3", None),
        ByteField("laser_reset_d4", None),
        ByteField("laser_reset_d3", None)
    ]

    def extract_padding(self, p):
        return "", p


class ResetTimingCtrl(Packet):
    name = "ResetTimingCtrl"
    fields_desc = [
        PacketField("reset_data_burst", None, ResetValues),
        PacketField("reset_snr_burst", None, ResetValues),
        PacketField("reset_rng_burst", None, ResetValues),
        PacketField("single_reset", None, ResetValues),
        PacketField("double_reset", None, DoubleResetValues),
    ]

    def extract_padding(self, p):
        return "", p


class PreambleParams(Packet):
    name = "PreambleParams"
    fields_desc = [
        ByteField("correlation_preamble_length", None),
        ByteField("preamble_length_snr_rng", None),
        ByteField("guard_time_data_mode", None),
        ByteField("type1_size_data", None),
        ByteField("type2_size_data", None),
        ByteField("type3_size_data", None),
        ByteField("type3_pattern", None),
        ByteField("delimiter_size", None),
        ByteField("delimiter_byte1", None),
        ByteField("delimiter_byte2", None),
        ByteField("delimiter_byte3", None)
    ]

    def extract_padding(self, p):
        return "", p


class PAS5211MsgSetOltOptics(PAS5211Msg):
    opcode = 106
    name = "PAS5211MsgSetOltOptics"
    fields_desc = [
        PacketField("burst_timing_ctrl", None, BurstTimingCtrl),
        PacketField("general_optics_params", None, GeneralOpticsParams),
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        PacketField("reset_timing_ctrl", None, ResetTimingCtrl),
        ByteField("voltage_if_mode", None),
        PacketField("preamble_params", None, PreambleParams),
        ByteField("reserved4", 0),
        ByteField("reserved5", 0),
        ByteField("reserved6", 0)
    ]


class PAS5211MsgSetOltOpticsResponse(PAS5211Msg):
    name = "PAS5211MsgSetOltOpticsResponse"
    fields_desc = []


class PAS5211MsgSetOpticsIoControl(PAS5211Msg):
    opcode = 108
    name = "PAS5211MsgSetOpticsIoControl"
    fields_desc = [
        ByteField("i2c_clk", None),
        ByteField("i2c_data", None),
        ByteField("tx_enable", None),
        ByteField("tx_fault", None),
        ByteField("tx_enable_polarity", None),
        ByteField("tx_fault_polarity", None),
    ]


class PAS5211MsgSetOpticsIoControlResponse(PAS5211Msg):
    name = "PAS5211MsgSetOpticsIoControlResponse"
    fields_desc = []

    def extract_padding(self, p):
        return "", p


class PAS5211MsgStartDbaAlgorithm(PAS5211Msg):
    opcode = 55
    name = "PAS5211MsgStartDbaAlgorithm"
    fields_desc = [
        LEShortField("size", 0),
        ByteField("initialization_data", None)
    ]


class PAS5211MsgStartDbaAlgorithmResponse(PAS5211Msg):
    name = "PAS5211MsgStartDbaAlgorithmResponse"
    opcode = 10295
    fields_desc = []


class PAS5211MsgSetGeneralParam(PAS5211Msg):
    opcode = 164
    name = "PAS5211MsgSetGeneralParam"
    fields_desc = [
        LEIntField("parameter", None),
        LEIntField("reserved", 0),
        LEIntField("value", None)
    ]


class PAS5211MsgSetGeneralParamResponse(PAS5211Msg):
    name = "PAS5211MsgSetGeneralParamResponse"
    fields_desc = []


class PAS5211MsgGetGeneralParam(PAS5211Msg):
    opcode = 165
    name = "PAS5211MsgGetGeneralParam"
    fields_desc = [
        LEIntField("parameter", None),
        LEIntField("reserved", 0),
    ]


class PAS5211MsgGetGeneralParamResponse(PAS5211Msg):
    name = "PAS5211MsgGetGeneralParamResponse"
    fields_desc = [
        LEIntField("parameter", None),
        LEIntField("reserved", 0),
        LEIntField("value", None)
    ]


class PAS5211MsgGetDbaMode(PAS5211Msg):
    opcode = 57
    name = "PAS5211MsgGetDbaMode"
    fields_desc = []


class PAS5211MsgGetDbaModeResponse(PAS5211Msg):
    name = "PAS5211MsgGetDbaModeResponse"
    fields_desc = [
        LEIntField("dba_mode", None),
    ]


class PAS5211MsgAddOltChannel(PAS5211Msg):
    opcode = 4
    name = "PAS5211MsgAddOltChannel"
    fields_desc = [

    ]


class PAS5211MsgAddOltChannelResponse(PAS5211Msg):
    name = "PAS5211MsgAddOltChannelResponse"
    fields_desc = [

    ]


class PAS5211MsgSetAlarmConfig(PAS5211Msg):
    opcode = 48
    name = "PAS5211MsgSetAlarmConfig"
    fields_desc = [
        LEShortField("type", None),
        LEShortField("activate", None),
        LEIntField("parameter1", None),
        LEIntField("parameter2", None),
        LEIntField("parameter3", None),
        LEIntField("parameter4", None)
    ]

class PAS5211MsgSetOltChannelActivationPeriod(PAS5211Msg):
    opcode = 11
    name = "PAS5211MsgSetOltChannelActivationPeriod"
    fields_desc = [
        LEIntField("activation_period", None)
    ]

class PAS5211MsgSetOltChannelActivationPeriodResponse(PAS5211Msg):
    name = "PAS5211MsgSetOltChannelActivationPeriodResponse"
    fields_desc = []

class PAS5211MsgSetAlarmConfigResponse(PAS5211Msg):
    name = "PAS5211MsgSetAlarmConfigResponse"
    fields_desc = []

class PAS5211MsgSendCliCommand(PAS5211Msg):
    opcode = 15
    name = "PAS5211MsgSendCliCommand"
    fields_desc = [
        FieldLenField("size", None, fmt="<H", length_of="command"),
        StrField("command", "")
    ]

class PAS5211MsgSwitchToInboundMode(PAS5211Msg):
    opcode = 0xec
    name = "PAS5211MsgSwitchToInboundMode"
    fields_desc = [
        MACField("mac", None),
        LEShortField("mode", 0)
    ]

class PAS5211MsgGetActivationAuthMode(PAS5211Msg):
    opcode = 145
    name = "PAS5211MsgGetActivationAuthMode"
    fields_desc = [
        LEShortField("nothing", 0)  # no idea why this is here
    ]


class PAS5211MsgGetActivationAuthModeResponse(PAS5211Msg):
    opcode = 10385
    name = "PAS5211MsgGetActivationAuthModeResponse"
    fields_desc = [
        LEShortField("mode", 0),
        LEShortField("reserved", 0),
    ]


class PAS5211MsgSetOnuOmciPortId(PAS5211Msg):
    opcode = 41
    name = "PAS5211MsgSetOnuOmciPortId"
    fields_desc = [
        LEShortField("port_id", 0),
        LEShortField("activate", PON_ENABLE)
    ]

class PAS5211MsgSetOnuOmciPortIdResponse(PAS5211Msg):
    opcode = 10281
    name = "PAS5211MsgSetOnuOmciPortIdResponse"
    fields_desc = []


class PAS5211MsgGetLogicalObjectStatus(PAS5211Msg):
    opcode = 223
    name = "PAS5211MsgGetLogicalObjectStatus"
    fields_desc = [
        LEIntField("type", None),
        LEIntField("value", None)
    ]

class PAS5211MsgGetLogicalObjectStatusResponse(PAS5211Msg):
    opcode = 10463
    name = "PAS5211MsgGetLogicalObjectStatusResponse"
    fields_desc = [
        LEIntField("type", None),
        LEIntField("value", None),
        FieldLenField("return_length", None, fmt="<H", length_of="return_value"),
        LEIntField("return_value", "")
    ]

class PAS5211MsgSetOnuAllocId(PAS5211Msg):
    opcode = 8
    name = "PAS5211MsgSetOnuAllocId"
    fields_desc = [
        LEShortField("alloc_id", None),
        LEShortField("allocate", None)
    ]

class PAS5211MsgSetOnuAllocIdResponse(PAS5211Msg):
    opcode = 10248
    name = "PAS5211MsgSetOnuAllocIdResponse"
    fields_desc = []

class PAS5211MsgSendDbaAlgorithmMsg(PAS5211Msg):
    opcode = 47
    name = "PAS5211MsgSendDbaAlgorithmMsg"
    fields_desc = [
        # LEShortField("id", None),
        FieldLenField("size", None, fmt="<H", length_of="data"),
        StrLenField("data", "", length_from=lambda x: x.size)
    ]

class PAS5211MsgSendDbaAlgorithmMsgResponse(PAS5211Msg):
    opcode = 10287
    name = "PAS5211MsgSendDbaAlgorithmMsgResponse"
    fields_desc = []

class PAS5211MsgSetPortIdConfig(PAS5211Msg):
    opcode = 18
    name = "PAS5211MsgSetPortIdConfig"
    fields_desc = [
        LEShortField("port_id", None),
        LEShortField("activate", PON_ENABLE),
        LEShortField("alloc_id", None),
        LEIntField("type", None),
        LEIntField("destination", None),  # Is this the CNI port
        # if yes then values are 0-11 (for ruby)
        LEShortField("reserved", None)
    ]

class PAS5211MsgSetPortIdConfigResponse(PAS5211Msg):
    opcode = 10258
    name = "PAS5211MsgSetPortIdConfigResponse"
    fields_desc = []

class PAS5211MsgGetOnuIdByPortId(PAS5211Msg):
    opcode = 196
    name = "PAS5211MsgGetOnuIdByPortId"
    fields_desc = [
        LEShortField("port_id", None),
        LEShortField("reserved", 0)
    ]

class PAS5211MsgGetOnuIdByPortIdResponse(PAS5211Msg):
    opcode = 196
    name = "PAS5211MsgGetOnuIdByPortIdResponse"
    fields_desc = [
        LEShortField("valid", None),
        LEShortField("onu_id", None)
    ]

class PAS5211SetVlanUplinkConfiguration(PAS5211Msg):
    opcode = 39
    name = "PAS5211SetVlanUplinkConfiguration"
    fields_desc = [
        LEShortField("port_id", None),
        LEShortField("pvid_config_enabled", None),
        LEShortField("min_cos", None),
        LEShortField("max_cos", None),
        LEIntField("de_bit", None),
        LEShortField("reserved", 0)
    ]

class PAS5211SetVlanUplinkConfigurationResponse(PAS5211Msg):
    opcode = 10279
    name = "PAS5211SetVlanUplinkConfigurationResponse"
    fields_desc = []

class PAS5211GetOnuAllocs(PAS5211Msg):
    opcode = 9
    name = "PAS5211GetOnuAllocs"
    fields_desc = [
        LEShortField("nothing", None)  # It's in the PMC code... so yeah.
    ]

class PAS5211GetOnuAllocsResponse(PAS5211Msg):
    opcode = 9
    name = "PAS5211GetOnuAllocsResponse"
    fields_desc = [
        LEShortField("allocs_number", None),
        FieldListField("alloc_ids", None, LEShortField("alloc_id", None))
    ]

class PAS5211GetSnInfo(PAS5211Msg):
    opcode = 7
    name = "PAS5211GetSnInfo"
    fields_desc = [
        StrFixedLenField("serial_number", None, 8)
    ]

class PAS5211GetSnInfoResponse(PAS5211Msg):
    opcode = 7
    name = "PAS5211GetSnInfoResponse"
    fields_desc = [
        StrFixedLenField("serial_number", None, 8),
        LEShortField("found", None),
        LEShortField("type", None),
        LEShortField("onu_state", None),
        LELongField("equalization_delay", None),
        LEShortField("reserved", None)
    ]

class PAS5211GetOnusRange(PAS5211Msg):
    opcode = 116
    name = "PAS5211GetOnusRange"
    fields_desc = [
        LEShortField("nothing", None)
    ]

class PAS5211GetOnusRangeResponse(PAS5211Msg):
    opcode = 116
    name = "PAS5211GetOnusRangeResponse"
    fields_desc = [
        LEIntField("min_distance", None),
        LEIntField("max_distance", None),
        LEIntField("actual_min_distance", None),
        LEIntField("actual_max_distance", None)
    ]

class PAS5211GetPortIdConfig(PAS5211Msg):
    opcode = 19
    name = "PAS5211GetPortIdConfig"
    fields_desc = [
        LEShortField("port_id", None),
        LEShortField("reserved", None)
    ]

class PAS5211GetPortIdConfigResponse(PAS5211Msg):
    opcode = 19
    name = "PAS5211GetPortIdConfigResponse"
    fields_desc = [
        LEShortField("activate", None),
        LEShortField("encryption_state", None),
        LEShortField("alloc_id", None),
        LEShortField("type", None),
        LEShortField("destination", None),
        LEShortField("reserved", None),
    ]

class PAS5211SetSVlanAtConfig(PAS5211Msg):
    opcode = 63
    name = "PAS5211SetSVlanAtConfig"
    fields_desc = [
        LEShortField("svlan_id", None),
        LEShortField("forwarding_mode", None),
        LEShortField("use_svlan", None),
        LEShortField("use_cvlan", None),
        LEShortField("use_pbits", None),
        LEShortField("discard_unknown", None),
    ]

class PAS5211SetSVlanAtConfigResponse(PAS5211Msg):
    opcode = 63
    name = "PAS5211SetSVlanAtConfigResponse"
    fields_desc = []


class PAS5211SetUplinkVlanHandl(PAS5211Msg):
    opcode = 34
    name = "PAS5211SetUplinkVlanHandl"
    fields_desc = [
        LEShortField("source_port_id", None),
        LEShortField("primary_vid", None),
        LEShortField("pvid_config_enabled", None),
        LEShortField("svlan_tag_operation", None),
        LEShortField("cvlan_tag_operation", None),
        LEShortField("new_svlan_tag", None),
        LEShortField("new_cvlan_tag", None),
        LEShortField("destination", None)
    ]

class PAS5211SetUplinkVlanHandlResponse(PAS5211Msg):
    opcode = 34
    name = "PAS5211SetUplinkVlanHandlResponse"
    fields_desc = []

class PAS5211SetVlanGenConfig(PAS5211Msg):
    opcode = 43
    name = "PAS5211SetVlanGenConfig"
    fields_desc = [
        LEShortField("direction", None),
        LEShortField("extended_svlan_type", None),
        LEShortField("insertion_svlan_ethertype", None),
        LEShortField("extended_cvlan_type", None),
        LEShortField("insertion_cvlan_ethertype", None),
        LEShortField("pon_pcp_code", None),
        LEShortField("cni_pcp_code", None),
        LEShortField("reserved", None)
    ]

class PAS5211SetVlanGenConfigResponse(PAS5211Msg):
    opcode = 43
    name = "PAS5211SetVlanGenConfigResponse"
    fields_desc = []


class PAS5211SetVlanDownConfig(PAS5211Msg):
    opcode = 32
    name = "PAS5211SetVlanDownConfig"
    fields_desc = [
        LEShortField("svlan_id", None),
        LEShortField("double_tag_handling", None),
        LEShortField("vlan_priority_handling", None)
    ]

class PAS5211SetVlanDownConfigResponse(PAS5211Msg):
    opcode = 32
    name = "PAS5211SetVlanDownConfigResponse"
    fields_desc = []

class PAS5211SetDownVlanHandl(PAS5211Msg):
    opcode = 27
    name = "PAS5211SetDownVlanHandl"
    fields_desc = [
        LEShortField("svlan_tag", None),
        LEShortField("cvlan_tag", None),
        LEShortField("double_tag_handling", None),
        LEShortField("priority_handling", None),
        LEShortField("input_priority", None),
        LEShortField("svlan_tag_operation", None),
        LEShortField("cvlan_tag_operation", None),
        LEShortField("port_id", None),
        LEShortField("new_cvlan_tag", None),
        LEShortField("destination", None),
        LEShortField("output_vlan_prio_handle", None),
        LEShortField("output_priority", None)
    ]

class PAS5211SetDownVlanHandlResponse(PAS5211Msg):
    opcode = 27
    name = "PAS5211SetDownVlanHandlResponse"
    fields_desc = []

class Frame(Packet):
    pass

class PAS5211MsgSendFrame(PAS5211Msg):
    opcode = 42
    name = "PAS5211MsgSendFrame"
    fields_desc = [
        FieldLenField("length", None, fmt="<H", length_of="frame"),
        LEShortField("port_type", PON_PORT_PON),
        LEShortField("port_id", 0),
        LEShortField("management_frame", PON_FALSE),
        ConditionalField(PacketField("frame", None, Packet), lambda pkt: pkt.management_frame == PON_FALSE),
        ConditionalField(PacketField("frame", None, OmciFrame), lambda pkt: pkt.management_frame == PON_TRUE)
    ]

    def extract_padding(self, p):
        return "", p

class PAS5211MsgSendFrameResponse(PAS5211Msg):
    name = "PAS5211MsgSendFrameResponse"
    fields_desc = []

class PAS5211Event(PAS5211Msg):
    opcode = 12

class PAS5211EventFrameReceived(PAS5211Event):
    name = "PAS5211EventFrameReceived"
    fields_desc = [
        FieldLenField("length", None, length_of="frame", fmt="<H"),
        LEShortField("port_type", PON_PORT_PON),
        LEShortField("port_id", 0),
        LEShortField("management_frame", PON_FALSE),
        LEShortField("classification_entity", None),
        LEShortField("l3_offset", None),
        LEShortField("l4_offset", None),
        LEShortField("ignored", 0),  # TODO these do receive values, but there is no code in PMC using it
        ConditionalField(PacketField("frame", None, Packet), lambda pkt: pkt.management_frame == PON_FALSE),
        ConditionalField(PacketField("frame", None, OmciFrame), lambda pkt: pkt.management_frame == PON_TRUE)
    ]

class PAS5211EventDbaAlgorithm(PAS5211Event):
    name = "PAS5211EventDbaAlgorithm"
    fields_desc = [
        FieldLenField("size", None, fmt="<H", length_of="data"),
        StrLenField("data", "", length_from=lambda x: x.size)
    ]

class PAS5211EventOnuActivation(PAS5211Event):
    name = "PAS5211EventOnuActivation"
    event_type = 1
    fields_desc = [
        StrFixedLenField("serial_number", None, length=8),
        LEIntField("equalization_period", None)
    ]

class PAS5211EventOnuDeactivation(PAS5211Event):
    name = "PAS5211EventOnuDeactivation"
    event_type = 2
    fields_desc = [
        LEShortField("code", None)
    ]

class PAS5211EventLogMsg(PAS5211Event):
    name = "PAS5211EventLogMsg"
    event_type = 3
    fields_desc = []

class PAS5211EventFWGeneralPrint(PAS5211Event):
    name = "PAS5211EventFWGeneralPrint"
    event_type = 4
    fields_desc = []

class PAS5211EventFWTracePrint(PAS5211Event):
    name = "PAS5211EventFWTracePrint"
    event_type = 5
    fields_desc = []

class PAS5211EventStartEncryption(PAS5211Event):
    name = "PAS5211EventStartEncryption"
    event_type = 6
    fields_desc = []

class PAS5211EventStopEncryption(PAS5211Event):
    name = "PAS5211EventStopEncryption"
    event_type = 7
    fields_desc = []

class PAS5211EventUpdateEncryption(PAS5211Event):
    name = "PAS5211EventUpdateEncryption"
    event_type = 8
    fields_desc = []

class PAS5211EventAlarmNotification(PAS5211Event):
    name = "PAS5211EventAlarmNotification"
    event_type = 9
    fields_desc = [
        LEShortField("code", None),
        LEIntField("parameter1", None),
        LEIntField("parameter2", None),
        LEIntField("parameter3", None),
        LEIntField("parameter4", None)
    ]

class PAS5211EventDBAAlgorithmEvent(PAS5211Event):
    name = "PAS5211EventDBAAlgorithmEvent"
    event_type = 11
    fields_desc = []

class PAS5211EventOLTReset(PAS5211Event):
    name = "PAS5211EventOLTReset"
    event_type = 12
    fields_desc = []

class PAS5211EventOnuSleepMode(PAS5211Event):
    name = "PAS5211EventOnuSleepMode"
    event_type = 13
    fields_desc = []

class PAS5211EventAssignAllocId(PAS5211Event):
    name = "PAS5211EventAssignAllocId"
    event_type = 14
    fields_desc = []

class PAS5211EventConfigOMCIPort(PAS5211Event):
    name = "PAS5211EventConfigOMCIPort"
    event_type = 15
    fields_desc = []

class PAS5211EventPloamMessageReceived(PAS5211Event):
    name = "PAS5211EventPloamMessageReceived"
    event_type = 17
    fields_desc = []

class PAS5211EventLoadOLTBinaryCompleted(PAS5211Event):
    name = "PAS5211EventLoadOLTBinaryCompleted"
    event_type = 18
    fields_desc = []

class PAS5211EventMasterOLTFail(PAS5211Event):
    name = "PAS5211EventMasterOLTFail"
    event_type = 19
    fields_desc = []

class PAS5211EventRedundantSwitchOverStatus(PAS5211Event):
    name = "PAS5211EventRedundantSwitchOverStatus"
    event_type = 20
    fields_desc = []

class PAS5211EventSyncOLTData(PAS5211Event):
    name = "PAS5211EventSyncOLTData"
    event_type = 21
    fields_desc = []

class PAS5211EventEQDChange(PAS5211Event):
    name = "PAS5211EventEQDChange"
    event_type = 22
    fields_desc = []

class PAS5211EventXAUIStatusNotification(PAS5211Event):
    name = "PAS5211EventXAUIStatusNotification"
    event_type = 23
    fields_desc = []

class PAS5211EventUnauthenticatedONU(PAS5211Event):
    name = "PAS5211EventUnauthenticatedONU"
    event_type = 24
    fields_desc = []

class PAS5211EventFalseQFullReported(PAS5211Event):
    name = "PAS5211EventFalseQFullReported"
    event_type = 25
    fields_desc = []

class PAS5211EventOpticalModuleIndication(PAS5211Event):
    name = "PAS5211EventOpticalModuleIndication"
    event_type = 27
    fields_desc = []

class PAS5211EventActivationFailure(PAS5211Event):
    name = "PAS5211EventActivationFailure"
    event_type = 28
    fields_desc = []

class PAS5211EventBipError(PAS5211Event):
    name = "PAS5211EventBipError"
    event_type = 29
    fields_desc = []

class PAS5211EventREIError(PAS5211Event):
    name = "PAS5211EventREIError"
    event_type = 30
    fields_desc = []

class PAS5211EventRDNMultiONUFailure(PAS5211Event):
    name = "PAS5211EventRDNMultiONUFailure"
    event_type = 31
    fields_desc = []

class PAS5211EventUnexpectedSN(PAS5211Event):
    name = "PAS5211EventUnexpectedSN"
    event_type = 32
    fields_desc = []

class PAS5211EventRDNSwitchOverONUResult(PAS5211Event):
    name = "PAS5211EventRDNSwitchOverONUResult"
    event_type = 33
    fields_desc = []

class PAS5211EventGMacMalfucntionSuspected(PAS5211Event):
    name = "PAS5211EventGMacMalfucntionSuspected"
    event_type = 34
    fields_desc = []


class PAS5211GetPortIdDownstreamPolicingConfig(PAS5211Msg):
    opcode = 82
    name = "PAS5211GetPortIdDownstreamPolicingConfig"
    fields_desc = [
        LEShortField("port_id", None),
        LEShortField("reserved", None)]

class PAS5211GetPortIdDownstreamPolicingConfigResponse(PAS5211Msg):
    opcode = 82
    name = "PAS5211GetPortIdDownstreamPolicingConfigResponse"
    fields_desc = [
        LEIntField("committed_bandwidth", None),
        LEIntField("excessive_bandwidth", None),
        LEShortField("committed_burst_limit", None),
        LEShortField("excessive_burst_limit", None),
        LEShortField("ds_policing_config_id", None),
        LEShortField("reserved", None)]

class PAS5211RemoveDownstreamPolicingConfig(PAS5211Msg):
    opcode = 76
    name = "PAS5211RemoveDownstreamPolicingConfig"
    fields_desc = [
        LEShortField("policing_config_id", None),
        LEShortField("reserved", None)]

class PAS5211RemoveDownstreamPolicingConfigResponse(PAS5211Msg):
    opcode = 76
    name = "PAS5211RemoveDownstreamPolicingConfigResponse"
    fields_desc = []

class PAS5211SetPortIdPolicingConfig(PAS5211Msg):
    opcode = 80
    name = "PAS5211SetPortIdPolicingConfig"
    fields_desc = [
        LEShortField("direction", None),
        LEShortField("port_id", None),
        LEShortField("policing_config_id", None),
        LEShortField("reserved", None)]

class PAS5211SetPortIdPolicingConfigResponse(PAS5211Msg):
    opcode = 80
    name = "PAS5211SetPortIdPolicingConfigResponse"
    fields_desc = []

class PAS5211UnsetPortIdPolicingConfig(PAS5211Msg):
    opcode = 81
    name = "PAS5211UnsetSetPortIdPolicingConfig"
    fields_desc = [
        LEShortField("direction", None),
        LEShortField("port_id", None)]

class PAS5211UnsetPortIdPolicingConfigResponse(PAS5211Msg):
    opcode = 81
    name = "PAS5211UnsetSetPortIdPolicingConfigResponse"
    fields_desc = []

class PAS5211SetDownstreamPolicingConfig(PAS5211Msg):
    opcode = 74
    name = "PAS5211SetDownstreamPolicingConfig"
    fields_desc = [
        LEIntField("committed_bandwidth", None),
        LEIntField("excessive_bandwidth", None),
        LEShortField("committed_burst_limit", None),
        LEShortField("excessive_burst_limit", None)]

class PAS5211SetDownstreamPolicingConfigResponse(PAS5211Msg):
    opcode = 74
    name = "PAS5211SetDownstreamPolicingConfigResponse"
    fields_desc = [
        LEShortField("policing_config_id", None),
        LEShortField("reserved", None)]

class PAS5211SetUpstreamPolicingConfig(PAS5211Msg):
    opcode = 77
    name = "PAS5211SetUpstreamPolicingConfig"
    fields_desc = [
        LEIntField("bandwidth", None),
        LEShortField("burst_limit", None),
        LEShortField("reserved", None)]

class PAS5211SetUpstreamPolicingConfigResponse(PAS5211Msg):
    opcode = 77
    name = "PAS5211SetDownstreamPolicingResponse"
    fields_desc = [
        LEShortField("policing_config_id", None),
        LEShortField("reserved", None)]

class PAS5211Dot3(Packet):
    name = "PAS5211Dot3"
    fields_desc = [DestMACField("dst"),
                   MACField("src", ETHER_ANY),
                   LenField("len", None, "H")]

    MIN_FRAME_SIZE = 60

    def post_build(self, pkt, payload):
        pkt += payload
        size = ord(payload[4]) + (ord(payload[5]) << 8)
        length = size + 6  # this is a idiosyncracy of the PASCOMM protocol
        pkt = pkt[:12] + chr(length >> 8) + chr(length & 0xff) + pkt[14:]
        padding = self.MIN_FRAME_SIZE - len(pkt)
        if padding > 0:
            pkt = pkt + ("\x00" * padding)
        return pkt

'''
This is needed in order to force scapy to use PAS5211Dot3
instead of the default Dot3 that the Ether class uses.
'''

@classmethod
def PAS_dispatch_hook(cls, _pkt=None, *args, **kargs):
    if _pkt and len(_pkt) >= 14:
        if struct.unpack("!H", _pkt[12:14])[0] <= 1500:
            return PAS5211Dot3
    return cls

Ether.dispatch_hook = PAS_dispatch_hook

# bindings for messages received
# fix for v2 of Microsemi OLT.
bind_layers(Ether, PAS5211FrameHeader, type=0x0a00)

bind_layers(PAS5211Dot3, PAS5211FrameHeader)
bind_layers(PAS5211FrameHeader, PAS5211MsgHeader)

bind_layers(PAS5211MsgHeader, PAS5211MsgGetProtocolVersion, opcode=0x3000 | 2)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetProtocolVersionResponse, opcode=0x2800 | 2)

bind_layers(PAS5211MsgHeader, PAS5211MsgGetOltVersion, opcode=0x3000 | 3)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetOltVersionResponse, opcode=0x3800 | 3)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetOltOptics, opcode=0x3000 | 106)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetOltOpticsResponse, opcode=0x2800 | 106)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetOpticsIoControl, opcode=0x3000 | 108)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetOpticsIoControlResponse, opcode=0x2800 | 108)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetGeneralParam, opcode=0x3000 | 164)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetGeneralParamResponse, opcode=0x2800 | 164)

bind_layers(PAS5211MsgHeader, PAS5211MsgGetGeneralParam, opcode=0x3000 | 165)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetGeneralParamResponse, opcode=0x2800 | 165)

bind_layers(PAS5211MsgHeader, PAS5211MsgAddOltChannel, opcode=0x3000 | 4)
bind_layers(PAS5211MsgHeader, PAS5211MsgAddOltChannelResponse, opcode=0x2800 | 4)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetAlarmConfig, opcode=0x3000 | 48)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetAlarmConfigResponse, opcode=0x2800 | 48)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetOltChannelActivationPeriod, opcode=0x3000 | 11)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetOltChannelActivationPeriodResponse, opcode=0x2800 | 11)

bind_layers(PAS5211MsgHeader, PAS5211MsgStartDbaAlgorithm, opcode=0x3000 | 55)
bind_layers(PAS5211MsgHeader, PAS5211MsgStartDbaAlgorithmResponse, opcode=0x2800 | 55)

bind_layers(PAS5211MsgHeader, PAS5211MsgGetDbaMode, opcode=0x3000 | 57)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetDbaModeResponse, opcode=0x2800 | 57)

bind_layers(PAS5211MsgHeader, PAS5211MsgSendFrame, opcode=0x3000 | 42)
bind_layers(PAS5211MsgHeader, PAS5211MsgSendFrameResponse, opcode=0x2800 | 42)

bind_layers(PAS5211MsgHeader, PAS5211MsgGetActivationAuthMode, opcode=0x3000 | 145)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetActivationAuthModeResponse, opcode=0x2800 | 145)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetOnuOmciPortId, opcode=0x3000 | 41)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetOnuOmciPortIdResponse, opcode=0x2800 | 41)

bind_layers(PAS5211MsgHeader, PAS5211MsgGetLogicalObjectStatus, opcode=0x3000 | 223)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetLogicalObjectStatusResponse, opcode=0x2800 | 223)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetOnuAllocId, opcode=0x3000 | 8)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetOnuAllocIdResponse, opcode=0x2800 | 8)

bind_layers(PAS5211MsgHeader, PAS5211MsgSendDbaAlgorithmMsg, opcode=0x3000 | 47)
bind_layers(PAS5211MsgHeader, PAS5211MsgSendDbaAlgorithmMsgResponse, opcode=0x2800 | 47)

bind_layers(PAS5211MsgHeader, PAS5211MsgSetPortIdConfig, opcode=0x3000 | 18)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetPortIdConfigResponse, opcode=0x2800 | 18)

bind_layers(PAS5211MsgHeader, PAS5211MsgGetOnuIdByPortId, opcode=0x3000 | 196)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetOnuIdByPortIdResponse, opcode=0x2800 | 196)

bind_layers(PAS5211MsgHeader, PAS5211SetVlanUplinkConfiguration, opcode=0x3000 | 39)
bind_layers(PAS5211MsgHeader, PAS5211SetVlanUplinkConfigurationResponse, opcode=0x2800 | 39)

bind_layers(PAS5211MsgHeader, PAS5211GetOnuAllocs, opcode=0x3000 | 9)
bind_layers(PAS5211MsgHeader, PAS5211GetOnuAllocsResponse, opcode=0x2800 | 9)

bind_layers(PAS5211MsgHeader, PAS5211GetSnInfo, opcode=0x3000 | 7)
bind_layers(PAS5211MsgHeader, PAS5211GetSnInfoResponse, opcode=0x2800 | 7)

bind_layers(PAS5211MsgHeader, PAS5211GetOnusRange, opcode=0x3000 | 116)
bind_layers(PAS5211MsgHeader, PAS5211GetOnusRangeResponse, opcode=0x2800 | 116)

bind_layers(PAS5211MsgHeader, PAS5211GetPortIdConfig, opcode=0x3000 | 19)
bind_layers(PAS5211MsgHeader, PAS5211GetPortIdConfigResponse, opcode=0x2800 | 19)

bind_layers(PAS5211MsgHeader, PAS5211SetSVlanAtConfig, opcode=0x3000 | 63)
bind_layers(PAS5211MsgHeader, PAS5211SetSVlanAtConfigResponse, opcode=0x2800 | 63)

bind_layers(PAS5211MsgHeader, PAS5211SetUplinkVlanHandl, opcode=0x3000 | 34)
bind_layers(PAS5211MsgHeader, PAS5211SetUplinkVlanHandlResponse, opcode=0x2800 | 34)

bind_layers(PAS5211MsgHeader, PAS5211SetVlanGenConfig, opcode=0x3000 | 43)
bind_layers(PAS5211MsgHeader, PAS5211SetVlanGenConfigResponse, opcode=0x2800 | 43)

bind_layers(PAS5211MsgHeader, PAS5211SetVlanDownConfig, opcode=0x3000 | 32)
bind_layers(PAS5211MsgHeader, PAS5211SetVlanDownConfigResponse, opcode=0x2800 | 32)

bind_layers(PAS5211MsgHeader, PAS5211SetDownVlanHandl, opcode=0x3000 | 27)
bind_layers(PAS5211MsgHeader, PAS5211SetDownVlanHandlResponse, opcode=0x2800 | 27)

bind_layers(PAS5211MsgHeader, PAS5211SetDownstreamPolicingConfig, opcode=0x3000 | 74)
bind_layers(PAS5211MsgHeader, PAS5211SetDownstreamPolicingConfigResponse, opcode=0x2800 | 74)

bind_layers(PAS5211MsgHeader, PAS5211SetUpstreamPolicingConfig, opcode=0x3000 | 77)
bind_layers(PAS5211MsgHeader, PAS5211SetUpstreamPolicingConfigResponse, opcode=0x2800 | 77)

bind_layers(PAS5211MsgHeader, PAS5211SetPortIdPolicingConfig, opcode=0x3000 | 80)
bind_layers(PAS5211MsgHeader, PAS5211SetPortIdPolicingConfigResponse, opcode=0x2800 | 80)

bind_layers(PAS5211MsgHeader, PAS5211UnsetPortIdPolicingConfig, opcode=0x3000 | 81)
bind_layers(PAS5211MsgHeader, PAS5211UnsetPortIdPolicingConfigResponse, opcode=0x2800 | 81)

bind_layers(PAS5211MsgHeader, PAS5211GetPortIdDownstreamPolicingConfig, opcode=0x3000 | 82)
bind_layers(PAS5211MsgHeader, PAS5211GetPortIdDownstreamPolicingConfigResponse, opcode=0x2800 | 82)

bind_layers(PAS5211MsgHeader, PAS5211RemoveDownstreamPolicingConfig, opcode=0x3000 | 76)
bind_layers(PAS5211MsgHeader, PAS5211RemoveDownstreamPolicingConfigResponse, opcode=0x2800 | 76)


# bindings for events received
bind_layers(PAS5211MsgHeader, PAS5211EventOnuActivation, opcode=0x2800 | 12, event_type=1)
bind_layers(PAS5211MsgHeader, PAS5211EventOnuDeactivation, opcode=0x2800 | 12, event_type=2)
bind_layers(PAS5211MsgHeader, PAS5211EventFrameReceived, opcode=0x2800 | 12, event_type=10)
bind_layers(PAS5211MsgHeader, PAS5211EventDbaAlgorithm, opcode=0x2800 | 12, event_type=11)
bind_layers(PAS5211MsgHeader, PAS5211EventAlarmNotification, opcode=0x2800 | 12, event_type=9)
bind_layers(PAS5211MsgHeader, PAS5211Event, opcode=0x2800 | 12)


class Display(object):
    def __init__(self, pkts):
        self.pkts = pkts

    def show(self, seq):
        self.pkts[seq].show()

    def __getitem__(self, key):
        self.show(key)

    def walk(self, index=0):
        while index < len(self.pkts):
            self.show(index)
            try:
                input("(current packet - %s) Next packet?" % index)
            except Exception as e:
                pass
            index += 1

if __name__ == '__main__':

    from scapy.utils import rdpcap
    import sys
    import code

    packets = rdpcap(sys.argv[1])
    p = Display(packets)

    def walk(index=0, interactive=True, channel=-1):
        if interactive is not True:
            for packet in packets:
                if PAS5211MsgHeader in packet:
                    if PAS5211MsgGetOltVersion not in packet and PAS5211MsgGetOltVersionResponse not in packet:
                        if channel is not -1:
                            if packet[PAS5211MsgHeader].channel_id == channel:
                                packet.show()
                        else:
                            packet.show()
        else:
            p.walk(index=index)

    code.interact(local=locals())
