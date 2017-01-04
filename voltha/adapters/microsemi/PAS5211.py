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
from scapy.fields import LEShortField, Field, LEIntField, LESignedIntField, FieldLenField, FieldListField, PacketField, \
    ByteField, StrFixedLenField, ConditionalField
from scapy.layers.l2 import Dot3, LLC
from scapy.layers.inet import ARP
from scapy.packet import Packet, bind_layers, split_layers
from scapy.utils import lhex
from scapy.volatile import RandSInt
from scapy.layers.ntp import XLEShortField
from voltha.extensions.omci.omci_frame import OmciFrame

"""
PAS5211 Constants
"""
#TODO get range from olt_version message
CHANNELS=range(0,4)

# from enum PON_true_false_t
PON_FALSE = 0
PON_TRUE = 1

# from enum PON_enable_disable_t
PON_DISABLE = 0
PON_ENABLE = 1

# from enym PON_mac_t
PON_MII = 0
PON_GMII = 1
PON_TBI = 2

PON_POLARITY_ACTIVE_LOW = 0
PON_POLARITY_ACTIVE_HIGH = 1

PON_OPTICS_VOLTAGE_IF_UNDEFINED = 0
PON_OPTICS_VOLTAGE_IF_CML = 1
PON_OPTICS_VOLTAGE_IF_LVPECL = 2

PON_SD_SOURCE_LASER_SD = 0
PON_SD_SOURCE_BCDR_LOCK = 1
PON_SD_SOURCE_BCDR_SD = 2

PON_RESET_TYPE_DELAY_BASED = 0
PON_RESET_TYPE_SINGLE_RESET = 1
PON_RESET_TYPE_DOUBLE_RESET = 2

PON_RESET_TYPE_NORMAL_START_BURST_BASED = 0
PON_RESET_TYPE_NORMAL_END_BURST_BASED = 1

#from PON_general_parameters_type_t
PON_COMBINED_LOSI_LOFI = 1000,
PON_TX_ENABLE_DEFAULT = 1001,
PON_FALSE_Q_FULL_EVENT_MODE = 1002,             #Enable or disable False queue full event from DBA
PON_PID_AID_MISMATCH_MIN_SILENCE_PERIOD = 1003, #Set PID_AID_MISMATCH min silence period. 0 - disable, Else - period in secs
PON_ENABLE_CLEAR_ALARM          = 1004,         #Set if FW generate clear alarm. 0 - generate clear alarm, Else - don't generate clear alarm
PON_ASSIGN_ALLOC_ID_PLOAM       = 1005,         #Enable or disabl send assign alloc id ploam. 0 - disable, 1 - enable
PON_BIP_ERR_POLLING_PERIOD_MS   = 1006,         #BIP error polling period, 200 - 65000, 0 - Disabled, Recommended: 5000 (default)
PON_IGNORE_SN_WHEN_ACTIVE		= 1007,         #Ignore SN when decatived 0 - consider SN (deactivate the onu if received same SN when activated (default)	1 - Ignore
PON_ONU_PRE_ASSIGNED_DELAY		= 1008,		    #0xffffffff - Disabled (default). Any other value (0 - 0xfffe) indicates that PA delay is enabled, with the specified delay value and included in the US_OVERHEAD PLOAM.
PON_DS_FRAGMENTATION			= 1009,		    #Enable or disable DS fragmentation, 0 disable, 1 enable
PON_REI_ERRORS_REPORT_ALL		= 1010,		    #Set if fw report rei alarm when errors is 0, 0 disable (default), 1 enable
PON_IGNORE_SFI_DEACTIVATION		= 1011,		    #Set if igonre sfi deactivation, 0 disable (default), 1 enable
PON_OVERRIDE_ALLOCATION_OVERHEAD	= 1012,	   	#Allows to override the allocation overhead set by optic-params configuration. This configuration is only allowed when the the pon channel is disabled.
PON_OPTICS_TIMELINE_OFFSET	= 1013,		        #Optics timeline offset, -128-127, : this parameter is very sensitive and requires coordination with PMC
PON_LAST_GENERAL_PARAMETER		= PON_OPTICS_TIMELINE_OFFSET		   #Last general meter



PON_GPIO_LINE_0 = 0
PON_GPIO_LINE_1 = 1
PON_GPIO_LINE_2 = 2
PON_GPIO_LINE_3 = 3
PON_GPIO_LINE_4 = 4
PON_GPIO_LINE_5 = 5
PON_GPIO_LINE_6 = 6
PON_GPIO_LINE_7 = 7
def PON_EXT_GPIO_LINE(line):
    return line + 8

# from enum PON_alarm_t
PON_ALARM_SOFTWARE_ERROR = 0
PON_ALARM_LOS = 1
PON_ALARM_LOSI = 2
PON_ALARM_DOWI = 3
PON_ALARM_LOFI = 4
PON_ALARM_RDII = 5
PON_ALARM_LOAMI = 6
PON_ALARM_LCDGI = 7
PON_ALARM_LOAI = 8
PON_ALARM_SDI = 9
PON_ALARM_SFI = 10
PON_ALARM_PEE = 11
PON_ALARM_DGI = 12
PON_ALARM_LOKI = 13
PON_ALARM_TIWI = 14
PON_ALARM_TIA = 15
PON_ALARM_VIRTUAL_SCOPE_ONU_LASER_ALWAYS_ON = 16
PON_ALARM_VIRTUAL_SCOPE_ONU_SIGNAL_DEGRADATION = 17
PON_ALARM_VIRTUAL_SCOPE_ONU_EOL = 18
PON_ALARM_VIRTUAL_SCOPE_ONU_EOL_DATABASE_IS_FULL = 19
PON_ALARM_AUTH_FAILED_IN_REGISTRATION_ID_MODE = 20
PON_ALARM_SUFI = 21
PON_ALARM_LAST_ALARM = 22

# from enum PON_general_parameters_type_t
PON_COMBINED_LOSI_LOFI 		            = 1000
PON_TX_ENABLE_DEFAULT 		            = 1001

# Enable or disable False queue full event from DBA
PON_FALSE_Q_FULL_EVENT_MODE             = 1002

# Set PID_AID_MISMATCH min silence period. 0 - disable, Else - period in secs
PON_PID_AID_MISMATCH_MIN_SILENCE_PERIOD = 1003

# Set if FW generate clear alarm. 0 - generate clear alarm, Else - don't
# generate clear alarm
PON_ENABLE_CLEAR_ALARM                  = 1004

# Enable or disabl send assign alloc id ploam. 0 - disable, 1 - enable
PON_ASSIGN_ALLOC_ID_PLOAM               = 1005

# BIP error polling period, 200 - 65000, 0 - Disabled, Recommended: 5000
# (default)
PON_BIP_ERR_POLLING_PERIOD_MS           = 1006

# Ignore SN when decatived 0 - consider SN (deactivate the onu if received
# same SN when activated (default)	1 - Ignore
PON_IGNORE_SN_WHEN_ACTIVE		        = 1007

# 0xffffffff - Disabled (default). Any other value (0 - 0xfffe) indicates
# that PA delay is enabled, with the specified delay value and included in
# the US_OVERHEAD PLOAM
PON_ONU_PRE_ASSIGNED_DELAY		        = 1008

# Enable or disable DS fragmentation, 0 disable, 1 enable
PON_DS_FRAGMENTATION			        = 1009

# Set if fw report rei alarm when errors is 0, 0 disable (default), 1 enable
PON_REI_ERRORS_REPORT_ALL		        = 1010

# Set if igonre sfi deactivation, 0 disable (default), 1 enable
PON_IGNORE_SFI_DEACTIVATION		        = 1011

# Allows to override the allocation overhead set by optic-params
# configuration. This configuration is only allowed when the the pon channel
# is disabled
PON_OVERRIDE_ALLOCATION_OVERHEAD	    = 1012

# Optics timeline offset, -128-127, : this parameter is very sensitive and
# requires coordination with PMC
PON_OPTICS_TIMELINE_OFFSET	            = 1013

# Last general meter
PON_LAST_GENERAL_PARAMETER		        = PON_OPTICS_TIMELINE_OFFSET

# from enum PON_dba_mode_t
PON_DBA_MODE_NOT_LOADED                 = 0
PON_DBA_MODE_LOADED_NOT_RUNNING         = 1
PON_DBA_MODE_RUNNING                    = 2
PON_DBA_MODE_LAST                       = 3

# from enum type typedef enum PON_port_frame_destination_t
PON_PORT_PON = 0
PON_PORT_SYSTEM = 1

# from enum PON_olt_hw_classification_t

PON_OLT_HW_CLASSIFICATION_PAUSE                    = 0
PON_OLT_HW_CLASSIFICATION_LINK_CONSTRAINT          = 1
PON_OLT_HW_CLASSIFICATION_IGMP                     = 2
PON_OLT_HW_CLASSIFICATION_MPCP                     = 3
PON_OLT_HW_CLASSIFICATION_OAM                      = 4
PON_OLT_HW_CLASSIFICATION_802_1X                   = 5
PON_OLT_HW_CLASSIFICATION_PPPOE_DISCOVERY          = 6
PON_OLT_HW_CLASSIFICATION_PPPOE_SESSION            = 7
PON_OLT_HW_CLASSIFICATION_DHCP_V4                  = 8
PON_OLT_HW_CLASSIFICATION_PIM                      = 9
PON_OLT_HW_CLASSIFICATION_DHCP_V6                  = 10
PON_OLT_HW_CLASSIFICATION_ICMP_V4                  = 11
PON_OLT_HW_CLASSIFICATION_MLD                      = 12
PON_OLT_HW_CLASSIFICATION_ARP                      = 13
PON_OLT_HW_CLASSIFICATION_CONF_DA                  = 14
PON_OLT_HW_CLASSIFICATION_CONF_RULE                = 15
PON_OLT_HW_CLASSIFICATION_DA_EQ_SA                 = 16
PON_OLT_HW_CLASSIFICATION_DA_EQ_MAC                = 17
PON_OLT_HW_CLASSIFICATION_DA_EQ_SEC_MAC            = 18
PON_OLT_HW_CLASSIFICATION_SA_EQ_MAC                = 19
PON_OLT_HW_CLASSIFICATION_SA_EQ_SEC_MAC            = 20
PON_OLT_HW_CLASSIFICATION_ETHERNET_MANAGEMENT      = 100
PON_OLT_HW_CLASSIFICATION_IPV4_LOCAL_MULTICAST     = 101
PON_OLT_HW_CLASSIFICATION_IPV4_MANAGEMENT          = 102
PON_OLT_HW_CLASSIFICATION_ALL_IPV4_MULTICAST       = 103
PON_OLT_HW_CLASSIFICATION_IPV6_LOCAL_MULTICAST     = 104
PON_OLT_HW_CLASSIFICATION_IPV6_MANAGEMENT          = 105
PON_OLT_HW_CLASSIFICATION_ALL_IPV6_MULTICAST       = 106
PON_OLT_HW_CLASSIFICATION_OTHER			           = 107
PON_OLT_HW_CLASSIFICATION_LAST_RULE                = 108

# from enum PON_activation_auth_type_t

PON_ACTIVATION_AUTH_AUTO 			  				= 0
PON_ACTIVATION_AUTH_HOST_CONTROLLED_SEPARATE_EVENTS = 1 # Host controlled: Separate events
PON_ACTIVATION_AUTH_HOST_CONTROLLED_LUMPED_SN   	= 2 # Host controlled: Lumped-SN-Response
PON_ACTIVATION_AUTH_REGISTRATION_ID_RAW   			= 3 # Registration-ID Raw
PON_ACTIVATION_AUTH_REGISTRATION_ID_LEARN   		= 4  # Registration-ID Learn

"""
Extra field structs
"""

class LESignedShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<h")

class XLESignedIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<i")
    def randval(self):
        return RandSInt()
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

"""
PAS5211 Message structs
"""

class PAS5211Msg(Packet):
    opcode = "Must be filled by subclass"
    pass

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


class PAS5211MsgGetOltVersion(PAS5211Msg):
    opcode = 3
    name = "PAS5211MsgGetOltVersion"
    fields_desc = [ ]

    def answers(self, other):
        return other.name == "PAS5211MsgGetOltVersionResponse"


class PAS5211MsgGetProtocolVersion(PAS5211Msg):
    opcode = 2
    name = "PAS5211MsgGetProtocolVersion"
    fields_desc = [ ]


class PAS5211MsgGetProtocolVersionResponse(PAS5211Msg):
    name = "PAS5211MsgGetProtocolVersionResponse"
    fields_desc = [
        LEShortField("major_hardware_version", 0),
        LEShortField("minor_hardware_version", 0),
        LEShortField("major_pfi_version", 0),
        LEShortField("minor_pfi_version", 0)
    ]

    def answers(self, other):
        return other.name == 'PAS5211MsgGetProtocolVersion'


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

    # FIXME: find a better way to pair messages together.
    def answers(self, other):
        return other.name == "PAS5211MsgGetOltVersion"


class SnrBurstDelay(Packet):
    name = "SnrBurstDelay"
    fields_desc= [
        LEShortField("timer_delay", None),
        LEShortField("preamble_delay", None),
        LEShortField("delimiter_delay", None),
        LEShortField("burst_delay", None)
    ]

    def extract_padding(self, p):
        return "", p

class RngBurstDelay(Packet):
    name = "SnrBurstDelay"
    fields_desc= [
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
    fields_desc= [
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
    opcode = 10346
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
    opcode = 10348
    name = "PAS5211MsgSetOpticsIoControlResponse"
    fields_desc = [ ]


class PAS5211MsgAddOltChannel(PAS5211Msg):
    opcode = 4
    name = "PAS5211MsgAddOltChannel"
    fields_desc = [

    ]


class PAS5211MsgAddOltChannelResponse(PAS5211Msg):
    opcode = 10244
    name = "PAS5211MsgAddOltChannelResponse"
    fields_desc = [

    ]

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

class PAS5211MsgStartDbaAlgorithm(PAS5211Msg):
    opcode = 55
    name = "PAS5211MsgStartDbaAlgorithm"
    fields_desc = [
        LEShortField("size", 0),
        ByteField("initialization_data", 0)
    ]


class PAS5211MsgStartDbaAlgorithmResponse(PAS5211Msg):
    name = "PAS5211MsgStartDbaAlgorithmResponse"
    opcode = 10295
    fields_desc = []



class PAS5211MsgSetOltChannelActivationPeriod(PAS5211Msg):
    opcode = 11
    name = "PAS5211MsgSetOltChannelActivationPeriod"
    fields_desc = [
        LEIntField("activation_period", None)
    ]


class PAS5211MsgSetOltChannelActivationPeriodResponse(PAS5211Msg):
    opcode = 10251
    name = "PAS5211MsgSetOltChannelActivationPeriodResponse"
    fields_desc = []


class PAS5211MsgSetAlarmConfigResponse(PAS5211Msg):
    opcode = 10288
    name = "PAS5211MsgSetAlarmConfigResponse"
    fields_desc = []

class PAS5211MsgGetDbaMode(PAS5211Msg):
    opcode = 57
    name = "PAS5211MsgGetDbaMode"
    fields_desc = []


class PAS5211MsgGetDbaModeResponse(PAS5211Msg):
    name = "PAS5211MsgGetDbaModeResponse"
    fields_desc = [
        LEIntField("dba_mode", None),
    ]

class PAS5211MsgGetActivationAuthMode(PAS5211Msg):
    opcode = 145
    name = "PAS5211MsgGetActivationAuthMode"
    fields_desc = [
        LEShortField("nothing", 0) # no idea why this is here
    ]

class PAS5211MsgGetActivationAuthModeResponse(PAS5211Msg):
    opcode = 10385
    name = "PAS5211MsgGetActivationAuthMode"
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


class PAS5211Event(PAS5211Msg):
    opcode = 12

class PAS5211EventOnuActivation(PAS5211Event):
    name = "PAS5211EventOnuActivation"
    fields_desc = [
        StrFixedLenField("serial_number", None, length=8),
        LEIntField("equalization_period", None)
    ]

    """
    Frame
    """

class PAS5211MsgSendFrame(PAS5211Msg):
    opcode = 42
    name = "PAS5211MsgSendFrame"
    fields_desc = [
        FieldLenField("length", None, fmt="<H", length_of="frame"),
        LEShortField("port_type", PON_PORT_PON),
        LEShortField("port_id", 0),
        LEShortField("management_frame", PON_FALSE),
        ConditionalField(PacketField("frame", None, Packet), lambda pkt: pkt.management_frame==PON_FALSE),
        ConditionalField(PacketField("frame", None, OmciFrame), lambda pkt: pkt.management_frame==PON_TRUE)
    ]


class PAS5211MsgSendFrameResponse(PAS5211Msg):
    opcode = 10282
    name = "PAS5211MsgSendFrameResponse"
    fields_desc = []


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
        LEShortField("ignored", 0), # TODO these do receive values, but there is no code in PMC using it
        ConditionalField(PacketField("frame", None, Packet), lambda pkt: pkt.management_frame==PON_FALSE),
        ConditionalField(PacketField("frame", None, OmciFrame), lambda pkt: pkt.management_frame==PON_TRUE)
    ]


"""
Bindings used for message processing
"""

split_layers(Dot3, LLC)
bind_layers(Dot3,PAS5211FrameHeader)
bind_layers(PAS5211FrameHeader, PAS5211MsgHeader)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetOltVersionResponse, opcode=0x3800 | 3)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetProtocolVersionResponse, opcode=0x2800 | 2)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetGeneralParamResponse, opcode=0x2800 | 165)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetAlarmConfigResponse, opcode=0x2800 | 48)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetDbaModeResponse, opcode=0x2800 | 57)
bind_layers(PAS5211MsgHeader, PAS5211MsgStartDbaAlgorithmResponse, opcode=0x2800 | 55)
bind_layers(PAS5211MsgHeader, PAS5211MsgSetOltChannelActivationPeriodResponse, opcode=0x2800 | 11)
bind_layers(PAS5211MsgHeader, PAS5211MsgGetActivationAuthModeResponse, opcode=0x2800 | 145)


bind_layers(PAS5211MsgHeader, PAS5211EventOnuActivation, opcode=0x2800 | 12, event_type=1)
bind_layers(PAS5211MsgHeader, PAS5211EventFrameReceived, opcode=0x2800 | 12, event_type=10)
bind_layers(PAS5211MsgHeader, PAS5211Event, opcode=0x2800 | 12)
