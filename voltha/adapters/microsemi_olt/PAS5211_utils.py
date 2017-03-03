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

from voltha.adapters.microsemi_olt.PAS5211 import PAS5211MsgGetGeneralParam, PAS5211MsgSetOpticsIoControl, \
    BurstTimingCtrl, PAS5211MsgSetOltOptics, PAS5211MsgSetAlarmConfig
from voltha.adapters.microsemi_olt.PAS5211_constants import PON_POLARITY_ACTIVE_LOW, \
    PON_POLARITY_ACTIVE_HIGH, PON_ALARM_LOS, \
    PON_ALARM_LOSI, PON_ALARM_DOWI, PON_ALARM_LOFI, PON_ALARM_RDII, PON_ALARM_LOAMI, PON_ALARM_LCDGI, PON_ALARM_LOAI, \
    PON_ALARM_SDI, PON_ALARM_SFI, PON_ALARM_PEE, PON_ALARM_DGI, PON_ALARM_LOKI, PON_ALARM_TIWI, PON_ALARM_TIA
from voltha.adapters.microsemi_olt.PAS5211_hardware import PON_ALARM_CODE_LOS, PON_ALARM_CODE_LOSI, PON_ALARM_CODE_DOWI, \
    PON_ALARM_CODE_LOFI, PON_ALARM_CODE_RDII, PON_ALARM_CODE_LOAMI, PON_ALARM_CODE_LCDGI, PON_ALARM_CODE_LOAI, \
    PON_ALARM_CODE_SDI, PON_ALARM_CODE_SFI, PON_ALARM_CODE_PEE, PON_ALARM_CODE_DGI, PON_ALARM_CODE_LOKI, \
    PON_ALARM_CODE_TIWI, PON_ALARM_CODE_TIA, PON_ALARM_CODE_LAST_ALARM


def general_param(parameter):
    return PAS5211MsgGetGeneralParam(parameter=parameter)


def io_ctrl_optics(i2c_clk, i2c_data, tx_enable, tx_fault,
                   tx_enable_polarity = PON_POLARITY_ACTIVE_LOW,
                   tx_fault_polarity= PON_POLARITY_ACTIVE_HIGH):
    channel_optic_ctrl_if = PAS5211MsgSetOpticsIoControl()

    channel_optic_ctrl_if.i2c_clk = i2c_clk
    channel_optic_ctrl_if.i2c_data = i2c_data
    channel_optic_ctrl_if.tx_enable = tx_enable
    channel_optic_ctrl_if.tx_fault = tx_fault
    channel_optic_ctrl_if.tx_enable_polarity = tx_enable_polarity
    channel_optic_ctrl_if.tx_fault_polarity = tx_fault_polarity

    return channel_optic_ctrl_if


def burst_timing(single, double, snr_burst=None, rng_burst=None):
    return BurstTimingCtrl(snr_burst_delay=snr_burst, rng_burst_delay=rng_burst,
                           burst_delay_single=single, burst_delay_double=double)


def olt_optics_pkt(voltage, burst=None, general=None, reset=None, preamble=None):
    return PAS5211MsgSetOltOptics(burst_timing_ctrl=burst,
                                  general_optics_params=general,
                                  voltage_if_mode=voltage,
                                  reset_timing_ctrl=reset,
                                  preamble_params=preamble)

def alarm_config(type, activate, parameters=[None, None, None, None]):
    while len(parameters) != 4:
        parameters.append(None)
    return PAS5211MsgSetAlarmConfig(type=get_alarm_code_for_type(type),
                                    activate=activate,
                                    parameter1=parameters[0],
                                    parameter2=parameters[1],
                                    parameter3=parameters[2],
                                    parameter4=parameters[3])


def get_alarm_code_for_type(type):
    try:
        return {
            PON_ALARM_LOS : PON_ALARM_CODE_LOS,
            PON_ALARM_LOSI : PON_ALARM_CODE_LOSI,
            PON_ALARM_DOWI : PON_ALARM_CODE_DOWI,
            PON_ALARM_LOFI : PON_ALARM_CODE_LOFI,
            PON_ALARM_RDII : PON_ALARM_CODE_RDII,
            PON_ALARM_LOAMI: PON_ALARM_CODE_LOAMI,
            PON_ALARM_LCDGI: PON_ALARM_CODE_LCDGI,
            PON_ALARM_LOAI : PON_ALARM_CODE_LOAI,
            PON_ALARM_SDI  : PON_ALARM_CODE_SDI,
            PON_ALARM_SFI  : PON_ALARM_CODE_SFI,
            PON_ALARM_PEE  : PON_ALARM_CODE_PEE,
            PON_ALARM_DGI  : PON_ALARM_CODE_DGI,
            PON_ALARM_LOKI : PON_ALARM_CODE_LOKI,
            PON_ALARM_TIWI : PON_ALARM_CODE_TIWI,
            PON_ALARM_TIA  : PON_ALARM_CODE_TIA
        }[type]
    except KeyError, e:
        return PON_ALARM_CODE_LAST_ALARM

