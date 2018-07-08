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
import unittest
from unittest import TestCase, main

from voltha.adapters.microsemi.chat import *
from voltha.extensions.omci.omci import OmciFrame, OmciGet, \
    OmciGetResponse

@unittest.SkipTest
class TestChat(TestCase):

    def check_gen(self, frames, raw_frames):
        self.assertEqual(len(frames), len(raw_frames),
                         "number of frames do not match")
        for i in range(len(frames)):
            generated = str(frames[i])
            expected = raw_frames[i]
            if generated != expected:
                print("Mismatch between generated vs expected frame:")
                print("Generated:")
                hexdump(generated)
                print("Expected:")
                hexdump(expected)
                self.fail("Mismatch between generated vs expected frame "
                          "(see above printout)")

    def check_parsed(self, in_raw, reference_msg, channel_id=-1, onu_id=-1,
                     onu_session_id=-1):

        in_pkt = PAS5211Dot3(in_raw)

        pas5211_header = in_pkt.payload.payload
        self.assertEqual(pas5211_header.channel_id, channel_id)
        self.assertEqual(pas5211_header.onu_id, onu_id)
        self.assertEqual(pas5211_header.onu_session_id, onu_session_id)

        pas5211_msg = in_pkt.payload.payload.payload
        # so that we ignore junk/padding/fcs/etc after payload
        pas5211_msg.remove_payload()
        if pas5211_msg != reference_msg:
            print("Decoded full packet:")
            in_pkt.show()
            hexdump(in_raw)
            print("Decoded payload message:")
            pas5211_msg.show()
            hexdump(str(pas5211_msg))
            print("Expected message:")
            reference_msg.show()
            hexdump(str(reference_msg))
            self.fail("Decoded message did not match! "
                      "(inspect above printouts)")
        self.assertEqual(pas5211_msg, reference_msg)

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_get_protocol_version

    def test_get_protocol_version(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgGetProtocolVersion(), 1),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x16\x01\x00'
                '\x01\x00\x10\x00\xcd\xab4\x12\x01\x00\x00\x00\x020\x00\x00'
                '\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_get_protocol_version_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00"\x01\x00\x01'
            '\x00\x18\x00\xcd\xab4\x12\x01\x00\x00\x00\x02(\x00\x00\xff\xff'
            '\xff\xff\xff\xff\xff\xff\x11R\x02\x00\x10\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00u\xd3Y'
            '\x1d',
            PAS5211MsgGetProtocolVersionResponse(
                major_hardware_version=21009,
                minor_hardware_version=2,
                major_pfi_version=16,
                minor_pfi_version=0
            )
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_get_olt_version

    def test_get_olt_version(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgGetOltVersion(), 1),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x16\x01\x00'
                '\x01\x00\x10\x00\xcd\xab4\x12\x01\x00\x00\x00\x030\x00\x00'
                '\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_get_olt_version_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00R\x01\x00\x01'
            '\x00H\x00\xcd\xab4\x12\x03\x00\x00\x00\x038\x00\x00\xff\xff\xff'
            '\xff\xff\xff\xff\xff\x02\x00\x03\x009\x00\xea\x03\x11R\x02\x00'
            '\x00\x00\x00\x00\x04\x00\x80\x00\xff\x0f\x00\x02\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B\xd7\xeb\xe1',
            PAS5211MsgGetOltVersionResponse(
                major_firmware_version=2,
                minor_firmware_version=3,
                build_firmware_version=57,
                maintenance_firmware_version=1002,
                major_hardware_version=21009,
                minor_hardware_version=2,
                system_port_mac_type=PON_MII,
                channels_supported=4,
                onus_supported_per_channel=128,
                ports_supported_per_channel=4095,
                alloc_ids_supported_per_channel=512,
                critical_events_counter=[0, 0, 0, 0],
                non_critical_events_counter=[1, 0, 0, 0]
            )
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_set_olt_optics

    def test_set_olt_optics(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSetOltOptics(
                burst_timing_ctrl=BurstTimingCtrl(
                    snr_burst_delay=SnrBurstDelay(
                        timer_delay=8,
                        preamble_delay=32,
                        delimiter_delay=128,
                        burst_delay=128),
                    rng_burst_delay=RngBurstDelay(
                        timer_delay=8,
                        preamble_delay=32,
                        delimiter_delay=128),
                        # burst_delay=63451),
                    burst_delay_single=1,
                    burst_delay_double=1
                ),
                general_optics_params=GeneralOpticsParams(
                    laser_reset_polarity=PON_POLARITY_ACTIVE_HIGH,
                    laser_sd_polarity=PON_POLARITY_ACTIVE_HIGH,
                    sd_source=PON_SD_SOURCE_LASER_SD,
                    sd_hold_snr_ranging=PON_DISABLE,
                    sd_hold_normal=PON_DISABLE,
                    reset_type_snr_ranging=PON_RESET_TYPE_DELAY_BASED,
                    reset_type_normal=PON_RESET_TYPE_NORMAL_START_BURST_BASED,
                    laser_reset_enable=PON_ENABLE,
                ),
                reset_timing_ctrl=ResetTimingCtrl(
                    reset_data_burst=ResetValues(
                        bcdr_reset_d2=1,
                        bcdr_reset_d1 = 11,
                        laser_reset_d2=2,
                        laser_reset_d1=5),
                    reset_snr_burst=ResetValues(
                        bcdr_reset_d2=2,
                        bcdr_reset_d1=9,
                        laser_reset_d2=2,
                        laser_reset_d1=1),
                    reset_rng_burst=ResetValues(
                        bcdr_reset_d2=2,
                        bcdr_reset_d1=9,
                        laser_reset_d2=2,
                        laser_reset_d1=1),
                    single_reset=ResetValues(
                        bcdr_reset_d2=1,
                        bcdr_reset_d1=1,
                        laser_reset_d2=1,
                        laser_reset_d1=1),
                    double_reset=DoubleResetValues(
                        bcdr_reset_d4=1,
                        bcdr_reset_d3=1,
                        laser_reset_d4=1,
                        laser_reset_d3=1)
                ),
                voltage_if_mode=PON_OPTICS_VOLTAGE_IF_LVPECL,
                preamble_params=PreambleParams(
                    correlation_preamble_length=8,
                    preamble_length_snr_rng=119,
                    guard_time_data_mode=32,
                    type1_size_data=0,
                    type2_size_data=0,
                    type3_size_data=5,
                    type3_pattern=170,
                    delimiter_size=20,
                    delimiter_byte1=171,
                    delimiter_byte2=89,
                    delimiter_byte3=131)
            ), 3, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00V\x01\x00'
                '\x01\x00P\x00\xcd\xab4\x12\x03\x00\x00\x00j0\x00\x00\x00\x00'
                '\xff\xff\xff\xff\xff\xff\x08\x00 \x00\x80\x00\x80\x00\x08'
                '\x00 \x00\x80\x00\x01\x00\x01\x00\x01\x01\x00\x00\x00\x00'
                '\x00\x01\x00\x00\x00\x01\x0b\x02\x05\x02\t\x02\x01\x02\t\x02'
                '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x08w \x00\x00\x05'
                '\xaa\x14\xabY\x83\x00\x00\x00'
            ]
        )

    def test_set_olt_optics_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00\x1a\x01\x00'
            '\x01\x00\x10\x00\xcd\xab4\x12\x03\x00\x00\x00j(\x00\x00\x00\x00'
            '\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe1?'
            '\x85\xce',
            PAS5211MsgSetOltOpticsResponse(),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_set_optics_io_control

    def test_set_optics_io_control(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSetOpticsIoControl(
                i2c_clk=PON_GPIO_LINE_1,
                i2c_data=PON_GPIO_LINE_0,
                tx_enable=PON_GPIO_LINE_6,
                tx_fault=PON_EXT_GPIO_LINE(6),
                tx_enable_polarity=PON_POLARITY_ACTIVE_LOW,
                tx_fault_polarity=PON_POLARITY_ACTIVE_HIGH
            ), 7, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x1c\x01'
                '\x00\x01\x00\x16\x00\xcd\xab4\x12\x07\x00\x00\x00l0\x00\x00'
                '\x00\x00\xff\xff\xff\xff\xff\xff\x01\x00\x06\x0e\x00\x01\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_set_optics_io_control_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00\x1a\x01\x00\x01'
            '\x00\x10\x00\xcd\xab4\x12\x07\x00\x00\x00l(\x00\x00\x00\x00\xff'
            '\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc2\x8b\xc4'
            '\xd7',
            PAS5211MsgSetOpticsIoControlResponse(),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_get_general_param

    def test_get_general_param(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgGetGeneralParam(
                parameter=PON_TX_ENABLE_DEFAULT
            ), 11, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x1e\x01'
                '\x00\x01\x00\x18\x00\xcd\xab4\x12\x0b\x00\x00\x00\xa50\x00'
                '\x00\x00\x00\xff\xff\xff\xff\xff\xff\xe9\x03\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_get_general_param_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00&\x01\x00\x01'
            '\x00\x1c\x00\xcd\xab4\x12\x0b\x00\x00\x00\xa5(\x00\x00\x00\x00'
            '\xff\xff\xff\xff\xff\xff\xe9\x03\x00\x00\x00\x00\x00\x00\x01\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd6Yf'
            '\xf9',
            PAS5211MsgGetGeneralParamResponse(
                parameter=PON_TX_ENABLE_DEFAULT,
                value=1
            ),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_set_general_param

    def test_set_general_param(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSetGeneralParam(
                parameter=PON_TX_ENABLE_DEFAULT,
                value=0
            ), 11, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x22\x01'
                '\x00\x01\x00\x1c\x00\xcd\xab4\x12\x0b\x00\x00\x00\xa40\x00'
                '\x00\x00\x00\xff\xff\xff\xff\xff\xff\xe9\x03\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_set_general_param_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00&\x01\x00\x01'
            '\x00\x1c\x00\xcd\xab4\x12\x0b\x00\x00\x00\xa4(\x00\x00\x00\x00'
            '\xff\xff\xff\xff\xff\xff\xe9\x03\x00\x00\x00\x00\x00\x00\x01\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd6Yf'
            '\xf9',
            PAS5211MsgSetGeneralParamResponse(),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_add_olt_channel

    def test_add_olt_channel(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgAddOltChannel(
            ), 12, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x16\x01'
                '\x00\x01\x00\x10\x00\xcd\xab4\x12\x0c\x00\x00\x00\x040\x00'
                '\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_add_olt_channel_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00\x1a\x01\x00'
            '\x01\x00\x10\x00\xcd\xab4\x12\x0c\x00\x00\x00\x04(\x00\x00\x00'
            '\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90L'
            '\xbf\xdd',
            PAS5211MsgAddOltChannelResponse(
            ),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_set_alarm_config

    def test_set_alarm_config(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSetAlarmConfig(
                type=PON_ALARM_SOFTWARE_ERROR,
                activate=PON_ENABLE
            ), 19, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00*\x01\x00'
                '\x01\x00$\x00\xcd\xab4\x12\x13\x00\x00\x0000\x00\x00\x00\x00'
                '\xff\xff\xff\xff\xff\xff\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_set_alarm_config_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00\x1a\x01\x00\x01'
            '\x00\x10\x00\xcd\xab4\x12\x13\x00\x00\x000(\x00\x00\x00\x00\xff'
            '\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4\xc5'
            '\xf4i',
            PAS5211MsgSetAlarmConfigResponse(),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_get_dba_mode

    def test_get_dba_mode(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgGetDbaMode(
            ), 23, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x16\x01'
                '\x00\x01\x00\x10\x00\xcd\xab4\x12\x17\x00\x00\x0090\x00\x00'
                '\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_get_dba_mode_response(self):
        self.check_parsed(
            'h\x05\xca\x05\xf2\xef\x00\x0c\xd5\x00\x01\x00\x00\x1e\x01\x00\x01'
            '\x00\x14\x00\xcd\xab4\x12\x17\x00\x00\x009(\x00\x00\x00\x00\xff'
            '\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x85\xd0?',
            PAS5211MsgGetDbaModeResponse(
                dba_mode=PON_DBA_MODE_RUNNING
            ),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_set_olt_channel_activation_period

    def test_set_olt_channel_activation_period(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSetOltChannelActivationPeriod(
                activation_period=1000
            ), 31, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x1a\x01\x00'
                '\x01\x00\x14\x00\xcd\xab4\x12\x1f\x00\x00\x00\x0b0\x00\x00'
                '\x00\x00\xff\xff\xff\xff\xff\xff\xe8\x03\x00\x00\x00\x00\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    def test_set_olt_channel_activation_period_response(self):
        self.check_parsed(
            '\x90\xe2\xba\x82\xf9w\x00\x0c\xd5\x00\x01\x01\x00\x1a\x01\x00\x01'
            '\x00\x10\x00\xcd\xab4\x12\x1f\x00\x00\x00\x0b(\x00\x00\x00\x00'
            '\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            PAS5211MsgSetOltChannelActivationPeriodResponse(),
            channel_id=0
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_send_cli_command

    def test_send_cli_command(self):
        msg = PAS5211MsgSendCliCommand(command="foo")
        self.assertEqual(str(msg), '\x03\x00foo')
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSendCliCommand(
                command="foo\r"
            ), 11),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x1c\x01\x00'
                '\x01\x00\x16\x00\xcd\xab4\x12\x0b\x00\x00\x00\x0f0\x00\x00'
                '\xff\xff\xff\xff\xff\xff\xff\xff\x04\x00\x66\x6f\x6f\x0d\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_switch_to_inbound_mode

    def test_switch_to_inbound_mode(self):
        msg = PAS5211MsgSendCliCommand(command="foo")
        self.assertEqual(str(msg), '\x03\x00foo')
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSwitchToInboundMode(
                mac='00:0c:d5:00:01:00'
            ), 11, channel_id=0),
            [
                '\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00\x1e\x01'
                '\x00\x01\x00\x18\x00\xcd\xab4\x12\x0b\x00\x00\x00\xec0\x00'
                '\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x0c\xd5\x00\x01\x00'
                '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            ]
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_send_frame

    def test_send_frame(self):
        self.check_gen(
            constructPAS5211Frames(PAS5211MsgSendFrame(
                port_type=PON_PORT_PON,
                port_id=0,
                management_frame=PON_TRUE,
                frame=OmciFrame(
                    transaction_id=0,
                    message_type=0x49,
                    omci_message=OmciGet(
                        entity_class=6,
                        entity_id=0x101,
                        # there is a more programmer friendly way to express it
                        attributes_mask=0x0800
                    )
                )
            ), 39, channel_id=0, onu_id=0, onu_session_id=1),
            [
                "\x00\x0c\xd5\x00\x01\x00h\x05\xca\x05\xf2\xef\x00J\x01\x00"
                "\x01\x00D\x00\xcd\xab4\x12'\x00\x00\x00*0\x00\x00\x00\x00"
                "\x00\x00\x01\x00\x00\x00,\x00\x00\x00\x00\x00\x01\x00\x00"
                "\x00I\n\x00\x06\x01\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00("
            ]
        )

    def test_send_frame_response(self):
        self.check_parsed(
            "\x90\xe2\xba\x82\xf9w\x00\x0c\xd5\x00\x01\x01\x00\x1a\x01\x00"
            "\x01\x00\x10\x00\xcd\xab4\x12'\x00\x00\x00*(\x00\x00\x00\x00"
            "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            PAS5211MsgSendFrameResponse(
            ),
            channel_id=0, onu_id=0, onu_session_id=1
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_receive_onu_activation_event

    def test_receive_onu_activation_event(self):
        self.check_parsed(
            '\x90\xe2\xba\x82\xf9w\x00\x0c\xd5\x00\x01\x01\x00&\x01\x00\x01'
            '\x00\x1c\x00\xcd\xab4\x12\x00\x00\x00\x00\x0c(\x01\x00\x00\x00'
            '\x00\x00\x01\x00\x00\x00PMCS\xd5b\x84\xac\x04\x12\x04\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            PAS5211EventOnuActivation(
                serial_number='PMCS\xd5b\x84\xac',
                equalization_period=266756
            ),
            channel_id=0, onu_id=0, onu_session_id=1
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~ test_frame_received_event

    def test_frame_received_event(self):
        self.check_parsed(
            '\x90\xe2\xba\x82\xf9w\x00\x0c\xd5\x00\x01\x01\x00Z\x01\x00\x01'
            '\x00P\x00\xcd\xab4\x12\x01\x00\x00\x00\x0c(\n\x00\x00\x00\x00'
            '\x00\x01\x00\x00\x000\x00\x00\x00\x00\x00\x01\x00\x15\x00 \x00'
            '\x13\x00\x00 \x00\x00)\n\x00\x06\x01\x01\x00\x08\x00PMCS\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00(',
            PAS5211EventFrameReceived(
                length=48,
                management_frame=PON_TRUE,
                classification_entity=21,  # use enums
                l3_offset=32,
                l4_offset=19,
                # ignored, yet we get a non-zero value from olt
                ignored=0x2000,
                frame=OmciFrame(
                    transaction_id=0,
                    message_type=0x29,
                    omci_message=OmciGetResponse(
                        entity_class=6,
                        entity_id=0x101,
                        success_code=0,
                        attributes_mask=0x0800,
                        data=dict(
                            vendor_id="PMCS"
                        )
                    ),
                    # omci_trailer=0x28
                )
            ),
            channel_id=0, onu_id=0, onu_session_id=1
        )


if __name__ == '__main__':
    main()
