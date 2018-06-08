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
from scapy.automaton import ATMT
import structlog
from voltha.adapters.microsemi_olt.BaseOltAutomaton import BaseOltAutomaton
from voltha.adapters.microsemi_olt.PAS5211 import PAS5211MsgGetProtocolVersion, PAS5211MsgGetOltVersion, \
    PAS5211MsgGetOltVersionResponse, PAS5211MsgGetProtocolVersionResponse, \
    SnrBurstDelay, RngBurstDelay, GeneralOpticsParams, ResetValues, ResetTimingCtrl, PreambleParams, \
    PAS5211MsgSetOltOpticsResponse, CHANNELS, PAS5211MsgSetOpticsIoControlResponse, PAS5211MsgGetGeneralParamResponse, \
    PAS5211MsgAddOltChannel, \
    PAS5211MsgAddOltChannelResponse, PAS5211MsgSetAlarmConfigResponse, PAS5211MsgGetDbaMode, \
    PAS5211MsgGetDbaModeResponse, PAS5211MsgStartDbaAlgorithm, \
    PAS5211MsgStartDbaAlgorithmResponse, PAS5211MsgSetOltChannelActivationPeriod, \
    PAS5211MsgSetOltChannelActivationPeriodResponse, PAS5211MsgHeader, PAS5211Event, PAS5211EventAlarmNotification
from voltha.adapters.microsemi_olt.PAS5211_constants import PON_OPTICS_VOLTAGE_IF_LVPECL, PON_ENABLE, \
    PON_POLARITY_ACTIVE_HIGH, PASCOMM_RETRIES, \
    PON_SD_SOURCE_LASER_SD, PON_RESET_TYPE_DELAY_BASED, PON_DISABLE, PON_RESET_TYPE_NORMAL_START_BURST_BASED, \
    PON_TX_ENABLE_DEFAULT, PON_ALARM_LOS, PON_DBA_MODE_LOADED_NOT_RUNNING, PON_DBA_MODE_RUNNING
from voltha.adapters.microsemi_olt.PAS5211_utils import general_param, olt_optics_pkt, burst_timing, io_ctrl_optics, \
    alarm_config
from voltha.extensions.omci.omci_frame import OmciFrame
import structlog

from voltha.protos.common_pb2 import ConnectStatus

log = structlog.get_logger()


class OltStateMachine(BaseOltAutomaton):
    send_state = []
    dba_needs_start = False
    retry = 10

    def check_channel_state(self):
        for i in CHANNELS:
            if not self.send_state[i]:
                return False
        self.send_state = []
        return True

    def master_filter(self, pkt):

        if not super(OltStateMachine, self).master_filter(pkt):
            return False

        if OmciFrame in pkt:
            log.debug("OMCI-message-type: {}".format(pkt[OmciFrame].message_type))
            return False

        if PAS5211Event in pkt:
            return False

        if PAS5211EventAlarmNotification in pkt:
            return False

        return True

    """
    States
    """

    @ATMT.state(initial=1)
    def disconnected(self):
        pass

    @ATMT.state()
    def wait_for_proto_version(self):
        pass

    @ATMT.state()
    def got_proto_version(self):
        pass

    @ATMT.state()
    def wait_for_olt_version(self):
        pass

    @ATMT.state()
    def got_olt_version(self):
        pass

    @ATMT.state()
    def wait_olt_optics(self):
        pass

    @ATMT.state()
    def got_olt_optics(self):
        pass

    @ATMT.state()
    def wait_olt_io_optics(self):
        pass

    @ATMT.state()
    def got_olt_io_optics(self):
        pass

    @ATMT.state()
    def wait_query_response(self):
        pass

    @ATMT.state()
    def got_query_response(self):
        pass

    @ATMT.state()
    def wait_olt_add(self):
        pass

    @ATMT.state()
    def got_olt_add(self):
        pass

    @ATMT.state()
    def wait_alarm_set(self):
        pass

    @ATMT.state()
    def got_alarm_set(self):
        pass

    @ATMT.state()
    def wait_dba_mode(self):
        pass

    @ATMT.state()
    def got_dba_mode(self):
        pass

    @ATMT.state()
    def wait_dba_start(self):
        pass

    @ATMT.state()
    def got_dba_start(self):
        pass

    @ATMT.state()
    def wait_activation(self):
        pass

    @ATMT.state(final=1)
    def end(self):
        log.debug('OLT state machine ended')
    #
    # @ATMT.state()
    # def wait_keepalive(self):
    #     pass

    @ATMT.state(error=1)
    def error(self):
        raise self.end()
        # pass

    """
    Transitions
    """

    # Transitions from disconnected state
    @ATMT.condition(disconnected)
    def send_proto_request(self):
        self.send(self.p(PAS5211MsgGetProtocolVersion()))
        raise self.wait_for_proto_version()

    # Transitions from wait_for_proto_version
    @ATMT.timeout(wait_for_proto_version, 3)
    def timeout_proto(self):
        log.debug("Timed out waiting for proto version")
        self.retry -= 1
        if self.retry < 0:
            log.error("Too many retries, aborting.")
            raise self.error()
        raise self.disconnected()

    @ATMT.receive_condition(wait_for_proto_version)
    def receive_proto_version(self, pkt):
        log.debug("Received proto version {}".format(type(pkt)))
        if PAS5211MsgGetProtocolVersionResponse in pkt:
            raise self.got_proto_version()
        else:
            log.error("Got garbage packet: {}".format(pkt.summary()))
            self.retry -= 1
            if self.retry < 0:
                log.error("Too many retries, aborting.")
                raise self.error()
            else:
                raise self.wait_for_proto_version()

    # Transitions from got_proto_version
    @ATMT.condition(got_proto_version)
    def send_olt_version(self):
        self.send(self.p(PAS5211MsgGetOltVersion()))
        log.debug("[SENT] PAS5211MsgGetOltVersion")
        raise self.wait_for_olt_version()

    # Transitions from waiting for olt version
    @ATMT.timeout(wait_for_olt_version, 3)
    def timeout_olt(self):
        log.debug("Timed out waiting for olt version")
        self.retry -= 1
        if self.retry < 0:
            log.error("Too many retries, aborting.")
            raise self.error()
        raise self.disconnected()

    @ATMT.receive_condition(wait_for_olt_version)
    def receive_olt_version(self, pkt):
        log.debug("Received proto version")
        if PAS5211MsgGetOltVersionResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgGetOltVersion")
            self.device.update_device_info_from_pkt(pkt)
            raise self.got_olt_version()
        else:
            log.error("Got garbage packet: {}".format(pkt.summary()))
            raise self.error()

    # Transitions from got_olt_version
    @ATMT.condition(got_olt_version)
    def send_olt_optics(self):
        snr_burst_delay = SnrBurstDelay(timer_delay=8, preamble_delay=32,
                                        delimiter_delay=128, burst_delay=128)
        rng_burst_delay = RngBurstDelay(timer_delay=8, preamble_delay=32,
                                        delimiter_delay=128)

        general_optics_param = GeneralOpticsParams(laser_reset_polarity=PON_POLARITY_ACTIVE_HIGH,
                                                   laser_sd_polarity=PON_POLARITY_ACTIVE_HIGH,
                                                   sd_source=PON_SD_SOURCE_LASER_SD, sd_hold_snr_ranging=PON_DISABLE,
                                                   sd_hold_normal=PON_DISABLE,
                                                   reset_type_snr_ranging=PON_RESET_TYPE_DELAY_BASED,
                                                   reset_type_normal=PON_RESET_TYPE_NORMAL_START_BURST_BASED,
                                                   laser_reset_enable=PON_ENABLE)

        reset = ResetTimingCtrl(reset_data_burst=ResetValues(bcdr_reset_d2=1,
                                                             bcdr_reset_d1=11,
                                                             laser_reset_d2=2,
                                                             laser_reset_d1=5),
                                reset_snr_burst=ResetValues(bcdr_reset_d2=2,
                                                            bcdr_reset_d1=9,
                                                            laser_reset_d2=2,
                                                            laser_reset_d1=1),
                                reset_rng_burst=ResetValues(bcdr_reset_d2=2,
                                                            bcdr_reset_d1=9,
                                                            laser_reset_d2=2,
                                                            laser_reset_d1=1),
                                single_reset=ResetValues(bcdr_reset_d2=1,
                                                         bcdr_reset_d1=1,
                                                         laser_reset_d2=1,
                                                         laser_reset_d1=1),
                                double_reset=ResetValues(bcdr_reset_d2=1,
                                                         bcdr_reset_d1=1,
                                                         laser_reset_d2=1,
                                                         laser_reset_d1=1))

        preamble = PreambleParams(correlation_preamble_length=8, preamble_length_snr_rng=119,
                                  guard_time_data_mode=32, type1_size_data=0,
                                  type2_size_data=0, type3_size_data=5,
                                  type3_pattern=170, delimiter_size=20,
                                  delimiter_byte1=171, delimiter_byte2=89,
                                  delimiter_byte3=131)

        olt_optics = olt_optics_pkt(PON_OPTICS_VOLTAGE_IF_LVPECL, burst=burst_timing(1, 1,
                                                                                     snr_burst=snr_burst_delay,
                                                                                     rng_burst=rng_burst_delay),
                                    general=general_optics_param,
                                    reset=reset,
                                    preamble=preamble)

        for id in CHANNELS:
            self.send_state.append(False)
            self.send(self.p(olt_optics, channel_id=id))
            log.debug("[SENT] PAS5211MsgSetOltOptics")

        raise self.wait_olt_optics()

    # Transitions from wait_olt_optics
    @ATMT.timeout(wait_olt_optics, 3)
    def olt_optics_timeout(self):
        log.error("Setting olt optics failed; disconnecting")
        raise self.error()

    @ATMT.receive_condition(wait_olt_optics)
    def receive_set_optics_response(self, pkt):
        if PAS5211MsgSetOltOpticsResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgSetOltOptics")
            self.send_state[pkt.channel_id] = True
            if self.check_channel_state():
                raise self.got_olt_optics()
            raise self.wait_olt_optics()

    # Transitions from got_olt_optics
    @ATMT.condition(got_olt_optics)
    def send_olt_io_optics(self):

        pkt = io_ctrl_optics(1, 0, 6, 14)
        self.send_state.append(False)
        self.send(self.p(pkt, channel_id=0))
        log.debug("[SENT] PAS5211MsgSetOpticsIoControl")

        pkt = io_ctrl_optics(3, 2, 7, 15)
        self.send_state.append(False)
        self.send(self.p(pkt, channel_id=1))
        log.debug("[SENT] PAS5211MsgSetOpticsIoControl")

        pkt = io_ctrl_optics(11, 10, 8, 16)
        self.send_state.append(False)
        self.send(self.p(pkt, channel_id=2))
        log.debug("[SENT] PAS5211MsgSetOpticsIoControl")

        pkt = io_ctrl_optics(13, 12, 9, 17)
        self.send_state.append(False)
        self.send(self.p(pkt, channel_id=3))
        log.debug("[SENT] PAS5211MsgSetOpticsIoControl")

        raise self.wait_olt_io_optics()

    # Transitions from wait olt io optics
    @ATMT.timeout(wait_olt_io_optics, 3)
    def olt_io_optics_timeout(self):
        log.error("Setting olt io optics failed; disconnecting")
        raise self.error()

    @ATMT.receive_condition(wait_olt_io_optics)
    def receive_io_optics_response(self, pkt):
        if PAS5211MsgSetOpticsIoControlResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgSetOpticsIoControl")
            self.send_state[pkt.channel_id] = True
            if self.check_channel_state():
                raise self.got_olt_io_optics()
            raise self.wait_olt_io_optics()

    # Transitions got olt io optics
    @ATMT.condition(got_olt_io_optics)
    def check_downstream_pon_tx(self):
        query = general_param(PON_TX_ENABLE_DEFAULT)
        for id in CHANNELS:
            self.send_state.append(False)
            self.send(self.p(query, channel_id=id))
            log.debug("[SENT] PAS5211MsgGetGeneralParam")

        raise self.wait_query_response()

    # Transitions from wait query response
    @ATMT.timeout(wait_query_response, 3)
    def query_timeout(self):
        log.error("Our queries have gone unanswered; disconnecting")
        raise self.error()

    @ATMT.receive_condition(wait_query_response)
    def check_pon_tx_state(self, pkt):
        if PAS5211MsgGetGeneralParamResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgGetGeneralParam")
            self.send_state[pkt.channel_id] = True
            if pkt.value == PON_ENABLE:
                # TODO: we may want to do something here.
                if self.check_channel_state():
                    raise self.got_query_response()
                else:
                    raise self.wait_query_response()
            else:
                log.error("TX downstream is not enabled")
                raise self.error()

    # Transitions from got_query_response
    @ATMT.condition(wait_query_response)
    def send_add_olt(self):
        olt_add = PAS5211MsgAddOltChannel()
        for id in CHANNELS:
            self.send_state.append(False)
            self.send(self.p(olt_add, channel_id=id))
            log.debug("[SENT] PAS5211MsgAddOltChannel")
        raise self.wait_olt_add()

    # Transitions from wait_olt_add
    @ATMT.timeout(wait_olt_add, 3)
    def olt_add_timeout(self):
        log.error("Cannot add olts; disconnecting")
        raise self.error()

    @ATMT.receive_condition(wait_olt_add)
    def wait_for_olt_add(self, pkt):
        if PAS5211MsgAddOltChannelResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgAddOltChannel")
            self.send_state[pkt.channel_id] = True
            if self.check_channel_state():
                raise self.got_olt_add()
            raise self.wait_olt_add()

    # Transitions from got_olt_add
    @ATMT.condition(got_olt_add)
    def send_alarm_config(self):
        alarm_msg = alarm_config(PON_ALARM_LOS, PON_ENABLE)
        for id in CHANNELS:
            self.send_state.append(False)
            self.send(self.p(alarm_msg, channel_id=id))
            log.debug("[SENT] PAS5211MsgSetAlarmConfig")
        raise self.wait_alarm_set()

    # Transitions for wait_alarm_set
    @ATMT.timeout(wait_alarm_set, 3)
    def alarm_timeout(self):
        log.error("Couldn't set alarms; disconnecting")
        raise self.error()

    @ATMT.receive_condition(wait_alarm_set)
    def wait_for_alarm_set(self, pkt):
        if PAS5211MsgSetAlarmConfigResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgSetAlarmConfig")
            self.send_state[pkt.channel_id] = True
            if self.check_channel_state():
                raise self.got_alarm_set()
            raise self.wait_alarm_set()

    # Transitions from got_alarm_set
    @ATMT.condition(got_alarm_set)
    def send_dba_mode(self):
        get_dba_mode = PAS5211MsgGetDbaMode()
        for id in CHANNELS:
            self.send_state.append(False)
            self.send(self.p(get_dba_mode, channel_id=id))
            log.debug("[SENT] PAS5211MsgGetDbaMode")

        raise self.wait_dba_mode()

    # Transitions from wait_dba_mode
    @ATMT.timeout(wait_dba_mode, 3)
    def dba_timeout(self):
        log.error("No DBA information returned; disconnecting")
        raise self.error()

    @ATMT.receive_condition(wait_dba_mode)
    def wait_for_dba_mode(self, pkt):

        if PAS5211MsgGetDbaModeResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgGetDbaMode")
            # TODO: What do we do in case the DBA is not loaded.
            if pkt.dba_mode == PON_DBA_MODE_LOADED_NOT_RUNNING:
                self.send_state[pkt.channel_id] = True
                self.dba_needs_start = True
            elif pkt.dba_mode == PON_DBA_MODE_RUNNING:
                self.send_state[pkt.channel_id] = True
            if self.check_channel_state():
                if self.dba_needs_start:
                    raise self.got_dba_mode()
                else:
                    raise self.got_dba_start()
        raise self.wait_dba_mode()

    # Transition from got_dba_mode
    @ATMT.condition(got_dba_mode)
    def send_start_dba(self):
        dba_start = PAS5211MsgStartDbaAlgorithm(
            size=0, initialization_data=None)
        for id in CHANNELS:
            self.send_state.append(False)
            self.send(self.p(dba_start, channel_id=id))
            log.debug("[SENT] PAS5211MsgStartDbaAlgorithm")
        raise self.wait_dba_start()

    # Transitions from wait_dba_start
    @ATMT.timeout(wait_dba_start, 3)
    def dba_start_timeout(self):
        log.error("DBA has not started; disconnecting")
        raise self.error()

    @ATMT.receive_condition(wait_dba_start)
    def wait_for_dba_start(self, pkt):
        if PAS5211MsgStartDbaAlgorithmResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgStartDbaAlgorithm")
            self.send_state[pkt.channel_id] = True
            if self.check_channel_state():
                raise self.got_dba_start()
        raise self.wait_dba_start()

    # Transitions from got_dba_start
    @ATMT.condition(got_dba_start)
    def send_activation_period(self):
        activation = PAS5211MsgSetOltChannelActivationPeriod(
            activation_period=1000)
        for id in CHANNELS:
            self.send_state.append(False)
            self.send(self.p(activation, channel_id=id))
            log.debug("[SENT] PAS5211MsgSetOltChannelActivationPeriod")

        raise self.wait_activation()

    # Transitions for wait_for_activation
    @ATMT.timeout(wait_activation, 3)
    def timeout_activation(self):
        log.error("No activation; disconnect")
        raise self.error()

    @ATMT.receive_condition(wait_activation)
    def wait_for_activation(self, pkt):
        if PAS5211MsgSetOltChannelActivationPeriodResponse in pkt:
            log.debug("[RESPONSE] PAS5211MsgSetOltChannelActivationPeriod")
            self.send_state[pkt.channel_id] = True
            if self.check_channel_state():
                log.info("Ruby OLT at {} initialised".format(self.target))
                # self.device.create_logical_device()
                self.device.activate()
                # self.device.add_upstream_port(129)
                # self.device.add_logical_upstream_port(129)
                # keep_alive = KeepAlive(
                #     iface=self.interface, comm=self.comm, target=self.target, device=self.device)
                # keep_alive.run()
                raise self.end()
        raise self.wait_activation()


class KeepAlive(BaseOltAutomaton):
    """
        Master filter: Only allow PAS5211MsgGetOltVersionResponse
    """

    def master_filter(self, pkt):
        if not super(KeepAlive, self).master_filter(pkt):
            return False

        if PAS5211MsgGetOltVersionResponse in pkt:
            return True

        return False

    """
        States
    """

    @ATMT.state(initial=1)
    def init_keepalive(self):
        log.debug('init-keepalive')

    @ATMT.state()
    def wait_keepalive(self):
        pass

    @ATMT.state(error=1)
    def error(self):
        raise self.end()

    @ATMT.state(final=1)
    def end(self):
        log.debug('init-keepalive-end')

    """
        Transitions
    """

    # Send Keep Alive
    @ATMT.condition(init_keepalive)
    def send_keepalive(self):
        self.send(self.p(PAS5211MsgGetOltVersion()))
        raise self.got_keepalive()

    # Timeout
    @ATMT.timeout(wait_keepalive, 1)
    def timeout_keepalive(self):
        log.error("OLT not responding to keep alive; disconnecting")
        raise self.error()

    # Received Keep Alive
    @ATMT.receive_condition(wait_keepalive)
    def got_keepalive(self, pkt):
        log.debug('keepalive-received')
        raise self.send_keepalive()
