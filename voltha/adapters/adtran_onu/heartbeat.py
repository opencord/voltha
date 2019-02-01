# Copyright 2017-present Adtran, Inc.
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

import structlog
from twisted.internet import reactor
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.extensions.omci.omci_me import OntGFrame


class HeartBeat(object):
    """Wraps health-check support for ONU"""
    INITIAL_DELAY = 60                      # Delay after start until first check
    TICK_DELAY = 2                          # Heartbeat interval
    HEARTBEAT_FAILED_LIMIT = 5

    def __init__(self, handler, device_id):
        self.log = structlog.get_logger(device_id=device_id)
        self._enabled = False
        self._handler = handler
        self._device_id = device_id
        self._defer = None
        self._alarm_active = False
        self._heartbeat_count = 0
        self._heartbeat_miss = 0
        self._alarms_raised_count = 0
        self.heartbeat_failed_limit = self.HEARTBEAT_FAILED_LIMIT
        self.heartbeat_last_reason = ''
        self.heartbeat_interval = self.TICK_DELAY

    def __str__(self):
        return "HeartBeat: count: {}, miss: {}".format(self._heartbeat_count,
                                                       self._heartbeat_miss)

    @staticmethod
    def create(handler, device_id):
        return HeartBeat(handler, device_id)

    def _start(self, delay=INITIAL_DELAY):
        self._defer = reactor.callLater(delay, self.check_pulse)

    def _stop(self):
        d, self._defer = self._defer, None
        if d is not None and not d.called():
            d.cancel()

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._enabled != value:
            self._enabled = value

            # if value:
            #     self._start()
            # else:
            #     self._stop()

    @property
    def check_item(self):
        return 'vendor_id'

    @property
    def check_value(self):
        # device = self._handler.adapter_agent.get_device(self._device_id)
        # return device.serial_number
        return 'ADTN'

    @property
    def alarm_active(self):
        return self._alarm_active

    @property
    def heartbeat_count(self):
        return self._heartbeat_count

    @property
    def heartbeat_miss(self):
        return self._heartbeat_miss

    @property
    def alarms_raised_count(self):
        return self._alarms_raised_count

    def check_pulse(self):
        if self.enabled:
            try:
                self._defer = self._handler.openomci.omci_cc.send(OntGFrame(self.check_item).get())
                self._defer.addCallbacks(self._heartbeat_success, self._heartbeat_fail)

            except Exception as e:
                self._defer = reactor.callLater(5, self._heartbeat_fail, e)

    def _heartbeat_success(self, results):
        self.log.debug('heartbeat-success')

        try:
            omci_response = results.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            value = data[self.check_item]

            if value != self.check_value:
                self._heartbeat_miss = self.heartbeat_failed_limit
                self.heartbeat_last_reason = "Invalid {}, got '{}' but expected '{}'".\
                    format(self.check_item, value, self.check_value)
            else:
                self._heartbeat_miss = 0
                self.heartbeat_last_reason = ''

        except Exception as e:
            self._heartbeat_miss = self.heartbeat_failed_limit
            self.heartbeat_last_reason = e.message

        self.heartbeat_check_status()

    def _heartbeat_fail(self, failure):
        self._heartbeat_miss += 1
        self.log.info('heartbeat-miss', failure=failure,
                      count=self._heartbeat_count,
                      miss=self._heartbeat_miss)
        self.heartbeat_last_reason = 'OMCI connectivity error'
        self.heartbeat_check_status()

    def on_heartbeat_alarm(self, active):
        # TODO: Do something here ?
        #
        #  TODO: If failed (active = true) due to bad serial-number shut off the UNI port?
        pass

    def heartbeat_check_status(self):
        """
        Check the number of heartbeat failures against the limit and emit an alarm if needed
        """
        device = self._handler.adapter_agent.get_device(self._device_id)

        try:
            from voltha.extensions.alarms.heartbeat_alarm import HeartbeatAlarm

            if self._heartbeat_miss >= self.heartbeat_failed_limit:
                if device.connect_status == ConnectStatus.REACHABLE:
                    self.log.warning('heartbeat-failed', count=self._heartbeat_miss)
                    device.connect_status = ConnectStatus.UNREACHABLE
                    device.oper_status = OperStatus.FAILED
                    device.reason = self.heartbeat_last_reason
                    self._handler.adapter_agent.update_device(device)
                    HeartbeatAlarm(self._handler.alarms, 'onu', self._heartbeat_miss).raise_alarm()
                    self._alarm_active = True
                    self.on_heartbeat_alarm(True)
            else:
                # Update device states
                if device.connect_status != ConnectStatus.REACHABLE and self._alarm_active:
                    device.connect_status = ConnectStatus.REACHABLE
                    device.oper_status = OperStatus.ACTIVE
                    device.reason = ''
                    self._handler.adapter_agent.update_device(device)
                    HeartbeatAlarm(self._handler.alarms, 'onu').clear_alarm()
                    self._alarm_active = False
                    self._alarms_raised_count += 1
                    self.on_heartbeat_alarm(False)

        except Exception as e:
            self.log.exception('heartbeat-check', e=e)

        # Reschedule next heartbeat
        if self.enabled:
            self._heartbeat_count += 1
            self._defer = reactor.callLater(self.heartbeat_interval, self.check_pulse)
