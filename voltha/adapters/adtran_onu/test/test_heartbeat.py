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

import pytest
from mock import patch, MagicMock
from voltha.adapters.adtran_onu.heartbeat import HeartBeat
from voltha.adapters.adtran_onu.adtran_onu_handler import AdtranOnuHandler
from voltha.protos.common_pb2 import OperStatus, ConnectStatus


#####################################
# Constants for moodule-level scope #
#####################################

DEVICE_ID = 0x12345678          # Arbitrary device ID
DELAY = 100                     # Delay for HeartBeat._start()


############
# Fixtures #
############

@pytest.fixture(scope='function', name='fxt_heartbeat')
def heartbeat():
    with patch('voltha.adapters.adtran_onu.heartbeat.structlog.get_logger'):
        return HeartBeat(MagicMock(spec=AdtranOnuHandler), DEVICE_ID)


##############
# Unit tests #
##############

# Basic test of HeartBeat() object creation
def test_heartbeat_init(fxt_heartbeat):
    assert fxt_heartbeat._device_id == DEVICE_ID


# Test Heartbeat.__str__() to ensure proper return value
def test_heartbeat___str__(fxt_heartbeat):
    assert str(fxt_heartbeat) == "HeartBeat: count: 0, miss: 0"


# Test static method constructor for HeartBeat()
def test_heartbeat_create():
    handler = MagicMock(spec=AdtranOnuHandler)
    heartbeat = HeartBeat.create(handler, DEVICE_ID)
    assert heartbeat._handler == handler
    assert heartbeat._device_id == DEVICE_ID


# Test Heartbeat._start() for expected operation
def test_heartbeat__start(fxt_heartbeat):
    with patch('voltha.adapters.adtran_onu.heartbeat.reactor.callLater') as mk_callLater:
        fxt_heartbeat._start(DELAY)
    mk_callLater.assert_called_once_with(DELAY, fxt_heartbeat.check_pulse)
    assert fxt_heartbeat._defer is not None


# Test Heartbeat._stop() for expected operation
def test_heartbeat__stop(fxt_heartbeat):
    # Must save mock reference because source code clears the _defer attribute
    fxt_heartbeat._defer = mk_defer = MagicMock()
    fxt_heartbeat._defer.called = MagicMock()
    fxt_heartbeat._defer.called.return_value = False
    fxt_heartbeat._stop()
    mk_defer.cancel.assert_called_once_with()


@pytest.mark.parametrize("setting, result", [(True, True), (False, False)])
# Test Heartbeat.enabled() property for expected operation
def test_heartbeat_enabled_getter(fxt_heartbeat, setting, result):
    fxt_heartbeat._enabled = setting
    assert fxt_heartbeat.enabled == result


@pytest.mark.parametrize("setting, result", [(True, True), (False, False)])
# Test Heartbeat.enabled() property for expected operation
def test_heartbeat_enabled_setter(fxt_heartbeat, setting, result):
    fxt_heartbeat._enabled = False
    fxt_heartbeat.enabled = setting
    assert fxt_heartbeat._enabled == result


# Test Heartbeat.check_item() property for expected operation
def test_heartbeat_check_item(fxt_heartbeat):
    assert fxt_heartbeat.check_item == 'vendor_id'


# Test Heartbeat.check_value() property for expected operation
def test_heartbeat_check_value(fxt_heartbeat):
    assert fxt_heartbeat.check_value == 'ADTN'


@pytest.mark.parametrize("setting, result", [(True, True), (False, False)])
# Test Heartbeat.alarm_active() property for expected operation
def test_heartbeat_alarm_active(fxt_heartbeat, setting, result):
    fxt_heartbeat._alarm_active = setting
    assert fxt_heartbeat.alarm_active == result


# Test Heartbeat.heartbeat_count() property for expected operation
def test_heartbeat_heartbeat_count(fxt_heartbeat):
    fxt_heartbeat._heartbeat_count = 10
    assert fxt_heartbeat.heartbeat_count == 10


# Test Heartbeat.heartbeat_miss() property for expected operation
def test_heartbeat_heartbeat_miss(fxt_heartbeat):
    fxt_heartbeat._heartbeat_miss = 5
    assert fxt_heartbeat.heartbeat_miss == 5


# Test Heartbeat.alarms_raised_count() property for expected operation
def test_heartbeat_alarms_raised_count(fxt_heartbeat):
    fxt_heartbeat._alarms_raised_count = 2
    assert fxt_heartbeat.alarms_raised_count == 2


# Test Heartbeat.check_pulse() for expected operation
def test_heartbeat_check_pulse(fxt_heartbeat):
    fxt_heartbeat._enabled = True
    fxt_heartbeat.check_pulse()
    fxt_heartbeat._handler.openomci.omci_cc.send.assert_called_once()
    fxt_heartbeat._defer.addCallbacks.assert_called_once_with(fxt_heartbeat._heartbeat_success,
                                                              fxt_heartbeat._heartbeat_fail)


# Test Heartbeat.check_pulse() for exception from calling send()
def test_heartbeat_check_pulse_exception(fxt_heartbeat):
    with patch('voltha.adapters.adtran_onu.heartbeat.reactor.callLater') as mk_callLater:
        fxt_heartbeat._enabled = True
        fxt_heartbeat._handler.openomci.omci_cc.send.side_effect = exception = AssertionError()
        fxt_heartbeat.check_pulse()
    fxt_heartbeat._handler.openomci.omci_cc.send.assert_called_once()
    fxt_heartbeat._defer.addCallbacks.assert_not_called()
    mk_callLater.assert_called_once_with(5, fxt_heartbeat._heartbeat_fail, exception)


@pytest.mark.parametrize("id_code, id_resp, hb_miss, reason",
                         [('vendor_id', 'ADTN', 0, ''),
                          ('vendor_id', 'ABCD', HeartBeat.HEARTBEAT_FAILED_LIMIT,
                           "Invalid vendor_id, got 'ABCD' but expected 'ADTN'"),
                          ('invalid', 'bogus', HeartBeat.HEARTBEAT_FAILED_LIMIT,
                           "vendor_id")])
# Test Heartbeat._heartbeat_success() for various parametrized conditions
def test_heartbeat__heartbeat_success(fxt_heartbeat, id_code, id_resp, hb_miss, reason):
    results = MagicMock()
    results.getfieldval.return_value = MagicMock()
    results.getfieldval.return_value.getfieldval.return_value = {id_code: id_resp}
    fxt_heartbeat.heartbeat_check_status = MagicMock()
    fxt_heartbeat._heartbeat_miss = fxt_heartbeat.heartbeat_failed_limit + 1
    fxt_heartbeat._heartbeat_success(results)
    assert fxt_heartbeat._heartbeat_miss == hb_miss
    assert fxt_heartbeat.heartbeat_last_reason == reason
    fxt_heartbeat.heartbeat_check_status.assert_called_once_with()


# Test Heartbeat._heartbeat_fail() for incrementing _heartbeat_miss attribute and proper reason setting
def test_heartbeat__heartbeat_fail(fxt_heartbeat):
    fxt_heartbeat.heartbeat_check_status = MagicMock()
    fxt_heartbeat._heartbeat_miss = fxt_heartbeat.heartbeat_failed_limit - 1
    fxt_heartbeat._heartbeat_fail(None)
    assert fxt_heartbeat._heartbeat_miss == fxt_heartbeat.heartbeat_failed_limit
    assert fxt_heartbeat.heartbeat_last_reason == 'OMCI connectivity error'
    fxt_heartbeat.heartbeat_check_status.assert_called_once_with()


@pytest.mark.parametrize("active", [True, False])
# Test Heartbeat.on_heartbeat_alarm() property for expected operation
def test_heartbeat_on_heartbeat_alarm(fxt_heartbeat, active):
    fxt_heartbeat.on_heartbeat_alarm(active)


@pytest.mark.parametrize("hb_miss, dcs_in, aa_in, dcs_out, dos_out, dr_out, aa_out, arc, oha",
                         [(HeartBeat.HEARTBEAT_FAILED_LIMIT, ConnectStatus.REACHABLE, False, ConnectStatus.UNREACHABLE,
                          OperStatus.FAILED, 'REASON', True, 5, True),
                          (0, ConnectStatus.UNKNOWN, True, ConnectStatus.REACHABLE,
                           OperStatus.ACTIVE, '', False, 6, False)])
# Test Heartbeat.heartbeat_check_status() for various parametrized conditions
def test_heartbeat_heartbeat_check_status(fxt_heartbeat, hb_miss, dcs_in, aa_in, dcs_out, dos_out, dr_out, aa_out, arc, oha):
    with patch('voltha.adapters.adtran_onu.heartbeat.reactor.callLater') as mk_callLater, \
            patch('voltha.extensions.alarms.heartbeat_alarm.HeartbeatAlarm', autospec=True):
        fxt_heartbeat.on_heartbeat_alarm = MagicMock()
        fxt_heartbeat._handler.alarms = MagicMock()
        fxt_heartbeat._handler.adapter_agent = MagicMock()
        fxt_heartbeat._handler.adapter_agent.get_device.return_value = device = MagicMock()
        device.connect_status = dcs_in
        device.oper_status = OperStatus.UNKNOWN
        device.reason = None
        fxt_heartbeat.heartbeat_last_reason = 'REASON'
        fxt_heartbeat._heartbeat_miss = hb_miss
        fxt_heartbeat._alarm_active = aa_in
        fxt_heartbeat._alarms_raised_count = 5
        fxt_heartbeat._enabled = True
        fxt_heartbeat._heartbeat_count = 10
        fxt_heartbeat.heartbeat_check_status()

    fxt_heartbeat._handler.adapter_agent.update_device.assert_called_once_with(device)
    assert device.connect_status == dcs_out
    assert device.oper_status == dos_out
    assert device.reason == dr_out
    assert fxt_heartbeat._alarm_active == aa_out
    assert fxt_heartbeat._alarms_raised_count == arc
    fxt_heartbeat.on_heartbeat_alarm.assert_called_once_with(oha)
    fxt_heartbeat.log.exception.assert_not_called()
    assert fxt_heartbeat.heartbeat_count == 11
    mk_callLater.assert_called_once_with(fxt_heartbeat.heartbeat_interval, fxt_heartbeat.check_pulse)


# Test Heartbeat.heartbeat_check_status() for AssertionError in call to _handler.adapter_agent.update_device()
def test_heartbeat_heartbeat_check_status_error(fxt_heartbeat):
    with patch('voltha.adapters.adtran_onu.heartbeat.reactor.callLater') as mk_callLater, \
            patch('voltha.extensions.alarms.heartbeat_alarm.HeartbeatAlarm', autospec=True):
        fxt_heartbeat.on_heartbeat_alarm = MagicMock()
        fxt_heartbeat._handler.alarms = MagicMock()
        fxt_heartbeat._handler.adapter_agent = MagicMock()
        fxt_heartbeat._handler.adapter_agent.get_device.return_value = device = MagicMock()
        fxt_heartbeat._handler.adapter_agent.update_device.side_effect = AssertionError()
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.UNKNOWN
        device.reason = None
        fxt_heartbeat.heartbeat_last_reason = 'REASON'
        fxt_heartbeat._heartbeat_miss = HeartBeat.HEARTBEAT_FAILED_LIMIT
        fxt_heartbeat._alarm_active = False
        fxt_heartbeat._alarms_raised_count = 5
        fxt_heartbeat._enabled = False
        fxt_heartbeat._heartbeat_count = 10
        fxt_heartbeat.heartbeat_check_status()

    fxt_heartbeat._handler.adapter_agent.update_device.assert_called_once_with(device)
    fxt_heartbeat.log.exception.assert_called_once()
    assert fxt_heartbeat.heartbeat_count == 10
    mk_callLater.assert_not_called()
