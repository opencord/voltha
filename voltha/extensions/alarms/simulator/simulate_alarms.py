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

from voltha.extensions.alarms.olt.olt_los_alarm import OltLosAlarm
from voltha.extensions.alarms.onu.onu_dying_gasp_alarm import OnuDyingGaspAlarm
from voltha.extensions.alarms.onu.onu_los_alarm import OnuLosAlarm
from voltha.extensions.alarms.onu.onu_lopc_miss_alarm import OnuLopcMissAlarm
from voltha.extensions.alarms.onu.onu_lopc_mic_error_alarm import OnuLopcMicErrorAlarm
from voltha.extensions.alarms.onu.onu_lob_alarm import OnuLobAlarm

from voltha.extensions.alarms.onu.onu_startup_alarm import OnuStartupAlarm
from voltha.extensions.alarms.onu.onu_signal_degrade_alarm import OnuSignalDegradeAlarm
from voltha.extensions.alarms.onu.onu_signal_fail_alarm import OnuSignalFailAlarm
from voltha.extensions.alarms.onu.onu_window_drift_alarm import OnuWindowDriftAlarm
from voltha.extensions.alarms.onu.onu_activation_fail_alarm import OnuActivationFailAlarm

from voltha.extensions.alarms.onu.onu_discovery_alarm import OnuDiscoveryAlarm

class AdapterAlarmSimulator(object):
    def __init__(self, adapter_alarms):
        self.adapter_alarms = adapter_alarms

    def simulate_alarm(self, alarm):
        if alarm.indicator == "los":
            alarm_obj = OltLosAlarm(self.adapter_alarms, intf_id=alarm.intf_id, port_type_name=alarm.port_type_name)
        elif alarm.indicator == "dying_gasp":
            alarm_obj = OnuDyingGaspAlarm(self.adapter_alarms, onu_id=alarm.onu_device_id, intf_id=alarm.intf_id)
        elif alarm.indicator == "onu_los":
            alarm_obj = OnuLosAlarm(self.adapter_alarms, onu_id=alarm.onu_device_id, intf_id=alarm.intf_id)
        elif alarm.indicator == "onu_lopc_miss":
            alarm_obj = OnuLopcMissAlarm(self.adapter_alarms, onu_id=alarm.onu_device_id, intf_id=alarm.intf_id)
        elif alarm.indicator == "onu_lopc_mic":
            alarm_obj = OnuLopcMicErrorAlarm(self.adapter_alarms, onu_id=alarm.onu_device_id, intf_id=alarm.intf_id)
        elif alarm.indicator == "onu_lob":
            alarm_obj = OnuLobAlarm(self.adapter_alarms, onu_id=alarm.onu_device_id, intf_id=alarm.intf_id)
        elif alarm.indicator == "onu_startup":
            alarm_obj = OnuStartupAlarm(self.adapter_alarms, intf_id=alarm.intf_id, onu_id=alarm.onu_device_id)
        elif alarm.indicator == "onu_signal_degrade":
            alarm_obj = OnuSignalDegradeAlarm(self.adapter_alarms, intf_id=alarm.intf_id, onu_id=alarm.onu_device_id,
                                  inverse_bit_error_rate=alarm.inverse_bit_error_rate)
        elif alarm.indicator == "onu_drift_of_window":
            alarm_obj = OnuWindowDriftAlarm(self.adapter_alarms, intf_id=alarm.intf_id,
                                onu_id=alarm.onu_device_id,
                                drift=alarm.drift,
                                new_eqd=alarm.new_eqd)
        elif alarm.indicator == "onu_signal_fail":
            alarm_obj = OnuSignalFailAlarm(self.adapter_alarms, intf_id=alarm.intf_id,
                               onu_id=alarm.onu_device_id,
                               inverse_bit_error_rate=alarm.inverse_bit_error_rate)
        elif alarm.indicator == "onu_activation":
            alarm_obj = OnuActivationFailAlarm(self.adapter_alarms, intf_id=alarm.intf_id,
                                   onu_id=alarm.onu_device_id)
        elif alarm.indicator == "onu_discovery":
            alarm_obj = OnuDiscoveryAlarm(self.adapter_alarms, pon_id=alarm.intf_id,
                                   serial_number=alarm.onu_serial_number)
        else:
            raise Exception("Unknown alarm indicator %s" % alarm.indicator)

        if alarm.operation == alarm.RAISE:
            alarm_obj.raise_alarm()
        elif alarm.operation == alarm.CLEAR:
            alarm_obj.clear_alarm()
        else:
            # This shouldn't happen
            raise Exception("Unknown alarm operation")
