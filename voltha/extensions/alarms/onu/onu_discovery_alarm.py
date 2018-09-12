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
from voltha.protos.events_pb2 import AlarmEventType, AlarmEventSeverity, AlarmEventCategory
from voltha.extensions.alarms.adapter_alarms import AlarmBase


class OnuDiscoveryAlarm(AlarmBase):
    def __init__(self, alarm_mgr, pon_id, serial_number):
        super(OnuDiscoveryAlarm, self).__init__(alarm_mgr, object_type='ONU Discovery',
                                                alarm='ONU_DISCOVERY',
                                                alarm_category=AlarmEventCategory.PON,
                                                resource_id=pon_id,
                                                alarm_type=AlarmEventType.EQUIPMENT,
                                                alarm_severity=AlarmEventSeverity.MAJOR)
        self._pon_id = pon_id
        self._serial_number = serial_number

    def get_context_data(self):
        return {
            'pon-id': self._pon_id,
            'serial-number': self._serial_number
        }

    def clear_alarm(self):
        raise NotImplementedError('ONU Discovery Alarms are auto-clear')
