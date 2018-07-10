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

from adapter_alarms import AlarmBase
from voltha.protos.events_pb2 import AlarmEventType, AlarmEventSeverity, AlarmEventCategory
"""
TODO:  To be Implemented in the openolt alarms
"""


class OnuActiveAlarm(AlarmBase):
    def __init__(self, handler, pon_id, serial_number, reg_id):
        super(OnuActiveAlarm, self).__init__(handler, 'ONU',
                                             alarm='ONU_ACTIVATED',
                                             alarm_category=AlarmEventCategory.PON,
                                             resource_id=pon_id,
                                             alarm_type=AlarmEventType.EQUIPMENT,
                                             alarm_severity=AlarmEventSeverity.CRITICAL)
        self._pon_id = pon_id
        self._serial_number = serial_number
        self._device_id = handler.device_id
        device = handler.adapter_agent.get_device(handler.device_id)
        self._olt_serial_number = device.serial_number
        self._host = device.ipv4_address
        self._datapath_id = device.parent_id
        self._reg_id = reg_id

    def get_context_data(self):
        return {
            'pon-id': self._pon_id,
            'serial-number': self._serial_number,
            'host': self._host,
            'olt_serial_number': self._olt_serial_number,
            'datapath_id': self._datapath_id,
            'device_id' : self._device_id,
            'registration_id' : self._reg_id
        }

    def clear_alarm(self):
        raise NotImplementedError('ONU Active Alarms are auto-clear')

