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

from voltha.extensions.alarms.adapter_alarms import AlarmBase
from voltha.protos.events_pb2 import AlarmEventType, AlarmEventSeverity, AlarmEventCategory


class OnuActiveAlarm(AlarmBase):
    def __init__(self, alarm_mgr, device_id, pon_id, onu_serial_number,
                 reg_id, olt_serial_number, ipv4_address=None, onu_id=None, datapath_id=None):
        super(OnuActiveAlarm, self).__init__(alarm_mgr, object_type='ONU',
                                             alarm='ONU_ACTIVATED',
                                             alarm_category=AlarmEventCategory.PON,
                                             resource_id=pon_id,
                                             alarm_type=AlarmEventType.EQUIPMENT,
                                             alarm_severity=AlarmEventSeverity.CRITICAL)
        self._pon_id = pon_id
        self._onu_id = onu_id
        self._onu_serial_number = onu_serial_number
        self._device_id = device_id
        self._olt_serial_number = olt_serial_number
        self._host = ipv4_address
        self._reg_id = reg_id
        self._datapath_id = datapath_id

    def get_context_data(self):
        data = {
            'pon_id': self._pon_id,
            'onu_id': self._onu_id,
            'serial_number': self._onu_serial_number,
            'olt_serial_number': self._olt_serial_number,
            'device_id': self._device_id,
            'registration_id': self._reg_id,
            'datapath_id': self._datapath_id
        }
        if self._host is not None:
            data['host'] = self._host

        return data

    def clear_alarm(self):
        raise NotImplementedError('ONU Active Alarms are auto-clear')

