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


class OnuEquipmentAlarm(AlarmBase):
    """
    The ONU Equipment Alarm is reported by both the CircuitPack (ME #6) and
    the ONT-G (ME # 256) to indicate failure on an internal interface or
    failed self-test.

    For CircuitPack equipment alarms, the intf_id reported is that of the
    UNI's logical port number

    For ONT-G equipment alarms, the intf_id reported is that of the PON/ANI
    physical port number

    Note: Some ONUs may use this alarm to report a self-test failure or may
          may report it with a different alarm number specifically for a
          self-test failure.
    """
    def __init__(self, alarm_mgr, onu_id, intf_id):
        super(OnuEquipmentAlarm, self).__init__(alarm_mgr, object_type='onu equipment',
                                                alarm='ONU_EQUIPMENT',
                                                alarm_category=AlarmEventCategory.ONU,
                                                alarm_type=AlarmEventType.EQUIPTMENT,
                                                alarm_severity=AlarmEventSeverity.CRITICAL)
        self._onu_id = onu_id
        self._intf_id = intf_id

    def get_context_data(self):
        return {'onu-id': self._onu_id,
                'onu-intf-id': self._intf_id}
