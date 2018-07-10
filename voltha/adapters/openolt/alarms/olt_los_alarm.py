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
from adapter_alarms import AlarmBase


class OltLosAlarm(AlarmBase):
    def __init__(self, handler, alarm_indication):
        try:
            super(OltLosAlarm, self).__init__(handler, 'olt LOS',
                                              alarm='LOS',
                                              alarm_indication=alarm_indication,
                                              alarm_category=AlarmEventCategory.OLT,
                                              alarm_type=AlarmEventType.COMMUNICATION,
                                              alarm_severity=AlarmEventSeverity.MAJOR)
            self._intf_id = self.alarm_indication.intf_id
            self._status = self.alarm_indication.status
        except Exception as e:
            self._handler.adapter.log.exception("olt-los-alarm-object", errmsg=e.message)
            raise Exception(e)

    def get_context_data(self):
        try:
            retval = {'olt-id': self._handler.device_id,
                      'logical-device-id': self._handler.logical_device_id,
                      'olt-intf-id:': self.alarm_indication.intf_id
                      }
        except Exception as e:
            raise Exception(e)
        return retval
