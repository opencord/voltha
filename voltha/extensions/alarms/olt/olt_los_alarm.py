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


class OltLosAlarm(AlarmBase):
    def __init__(self, alarm_mgr, intf_id, port_type_name):
        super(OltLosAlarm, self).__init__(alarm_mgr, object_type='olt LOS',
                                          alarm='OLT_LOS',
                                          alarm_category=AlarmEventCategory.OLT,
                                          alarm_type=AlarmEventType.COMMUNICATION,
                                          alarm_severity=AlarmEventSeverity.MAJOR)
        # Added port type to indicate if alarm was on NNI or PON
        self._intf_id = intf_id
        self._port_type_name = port_type_name

    def get_context_data(self):
        return {'olt-intf-id:': self._intf_id,
                'olt-port-type-name': self._port_type_name}
