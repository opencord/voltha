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

import structlog
import arrow
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory

# TODO: In the device adapter, the following alarms are still TBD
# TODO: In the device adapter, the following alarms are still TBD
#       (Taken from openolt_alarms


# onu_alarm_ind
# onu_startup_failure_indication
# onu_signal_degrade_indication
# onu_drift_of_window_ind
# onu_loss_omci_ind
# onu_signals_fail_ind
# onu_tiwi_ind
# onu_activation_fail_ind
# onu_processing_error_ind


class AdapterAlarms:
    def __init__(self, adapter, device_id, logical_device_id):
        self.log = structlog.get_logger(device_id=device_id)
        self.adapter = adapter
        self.device_id = device_id
        self.logical_device_id = logical_device_id
        self.lc = None

    def format_id(self, alarm):
        return 'voltha.{}.{}.{}'.format(self.adapter.adapter.name,
                                        self.device_id,
                                        alarm)

    def format_description(self, _object, alarm, status):
        return '{} Alarm - {} - {}'.format(_object.upper(),
                                           alarm.upper(),
                                           'Raised' if status else 'Cleared')

    def send_alarm(self, context_data, alarm_data):
        try:
            current_context = {}

            if isinstance(context_data, dict):
                for key, value in context_data.iteritems():
                    current_context[key] = str(value)

            alarm_event = self.adapter.create_alarm(
                id=alarm_data.get('id', 'voltha.{}.{}.olt'.format(self.adapter.adapter_name,
                                                                  self.device_id)),
                resource_id=str(alarm_data.get('resource_id', self.device_id)),
                description="{}.{} - {}".format(self.adapter.adapter_name, self.device_id,
                                                alarm_data.get('description')),
                type=alarm_data.get('type'),
                category=alarm_data.get('category'),
                severity=alarm_data.get('severity'),
                state=alarm_data.get('state'),
                raised_ts=alarm_data.get('ts', 0),
                context=current_context,
                logical_device_id=self.logical_device_id
            )
            self.adapter.submit_alarm(self.device_id, alarm_event)

        except Exception as e:
            self.log.exception('failed-to-send-alarm', e=e)
            raise Exception(e)


class AlarmBase(object):
    def __init__(self, handler, object_type, alarm,
                 alarm_category,
                 alarm_indication,
                 resource_id=None,
                 alarm_type=AlarmEventType.EQUIPMENT,
                 alarm_severity=AlarmEventSeverity.CRITICAL
                 ):

        self._handler = handler
        self._object_type = object_type
        self._alarm = alarm
        self._alarm_category = alarm_category
        self._alarm_type = alarm_type
        self._alarm_severity = alarm_severity
        self._resource_id = resource_id
        self.alarm_indication = alarm_indication

    def get_alarm_data(self, status):
        data = {
            'ts': arrow.utcnow().timestamp,
            'description': self._handler.format_description(self._object_type,
                                                            self._alarm,
                                                            status),
            'id': self._handler.format_id(self._alarm),
            'type': self._alarm_type,
            'category': self._alarm_category,
            'severity': self._alarm_severity,
            'state': AlarmEventState.RAISED if status else AlarmEventState.CLEARED
        }
        if self._resource_id is not None:
            data['resource_id'] = self._resource_id
        return data

    def get_context_data(self):
        return {}   # You should override this if needed

    def raise_alarm(self):
        alarm_data = self.get_alarm_data(True)
        context_data = self.get_context_data()
        self._handler.send_alarm(context_data, alarm_data)

    def clear_alarm(self):
        alarm_data = self.get_alarm_data(False)
        context_data = self.get_context_data()
        self._handler.send_alarm(context_data, alarm_data)
