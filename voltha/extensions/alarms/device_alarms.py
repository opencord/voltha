#
# Copyright 2019 the original author or authors.
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
log = structlog.get_logger()


class DeviceAlarms:
    """
    Class for managing device alarms
    """
    def __init__(self, data_model):
        """
        Adapter alarm manager initializer

        :param data_model: data_model
        """
        self.log = structlog.get_logger()
        self.data_model = data_model
        self.lc = None

    def format_id(self, alarm):
        """
        Format the Unique Alarm ID for this alarm.  This is provided in the
        alarms 'id' field

        :param alarm: (str) The name of the alarm such as 'Discover' or 'LOS'

        :return: (str) Alarm ID
        """
        return 'voltha.{}.{}.{}'.format(self.data_model._adapter_name(),
                                        self.data_model._device_id(),
                                        alarm)

    def format_description(self, _object, alarm, status):
        """
        Format the textual description field of this alarm

        :param _object: ()
        :param alarm: (str) The name of the alarm such as 'Discover' or 'LOS'
        :param status: (bool) If True, the alarm is active (it is being raised)

        :return: (str) Alarm description
        """
        return '{} Alarm - {} - {}'.format(_object.upper(),
                                           alarm.upper(),
                                           'Raised' if status else 'Cleared')

    def send_alarm(self, context_data, alarm_data):
        """
        Send the alarm to the event bus

        :param context_data: (dict) Alarm specific context data
        :param alarm_data: (dict) Common Alarm information dictionary
        """
        try:
            current_context = {}
            if isinstance(context_data, dict):
                for key, value in context_data.iteritems():
                    current_context[key] = str(value)
            # FIXME - The entity that is raising the alarm needs to
            # provide the onu and olt serial numbers.
            alarm_event = self.data_model.create_alarm(
                id=alarm_data.get('id', 'voltha.{}.{}.olt'.format(
                    self.data_model._adapter_name(),
                    self.data_model._device_id())),
                resource_id=str(alarm_data.get('resource_id',
                                               self.data_model.device.id)),
                description="{}.{} - {}".format(self.data_model._adapter_name(),
                                                self.data_model._device_id(),
                                                alarm_data.get('description')),
                type=alarm_data.get('type'),
                category=alarm_data.get('category'),
                severity=alarm_data.get('severity'),
                state=alarm_data.get('state'),
                raised_ts=alarm_data.get('ts', 0),
                context=current_context,
                alarm_type_name=alarm_data.get('alarm_type_name')
            )
            self.data_model.submit_alarm(alarm_event)

        except Exception as e:
            self.log.exception('failed-to-send-alarm', e=e)
            raise
