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
from voltha.protos.events_pb2 import AlarmEventType, AlarmEventSeverity,\
    AlarmEventState, AlarmEventCategory
log = structlog.get_logger()


# TODO: In the device adapter, the following alarms are still TBD
#       (Taken from openolt_alarms)
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
    """
    Class for managing Alarms within a given Device Handler instance
    """
    def __init__(self, adapter_agent, device_id, logical_device_id):
        """
        Adapter alarm manager initializer

        :param adapter_agent: (AdapterAgent) Adapter agent reference
        :param device_id: (str) Device handler's unique device id
        :param logical_device_id: (str) Logical Device that the device is a member of
        """
        self.log = structlog.get_logger(device_id=device_id)
        self.adapter_agent = adapter_agent
        self.device_id = device_id
        self.logical_device_id = logical_device_id
        self.adapter_name = adapter_agent.adapter_name
        self.lc = None

    def format_id(self, alarm):
        """
        Format the Unique Alarm ID for this alarm.  This is provided in the alarms
        'id' field

        :param alarm: (str) The name of the alarm such as 'Discover' or 'LOS'

        :return: (str) Alarm ID
        """
        return 'voltha.{}.{}.{}'.format(self.adapter_name,
                                        self.device_id,
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
            ser_num = None
            device = self.adapter_agent.get_device(device_id=self.device_id)
            ser_num = device.serial_number


            """
            Only put in the onu serial numbers since the OLT does not currently have a serial number and the
            value is the ip:port address.
            """
            if isinstance(context_data, dict) and '_onu' in device.type.lower():
                current_context["onu_serial_number"] = ser_num
            alarm_event = self.adapter_agent.create_alarm(
                id=alarm_data.get('id', 'voltha.{}.{}.olt'.format(self.adapter_name,
                                                                  self.device_id)),
                resource_id=str(alarm_data.get('resource_id', self.device_id)),
                description="{}.{} - {}".format(self.adapter_name, self.device_id,
                                                alarm_data.get('description')),
                type=alarm_data.get('type'),
                category=alarm_data.get('category'),
                severity=alarm_data.get('severity'),
                state=alarm_data.get('state'),
                raised_ts=alarm_data.get('ts', 0),
                context=current_context,
                logical_device_id=self.logical_device_id,
                alarm_type_name=alarm_data.get('alarm_type_name')
            )
            self.adapter_agent.submit_alarm(self.device_id, alarm_event)

        except Exception as e:
            self.log.exception('failed-to-send-alarm', e=e)
            raise


class AlarmBase(object):
    """Base class for alarms"""
    def __init__(self, alarm_mgr, object_type, alarm,
                 alarm_category,
                 resource_id=None,
                 alarm_type=AlarmEventType.EQUIPMENT,
                 alarm_severity=AlarmEventSeverity.CRITICAL):
        """
        Initializer for the Alarm base class

        :param alarm_mgr: (AdapterAlarms) Reference to the device handler's Adapter
                                          Alarm manager
        :param object_type: (str) Type of device generating the alarm such as 'olt' or 'onu'
        :param alarm: (str) A textual name for the alarm such as 'HeartBeat' or 'Discovery'
        :param alarm_category: (AlarmEventCategory) Refers to functional category of
                                                    the alarm
        :param resource_id: (str) Identifier of the originating resource of the alarm
        :param alarm_type: (AlarmEventType) Refers to the area of the system impacted
                                            by the alarm
        :param alarm_severity: (AlarmEventSeverity) Overall impact of the alarm on the
                                                    system
        """
        self._alarm_mgr = alarm_mgr
        self._object_type = object_type
        self._alarm = alarm
        self._alarm_category = alarm_category
        self._alarm_type = alarm_type
        self._alarm_severity = alarm_severity
        self._resource_id = resource_id

    def get_alarm_data(self, status):
        """
        Get the alarm specific data and format it into a dictionary.  When the alarm
        is being sent to the event bus, this dictionary provides a majority of the
        fields for the alarms.

        :param status: (bool) True if the alarm is active/raised
        :return: (dict) Alarm data
        """
        data = {
            'ts': arrow.utcnow().timestamp,
            'description': self._alarm_mgr.format_description(self._object_type,
                                                              self._alarm,
                                                              status),
            'id': self._alarm_mgr.format_id(self._alarm),
            'type': self._alarm_type,
            'category': self._alarm_category,
            'severity': self._alarm_severity,
            'state': AlarmEventState.RAISED if status else AlarmEventState.CLEARED,
            'alarm_type_name': self._alarm
        }
        if self._resource_id is not None:
            data['resource_id'] = self._resource_id
        return data

    def get_context_data(self):
        """
        Get alarm specific context data. If an alarm has specific data to specify, it is
        included in the context field in the published event

        :return: (dict) Dictionary with alarm specific context data
        """
        return {}   # NOTE: You should override this if needed

    def raise_alarm(self):
        """
        Called to set the state of an alarm to active and to send it to the event bus
        """
        alarm_data = self.get_alarm_data(True)
        context_data = self.get_context_data()
        self._alarm_mgr.send_alarm(context_data, alarm_data)

    def clear_alarm(self):
        """
        Called to set the state of an alarm to inactive and to send it to the event bus
        """
        alarm_data = self.get_alarm_data(False)
        context_data = self.get_context_data()
        self._alarm_mgr.send_alarm(context_data, alarm_data)
