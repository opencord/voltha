#
# Copyright 2018 the original author or authors.
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
#

import arrow
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory

class OpenOltAlarmMgr(object):
    def __init__(self, log, adapter_agent):
        self.log = log
        self.adapter_agent = adapter_agent

    def process_alarms(self, alarm_ind, device_id):
        self.log.debug('alarm indication', alarm=alarm_ind)

        try:
            self.device_id = device_id
            if alarm_ind.HasField('los_ind'):
                self.los_indication(alarm_ind.los_ind)
            elif alarm_ind.HasField('dying_gasp_ind'):
                self.dying_gasp_indication(alarm_ind.dying_gasp_ind)
            elif alarm_ind.HasField('onu_alarm_ind'):
                self.onu_alarm_indication(alarm_ind.onu_alarm_ind)
            elif alarm_ind.HasField('onu_startup_fail_ind'):
                self.onu_startup_failure_indication(
                    alarm_ind.onu_startup_fail_ind)
            elif alarm_ind.HasField('onu_signal_degrade_ind'):
                self.onu_signal_degrade_indication(
                    alarm_ind.onu_signal_degrade_ind)
            elif alarm_ind.HasField('onu_drift_of_window_ind'):
                self.onu_drift_of_window_indication(
                    alarm_ind.onu_drift_of_window_ind)
            elif alarm_ind.HasField('onu_loss_omci_ind'):
                self.onu_loss_omci_indication(alarm_ind.onu_loss_omci_ind)
            elif alarm_ind.HasField('onu_signals_fail_ind'):
                self.onu_signals_failure_indication(
                    alarm_ind.onu_signals_fail_ind)
            elif alarm_ind.HasField('onu_tiwi_ind'):
                self.onu_transmission_interference_warning(
                    alarm_ind.onu_tiwi_ind)
            elif alarm_ind.HasField('onu_activation_fail_ind'):
                self.onu_activation_failure_indication(
                    alarm_ind.onu_activation_fail_ind)
            elif alarm_ind.HasField('onu_processing_error_ind'):
                self.onu_processing_error_indication(
                    alarm_ind.onu_processing_error_ind)
            else:
                self.log.warn('unknow alarm type', alarm=alarm_ind)

        except Exception as e:
            self.log.error('sorting of alarm went wrong', error=e,
                           alarm=alarm_ind)

    def los_indication(self, los_ind):
        self.log.debug('los indication received', los_ind=los_ind)
        try:

            self.log.debug('openolt-alarmindication-dispatch-los', int_id=los_ind.intf_id, \
                           status=los_ind.status)
            self.olt_los_alarm(self.device_id, los_ind.intf_id, \
                               los_ind.status)

            self.log.info('los indication', intf_id=los_ind.intf_id,
                          status=los_ind.status)
        except Exception as e:
            self.log.error('error parsing los indication', error=e)

    def dying_gasp_indication(self, dying_gasp_ind):
        try:
            alarm_dgi = dying_gasp_ind
            onu_id = alarm_dgi.onu_id
            self.log.debug('openolt-alarmindication-dispatch-dying-gasp', int_id=alarm_dgi.intf_id, \
                           onu_id=alarm_dgi.onu_id, status=alarm_dgi.status)
            self.olt_subs_term_dgi_alarm(self.device_id, alarm_dgi.intf_id, \
                                         onu_id, alarm_dgi.status)
        except Exception as e:
            self.log.error('error parsing dying_gasp_indication indication', error=e)

    def onu_alarm_indication(self, onu_alarm_ind):
        self.log.info('not implemented yet')

    def onu_startup_failure_indication(self, onu_startup_fail_ind):
        self.log.info('not implemented yet')

    def onu_signal_degrade_indication(self, onu_signal_degrade_ind):
        self.log.info('not implemented yet')

    def onu_drift_of_window_indication(self, onu_drift_of_window_ind):
        self.log.info('not implemented yet')

    def onu_loss_omci_indication(self, onu_loss_omci_ind):
        self.log.info('not implemented yet')

    def onu_signals_failure_indication(self, onu_signals_fail_ind):
        self.log.info('not implemented yet')

    def onu_transmission_interference_warning(self, onu_tiwi_ind):
        self.log.info('not implemented yet')

    def onu_activation_failure_indication(self, onu_activation_fail_ind):
        self.log.info('not implemented yet')

    def onu_processing_error_indication(self, onu_processing_error_ind):
        self.log.info('not implemented yet')




    """ Methods"""

    def olt_los_alarm(self, device_id, Iface_ID,\
                         los_status):

        """

        :param device_id:
        :param Iface_ID:
        :param los_status:
        :param IfaceLos_data:
        :return:
        """
        try:
            IfaceLos_data = {}
            IfaceLos_data["los_status"] = los_status.__str__()
            IfaceLos_data["olt_id"] = device_id.__str__()

            self.log.info('olt-iface-los-alarm-call-handle')
            self.handle_alarms(device_id,"pon_ni",\
                               Iface_ID,\
                               "loss_of_signal",los_status,"high",\
                               IfaceLos_data)
        except Exception as err:
            self.log.error('olt-iface-los-alarm-call-handle', error=err.message)
        return



    def olt_subs_term_los_alarm(self, device_id, Iface_ID,
                         los_status, SubTermAlarm_Data):
        self.log.info('ONU-Alarms-for-Subscriber-Terminal-LOS')
        self.handle_alarms(device_id,"onu",\
                           Iface_ID,\
                           "ONU : Loss Of Signal",\
                           los_status, "medium",\
                           SubTermAlarm_Data)

    def olt_subs_term_dgi_alarm(self, device_id, intf_id, \
                                onu_id, dgi_status):
        """
        This handles the dying gasp signal from the ONU supporting the subscriber endpoint.
        20810706:   Currently triggering this can be accomplished by pulling power on the ONU.  The dying gasp
            signal will be generated.   Sending an onu reboot signal does not generate the alarm.

        :param device_id:
        :param intf_id:
        :param onu_id:
        :param dgi_status:
        :param balSubTermDgi_data:
        :param ind_info:
        :return:
        """

        try:
            self.log.info('Subscriber-terminal-dying-gasp')
            subTermDgi_data = {}
            subTermDgi_data["dgi_status"] = dgi_status.__str__()
            subTermDgi_data["onu_id"] = onu_id.__str__()
            ind_info = dict()
            ind_info['_object_type'] = 'sub_term_indication'
            ind_info['_sub_group_type'] = 'dgi_indication'

            """
            Note:  The alarm_data structure must be of a compatible structure for the alarmevent type
                    if it is not and error will be generated that is less than intuitive
            """
            self.handle_alarms(device_id, "pon_ni", \
                               intf_id, \
                               "subscriber_onu_dying_gasp", dgi_status, "medium", \
                               subTermDgi_data)
            if dgi_status == 1 or dgi_status == "on":
                """
                Currently the onu_id that is passed represents the onu channel id on the olt.  
                If the onu_channel_num is passed then the onu_id will be resolved by the lookup
                using the proxy address channel ID
                """
                child_device = self.adapter_agent.get_child_device(
                    device_id, onu_id=onu_id,
                    parent_port_no=intf_id)
                if child_device is None:
                    self.log.info('Onu-is-not-configured', onu_id=onu_id)
                    return
                msg = {'proxy_address': child_device.proxy_address,
                       'event': 'deactivate-onu', 'event_data': ind_info}
                # Send the event message to the ONU adapter
                self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                               msg)
        except Exception as err:
            self.log.exceptiuon('Subscriber-terminal-dying-gasp', onu_id=onu_id, errmsg=err.message)

    """
       The primary alarm dispatcher. 
       The alarms get set up in the above methods that in turn 
       send to these methods
       """
    def handle_alarms(self, _device_id, _object, resource_id, alarm,
                      status, priority,
                      alarm_data=None):
        """

        :param _device_id:
        :param _object:
        :param key:
        :param alarm:
        :param status:
        :param priority:
        :param alarm_data:
        :return:
        """

        try:
            self.log.info('handle-alarms-received-alarm-msg',
                          object=_object,
                          resource_id=resource_id,
                          alarm=alarm,
                          status=status,
                          priority=priority,
                          alarm_data=alarm_data)
            id = 'voltha.{}.{}.{}'.format("open_olt",
                                          _device_id, _object)
            description = '{} Alarm - {} - {}'.format(_object.upper(),
                                                      alarm.upper(),
                                                      'Raised' if status else 'Cleared')
            if priority == 'low':
                severity = AlarmEventSeverity.MINOR
            elif priority == 'medium':
                severity = AlarmEventSeverity.MAJOR
            elif priority == 'high':
                severity = AlarmEventSeverity.CRITICAL
            else:
                severity = AlarmEventSeverity.INDETERMINATE
            ts = arrow.utcnow().timestamp
            self.log.info('handle-alarms-submitting')
            try:
                alarm_event = self.adapter_agent.create_alarm(
                    id=id,
                    resource_id=str(resource_id),
                    type=AlarmEventType.EQUIPMENT,
                    category=AlarmEventCategory.PON,
                    severity=severity,
                    state=AlarmEventState.RAISED if status == 'raised' else AlarmEventState.CLEARED,
                    description=description,
                    context=alarm_data,
                    raised_ts=ts)
            except Exception as createErr:
                self.log.exception("handle-alarms-submitted", errmsg=createErr.message)
            self.adapter_agent.submit_alarm(_device_id, alarm_event)
            self.log.info('handle-alarms-submitted')
        except Exception as e:
            self.log.exception('handle-alarms-failed-to-submit-alarm', errmsg=e.message)

        # take action based on alarm type, only pon_ni and onu objects report alarms
        if object == 'pon_ni':
            # place holder for future handling
            pass
        elif object == 'onu':
            # place holder for future handling
            pass