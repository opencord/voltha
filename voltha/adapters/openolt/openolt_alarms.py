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
import voltha.adapters.openolt.openolt_platform as platform
from voltha.protos.device_pb2 import Port
from voltha.adapters.openolt.alarms.adapter_alarms import AdapterAlarms
from voltha.adapters.openolt.alarms.olt_los_alarm import OltLosAlarm
from voltha.adapters.openolt.alarms.onu_dying_gasp_alarm import OnuDyingGaspAlarm


class OpenOltAlarmMgr(object):
    def __init__(self, log, adapter_agent, device_id, logical_device_id):
        """
        20180711 -  Addition of adapter_agent and device_id
            to facilitate alarm processing and kafka posting
        :param log:
        :param adapter_agent:
        :param device_id:
        """
        self.log = log
        self.adapter_agent = adapter_agent
        self.device_id = device_id
        self.logical_device_id = logical_device_id
        try:
            self.alarms = AdapterAlarms(self.adapter_agent, self.device_id, self.logical_device_id)
        except Exception as initerr:
            self.log.exception("alarmhandler-init-error", errmsg=initerr.message)
            raise Exception(initerr)

    def process_alarms(self, alarm_ind):
        try:
            self.log.debug('alarm-indication', alarm=alarm_ind, device_id=self.device_id)
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

        try:
            self.log.debug('los indication received', los_ind=los_ind,
                           int_id=los_ind.intf_id, status=los_ind.status)

            try:

                if (los_ind.status == 1 or los_ind.status == "on"):
                    OltLosAlarm(self.alarms, alarm_indication=los_ind).raise_alarm()
                else:
                    OltLosAlarm(self.alarms, alarm_indication=los_ind).clear_alarm()
            except Exception as alarm_err:
                self.log.error('los-indication', errmsg=alarm_err.message)

        except Exception as e:
            self.log.error('los-indication', errmsg=e.message)

    def dying_gasp_indication(self, dying_gasp_ind):
        try:
            alarm_dgi = dying_gasp_ind
            onu_id = alarm_dgi.onu_id
            self.log.debug('openolt-alarmindication-dispatch-dying-gasp', int_id=alarm_dgi.intf_id,
                           onu_id=alarm_dgi.onu_id, status=alarm_dgi.status)
            try:
                """
                Get the ONU ID.  This isw necessary since the dirvers are 
                not passing the id.  They are using a placeholder
                """
                onu_device_id = "place_holder"
                try:
                    ind_onu_id = dying_gasp_ind.onu_id
                    onu_device = self.adapter_agent.get_child_device(
                        self.device_id,
                        parent_port_no=platform.intf_id_to_port_no(
                            dying_gasp_ind.intf_id, Port.PON_OLT),
                        onu_id=dying_gasp_ind.onu_id)
                    onu_device_id = onu_device.id
                except Exception as inner:
                    self.log.exception('dying-gasp-indication-resolve_onu-id', errmsg=inner.message)
                if (dying_gasp_ind.status == 1 or dying_gasp_ind.status == "on"):
                    OnuDyingGaspAlarm(self.alarms, dying_gasp_ind, onu_device_id).raise_alarm()
                else:
                    OnuDyingGaspAlarm(self.alarms, dying_gasp_ind, onu_device_id).clear_alarm()
            except Exception as alarm_err:
                self.log.exception('dying-gasp-indication', errmsg=alarm_err.message)

        except Exception as e:
            self.log.error('dying_gasp_indication', error=e)

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
