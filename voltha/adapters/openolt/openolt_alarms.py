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



class OpenOltAlarmMgr(object):
    def __init__(self, log):
        self.log = log

    def process_alarms(self, alarm_ind):
        self.log.debug('alarm indication', alarm=alarm_ind)

        try:

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
            self.log.info('los indication', intf_id=los_ind.intf_id,
                          status=los_ind.status)
        except Exception as e:
            self.log.error('error parsing los indication', error=e)

    def dying_gasp_indication(self, dying_gasp_ind):
        self.log.info('not implemented yet')

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