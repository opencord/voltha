# Copyright 2017-present Adtran, Inc.
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

from voltha.protos.device_pb2 import PmConfig, PmConfigs, PmGroupConfig
from ..adtran_olt.pki.adapter_pm_metrics import AdapterPmMetrics


class OnuPmMetrics(AdapterPmMetrics):
    def __init__(self, handler, device, grouped=False, freq_override=False):
        super(OnuPmMetrics, self).__init__(handler, device,
                                           grouped=grouped, freq_override=freq_override)

        # PM Config Types are COUNTER, GUAGE, and STATE  # Note: GAUGE is misspelled in device.proto
        self.omci_pm_names = {
            ('enabled', PmConfig.STATE),
            ('tx_frames', PmConfig.COUNTER),
            ('tx_errors', PmConfig.COUNTER),
            ('rx_frames', PmConfig.COUNTER),
            ('rx_unknown_tid', PmConfig.COUNTER),
            ('rx_onu_frames', PmConfig.COUNTER),        # Rx ONU autonomouse messages
            ('rx_alarm_overflow', PmConfig.COUNTER),    # Autonomous ONU generated alarm message overflows
            ('rx_avc_overflow', PmConfig.COUNTER),      # Autonomous ONU generated AVC message overflows
            ('rx_onu_discards', PmConfig.COUNTER),      # Autonomous ONU message unknown type discards
            ('rx_timeouts', PmConfig.COUNTER),
            ('consecutive_errors', PmConfig.COUNTER),
            ('reply_min', PmConfig.GUAGE),      # Milliseconds
            ('reply_max', PmConfig.GUAGE),      # Milliseconds
            ('reply_average', PmConfig.GUAGE),  # Milliseconds
        }
        self.health_pm_names = {
            ('enabled', PmConfig.STATE),
            ('alarm_active', PmConfig.STATE),
            ('heartbeat_count', PmConfig.COUNTER),
            ('heartbeat_miss', PmConfig.COUNTER),
            ('alarms_raised_count', PmConfig.COUNTER),
            ('heartbeat_failed_limit', PmConfig.COUNTER),
            ('heartbeat_interval', PmConfig.COUNTER),
        }
        # TODO Add PON Port PM
        # TODO Add UNI Port PM

        self.omci_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                    for (m, t) in self.omci_pm_names}
        self.health_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                      for (m, t) in self.health_pm_names}

    def update(self, pm_config):
        # TODO: Test both 'group' and 'non-group' functionality
        # TODO: Test frequency override capability for a particular group
        if self.default_freq != pm_config.default_freq:
            # Update the callback to the new frequency.
            self.default_freq = pm_config.default_freq
            self.lc.stop()
            self.lc.start(interval=self.default_freq / 10)

        if pm_config.grouped is True:
            for m in pm_config.groups:
                pass
                # self.pm_group_metrics[m.group_name].config.enabled = m.enabled
                # if m.enabled is True:,
            ('tx_errors', PmConfig.COUNTER),
            ('rx_frames', PmConfig.COUNTER),
                #     self.enable_pm_collection(m.group_name, remote)
                # else:
                #     self.disable_pm_collection(m.group_name, remote)
        else:
            for m in pm_config.metrics:
                self.omci_metrics_config[m.name].enabled = m.enabled
                self.health_metrics_config[m.name].enabled = m.enabled

    def make_proto(self):
        pm_config = PmConfigs(id=self.id, default_freq=self.default_freq,
                              grouped=self.grouped,
                              freq_override=self.freq_override)
        metrics = set()

        if self.grouped:
            pm_omci_stats = PmGroupConfig(group_name='OMCI',
                                          group_freq=self.default_freq,
                                          enabled=True)

            pm_health_stats = PmGroupConfig(group_name='Heartbeat',
                                            group_freq=self.default_freq,
                                            enabled=True)
            # TODO Add PON Port PM
            # TODO Add UNI Port PM
        else:
            pm_omci_stats = pm_config
            pm_health_stats = pm_config
            # TODO Add PON Port PM
            # TODO Add UNI Port PM

        for m in sorted(self.omci_metrics_config):
            pm = self.omci_metrics_config[m]
            if not self.grouped:
                if pm.name in metrics:
                    continue
                metrics.add(pm.name)

            pm_omci_stats.metrics.extend([PmConfig(name=pm.name,
                                                   type=pm.type,
                                                   enabled=pm.enabled)])

        for m in sorted(self.health_metrics_config):
            pm = self.health_metrics_config[m]
            if not self.grouped:
                if pm.name in metrics:
                    continue
                metrics.add(pm.name)

            pm_health_stats.metrics.extend([PmConfig(name=pm.name,
                                                     type=pm.type,
                                                     enabled=pm.enabled)])

        return pm_config

    def collect_port_metrics(self):
        metrics = dict()
        metrics['omci'] = self.collect_metrics(self.handler.omci,
                                               self.omci_pm_names,
                                               self.omci_metrics_config)

        metrics['heartbeat'] = self.collect_metrics(self.handler.heartbeat,
                                                    self.health_pm_names,
                                                    self.health_metrics_config)

        # TODO Add PON Port PM
        # TODO Add UNI Port PM

        return metrics





