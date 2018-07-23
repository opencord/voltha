# Copyright 2017-present Open Networking Foundation
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
from voltha.extensions.pki.adapter_pm_metrics import AdapterPmMetrics
from voltha.extensions.pki.onu.onu_pm_interval_metrics import OnuPmIntervalMetrics


class OnuOmciPmMetrics(AdapterPmMetrics):
    def __init__(self, adapter_agent, device_id,
                 grouped=False, freq_override=False, **kwargs):
        """
        Initializer for shared ONU Device Adapter OMCI CC PM metrics

        :param adapter_agent: (AdapterAgent) Adapter agent for the device
        :param device_id: (str) Device ID
        :param grouped: (bool) Flag indicating if statistics are managed as a group
        :param freq_override: (bool) Flag indicating if frequency collection can be specified
                                     on a per group basis
        :param kwargs: (dict) Device Adapter specific values. For an ONU Device adapter, the
                              expected key-value pairs are listed below. If not provided, the
                              associated PM statistics are not gathered:

                              'omci-cc': Reference to the OMCI_CC object for retrieval of OpenOMCI
                                         Communications channel statistics. Available from the ONU's
                                         OpenOMCI OnuDeviceEntry object.
        """
        super(OnuOmciPmMetrics, self).__init__(adapter_agent, device_id,
                                               grouped=grouped, freq_override=freq_override,
                                               **kwargs)
        self._omci_cc = kwargs.pop('omci-cc', None)

        # PM Config Types are COUNTER, GUAGE, and STATE  # Note: GAUGE is misspelled in device.proto
        self.omci_pm_names = {
            ('enabled', PmConfig.STATE),
            ('tx_frames', PmConfig.COUNTER),
            ('tx_errors', PmConfig.COUNTER),
            ('rx_frames', PmConfig.COUNTER),
            ('rx_unknown_tid', PmConfig.COUNTER),
            ('rx_onu_frames', PmConfig.COUNTER),        # Rx ONU autonomous messages
            ('rx_alarm_overflow', PmConfig.COUNTER),    # Autonomous ONU generated alarm message overflows
            ('rx_avc_overflow', PmConfig.COUNTER),      # Autonomous ONU generated AVC message overflows
            ('rx_onu_discards', PmConfig.COUNTER),      # Autonomous ONU message unknown type discards
            ('rx_unknown_me', PmConfig.COUNTER),        # Managed Entities without a decode definition
            ('rx_timeouts', PmConfig.COUNTER),
            ('consecutive_errors', PmConfig.COUNTER),
            ('reply_min', PmConfig.GUAGE),      # Milliseconds
            ('reply_max', PmConfig.GUAGE),      # Milliseconds
            ('reply_average', PmConfig.GUAGE),  # Milliseconds
        }
        self.omci_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                    for (m, t) in self.omci_pm_names}

        self.openomci_interval_pm = OnuPmIntervalMetrics(adapter_agent, device_id)

    def update(self, pm_config):
        # TODO: Test both 'group' and 'non-group' functionality
        # TODO: Test frequency override capability for a particular group
        if self.default_freq != pm_config.default_freq:
            # Update the callback to the new frequency.
            self.default_freq = pm_config.default_freq
            self.lc.stop()
            self.lc.start(interval=self.default_freq / 10)

        if pm_config.grouped:
            for m in pm_config.groups:
                # TODO: Need to support individual group enable/disable
                pass
                # self.pm_group_metrics[m.group_name].config.enabled = m.enabled
                # if m.enabled is True:,
                #     self.enable_pm_collection(m.group_name, remote)
                # else:
                #     self.disable_pm_collection(m.group_name, remote)
        else:
            for m in pm_config.metrics:
                self.omci_metrics_config[m.name].enabled = m.enabled

        self.openomci_interval_pm.update(pm_config)

    def make_proto(self, pm_config=None):
        assert pm_config is not None

        if self._omci_cc is not None:
            if self.grouped:
                pm_omci_stats = PmGroupConfig(group_name='OMCI',
                                              group_freq=self.default_freq,
                                              enabled=True)
            else:
                pm_omci_stats = pm_config

            metrics = set()
            for m in sorted(self.omci_metrics_config):
                pm = self.omci_metrics_config[m]
                if not self.grouped:
                    if pm.name in metrics:
                        continue
                    metrics.add(pm.name)

                pm_omci_stats.metrics.extend([PmConfig(name=pm.name,
                                                       type=pm.type,
                                                       enabled=pm.enabled)])
            if self.grouped:
                pm_config.groups.extend([pm_omci_stats])

        return self.openomci_interval_pm.make_proto(pm_config)

    def collect_device_metrics(self, metrics=None):
        # TODO: Currently PM collection is done for all metrics/groups on a single timer
        if metrics is None:
            metrics = dict()

        # Note: Interval PM is collection done autonomously, not through this method

        if self._omci_cc is not None:
            metrics['omci-cc'] = self.collect_metrics(self._omci_cc,
                                                      self.omci_pm_names,
                                                      self.omci_metrics_config)
        return metrics
