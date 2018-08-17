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

from voltha.protos.device_pb2 import PmConfig, PmGroupConfig
from voltha.extensions.kpi.adapter_pm_metrics import AdapterPmMetrics
from voltha.extensions.kpi.onu.onu_pm_interval_metrics import OnuPmIntervalMetrics


class OnuOmciPmMetrics(AdapterPmMetrics):
    """ ONU OMCI related metrics """

    # Metric default settings
    DEFAULT_OMCI_CC_ENABLED = False
    DEFAULT_OMCI_CC_FREQUENCY = 1200        # 1/10ths of a second

    OMCI_CC_GROUP_NAME = 'OMCI_CC'

    def __init__(self, adapter_agent, device_id, logical_device_id,
                 grouped=False, freq_override=False, **kwargs):
        """
        Initializer for shared ONU Device Adapter OMCI CC PM metrics

        :param adapter_agent: (AdapterAgent) Adapter agent for the device
        :param device_id: (str) Device ID
        :param logical_device_id: (str) VOLTHA Logical Device ID
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
        super(OnuOmciPmMetrics, self).__init__(adapter_agent, device_id, logical_device_id,
                                               grouped=grouped, freq_override=freq_override,
                                               **kwargs)
        self._omci_cc = kwargs.pop('omci-cc', None)

        self.omci_pm_names = {
            ('tx_frames', PmConfig.COUNTER),
            ('tx_errors', PmConfig.COUNTER),
            ('rx_frames', PmConfig.COUNTER),
            ('rx_unknown_tid', PmConfig.COUNTER),
            ('rx_onu_frames', PmConfig.COUNTER),        # Rx ONU autonomous messages
            ('rx_unknown_me', PmConfig.COUNTER),        # Managed Entities without a decode definition
            ('rx_timeouts', PmConfig.COUNTER),
            ('consecutive_errors', PmConfig.COUNTER),
            ('reply_min', PmConfig.GAUGE),      # Milliseconds
            ('reply_max', PmConfig.GAUGE),      # Milliseconds
            ('reply_average', PmConfig.GAUGE),  # Milliseconds
        }
        self.omci_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                    for (m, t) in self.omci_pm_names}

        self.openomci_interval_pm = OnuPmIntervalMetrics(adapter_agent, device_id, logical_device_id)

    def update(self, pm_config):
        # TODO: Test frequency override capability for a particular group
        if self.default_freq != pm_config.default_freq:
            # Update the callback to the new frequency.
            self.default_freq = pm_config.default_freq
            self.lc.stop()
            self.lc.start(interval=self.default_freq / 10)

        if pm_config.grouped:
            for group in pm_config.groups:
                group_config = self.pm_group_metrics.get(group.group_name)
                if group_config is not None:
                    group_config.enabled = group.enabled
        else:
            for m in pm_config.metrics:
                self.omci_metrics_config[m.name].enabled = m.enabled

        self.openomci_interval_pm.update(pm_config)

    def make_proto(self, pm_config=None):
        assert pm_config is not None

        if self._omci_cc is not None:
            if self.grouped:
                pm_omci_stats = PmGroupConfig(group_name=OnuOmciPmMetrics.OMCI_CC_GROUP_NAME,
                                              group_freq=OnuOmciPmMetrics.DEFAULT_OMCI_CC_FREQUENCY,
                                              enabled=OnuOmciPmMetrics.DEFAULT_OMCI_CC_ENABLED)
                self.pm_group_metrics[pm_omci_stats.group_name] = pm_omci_stats
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

    def collect_metrics(self, data=None):
        """
        Collect metrics for this adapter.

        The data collected (or passed in) is a list of pairs/tuples.  Each
        pair is composed of a MetricMetaData metadata-portion and list of MetricValuePairs
        that contains a single individual metric or list of metrics if this is a
        group metric.

        This method is called for each adapter at a fixed frequency.
        TODO: Currently all group metrics are collected on a single timer tick.
              This needs to be fixed as independent group or instance collection is
              desirable.

        :param data: (list) Existing list of collected metrics (MetricInformation).
                            This is provided to allow derived classes to call into
                            further encapsulated classes.

        :return: (list) metadata and metrics pairs - see description above
        """
        if data is None:
            data = list()

        # Note: Interval PM is collection done autonomously, not through this method

        if self._omci_cc is not None:
            group_name = OnuOmciPmMetrics.OMCI_CC_GROUP_NAME
            if self.pm_group_metrics[group_name].enabled:
                group_data = self.collect_group_metrics(group_name,
                                                        self._omci_cc,
                                                        self.omci_pm_names,
                                                        self.omci_metrics_config)
                if group_data is not None:
                    data.append(group_data)
        return data
