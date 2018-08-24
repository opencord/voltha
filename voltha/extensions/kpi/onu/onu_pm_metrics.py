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
from voltha.extensions.kpi.adapter_pm_metrics import AdapterPmMetrics
from voltha.extensions.kpi.onu.onu_omci_pm import OnuOmciPmMetrics


class OnuPmMetrics(AdapterPmMetrics):
    """
    Shared ONU Device Adapter PM Metrics Manager

    This class specifically addresses ONU general PM (health, ...) area
    specific PM (OMCI, PON, UNI) is supported in encapsulated classes accessible
    from this object
    """

    # Metric default settings
    DEFAULT_HEARTBEAT_ENABLED = False
    DEFAULT_HEARTBEAT_FREQUENCY = 1200  # 1/10ths of a second
    #
    # Currently only a single KPI metrics collection occurs (individual group
    # frequency not supported). The next value defines this single frequency until
    # the KPI shared library supports individual collection.
    DEFAULT_ONU_COLLECTION_FREQUENCY = 60 * 10      # 1 minute

    def __init__(self, adapter_agent, device_id, logical_device_id,
                 grouped=False, freq_override=False, **kwargs):
        """
        Initializer for shared ONU Device Adapter PM metrics

        :param adapter_agent: (AdapterAgent) Adapter agent for the device
        :param device_id: (str) Device ID
        :param logical_device_id: (str) VOLTHA Logical Device ID
        :param grouped: (bool) Flag indicating if statistics are managed as a group
        :param freq_override: (bool) Flag indicating if frequency collection can be specified
                                     on a per group basis
        :param kwargs: (dict) Device Adapter specific values. For an ONU Device adapter, the
                              expected key-value pairs are listed below. If not provided, the
                              associated PMv statistics are not gathered:

                              'heartbeat': Reference to the a class that provides an ONU heartbeat
                                           statistics.   TODO: This should be standardized across adapters
        """
        super(OnuPmMetrics, self).__init__(adapter_agent, device_id, logical_device_id,
                                           grouped=grouped, freq_override=freq_override,
                                           **kwargs)

        # The following HeartBeat PM is only an example. We may want to have a common heartbeat
        # object for OLT and ONU DAs that work the same.  If so, it could also provide PM information
        #
        # TODO: In the actual 'collection' of PM data, I have the heartbeat stats disabled since
        #       there is not yet a common 'heartbeat' object
        #
        self.health_pm_names = {
            ('alarm_active', PmConfig.STATE),
            ('heartbeat_count', PmConfig.COUNTER),
            ('heartbeat_miss', PmConfig.COUNTER),
            ('alarms_raised_count', PmConfig.COUNTER),
            ('heartbeat_failed_limit', PmConfig.COUNTER),
            ('heartbeat_interval', PmConfig.COUNTER),
        }
        # TODO Add PON Port pollable PM as a separate class and include like OMCI
        # TODO Add UNI Port pollable PM as a separate class and include like OMCI
        self._heartbeat = kwargs.pop('heartbeat', None)
        self.health_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                      for (m, t) in self.health_pm_names}

        self.omci_pm = OnuOmciPmMetrics(adapter_agent, device_id, logical_device_id,
                                        grouped=grouped, freq_override=freq_override,
                                        **kwargs)

    def update(self, pm_config):
        try:
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
                msg = 'There are no independent ONU metrics, only group metrics at this time'
                raise NotImplemented(msg)

        except Exception as e:
            self.log.exception('update-failure', e=e)
            raise

        self.omci_pm.update(pm_config)

    def make_proto(self, pm_config=None):
        if pm_config is None:
            pm_config = PmConfigs(id=self.device_id,
                                  default_freq=self.default_freq,
                                  grouped=self.grouped,
                                  freq_override=self.freq_override)
        metrics = set()

        if self._heartbeat is not None:
            if self.grouped:
                pm_health_stats = PmGroupConfig(group_name='Heartbeat',
                                                group_freq=OnuPmMetrics.DEFAULT_HEARTBEAT_FREQUENCY,
                                                enabled=OnuPmMetrics.DEFAULT_HEARTBEAT_ENABLED)
                self.pm_group_metrics[pm_health_stats.group_name] = pm_health_stats
            else:
                pm_health_stats = pm_config

            # Add metrics to the PM Group (or as individual metrics_
            for m in sorted(self.health_metrics_config):
                pm = self.health_metrics_config[m]
                if not self.grouped:
                    if pm.name in metrics:
                        continue
                    metrics.add(pm.name)

                pm_health_stats.metrics.extend([PmConfig(name=pm.name,
                                                         type=pm.type,
                                                         enabled=pm.enabled)])
            if self.grouped:
                pm_config.groups.extend([pm_health_stats])

        # TODO Add PON Port PM
        # TODO Add UNI Port PM
        pm_config = self.omci_pm.make_proto(pm_config)
        return pm_config

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

        # TODO: Heartbeat stats disabled since it is not a common item on all ONUs (or OLTs)
        # if self._heartbeat is not None:
        #     data.extend(self.collect_metrics(self._heartbeat, self.health_pm_names,
        #                                      self.health_metrics_config))
        return self.omci_pm.collect_metrics(data=data)
