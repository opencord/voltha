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
from voltha.extensions.pki.onu.onu_omci_pm import OnuOmciPmMetrics


class OnuPmMetrics(AdapterPmMetrics):
    """
    Shared ONU Device Adapter PM Metrics Manager

    This class specifically addresses ONU genernal PM (health, ...) area
    specific PM (OMCI, PON, UNI) is supported in encapsulated classes accessible
    from this object
    """
    def __init__(self, adapter_agent, device_id, grouped=False, freq_override=False, **kwargs):
        """
        Initializer for shared ONU Device Adapter PM metrics

        :param adapter_agent: (AdapterAgent) Adapter agent for the device
        :param device_id: (str) Device ID
        :param grouped: (bool) Flag indicating if statistics are managed as a group
        :param freq_override: (bool) Flag indicating if frequency collection can be specified
                                     on a per group basis
        :param kwargs: (dict) Device Adapter specific values. For an ONU Device adapter, the
                              expected key-value pairs are listed below. If not provided, the
                              associated PM statistics are not gathered:

                              'heartbeat': Reference to the a class that provides an ONU heartbeat
                                           statistics.   TODO: This needs to be standardized
        """
        super(OnuPmMetrics, self).__init__(adapter_agent, device_id,
                                           grouped=grouped, freq_override=freq_override, **kwargs)

        #
        # The following HeartBeat PM is only an example. We may want to have a common heartbeat
        # object for OLT and ONU DAs that work the same.  If so, it could also provide PM information
        #
        # TODO: In the actual 'collection' of PM data, I have the heartbeat stats disabled since
        #       there is not yet a common 'heartbeat' object
        #
        self.health_pm_names = {
            ('enabled', PmConfig.STATE),
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

        self.omci_pm = OnuOmciPmMetrics(adapter_agent, device_id, grouped=grouped,
                                        freq_override=freq_override, **kwargs)

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
                self.health_metrics_config[m.name].enabled = m.enabled

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
                                                group_freq=self.default_freq,
                                                enabled=True)
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

    def collect_group_metrics(self, metrics=None):
        # TODO: Currently PM collection is done for all metrics/groups on a single timer
        if metrics is None:
            metrics = dict()

        # TODO: Heartbeat stats disabled since it is not a common item on all ONUs (or OLTs)
        # if self._heartbeat is not None:
        #     metrics['heartbeat'] = self.collect_metrics(self._heartbeat,
        #                                                 self.health_pm_names,
        #                                                 self.health_metrics_config)
        self.omci_pm.collect_device_metrics(metrics=metrics)
        # TODO Add PON Port PM
        # TODO Add UNI Port PM
        return metrics
