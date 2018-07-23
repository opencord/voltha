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
from voltha.extensions.omci.omci_entities import EthernetFrameUpstreamPerformanceMonitoringHistoryData, \
    EthernetFrameDownstreamPerformanceMonitoringHistoryData, EthernetFrameExtendedPerformanceMonitoring, \
    EthernetFrameExtendedPerformanceMonitoring64Bit


class OnuPmIntervalMetrics(AdapterPmMetrics):
    """
    ONU OMCI PM Interval metrics

    These differ from other PM Metrics as they are collected and generated as a
    result of receipt of OMCI get responses on various PM History MEs.  They are
    also always managed as a group with a fixed frequency.
    """
    def __init__(self, adapter_agent, device_id, **kwargs):
        super(OnuPmIntervalMetrics, self).__init__(adapter_agent, device_id,
                                                   grouped=True, freq_override=False,
                                                   **kwargs)

        # PM Config Types are COUNTER, GUAGE, and STATE  # Note: GAUGE is misspelled in device.proto
        ethernet_upstream_history = {
            ('enabled', PmConfig.STATE),
            ('class_id', PmConfig.GUAGE),
            ('entity_id', PmConfig.GUAGE),
            ("interval_end_time", PmConfig.GUAGE),
            ("drop_events", PmConfig.COUNTER),
            ("octets", PmConfig.COUNTER),
            ("packets", PmConfig.COUNTER),
            ("broadcast_packets", PmConfig.COUNTER),
            ("multicast_packets", PmConfig.COUNTER),
            ("crc_errored_packets", PmConfig.COUNTER),
            ("undersize_packets", PmConfig.COUNTER),
            ("oversize_packets", PmConfig.COUNTER),
            ("64_octets", PmConfig.COUNTER),
            ("65_to_127_octets", PmConfig.COUNTER),
            ("128_to_255_octets", PmConfig.COUNTER),
            ("256_to_511_octets", PmConfig.COUNTER),
            ("512_to_1023_octets", PmConfig.COUNTER),
            ("1024_to_1518_octets", PmConfig.COUNTER)
        }
        self._ethernet_upstream_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                                  for (m, t) in ethernet_upstream_history}
        self._configs = {
            EthernetFrameUpstreamPerformanceMonitoringHistoryData.class_id: self._ethernet_upstream_history_config,
            EthernetFrameDownstreamPerformanceMonitoringHistoryData.class_id: self._ethernet_upstream_history_config,
            EthernetFrameExtendedPerformanceMonitoring.class_id: self._ethernet_upstream_history_config,
            EthernetFrameExtendedPerformanceMonitoring64Bit.class_id: self._ethernet_upstream_history_config
        }

    def update(self, pm_config):
        """
        Update the PM Configuration.

        For historical PM Intervals, the frequency always zero since the actual collection
        and publishing is provided by the OpenOMCI library

        :param pm_config:
        """
        for m in pm_config.groups:
            # TODO: Need to support individual group enable/disable
            pass
            # self.pm_group_metrics[m.group_name].config.enabled = m.enabled
            # if m.enabled is True:,
            #     self.enable_pm_collection(m.group_name, remote)
            # else:
            #     self.disable_pm_collection(m.group_name, remote)

    def make_proto(self, pm_config=None):
        """
        From the PM Configurations defined in this class's initializer, create
        the PMConfigs protobuf message that defines our PM configuation and
        data.

        All ONU PM Interval metrics are grouped metrics that are generated autonmouslly
        from the OpenOMCI Performace Intervals state machine.

        :param pm_config (PMConfigs) PM Configuration message to add OpenOMCI config items too
        :return: (PmConfigs) PM Configuration Protobuf message
        """
        assert pm_config is not None
        # TODO: Just an example.  Many more to come...
        pm_ethernet_upstream_history = PmGroupConfig(group_name='Upstream Ethernet History',
                                                     group_freq=0,
                                                     enabled=True)

        for m in sorted(self._ethernet_upstream_history_config):
            pm = self._ethernet_upstream_history_config[m]
            pm_ethernet_upstream_history.metrics.extend([PmConfig(name=pm.name,
                                                                  type=pm.type,
                                                                  enabled=pm.enabled)])
        pm_config.groups.extend([pm_ethernet_upstream_history,
                                 # TODO: More to come...
                                 ])
        return pm_config

    def publish_metrics(self, interval_data):
        """
        Collect the metrics for this ONU PM Interval

        :param interval_data: (dict) PM interval dictionary with structure of
                    {
                        'class_id': self._class_id,
                        'entity_id': self._entity_id,
                        'me_name': self._entity.__name__,   # Mostly for debugging...
                        'interval_utc_time': None,
                        # Counters added here as they are retrieved
                    }

        :return: (dict) Key/Value of metric data
        """
        try:
            import arrow
            from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs
            # Locate config

            config = self._configs.get(interval_data['class_id'])

            if config is not None and config['enabled'].enabled:
                # Extract only the metrics we need to publish
                config_keys = config.keys()
                metrics = {
                    interval_data['me_name']: {k: v
                                               for k, v in interval_data.items()
                                               if k in config_keys and v is not None}
                }
                # Prepare the KpiEvent for submission
                kpi_event = KpiEvent(
                    type=KpiEventType.slice,
                    ts=arrow.get(interval_data['interval_utc_time']).timestamp,
                    prefixes={
                        self.prefix + '.{}'.format(k): MetricValuePairs(metrics=metrics[k])
                        for k in metrics.keys()}
                )
                self.adapter_agent.submit_kpis(kpi_event)

        except Exception as e:
            self.log.exception('failed-to-submit-kpis', e=e)
