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
from voltha.extensions.omci.omci_entities import \
    EthernetFrameUpstreamPerformanceMonitoringHistoryData, \
    EthernetFrameDownstreamPerformanceMonitoringHistoryData, \
    EthernetFrameExtendedPerformanceMonitoring, \
    EthernetFrameExtendedPerformanceMonitoring64Bit, \
    EthernetPMMonitoringHistoryData, FecPerformanceMonitoringHistoryData, \
    GemPortNetworkCtpMonitoringHistoryData, XgPonTcPerformanceMonitoringHistoryData, \
    XgPonDownstreamPerformanceMonitoringHistoryData, \
    XgPonUpstreamPerformanceMonitoringHistoryData


class OnuPmIntervalMetrics(AdapterPmMetrics):
    """
    ONU OMCI PM Interval metrics

    These differ from other PM Metrics as they are collected and generated as a
    result of receipt of OMCI get responses on various PM History MEs.  They are
    also always managed as a group with a fixed frequency of 15 minutes.
    """
    ME_ID_INFO = {
        EthernetFrameUpstreamPerformanceMonitoringHistoryData.class_id: 'Ethernet Bridge Port History',
        EthernetFrameDownstreamPerformanceMonitoringHistoryData.class_id: 'Ethernet Bridge Port History',
        EthernetFrameExtendedPerformanceMonitoring.class_id: 'Ethernet Bridge Port History',
        EthernetFrameExtendedPerformanceMonitoring64Bit.class_id: 'Ethernet Bridge Port History',
        EthernetPMMonitoringHistoryData.class_id: 'Ethernet UNI History',
        FecPerformanceMonitoringHistoryData.class_id: 'FEC History',
        GemPortNetworkCtpMonitoringHistoryData.class_id: 'GEM Port History',
        XgPonTcPerformanceMonitoringHistoryData.class_id: 'xgPON TC History',
        XgPonDownstreamPerformanceMonitoringHistoryData.class_id: 'xgPON Downstream History',
        XgPonUpstreamPerformanceMonitoringHistoryData.class_id: 'xgPON Upstream History'
    }

    def __init__(self, adapter_agent, device_id, **kwargs):
        super(OnuPmIntervalMetrics, self).__init__(adapter_agent, device_id,
                                                   grouped=True, freq_override=False,
                                                   **kwargs)
        ethernet_bridge_history = {
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
        self._ethernet_bridge_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                                for (m, t) in ethernet_bridge_history}

        ethernet_uni_history = {   # Ethernet History Data (Class ID 24)
            ('class_id', PmConfig.GUAGE),
            ('entity_id', PmConfig.GUAGE),
            ("interval_end_time", PmConfig.GUAGE),
            ("fcs_errors", PmConfig.COUNTER),
            ("excessive_collision_counter", PmConfig.COUNTER),
            ("late_collision_counter", PmConfig.COUNTER),
            ("frames_too_long", PmConfig.COUNTER),
            ("buffer_overflows_on_rx", PmConfig.COUNTER),
            ("buffer_overflows_on_tx", PmConfig.COUNTER),
            ("single_collision_frame_counter", PmConfig.COUNTER),
            ("multiple_collisions_frame_counter", PmConfig.COUNTER),
            ("sqe_counter", PmConfig.COUNTER),
            ("deferred_tx_counter", PmConfig.COUNTER),
            ("internal_mac_tx_error_counter", PmConfig.COUNTER),
            ("carrier_sense_error_counter", PmConfig.COUNTER),
            ("alignment_error_counter", PmConfig.COUNTER),
            ("internal_mac_rx_error_counter", PmConfig.COUNTER),
        }
        self._ethernet_uni_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                             for (m, t) in ethernet_uni_history}

        fec_history = {   # FEC History Data (Class ID 312)
            ('class_id', PmConfig.GUAGE),
            ('entity_id', PmConfig.GUAGE),
            ("interval_end_time", PmConfig.GUAGE),
            ("corrected_bytes", PmConfig.COUNTER),
            ("corrected_code_words", PmConfig.COUNTER),
            ("uncorrectable_code_words", PmConfig.COUNTER),
            ("total_code_words", PmConfig.COUNTER),
            ("fec_seconds", PmConfig.COUNTER),
        }
        self._fec_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                    for (m, t) in fec_history}

        gem_port_history = {  # GEM Port Network CTP History Data (Class ID 341)
            ('class_id', PmConfig.GUAGE),
            ('entity_id', PmConfig.GUAGE),
            ("interval_end_time", PmConfig.GUAGE),
            ("transmitted_gem_frames", PmConfig.COUNTER),
            ("received_gem_frames", PmConfig.COUNTER),
            ("received_payload_bytes", PmConfig.COUNTER),
            ("transmitted_payload_bytes", PmConfig.COUNTER),
            ("encryption_key_errors", PmConfig.COUNTER),
        }
        self._gem_port_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                         for (m, t) in gem_port_history}

        xgpon_tc_history = {  # XgPon TC History Data (Class ID 344)
            ('class_id', PmConfig.GUAGE),
            ('entity_id', PmConfig.GUAGE),
            ("interval_end_time", PmConfig.GUAGE),
            ("psbd_hec_error_count", PmConfig.COUNTER),
            ("xgtc_hec_error_count", PmConfig.COUNTER),
            ("unknown_profile_count", PmConfig.COUNTER),
            ("transmitted_xgem_frames", PmConfig.COUNTER),
            ("fragment_xgem_frames", PmConfig.COUNTER),
            ("xgem_hec_lost_words_count", PmConfig.COUNTER),
            ("xgem_key_errors", PmConfig.COUNTER),
            ("xgem_hec_error_count", PmConfig.COUNTER),
        }
        self._xgpon_tc_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                         for (m, t) in xgpon_tc_history}

        xgpon_downstream_history = {  # XgPon Downstream History Data (Class ID 345)
            ('class_id', PmConfig.GUAGE),
            ('entity_id', PmConfig.GUAGE),
            ("interval_end_time", PmConfig.GUAGE),
            ("ploam_mic_error_count", PmConfig.COUNTER),
            ("downstream_ploam_messages_count", PmConfig.COUNTER),
            ("profile_messages_received", PmConfig.COUNTER),
            ("ranging_time_messages_received", PmConfig.COUNTER),
            ("deactivate_onu_id_messages_received", PmConfig.COUNTER),
            ("disable_serial_number_messages_received", PmConfig.COUNTER),
            ("request_registration_messages_received", PmConfig.COUNTER),
            ("assign_alloc_id_messages_received", PmConfig.COUNTER),
            ("key_control_messages_received", PmConfig.COUNTER),
            ("sleep_allow_messages_received", PmConfig.COUNTER),
            ("baseline_omci_messages_received_count", PmConfig.COUNTER),
            ("extended_omci_messages_received_count", PmConfig.COUNTER),
            ("assign_onu_id_messages_received", PmConfig.COUNTER),
            ("omci_mic_error_count", PmConfig.COUNTER),
        }
        self._xgpon_downstream_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                                 for (m, t) in xgpon_downstream_history}

        xgpon_upstream_history = {  # XgPon Upstream History Data (Class ID 346)
            ('class_id', PmConfig.GUAGE),
            ('entity_id', PmConfig.GUAGE),
            ("interval_end_time", PmConfig.GUAGE),
            ("upstream_ploam_message_count", PmConfig.COUNTER),
            ("serial_number_onu_message_count", PmConfig.COUNTER),
            ("registration_message_count", PmConfig.COUNTER),
            ("key_report_message_count", PmConfig.COUNTER),
            ("acknowledge_message_count", PmConfig.COUNTER),
            ("sleep_request_message_count", PmConfig.COUNTER),
        }
        self._xgpon_upstream_history_config = {m: PmConfig(name=m, type=t, enabled=True)
                                               for (m, t) in xgpon_upstream_history}
        self._configs = {
            EthernetFrameUpstreamPerformanceMonitoringHistoryData.class_id: self._ethernet_bridge_history_config,
            EthernetFrameDownstreamPerformanceMonitoringHistoryData.class_id: self._ethernet_bridge_history_config,
            EthernetFrameExtendedPerformanceMonitoring.class_id: self._ethernet_bridge_history_config,
            EthernetFrameExtendedPerformanceMonitoring64Bit.class_id: self._ethernet_bridge_history_config,
            EthernetPMMonitoringHistoryData.class_id: self._ethernet_uni_history_config,
            FecPerformanceMonitoringHistoryData.class_id: self._fec_history_config,
            GemPortNetworkCtpMonitoringHistoryData.class_id: self._gem_port_history_config,
            XgPonTcPerformanceMonitoringHistoryData.class_id: self._xgpon_tc_history_config,
            XgPonDownstreamPerformanceMonitoringHistoryData.class_id: self._xgpon_downstream_history_config,
            XgPonUpstreamPerformanceMonitoringHistoryData.class_id: self._xgpon_upstream_history_config
        }

    def update(self, pm_config):
        """
        Update the PM Configuration.

        For historical PM Intervals, the frequency always zero since the actual collection
        and publishing is provided by the OpenOMCI library

        :param pm_config:
        """
        self.log.debug('update')

        try:
            for group in pm_config.groups:
                group_config = self.pm_group_metrics.get(group.group_name)
                if group_config is not None and group_config.enabled != group.enabled:
                    group_config.enabled = group.enabled
                    # TODO: For OMCI PM Metrics, tie this into add/remove of the PM Interval ME itself

        except Exception as e:
            self.log.exception('update-failure', e=e)
            raise

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

        pm_ethernet_bridge_history = PmGroupConfig(group_name=OnuPmIntervalMetrics.ME_ID_INFO[EthernetFrameUpstreamPerformanceMonitoringHistoryData.class_id],
                                                   group_freq=0,
                                                   enabled=True)
        self.pm_group_metrics[pm_ethernet_bridge_history.group_name] = pm_ethernet_bridge_history

        for m in sorted(self._ethernet_bridge_history_config):
            pm = self._ethernet_bridge_history_config[m]
            pm_ethernet_bridge_history.metrics.extend([PmConfig(name=pm.name,
                                                                type=pm.type,
                                                                enabled=pm.enabled)])

        pm_ethernet_uni_history = PmGroupConfig(group_name=OnuPmIntervalMetrics.ME_ID_INFO[EthernetPMMonitoringHistoryData.class_id],
                                                group_freq=0,
                                                enabled=True)
        self.pm_group_metrics[pm_ethernet_uni_history.group_name] = pm_ethernet_uni_history

        for m in sorted(self._ethernet_uni_history_config):
            pm = self._ethernet_uni_history_config[m]
            pm_ethernet_uni_history.metrics.extend([PmConfig(name=pm.name,
                                                             type=pm.type,
                                                             enabled=pm.enabled)])

        pm_fec_history = PmGroupConfig(group_name=OnuPmIntervalMetrics.ME_ID_INFO[FecPerformanceMonitoringHistoryData.class_id],
                                       group_freq=0,
                                       enabled=True)
        self.pm_group_metrics[pm_fec_history.group_name] = pm_fec_history

        for m in sorted(self._fec_history_config):
            pm = self._fec_history_config[m]
            pm_fec_history.metrics.extend([PmConfig(name=pm.name,
                                                    type=pm.type,
                                                    enabled=pm.enabled)])

        pm_gem_port_history = PmGroupConfig(group_name=OnuPmIntervalMetrics.ME_ID_INFO[GemPortNetworkCtpMonitoringHistoryData.class_id],
                                            group_freq=0,
                                            enabled=True)
        self.pm_group_metrics[pm_gem_port_history.group_name] = pm_gem_port_history

        for m in sorted(self._gem_port_history_config):
            pm = self._gem_port_history_config[m]
            pm_gem_port_history.metrics.extend([PmConfig(name=pm.name,
                                                         type=pm.type,
                                                         enabled=pm.enabled)])

        pm_xgpon_tc_history = PmGroupConfig(group_name=OnuPmIntervalMetrics.ME_ID_INFO[XgPonTcPerformanceMonitoringHistoryData.class_id],
                                            group_freq=0,
                                            enabled=True)
        self.pm_group_metrics[pm_xgpon_tc_history.group_name] = pm_xgpon_tc_history

        for m in sorted(self._xgpon_tc_history_config):
            pm = self._xgpon_tc_history_config[m]
            pm_xgpon_tc_history.metrics.extend([PmConfig(name=pm.name,
                                                         type=pm.type,
                                                         enabled=pm.enabled)])

        pm_xgpon_downstream_history = PmGroupConfig(group_name=OnuPmIntervalMetrics.ME_ID_INFO[XgPonDownstreamPerformanceMonitoringHistoryData.class_id],
                                                    group_freq=0,
                                                    enabled=True)
        self.pm_group_metrics[pm_xgpon_downstream_history.group_name] = pm_xgpon_downstream_history

        for m in sorted(self._xgpon_downstream_history_config):
            pm = self._xgpon_downstream_history_config[m]
            pm_xgpon_downstream_history.metrics.extend([PmConfig(name=pm.name,
                                                                 type=pm.type,
                                                                 enabled=pm.enabled)])

        pm_xgpon_upstream_history = PmGroupConfig(group_name=OnuPmIntervalMetrics.ME_ID_INFO[XgPonUpstreamPerformanceMonitoringHistoryData.class_id],
                                                  group_freq=0,
                                                  enabled=True)
        self.pm_group_metrics[pm_xgpon_upstream_history.group_name] = pm_xgpon_upstream_history

        for m in sorted(self._xgpon_upstream_history_config):
            pm = self._xgpon_upstream_history_config[m]
            pm_xgpon_upstream_history.metrics.extend([PmConfig(name=pm.name,
                                                               type=pm.type,
                                                               enabled=pm.enabled)])

        pm_config.groups.extend([stats for stats in self.pm_group_metrics.itervalues()])

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
        self.log.debug('publish-metrics', metrics=interval_data)

        try:
            import arrow
            from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs
            # Locate config

            class_id = interval_data['class_id']
            config = self._configs.get(class_id)
            group = self.pm_group_metrics.get(OnuPmIntervalMetrics.ME_ID_INFO.get(class_id, ''))

            if config is not None and group is not None and group.enabled:
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
