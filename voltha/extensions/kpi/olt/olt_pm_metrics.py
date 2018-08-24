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


class OltPmMetrics(AdapterPmMetrics):
    """
    Shared OL Device Adapter PM Metrics Manager

    This class specifically addresses ONU general PM (health, ...) area
    specific PM (OMCI, PON, UNI) is supported in encapsulated classes accessible
    from this object
    """
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
                              associated PM statistics are not gathered:

                              'nni-ports': List of objects that provide NNI (northbound) port statistics
                              'pon-ports': List of objects that provide PON port statistics
        """
        super(OltPmMetrics, self).__init__(adapter_agent, device_id, logical_device_id,
                                           grouped=grouped, freq_override=freq_override,
                                           **kwargs)

        # PM Config Types are COUNTER, GAUGE, and STATE
        self.nni_pm_names = {
            ('intf_id', PmConfig.CONTEXT),      # Physical device interface ID/Port number

            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),

            ('rx_bytes', PmConfig.COUNTER),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_ucast_packets', PmConfig.COUNTER),
            ('rx_mcast_packets', PmConfig.COUNTER),
            ('rx_bcast_packets', PmConfig.COUNTER),
            ('rx_error_packets', PmConfig.COUNTER),

            ('tx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_ucast_packets', PmConfig.COUNTER),
            ('tx_mcast_packets', PmConfig.COUNTER),
            ('tx_bcast_packets', PmConfig.COUNTER),
            ('tx_error_packets', PmConfig.COUNTER),
            ('rx_crc_errors', PmConfig.COUNTER),
            ('bip_errors', PmConfig.COUNTER),
        }
        self.pon_pm_names = {
            ('intf_id', PmConfig.CONTEXT),        # Physical device port number (PON)
            ('pon_id', PmConfig.CONTEXT),         # PON ID (0..n)

            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
            ('tx_bip_errors', PmConfig.COUNTER),
            ('in_service_onus', PmConfig.GAUGE),
            ('closest_onu_distance', PmConfig.GAUGE)
        }
        self.onu_pm_names = {
            ('intf_id', PmConfig.CONTEXT),        # Physical device port number (PON)
            ('pon_id', PmConfig.CONTEXT),
            ('onu_id', PmConfig.CONTEXT),

            ('fiber_length', PmConfig.GAUGE),
            ('equalization_delay', PmConfig.GAUGE),
            ('rssi', PmConfig.GAUGE),
        }
        self.gem_pm_names = {
            ('intf_id', PmConfig.CONTEXT),        # Physical device port number (PON)
            ('pon_id', PmConfig.CONTEXT),
            ('onu_id', PmConfig.CONTEXT),
            ('gem_id', PmConfig.CONTEXT),

            ('alloc_id', PmConfig.GAUGE),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
        }
        self.nni_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                   for (m, t) in self.nni_pm_names}
        self.pon_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                   for (m, t) in self.pon_pm_names}
        self.onu_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                   for (m, t) in self.onu_pm_names}
        self.gem_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                   for (m, t) in self.gem_pm_names}

        self._nni_ports = kwargs.pop('nni-ports', None)
        self._pon_ports = kwargs.pop('pon-ports', None)

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
                msg = 'There are no independent OLT metrics, only group metrics at this time'
                raise NotImplemented(msg)

        except Exception as e:
            self.log.exception('update-failure', e=e)
            raise

    def make_proto(self, pm_config=None):
        if pm_config is None:
            pm_config = PmConfigs(id=self.device_id, default_freq=self.default_freq,
                                  grouped=self.grouped,
                                  freq_override=self.freq_override)
        metrics = set()
        have_nni = self._nni_ports is not None and len(self._nni_ports) > 0
        have_pon = self._pon_ports is not None and len(self._pon_ports) > 0

        if self.grouped:
            if have_nni:
                pm_ether_stats = PmGroupConfig(group_name='Ethernet',
                                               group_freq=self.default_freq,
                                               enabled=True)
                self.pm_group_metrics[pm_ether_stats.group_name] = pm_ether_stats

            else:
                pm_ether_stats = None

            if have_pon:
                pm_pon_stats = PmGroupConfig(group_name='PON',
                                             group_freq=self.default_freq,
                                             enabled=True)

                pm_onu_stats = PmGroupConfig(group_name='ONU',
                                             group_freq=self.default_freq,
                                             enabled=True)

                pm_gem_stats = PmGroupConfig(group_name='GEM',
                                             group_freq=self.default_freq,
                                             enabled=True)

                self.pm_group_metrics[pm_pon_stats.group_name] = pm_pon_stats
                self.pm_group_metrics[pm_onu_stats.group_name] = pm_onu_stats
                self.pm_group_metrics[pm_gem_stats.group_name] = pm_gem_stats
            else:
                pm_pon_stats = None
                pm_onu_stats = None
                pm_gem_stats = None

        else:
            pm_ether_stats = pm_config if have_nni else None
            pm_pon_stats = pm_config if have_pon else None
            pm_onu_stats = pm_config if have_pon else None
            pm_gem_stats = pm_config if have_pon else None

        if have_nni:
            for m in sorted(self.nni_metrics_config):
                pm = self.nni_metrics_config[m]
                if not self.grouped:
                    if pm.name in metrics:
                        continue
                    metrics.add(pm.name)
                pm_ether_stats.metrics.extend([PmConfig(name=pm.name,
                                                        type=pm.type,
                                                        enabled=pm.enabled)])
        if have_pon:
            for m in sorted(self.pon_metrics_config):
                pm = self.pon_metrics_config[m]
                if not self.grouped:
                    if pm.name in metrics:
                        continue
                    metrics.add(pm.name)
                pm_pon_stats.metrics.extend([PmConfig(name=pm.name,
                                                      type=pm.type,
                                                      enabled=pm.enabled)])

            for m in sorted(self.onu_metrics_config):
                pm = self.onu_metrics_config[m]
                if not self.grouped:
                    if pm.name in metrics:
                        continue
                    metrics.add(pm.name)
                pm_onu_stats.metrics.extend([PmConfig(name=pm.name,
                                                      type=pm.type,
                                                      enabled=pm.enabled)])

            for m in sorted(self.gem_metrics_config):
                pm = self.gem_metrics_config[m]
                if not self.grouped:
                    if pm.name in metrics:
                        continue
                    metrics.add(pm.name)
                pm_gem_stats.metrics.extend([PmConfig(name=pm.name,
                                                      type=pm.type,
                                                      enabled=pm.enabled)])
        if self.grouped:
            pm_config.groups.extend([stats for stats in
                                     self.pm_group_metrics.itervalues()])

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

        group_name = 'Ethernet'
        if self.pm_group_metrics[group_name].enabled:
            for port in self._nni_ports:
                group_data = self.collect_group_metrics(group_name,
                                                        port,
                                                        self.nni_pm_names,
                                                        self.nni_metrics_config)
                if group_data is not None:
                    data.append(group_data)

        for port in self._pon_ports:
            group_name = 'PON'
            if self.pm_group_metrics[group_name].enabled:
                group_data = self.collect_group_metrics(group_name,
                                                        port,
                                                        self.pon_pm_names,
                                                        self.pon_metrics_config)
                if group_data is not None:
                    data.append(group_data)

            for onu_id in port.onu_ids:
                onu = port.onu(onu_id)
                if onu is not None:
                    group_name = 'ONU'
                    if self.pm_group_metrics[group_name].enabled:
                        group_data = self.collect_group_metrics(group_name,
                                                                onu,
                                                                self.onu_pm_names,
                                                                self.onu_metrics_config)
                        if group_data is not None:
                            data.append(group_data)

                    group_name = 'GEM'
                    if self.pm_group_metrics[group_name].enabled:
                        for gem in onu.gem_ports:
                            if not gem.multicast:
                                group_data = self.collect_group_metrics(group_name,
                                                                        onu,
                                                                        self.gem_pm_names,
                                                                        self.gem_metrics_config)
                                if group_data is not None:
                                    data.append(group_data)

                            # TODO: Do any multicast GEM PORT metrics here...
        return data
