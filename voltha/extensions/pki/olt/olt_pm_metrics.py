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


class OltPmMetrics(AdapterPmMetrics):
    """
    Shared OL Device Adapter PM Metrics Manager

    This class specifically addresses ONU genernal PM (health, ...) area
    specific PM (OMCI, PON, UNI) is supported in encapsulated classes accessible
    from this object
    """
    def __init__(self, adapter_agent, device_id, grouped=False, freq_override=False,
                 **kwargs):
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

                              'nni-ports': List of objects that provide NNI (northbound) port statistics
                              'pon-ports': List of objects that provide PON port statistics
        """
        super(OltPmMetrics, self).__init__(adapter_agent, device_id,
                                           grouped=grouped, freq_override=freq_override,
                                           **kwargs)

        # PM Config Types are COUNTER, GUAGE, and STATE     # GAUGE is misspelled device.proto
        self.nni_pm_names = {
            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),
            ('port_no', PmConfig.GUAGE),  # Device and logical_device port numbers same
            ('rx_packets', PmConfig.COUNTER),
            ('rx_bytes', PmConfig.COUNTER),
            ('rx_dropped', PmConfig.COUNTER),
            ('rx_errors', PmConfig.COUNTER),
            ('rx_bcast', PmConfig.COUNTER),
            ('rx_mcast', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
            ('tx_dropped', PmConfig.COUNTER),
            ('tx_bcast', PmConfig.COUNTER),
            ('tx_mcast', PmConfig.COUNTER),
            #
            # Commented out are from spec. May not be supported or implemented yet
            # ('rx_64', PmConfig.COUNTER),
            # ('rx_65_127', PmConfig.COUNTER),
            # ('rx_128_255', PmConfig.COUNTER),
            # ('rx_256_511', PmConfig.COUNTER),
            # ('rx_512_1023', PmConfig.COUNTER),
            # ('rx_1024_1518', PmConfig.COUNTER),
            # ('rx_frame_err', PmConfig.COUNTER),
            # ('rx_over_err', PmConfig.COUNTER),
            # ('rx_crc_err', PmConfig.COUNTER),
            # ('rx_64', PmConfig.COUNTER),
            # ('tx_65_127', PmConfig.COUNTER),
            # ('tx_128_255', PmConfig.COUNTER),
            # ('tx_256_511', PmConfig.COUNTER),
            # ('tx_512_1023', PmConfig.COUNTER),
            # ('tx_1024_1518', PmConfig.COUNTER),
            # ('collisions', PmConfig.COUNTER),
        }
        self.pon_pm_names = {
            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),
            ('port_no', PmConfig.GUAGE),        # Physical device port number
            ('pon_id', PmConfig.GUAGE),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
            ('tx_bip_errors', PmConfig.COUNTER),
            ('in_service_onus', PmConfig.GUAGE),
            ('closest_onu_distance', PmConfig.GUAGE)
        }
        self.onu_pm_names = {
            ('pon_id', PmConfig.GUAGE),
            ('onu_id', PmConfig.GUAGE),
            ('fiber_length', PmConfig.GUAGE),
            ('equalization_delay', PmConfig.GUAGE),
            ('rssi', PmConfig.GUAGE),            #
        }
        self.gem_pm_names = {
            ('pon_id', PmConfig.GUAGE),
            ('onu_id', PmConfig.GUAGE),
            ('gem_id', PmConfig.GUAGE),
            ('alloc_id', PmConfig.GUAGE),
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
                # if m.enabled is True:
                #     self.enable_pm_collection(m.group_name, remote)
                # else:
                #     self.disable_pm_collection(m.group_name, remote)
        else:
            for m in pm_config.metrics:
                self.nni_metrics_config[m.name].enabled = m.enabled
                self.pon_metrics_config[m.name].enabled = m.enabled
                self.onu_metrics_config[m.name].enabled = m.enabled
                self.gem_metrics_config[m.name].enabled = m.enabled

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
            else:
                pm_ether_stats = None

            if have_pon:
                pm_pon_stats = PmGroupConfig(group_name='PON',
                                             group_freq=self.default_freq,
                                             enabled=True)

                pm_ont_stats = PmGroupConfig(group_name='ONT',
                                             group_freq=self.default_freq,
                                             enabled=True)

                pm_gem_stats = PmGroupConfig(group_name='GEM',
                                             group_freq=self.default_freq,
                                             enabled=True)
            else:
                pm_pon_stats = None
                pm_ont_stats = None
                pm_gem_stats = None

        else:
            pm_ether_stats = pm_config if have_nni else None
            pm_pon_stats = pm_config if have_pon else None
            pm_ont_stats = pm_config if have_pon else None
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
                pm_ont_stats.metrics.extend([PmConfig(name=pm.name,
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
            pm_groups = [stats for stats in (pm_ether_stats,
                                             pm_pon_stats,
                                             pm_ont_stats,
                                             pm_gem_stats) if stats is not None]
            pm_config.groups.extend(pm_groups)

        return pm_config

    def collect_group_metrics(self, metrics=None):
        # TODO: Currently PM collection is done for all metrics/groups on a single timer
        if metrics is None:
            metrics = dict()

        for port in self._nni_ports:
            metrics['nni.{}'.format(port.port_no)] = self.collect_nni_metrics(port)

        for port in self._pon_ports:
            metrics['pon.{}'.format(port.pon_id)] = self.collect_pon_metrics(port)

            for onu_id in port.onu_ids:
                onu = port.onu(onu_id)
                if onu is not None:
                    metrics['pon.{}.onu.{}'.format(port.pon_id, onu.onu_id)] = \
                        self.collect_onu_metrics(onu)
                    for gem in onu.gem_ports:
                        if gem.multicast:
                            continue

                        metrics['pon.{}.onu.{}.gem.{}'.format(port.pon_id,
                                                              onu.onu_id,
                                                              gem.gem_id)] = \
                            self.collect_gem_metrics(gem)
            # TODO: Do any multicast GEM PORT metrics here...
        return metrics

    def collect_nni_metrics(self, nni_port):
        stats = {metric: getattr(nni_port, metric) for (metric, t) in self.nni_pm_names}
        return {metric: value for metric, value in stats.iteritems()
                if self.nni_metrics_config[metric].enabled}

    def collect_pon_metrics(self, pon_port):
        stats = {metric: getattr(pon_port, metric) for (metric, t) in self.pon_pm_names}
        return {metric: value for metric, value in stats.iteritems()
                if self.pon_metrics_config[metric].enabled}

    def collect_onu_metrics(self, onu):
        stats = {metric: getattr(onu, metric) for (metric, t) in self.onu_pm_names}
        return {metric: value for metric, value in stats.iteritems()
                if self.onu_metrics_config[metric].enabled}

    def collect_gem_metrics(self, gem):
        stats = {metric: getattr(gem, metric) for (metric, t) in self.gem_pm_names}
        return {metric: value for metric, value in stats.iteritems()
                if self.gem_metrics_config[metric].enabled}
