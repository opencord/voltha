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

import structlog
from twisted.internet.task import LoopingCall
# from voltha.protos import ponsim_pb2
from voltha.protos.device_pb2 import PmConfig, PmConfigs
from google.protobuf.empty_pb2 import Empty


class AdapterPmMetrics:
    def __init__(self, adapter, device):
        # self.pm_names = {'tx_64_pkts', 'tx_65_127_pkts', 'tx_128_255_pkts',
        #                  'tx_256_511_pkts', 'tx_512_1023_pkts',
        #                  'tx_1024_1518_pkts', 'tx_1519_9k_pkts',
        #                  'rx_64_pkts', 'rx_65_127_pkts',
        #                  'rx_128_255_pkts', 'rx_256_511_pkts',
        #                  'rx_512_1023_pkts', 'rx_1024_1518_pkts',
        #                  'rx_1519_9k_pkts'}
        self.pm_names = {'rx_frames', 'tx_frames'}
        self.log = structlog.get_logger(device_id=device.id)
        self.device = device
        self.id = device.id
        self.name = adapter.name
        self.default_freq = 150
        self.grouped = False
        self.freq_override = False
        self.pon_metrics_config = dict()
        self.nni_metrics_config = dict()
        self.lc = None

        for m in self.pm_names:
            self.pon_metrics_config[m] = PmConfig(name=m, type=PmConfig.COUNTER,
                                                  enabled=True)
            self.nni_metrics_config[m] = PmConfig(name=m, type=PmConfig.COUNTER,
                                                  enabled=True)

    def update(self, pm_config):
        if self.default_freq != pm_config.default_freq:
            # Update the callback to the new frequency.
            self.default_freq = pm_config.default_freq
            self.lc.stop()
            self.lc.start(interval=self.default_freq / 10)

        for m in pm_config.metrics:
            self.pon_metrics_config[m.name].enabled = m.enabled
            self.nni_metrics_config[m.name].enabled = m.enabled

    def make_proto(self):
        pm_config = PmConfigs(id=self.id, default_freq=self.default_freq,
                              grouped=False, freq_override=False)

        for m in sorted(self.pon_metrics_config):
            pm = self.pon_metrics_config[m]  # Either will do they're the same
            pm_config.metrics.extend([PmConfig(name=pm.name, type=pm.type,
                                               enabled=pm.enabled)])
        return pm_config

    def collect_port_metrics(self):
        port_metrics = dict()
        # TODO: Implement
        stats = {}
        port_metrics['pon'] = self.extract_pon_metrics(stats, 100)
        port_metrics['nni'] = self.extract_nni_metrics(stats, 200)
        return port_metrics

    def extract_pon_metrics(self, stats, fake_value):
        return {
            'rx_frames': fake_value,
            'tx_frames': fake_value
        }
        # rtrn_pon_metrics = dict()
        #
        # for m in stats.metrics:
        #     if m.port_name == "pon":
        #         for p in m.packets:
        #             if self.pon_metrics_config[p.name].enabled:
        #                 rtrn_pon_metrics[p.name] = p.value
        #         return rtrn_pon_metrics

    def extract_nni_metrics(self, stats, fake_value):
        return {
            'rx_frames': fake_value,
            'tx_frames': fake_value
        }
        # rtrn_pon_metrics = dict()
        # for m in stats.metrics:
        #     if m.port_name == "nni":
        #         for p in m.packets:
        #             if self.pon_metrics_config[p.name].enabled:
        #                 rtrn_pon_metrics[p.name] = p.value
        #         return rtrn_pon_metrics

    def start_collector(self, callback):
        self.log.info("starting-pm-collection", device_name=self.name,
                      device_id=self.device.id)
        prefix = 'voltha.{}.{}'.format(self.name, self.device.id)
        self.lc = LoopingCall(callback, self.device.id, prefix)
        self.lc.start(interval=self.default_freq / 10)
