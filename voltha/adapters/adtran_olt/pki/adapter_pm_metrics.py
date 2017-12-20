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
from voltha.protos.device_pb2 import PmConfig, PmConfigs, PmGroupConfig


class AdapterPmMetrics(object):
    def __init__(self, handler, device, grouped=False, freq_override=False):
        self.log = structlog.get_logger(device_id=device.id)
        self.device = device
        self.id = device.id
        self.handler = handler
        self.name = handler.adapter.name
        self.default_freq = 150
        self.grouped = grouped
        self.freq_override = grouped and freq_override
        self.lc = None

    def update(self, pm_config):
        raise NotImplementedError('Your derived class should override this method')

    # def enable_pm_collection(self, pm_group, remote):
    #     if pm_group == 'Ethernet':
    #         self.configure_pm_collection_freq(self.default_freq / 10, remote)
    #
    # def disable_pm_collection(self, pm_group, remote):
    #     if pm_group == 'nni':
    #         self.configure_pm_collection_freq(0, remote)

    def make_proto(self):
        raise NotImplementedError('Your derived class should override this method')

    def start_collector(self, callback):
        self.log.info("starting-pm-collection", device_name=self.name,
                      device_id=self.device.id)
        prefix = 'voltha.{}.{}'.format(self.name, self.device.id)

        if self.lc is None:
            self.lc = LoopingCall(callback, self.device.id, prefix)

        self.lc.start(interval=self.default_freq / 10)

    def stop_collector(self):
        if self.lc is not None:
            self.lc.stop()

    def collect_metrics(self, group, names, config):
        stats = {metric: getattr(group, metric) for (metric, t) in names}
        return {metric: value for metric, value in stats.iteritems()
                if config[metric].enabled}
