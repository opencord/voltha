# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import structlog
import json

log = structlog.get_logger()


class BestEffort(object):
    def __init__(self, bandwidth, priority, weight):
        self.bandwidth = bandwidth   # bps
        self.priority = priority     # 0.255
        self.weight = weight         # 0..100

    def __str__(self):
        return "BestEffort: {}/p-{}/w-{}".format(self.bandwidth,
                                                 self.priority,
                                                 self.weight)

    def to_dict(self):
        val = {
            'bandwidth': self.bandwidth,
            'priority': self.priority,
            'weight': self.weight
        }
        return val

    def add_to_hardware(self, session, pon_id, onu_id, alloc_id, best_effort):
        from ..adtran_olt_handler import AdtranOltHandler

        uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(pon_id, onu_id, alloc_id)
        data = json.dumps({'best-effort': best_effort.to_dict()})
        name = 'tcont-best-effort-{}-{}: {}'.format(pon_id, onu_id, alloc_id)

        return session.request('PATCH', uri, data=data, name=name)
