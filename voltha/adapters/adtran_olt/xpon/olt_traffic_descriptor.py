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
from traffic_descriptor import TrafficDescriptor
from twisted.internet.defer import inlineCallbacks, returnValue

log = structlog.get_logger()


class OltTrafficDescriptor(TrafficDescriptor):
    """
    Adtran ONU specific implementation
    """
    def __init__(self, fixed, assured, maximum,
                 additional=TrafficDescriptor.AdditionalBwEligibility.DEFAULT,
                 best_effort=None,
                 name=None,
                 is_mock=False,
                 pb_data=None):
        super(OltTrafficDescriptor, self).__init__(fixed, assured, maximum,
                                                   additional=additional,
                                                   best_effort=best_effort,
                                                   name=name)
        self._is_mock = is_mock
        self.data = pb_data

    @staticmethod
    def create(traffic_disc):
        from best_effort import BestEffort

        assert isinstance(traffic_disc, dict), 'Traffic Descriptor should be a dictionary'

        additional = TrafficDescriptor.AdditionalBwEligibility.from_value(
            traffic_disc['additional-bw-eligibility-indicator'])

        if additional == TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
            best_effort = BestEffort(traffic_disc['maximum-bandwidth'],
                                     traffic_disc['priority'],
                                     traffic_disc['weight'])
        else:
            best_effort = None

        return OltTrafficDescriptor(traffic_disc['fixed-bandwidth'],
                                    traffic_disc['assured-bandwidth'],
                                    traffic_disc['maximum-bandwidth'],
                                    name=traffic_disc['name'],
                                    best_effort=best_effort,
                                    additional=additional,
                                    pb_data=traffic_disc['data'])

    @inlineCallbacks
    def add_to_hardware(self, session, pon_id, onu_id, alloc_id):
        from ..adtran_olt_handler import AdtranOltHandler

        if self._is_mock:
            returnValue('mock')

        uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(pon_id, onu_id, alloc_id)
        data = json.dumps({'traffic-descriptor': self.to_dict()})
        name = 'tcont-td-{}-{}: {}'.format(pon_id, onu_id, alloc_id)
        try:
            results = yield session.request('PATCH', uri, data=data, name=name)

        except Exception as e:
            log.exception('traffic-descriptor', td=self, e=e)
            raise

        if self.additional_bandwidth_eligibility == \
                TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
            if self.best_effort is None:
                raise ValueError('TCONT is best-effort but does not define best effort sharing')

            try:
                results = yield self.best_effort.add_to_hardware(session, pon_id, onu_id, alloc_id)

            except Exception as e:
                log.exception('best-effort', best_effort=self.best_effort, e=e)
                raise

        returnValue(results)
