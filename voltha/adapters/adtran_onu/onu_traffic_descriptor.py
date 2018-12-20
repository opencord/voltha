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

from voltha.adapters.adtran_olt.xpon.traffic_descriptor import TrafficDescriptor
from voltha.adapters.adtran_olt.xpon.best_effort import BestEffort
from twisted.internet.defer import inlineCallbacks, returnValue, succeed


class OnuTrafficDescriptor(TrafficDescriptor):
    """
    Adtran ONU specific implementation
    """
    def __init__(self, fixed, assured, maximum,
                 additional=TrafficDescriptor.AdditionalBwEligibility.DEFAULT,
                 best_effort=None):
        super(OnuTrafficDescriptor, self).__init__(fixed, assured, maximum,
                                                   additional=additional,
                                                   best_effort=best_effort)

    @staticmethod
    def create(traffic_disc):
        assert isinstance(traffic_disc, dict), 'Traffic Descriptor should be a dictionary'

        additional = TrafficDescriptor.AdditionalBwEligibility.from_value(
            traffic_disc['additional-bw-eligibility-indicator'])

        if additional == TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
            best_effort = BestEffort(traffic_disc['maximum-bandwidth'],
                                     traffic_disc['priority'],
                                     traffic_disc['weight'])
        else:
            best_effort = None

        return OnuTrafficDescriptor(traffic_disc['fixed-bandwidth'],
                                    traffic_disc['assured-bandwidth'],
                                    traffic_disc['maximum-bandwidth'],
                                    best_effort=best_effort,
                                    additional=additional)

    @inlineCallbacks
    def add_to_hardware(self, omci):

        results = succeed('TODO: Implement me')
        # from ..adtran_olt_handler import AdtranOltHandler
        #
        # uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(pon_id, onu_id, alloc_id)
        # data = json.dumps({'traffic-descriptor': self.to_dict()})
        # name = 'tcont-td-{}-{}: {}'.format(pon_id, onu_id, alloc_id)
        # try:
        #     results = yield session.request('PATCH', uri, data=data, name=name)
        #
        # except Exception as e:
        #     log.exception('traffic-descriptor', td=self, e=e)
        #     raise
        #
        # if self.additional_bandwidth_eligibility == \
        #         TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
        #     if self.best_effort is None:
        #         raise ValueError('TCONT is best-effort but does not define best effort sharing')
        #
        #     try:
        #         results = yield self.best_effort.add_to_hardware(session, pon_id, onu_id, alloc_id)
        #
        #     except Exception as e:
        #         log.exception('best-effort', best_effort=self.best_effort, e=e)
        #         raise
        returnValue(results)
