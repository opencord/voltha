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
from ..adtran_olt_handler import AdtranOltHandler
from voltha.adapters.openolt.protos import openolt_pb2

log = structlog.get_logger()


class OltTrafficDescriptor(TrafficDescriptor):
    """
    Adtran ONU specific implementation
    """
    def __init__(self, pon_id, onu_id, alloc_id, fixed, assured, maximum,
                 additional=TrafficDescriptor.AdditionalBwEligibility.DEFAULT,
                 best_effort=None,
                 is_mock=False):
        super(OltTrafficDescriptor, self).__init__(fixed, assured, maximum,
                                                   additional=additional,
                                                   best_effort=best_effort)
        self.pon_id = pon_id
        self.onu_id = onu_id
        self.alloc_id = alloc_id
        self._is_mock = is_mock

    @staticmethod
    def create(tcont, pon_id, onu_id, _uni_id, _ofp_port_no):
        alloc_id = tcont.alloc_id
        shaping_info = tcont.traffic_shaping_info
        fixed = shaping_info.cir
        assured = 0
        maximum = shaping_info.pir

        best_effort = None
        # if shaping_info.add_bw_ind == openolt_pb2.InferredAdditionBWIndication_Assured:
        #     pass
        #               TODO: Support additional BW decode
        # elif shaping_info.add_bw_ind == openolt_pb2.InferredAdditionBWIndication_BestEffort:
        #     pass
        # additional = TrafficDescriptor.AdditionalBwEligibility.from_value(
        #     traffic_disc['additional-bw-eligibility-indicator'])
        #
        # if additional == TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
        #     best_effort = BestEffort(traffic_disc['maximum-bandwidth'],
        #                              traffic_disc['priority'],
        #                              traffic_disc['weight'])
        # else:
        #     best_effort = None

        return OltTrafficDescriptor(pon_id, onu_id, alloc_id,
                                    fixed, assured, maximum, best_effort=best_effort)

    @inlineCallbacks
    def add_to_hardware(self, session):
        # TODO: Traffic descriptors are no longer shared, save pon and onu ID to base class
        if self._is_mock:
            returnValue('mock')

        uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(self.pon_id,
                                                            self.onu_id,
                                                            self.alloc_id)
        data = json.dumps({'traffic-descriptor': self.to_dict()})
        name = 'tcont-td-{}-{}: {}'.format(self.pon_id, self.onu_id, self.alloc_id)
        try:
            results = yield session.request('PATCH', uri, data=data, name=name)

        except Exception as e:
            log.exception('traffic-descriptor', td=self, e=e)
            raise

        # TODO: Add support for best-effort sharing
        # if self.additional_bandwidth_eligibility == \
        #         TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
        #     if self.best_effort is None:
        #         raise ValueError('TCONT is best-effort but does not define best effort sharing')
        #
        #     try:
        #         results = yield self.best_effort.add_to_hardware(session)
        #
        #     except Exception as e:
        #         log.exception('best-effort', best_effort=self.best_effort, e=e)
        #         raise

        returnValue(results)
