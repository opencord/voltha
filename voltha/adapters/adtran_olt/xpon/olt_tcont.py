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
from twisted.internet.defer import inlineCallbacks, returnValue
from tcont import TCont
from voltha.adapters.openolt.protos import openolt_pb2
from olt_traffic_descriptor import OltTrafficDescriptor
from ..adtran_olt_handler import AdtranOltHandler

log = structlog.get_logger()


class OltTCont(TCont):
    """
    Adtran OLT specific implementation
    """
    def __init__(self, alloc_id, tech_profile_id, traffic_descriptor, pon_id, onu_id, uni_id, is_mock=False):
        super(OltTCont, self).__init__(alloc_id, tech_profile_id, traffic_descriptor, uni_id, is_mock=is_mock)
        self.pon_id = pon_id
        self.onu_id = onu_id

    def __str__(self):
        return "TCont: {}/{}/{}, alloc-id: {}".format(self.pon_id, self.onu_id,
                                                      self.uni_id, self.alloc_id)

    @staticmethod
    def create(tcont, pon_id, onu_id, tech_profile_id, uni_id, ofp_port_no):
        # Only valid information in the upstream tcont of a tech profile
        if tcont.direction != openolt_pb2.UPSTREAM:
            return None

        td = OltTrafficDescriptor.create(tcont, pon_id, onu_id, uni_id, ofp_port_no)
        return OltTCont(tcont.alloc_id, tech_profile_id, td, pon_id, onu_id, uni_id)

    @inlineCallbacks
    def add_to_hardware(self, session):
        if self._is_mock:
            returnValue('mock')

        uri = AdtranOltHandler.GPON_TCONT_CONFIG_LIST_URI.format(self.pon_id, self.onu_id)
        data = json.dumps({'alloc-id': self.alloc_id})
        name = 'tcont-create-{}-{}: {}'.format(self.pon_id, self.onu_id, self.alloc_id)

        # For TCONT, only leaf is the key. So only post needed
        try:
            results = yield session.request('POST', uri, data=data, name=name,
                                            suppress_error=False)
        except Exception as _e:
            results = None

        if self.traffic_descriptor is not None:
            try:
                results = yield self.traffic_descriptor.add_to_hardware(session)

            except Exception as e:
                log.exception('traffic-descriptor', tcont=self,
                              td=self.traffic_descriptor, e=e)
                raise

        returnValue(results)

    def remove_from_hardware(self, session):
        if self._is_mock:
            returnValue('mock')

        uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(self.pon_id, self.onu_id, self.alloc_id)
        name = 'tcont-delete-{}-{}: {}'.format(self.pon_id, self.onu_id, self.alloc_id)
        return session.request('DELETE', uri, name=name)









