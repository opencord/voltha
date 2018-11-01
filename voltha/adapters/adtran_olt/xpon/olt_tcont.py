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
from twisted.internet.defer import  inlineCallbacks, returnValue
from tcont import TCont

log = structlog.get_logger()


class OltTCont(TCont):
    """
    Adtran OLT specific implementation
    """
    def __init__(self, alloc_id, traffic_descriptor, pon_id, onu_id,
                 name=None, is_mock=False,
                 pb_data=None):
        super(OltTCont, self).__init__(alloc_id, traffic_descriptor, name=name)
        self._is_mock = is_mock
        self.pon_id = pon_id
        self.onu_id = onu_id
        self.data = pb_data             # Needed for non-xPON mode

    @staticmethod
    def create(tcont, td, pon_id, onu_id):
        from olt_traffic_descriptor import OltTrafficDescriptor

        assert isinstance(tcont, dict), 'TCONT should be a dictionary'
        assert isinstance(td, OltTrafficDescriptor), 'Invalid Traffic Descriptor data type'

        return OltTCont(tcont['alloc-id'], td, pon_id, onu_id,
                        name=tcont['name'],
                        pb_data=tcont['data'])

    @inlineCallbacks
    def add_to_hardware(self, session):
        from ..adtran_olt_handler import AdtranOltHandler
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
                results = yield self.traffic_descriptor.add_to_hardware(session,
                                                                        self.pon_id, self.onu_id,
                                                                        self.alloc_id)
            except Exception as e:
                log.exception('traffic-descriptor', tcont=self,
                              td=self.traffic_descriptor, e=e)
                raise

        returnValue(results)

    def remove_from_hardware(self, session):
        from ..adtran_olt_handler import AdtranOltHandler

        pon_id = self.pon_id
        onu_id = self.onu_id        # TODO: Cleanup parameters

        uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(pon_id, onu_id, self.alloc_id)
        name = 'tcont-delete-{}-{}: {}'.format(self.pon_id, self.onu_id, self.alloc_id)
        return session.request('DELETE', uri, name=name)









