#
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

from gem_port import GemPort
from twisted.internet.defer import inlineCallbacks, returnValue
from ..adtran_olt_handler import AdtranOltHandler

log = structlog.get_logger()


class OltGemPort(GemPort):
    """
    Adtran OLT specific implementation
    """
    def __init__(self, gem_id, alloc_id, tech_profile_id, pon_id, onu_id, uni_id,
                 encryption=False,
                 multicast=False,
                 traffic_class=None,
                 handler=None,
                 is_mock=False):
        super(OltGemPort, self).__init__(gem_id, alloc_id, uni_id, tech_profile_id,
                                         encryption=encryption,
                                         multicast=multicast,
                                         traffic_class=traffic_class,
                                         handler=handler,
                                         is_mock=is_mock)
        self._timestamp = None
        self._pon_id = pon_id
        self._onu_id = onu_id       # None if this is a multicast GEM Port

    def __str__(self):
        return "GemPort: {}/{}/{}, alloc-id: {}, gem-id: {}".format(self.pon_id, self.onu_id,
                                                                    self.uni_id, self.alloc_id,
                                                                    self.gem_id)

    @staticmethod
    def create(handler, gem, alloc_id, tech_profile_id, pon_id, onu_id, uni_id, _ofp_port_no):
        return OltGemPort(gem.gemport_id,
                          alloc_id,
                          tech_profile_id,
                          pon_id, onu_id, uni_id,
                          encryption=gem.aes_encryption.lower() == 'true',
                          handler=handler,
                          multicast=False)

    @property
    def pon_id(self):
        return self._pon_id

    @property
    def onu_id(self):
        return self._onu_id

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value

    @property
    def encryption(self):
        return self._encryption

    @encryption.setter
    def encryption(self, value):
        assert isinstance(value, bool), 'encryption is a boolean'

        if self._encryption != value:
            self._encryption = value
            self.set_config(self._handler.rest_client, 'encryption', value)

    @inlineCallbacks
    def add_to_hardware(self, session, operation='POST'):
        if self._is_mock:
            returnValue('mock')

        uri = AdtranOltHandler.GPON_GEM_CONFIG_LIST_URI.format(self.pon_id, self.onu_id)
        data = json.dumps(self.to_dict())
        name = 'gem-port-create-{}-{}: {}/{}'.format(self.pon_id, self.onu_id,
                                                     self.gem_id,
                                                     self.alloc_id)
        try:
            results = yield session.request(operation, uri, data=data, name=name)
            returnValue(results)

        except Exception as e:
            if operation == 'POST':
                result = yield self.add_to_hardware(session, operation='PATCH')
                returnValue(result)
            else:
                log.exception('add-2-hw', gem=self, e=e)
                raise

    def remove_from_hardware(self, session):
        if self._is_mock:
            returnValue('mock')

        uri = AdtranOltHandler.GPON_GEM_CONFIG_URI.format(self.pon_id, self.onu_id, self.gem_id)
        name = 'gem-port-delete-{}-{}: {}'.format(self.pon_id, self.onu_id, self.gem_id)
        return session.request('DELETE', uri, name=name)

    def set_config(self, session, leaf, value):
        from ..adtran_olt_handler import AdtranOltHandler

        data = json.dumps({leaf: value})
        uri = AdtranOltHandler.GPON_GEM_CONFIG_URI.format(self.pon_id,
                                                          self.onu_id,
                                                          self.gem_id)
        name = 'onu-set-config-{}-{}-{}'.format(self._pon_id, leaf, str(value))
        return session.request('PATCH', uri, data=data, name=name)
