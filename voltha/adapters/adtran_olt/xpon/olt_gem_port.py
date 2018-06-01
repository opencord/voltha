
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

log = structlog.get_logger()


class OltGemPort(GemPort):
    """
    Adtran OLT specific implementation
    """
    def __init__(self, gem_id, alloc_id,
                 encryption=False,
                 omci_transport=False,
                 multicast=False,
                 tcont_ref=None,
                 traffic_class=None,
                 intf_ref=None,
                 untagged=False,
                 name=None,
                 handler=None,
                 is_mock=False):
        super(OltGemPort, self).__init__(gem_id, alloc_id,
                                         encryption=encryption,
                                         omci_transport=omci_transport,
                                         multicast=multicast,
                                         tcont_ref=tcont_ref,
                                         traffic_class=traffic_class,
                                         intf_ref=intf_ref,
                                         untagged=untagged,
                                         name=name,
                                         handler=handler)
        self._is_mock = is_mock

    @staticmethod
    def create(handler, gem_port):
        mcast = gem_port['gemport-id'] in [4095]    # TODO: Perform proper lookup
        untagged = 'untagged' in gem_port['name'].lower()
        # TODO: Use next once real BBF mcast available.
        # port_ref = 'channel-pair-ref 'if mcast else 'venet-ref'
        port_ref = 'venet-ref 'if mcast else 'venet-ref'

        return OltGemPort(gem_port['gemport-id'],
                          None,
                          encryption=gem_port['encryption'],  # aes_indicator,
                          tcont_ref=gem_port['tcont-ref'],
                          name=gem_port['name'],
                          traffic_class=gem_port['traffic-class'],
                          intf_ref=gem_port.get(port_ref),
                          handler=handler,
                          multicast=mcast,
                          untagged=untagged)

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
    def add_to_hardware(self, session, pon_id, onu_id, operation='POST'):
        from ..adtran_olt_handler import AdtranOltHandler
        log.info('add-gem-port-2-hw', pon_id=pon_id, onu_id=onu_id,
                 operation=operation, gem_port=self)
        uri = AdtranOltHandler.GPON_GEM_CONFIG_LIST_URI.format(pon_id, onu_id)
        data = json.dumps(self.to_dict())
        name = 'gem-port-create-{}-{}: {}/{}'.format(pon_id, onu_id,
                                                     self.gem_id,
                                                     self.alloc_id)
        try:
            results = yield session.request(operation, uri, data=data, name=name)

        except Exception as e:
            if operation == 'POST':
                returnValue(self.add_to_hardware(session, pon_id, onu_id,
                                                 operation='PATCH'))
            else:
                log.exception('add-2-hw', gem=self, e=e)
                raise

        returnValue(results)

    def remove_from_hardware(self, session, pon_id, onu_id):
        from ..adtran_olt_handler import AdtranOltHandler

        uri = AdtranOltHandler.GPON_GEM_CONFIG_URI.format(pon_id, onu_id, self.gem_id)
        name = 'gem-port-delete-{}-{}: {}'.format(pon_id, onu_id, self.gem_id)
        return session.request('DELETE', uri, name=name)

    def set_config(self, session, leaf, value):
        from ..adtran_olt_handler import AdtranOltHandler

        data = json.dumps({leaf: value})
        uri = AdtranOltHandler.GPON_GEM_CONFIG_URI.format(self.pon_id,
                                                          self.onu_id,
                                                          self.gem_id)
        name = 'onu-set-config-{}-{}-{}'.format(self._pon_id, leaf, str(value))
        return session.request('PATCH', uri, data=data, name=name)
