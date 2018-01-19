
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
from voltha.adapters.adtran_olt.xpon.gem_port import GemPort
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
from omci.omci_me import GemPortNetworkCtpFrame


class OnuGemPort(GemPort):
    """
    Adtran ONU specific implementation
    """
    def __init__(self, gem_id, alloc_id,
                 encryption=False,
                 omci_transport=False,
                 multicast=False,
                 tcont_ref=None,
                 traffic_class=None,
                 intf_ref=None,
                 exception=False,  # FIXED_ONU
                 name=None,
                 handler=None,
                 is_mock=False):
        super(OnuGemPort, self).__init__(gem_id, alloc_id,
                                         encryption=encryption,
                                         omci_transport=omci_transport,
                                         multicast=multicast,
                                         tcont_ref=tcont_ref,
                                         traffic_class=traffic_class,
                                         intf_ref=intf_ref,
                                         exception=exception,
                                         name=name,
                                         handler=handler)
        self._is_mock = is_mock
        self.log = structlog.get_logger(device_id=handler.device_id, gem_id=gem_id)

    @property
    def encryption(self):
        return self._encryption

    @encryption.setter
    def encryption(self, value):
        assert isinstance(value, bool), 'encryption is a boolean'

        if self._encryption != value:
            self._encryption = value
            omci = None     # TODO: Get from handler

    @staticmethod
    def create(handler, gem_port, is_mock=False):
        return OnuGemPort(gem_port['gemport-id'],
                          None,
                          encryption=gem_port['encryption'],  # aes_indicator,
                          tcont_ref=gem_port['tcont-ref'],
                          name=gem_port['name'],
                          traffic_class=gem_port['traffic-class'],
                          handler=handler,
                          is_mock=is_mock)

    @inlineCallbacks
    def add_to_hardware(self, omci):
        if self._is_mock:
            returnValue('mock')

        omci = self._handler.omci
        tcont = self.tcont
        assert omci is not None, 'No OMCI engine'
        assert tcont is not None, 'No TCONT'
        assert tcont.entity_id == 0x8001, 'Hardcoded Entity ID NOT FOUND'

        try:
            direction = "downstream" if self.multicast else "bi-directional"
            assert not self.multicast, 'MCAST is not supported yet'

            # TODO: For TCONT ID, get the TCONT's entity ID that you programmed
            # TODO: For TM, is this the entity ID for a traffic descriptor?
            # results = yield omci.send_create_gem_port_network_ctp(self.gem_id,      # Entity ID
            #                                                       self.gem_id,      # Port ID
            #                                                       tcont.entity_id,  # TCONT ID
            #                                                       direction,        # Direction
            #                                                       0x100)            # TM
            results = None
            # results = yield omci.send(GemPortNetworkCtpFrame(self.gem_id,      # Entity ID
            #                                                  self.gem_id,      # Port ID
            #                                                  tcont.entity_id,  # TCONT ID
            #                                                  direction,        # Direction
            #                                                  0x100).create()   # TM

        except Exception as e:
            self.log.exception('gemport-create', e=e)
            raise

        try:
            # GEM Interworking config
            # TODO: For service mapper ID, always hardcoded or does it come from somewhere else
            #       It is probably the TCONT entity ID
            results = None
            # results = yield omci.send_create_gem_inteworking_tp(self.gem_id,      # Entity ID
            #                                                     self.gem_id,      # GEMPort NET CTP ID
            #                                                     tcont.entity_id)  # Service Mapper Profile ID
        except Exception as e:
            self.log.exception('interworking-create', e=e)
            raise

        try:
            # Mapper Service Profile config
            # TODO: All p-bits currently go to the one and only GEMPORT ID for now
            # TODO: The entity ID is probably the TCONT entity ID
            results = None
            # results = omci.send_set_8021p_mapper_service_profile(tcont.entity_id,  # Entity ID
            #                                                      self.gem_id)      # Interworking TP ID
        except Exception as e:
            self.log.exception('mapper-set', e=e)
            raise

        returnValue(results)

    @inlineCallbacks
    def remove_from_hardware(self, omci):
        if self._is_mock:
            returnValue('mock')

        omci = self._handler.omci
        assert omci is not None, 'No OMCI engine'

        results = succeed('TODO: Implement me')

        # uri = AdtranOltHandler.GPON_GEM_CONFIG_URI.format(pon_id, onu_id, self.gem_id)
        # name = 'gem-port-delete-{}-{}: {}'.format(pon_id, onu_id, self.gem_id)
        # return session.request('DELETE', uri, name=name)
        returnValue(results)

    def set_config(self, omci, value, leaf):
        if self._is_mock:
            return

        # from ..adtran_olt_handler import AdtranOltHandler
        #
        # data = json.dumps({leaf: value})
        # uri = AdtranOltHandler.GPON_GEM_CONFIG_URI.format(self.pon_id,
        #                                                   self.onu_id,
        #                                                   self.gem_id)
        # name = 'onu-set-config-{}-{}-{}'.format(self._pon_id, leaf, str(value))
        # return session.request('PATCH', uri, data=data, name=name)
        pass # TODO: Implement me
