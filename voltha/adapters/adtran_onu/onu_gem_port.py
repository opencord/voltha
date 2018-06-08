
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
from twisted.internet.defer import inlineCallbacks, returnValue
from voltha.extensions.omci.omci_me import GemPortNetworkCtpFrame, GemInterworkingTpFrame


class OnuGemPort(GemPort):
    """
    Adtran ONU specific implementation
    """
    def __init__(self, gem_id, alloc_id, entity_id,
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
        super(OnuGemPort, self).__init__(gem_id, alloc_id,
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
        self._entity_id = entity_id
        self.log = structlog.get_logger(device_id=handler.device_id, gem_id=gem_id)

    @property
    def entity_id(self):
        return self._entity_id

    @property
    def encryption(self):
        return self._encryption

    @encryption.setter
    def encryption(self, value):
        assert isinstance(value, bool), 'encryption is a boolean'

        if self._encryption != value:
            self._encryption = value

    @staticmethod
    def create(handler, gem_port, entity_id, is_mock=False):

        return OnuGemPort(gem_port['gemport-id'],
                          None,
                          entity_id,
                          encryption=gem_port['encryption'],  # aes_indicator,
                          tcont_ref=gem_port['tcont-ref'],
                          name=gem_port['name'],
                          traffic_class=gem_port['traffic-class'],
                          handler=handler,
                          untagged='untagged' in gem_port['name'].lower(),
                          is_mock=is_mock)

    @inlineCallbacks
    def add_to_hardware(self, omci,
                        tcont_entity_id,
                        ieee_mapper_service_profile_entity_id,
                        gal_enet_profile_entity_id):
        self.log.debug('add-to-hardware', gem_id=self.gem_id,
                       tcont_entity_id=tcont_entity_id,
                       ieee_mapper_service_profile_entity_id=ieee_mapper_service_profile_entity_id,
                       gal_enet_profile_entity_id=gal_enet_profile_entity_id)
        if self._is_mock:
            returnValue('mock')

        try:
            direction = "downstream" if self.multicast else "bi-directional"
            assert not self.multicast, 'MCAST is not supported yet'

            frame = GemPortNetworkCtpFrame(
                    self.entity_id,          # same entity id as GEM port
                    port_id=self.gem_id,
                    tcont_id=tcont_entity_id,
                    direction=direction,
                    upstream_tm=0x8000      # TM ID, 32768 unique ID set in TD set  TODO: Parameterize
                                            # This is Priority Queue ME with this entity ID
                                            # and the ME's related port value is 0x01.00.0007
                                            # which is  slot=0x01, tcont# = 0x00, priority= 0x0007
            ).create()
            results = yield omci.send(frame)

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-gem-port-network-ctp', status=status, error_mask=error_mask)

        except Exception as e:
            self.log.exception('gemport-create', e=e)
            raise

        try:
            frame = GemInterworkingTpFrame(
                self.entity_id,          # same entity id as GEM port
                gem_port_network_ctp_pointer=self.entity_id,
                interworking_option=5,                             # IEEE 802.1
                service_profile_pointer=ieee_mapper_service_profile_entity_id,
                interworking_tp_pointer=0x0,
                pptp_counter=1,
                gal_profile_pointer=gal_enet_profile_entity_id
            ).create()
            results = yield omci.send(frame)

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-gem-interworking-tp', status=status, error_mask=error_mask)

        except Exception as e:
            self.log.exception('interworking-create', e=e)
            raise

        returnValue(results)

    @inlineCallbacks
    def remove_from_hardware(self, omci):
        self.log.debug('remove-from-hardware',  gem_id=self.gem_id)
        if self._is_mock:
            returnValue('mock')

        try:
            frame = GemInterworkingTpFrame(self.entity_id).delete()
            results = yield omci.send(frame)

            status = results.fields['omci_message'].fields['success_code']
            self.log.debug('delete-gem-interworking-tp', status=status)

        except Exception as e:
            self.log.exception('interworking-delete', e=e)
            raise

        try:
            frame = GemPortNetworkCtpFrame(self.entity_id).delete()
            results = yield omci.send(frame)

            status = results.fields['omci_message'].fields['success_code']
            self.log.debug('delete-gem-port-network-ctp', status=status)

        except Exception as e:
            self.log.exception('gemport-delete', e=e)
            raise

        returnValue(results)
