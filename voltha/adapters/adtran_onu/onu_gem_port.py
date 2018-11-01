
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
from voltha.extensions.omci.omci_defs import ReasonCodes


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
                 name=None,
                 handler=None):
        super(OnuGemPort, self).__init__(gem_id, alloc_id,
                                         encryption=encryption,
                                         omci_transport=omci_transport,
                                         multicast=multicast,
                                         tcont_ref=tcont_ref,
                                         traffic_class=traffic_class,
                                         name=name,
                                         handler=handler)
        self._entity_id = entity_id
        self._tcont_entity_id = None
        self._interworking = False
        self.log = structlog.get_logger(device_id=handler.device_id, gem_id=gem_id)

    @property
    def entity_id(self):
        return self._entity_id

    @property
    def encryption(self):
        return self._encryption

    @property
    def in_hardware(self):
        return self._tcont_entity_id is not None and self._interworking

    @encryption.setter
    def encryption(self, value):
        assert isinstance(value, bool), 'encryption is a boolean'

        if self._encryption != value:
            self._encryption = value

    @staticmethod
    def create(handler, gem_port, entity_id):
        return OnuGemPort(gem_port['gemport-id'],
                          None,
                          entity_id,
                          encryption=gem_port['encryption'],  # aes_indicator,
                          tcont_ref=gem_port['tcont-ref'],
                          name=gem_port['name'],
                          traffic_class=gem_port['traffic-class'],
                          handler=handler)

    @inlineCallbacks
    def add_to_hardware(self, omci,
                        tcont_entity_id,
                        ieee_mapper_service_profile_entity_id,
                        gal_enet_profile_entity_id):

        self.log.debug('add-to-hardware', gem_id=self.gem_id,
                       gem_entity_id=self.entity_id,
                       tcont_entity_id=tcont_entity_id,
                       ieee_mapper_service_profile_entity_id=ieee_mapper_service_profile_entity_id,
                       gal_enet_profile_entity_id=gal_enet_profile_entity_id)

        if self._tcont_entity_id is not None and self._tcont_entity_id != tcont_entity_id:
            raise KeyError('GEM Port already assigned to TCONT: {}'.format(self._tcont_entity_id))

        results = None
        if self._tcont_entity_id is None:
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

                if status == ReasonCodes.Success or status == ReasonCodes.InstanceExists:
                    self._tcont_entity_id = tcont_entity_id
                else:
                    raise Exception('GEM Port create failed with status: {}'.format(status))

            except Exception as e:
                self.log.exception('gemport-create', e=e)
                raise

        if not self._interworking:
            try:
                extra = {'gal_loopback_configuration': 0}   # No loopback

                frame = GemInterworkingTpFrame(
                    self.entity_id,          # same entity id as GEM port
                    gem_port_network_ctp_pointer=self.entity_id,
                    interworking_option=5,                             # IEEE 802.1
                    service_profile_pointer=ieee_mapper_service_profile_entity_id,
                    interworking_tp_pointer=0x0,
                    pptp_counter=1,
                    gal_profile_pointer=gal_enet_profile_entity_id,
                    attributes=extra
                ).create()
                results = yield omci.send(frame)

                status = results.fields['omci_message'].fields['success_code']
                error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
                self.log.debug('create-gem-interworking-tp', status=status, error_mask=error_mask)

                if status == ReasonCodes.Success or status == ReasonCodes.InstanceExists:
                    self._interworking = True
                else:
                    raise Exception('GEM Interworking create failed with status: {}'.format(status))

            except Exception as e:
                self.log.exception('interworking-create', e=e)
                raise

        returnValue(results)

    @inlineCallbacks
    def remove_from_hardware(self, omci):
        self.log.debug('remove-from-hardware',  gem_id=self.gem_id)

        results = None
        if self._interworking:
            try:
                frame = GemInterworkingTpFrame(self.entity_id).delete()
                results = yield omci.send(frame)
                status = results.fields['omci_message'].fields['success_code']
                self.log.debug('delete-gem-interworking-tp', status=status)

                if status == ReasonCodes.Success:
                    self._interworking = False

            except Exception as e:
                self.log.exception('interworking-delete', e=e)
                raise

        if self._tcont_entity_id is not None:
            try:
                frame = GemPortNetworkCtpFrame(self.entity_id).delete()
                results = yield omci.send(frame)

                status = results.fields['omci_message'].fields['success_code']
                self.log.debug('delete-gem-port-network-ctp', status=status)

                if status == ReasonCodes.Success:
                    self._tcont_entity_id = None

            except Exception as e:
                self.log.exception('gemport-delete', e=e)
                raise

        returnValue(results)
