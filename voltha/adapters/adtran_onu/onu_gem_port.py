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
from voltha.adapters.adtran_olt.xpon.gem_port import GemPort
from twisted.internet.defer import inlineCallbacks, returnValue
from voltha.extensions.omci.omci_me import GemPortNetworkCtpFrame, GemInterworkingTpFrame
from voltha.extensions.omci.omci_defs import ReasonCodes


class OnuGemPort(GemPort):
    """
    Adtran ONU specific implementation
    """
    UPSTREAM = 1
    DOWNSTREAM = 2
    BIDIRECTIONAL = 3

    def __init__(self, handler, gem_data, alloc_id, tech_profile_id,
                 uni_id, entity_id,
                 multicast=False, traffic_class=None, is_mock=False):
        gem_id = gem_data['gemport-id']
        self.log = structlog.get_logger(device_id=handler.device_id, gem_id=gem_id)
        encryption = gem_data['encryption']

        super(OnuGemPort, self).__init__(gem_id, alloc_id, uni_id,
                                         tech_profile_id,
                                         encryption=encryption,
                                         multicast=multicast,
                                         traffic_class=traffic_class,
                                         handler=handler,
                                         is_mock=is_mock)
        try:
            self._gem_data = gem_data
            self._entity_id = entity_id
            self._tcont_entity_id = None
            self._interworking = False
            self.uni_id = gem_data['uni-id']
            self.direction = gem_data.get('direction', OnuGemPort.BIDIRECTIONAL)

            # IEEE 802.1p Mapper ME (#130) related parameters
            self._pbit_map = None
            self.pbit_map = gem_data.get('pbit-map', '0b00000011')

            # Upstream priority queue ME (#277) related parameters
            self.priority_q = gem_data.get('priority-q', 3)

            self._max_q_size = None
            self.max_q_size = gem_data.get('max-q-size', 'auto')

            self.weight = gem_data.get('weight', 8)

            self._discard_config = None
            self.discard_config = gem_data.get('discard-config',  None)

            self._discard_policy = None
            self.discard_policy = gem_data.get('discard-policy', 'TailDrop')

            # Traffic scheduler ME (#278) related parameters
            self._scheduling_policy = None
            self.scheduling_policy = gem_data.get('scheduling-policy', 'WRR')

        except Exception as _e:
            raise

    @property
    def entity_id(self):
        return self._entity_id

    @property
    def discard_config(self):
        return self._discard_config

    @discard_config.setter
    def discard_config(self, discard_config):
        assert isinstance(discard_config, dict), "discard-config not dict"
        assert 'max-probability' in discard_config, "max-probability missing"
        assert 'max-threshold' in discard_config, "max-hreshold missing"
        assert 'min-threshold' in discard_config, "min-threshold missing"
        self._discard_config = discard_config

    @property
    def discard_policy(self):
        self.log.debug('function-entry')
        return self._discard_policy

    @discard_policy.setter
    def discard_policy(self, discard_policy):
        dp = ("TailDrop", "WTailDrop", "RED", "WRED")
        assert (isinstance(discard_policy, str))
        assert (discard_policy in dp)
        self._discard_policy = discard_policy

    @property
    def max_q_size(self):
        return self._max_q_size

    @max_q_size.setter
    def max_q_size(self, max_q_size):
        if isinstance(max_q_size, str):
            assert (max_q_size == "auto")
        else:
            assert (isinstance(max_q_size, int))

        self._max_q_size = max_q_size

    @property
    def pbit_map(self):
        return self._pbit_map

    @pbit_map.setter
    def pbit_map(self, pbit_map):
        assert (isinstance(pbit_map, str))
        assert (len(pbit_map[2:]) == 8)  # Example format of pbit_map: "0b00000101"
        try:
            _ = int(pbit_map[2], 2)
        except ValueError:
            raise Exception("pbit_map-not-binary-string-{}".format(pbit_map))

        # remove '0b'
        self._pbit_map = pbit_map[2:]

    @property
    def scheduling_policy(self):
        return self._scheduling_policy

    @scheduling_policy.setter
    def scheduling_policy(self, scheduling_policy):
        sp = ("WRR", "StrictPriority")
        assert (isinstance(scheduling_policy, str))
        assert (scheduling_policy in sp)
        self._scheduling_policy = scheduling_policy

    @property
    def in_hardware(self):
        return self._tcont_entity_id is not None and self._interworking

    @staticmethod
    def create(handler, gem_data, alloc_id, tech_profile_id, uni_id, entity_id):
        return OnuGemPort(handler, gem_data, alloc_id,
                          tech_profile_id, uni_id, entity_id)

    @property
    def tcont(self):
        """ Get the associated TCONT object """
        return self._handler.pon_port.tconts.get(self.alloc_id)

    @inlineCallbacks
    def add_to_hardware(self, omci,
                        tcont_entity_id,
                        ieee_mapper_service_profile_entity_id,
                        gal_enet_profile_entity_id):
        if self._is_mock:
            returnValue('mock')

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
        if self._is_mock:
            returnValue('mock')

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
