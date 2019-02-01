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
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.adapters.adtran_olt.xpon.tcont import TCont
from voltha.adapters.adtran_olt.xpon.traffic_descriptor import TrafficDescriptor
from voltha.extensions.omci.omci_me import TcontFrame
from voltha.extensions.omci.omci_defs import ReasonCodes


class OnuTCont(TCont):
    """
    Adtran ONU specific implementation
    """
    FREE_TCONT_ALLOC_ID = 0xFFFF
    FREE_GPON_TCONT_ALLOC_ID = 0xFF     # SFU may use this to indicate a free TCONT

    def __init__(self, handler, alloc_id, sched_policy, tech_profile_id, uni_id, traffic_descriptor, is_mock=False):
        super(OnuTCont, self).__init__(alloc_id, tech_profile_id, traffic_descriptor, uni_id, is_mock=is_mock)
        self.log = structlog.get_logger(device_id=handler.device_id, alloc_id=alloc_id)

        self._handler = handler
        self.sched_policy = sched_policy
        self._entity_id = None
        self._free_alloc_id = OnuTCont.FREE_TCONT_ALLOC_ID

    @property
    def entity_id(self):
        return self._entity_id

    @staticmethod
    def create(handler, tcont, td):
        assert isinstance(tcont, dict), 'TCONT should be a dictionary'
        assert isinstance(td, TrafficDescriptor), 'Invalid Traffic Descriptor data type'
        return OnuTCont(handler,
                        tcont['alloc-id'],
                        tcont['q-sched-policy'],
                        tcont['tech-profile-id'],
                        tcont['uni-id'],
                        td)

    @inlineCallbacks
    def add_to_hardware(self, omci, tcont_entity_id, prev_alloc_id=FREE_TCONT_ALLOC_ID):
        self.log.debug('add-to-hardware', tcont_entity_id=tcont_entity_id)
        if self._is_mock:
            returnValue('mock')

        if self._entity_id == tcont_entity_id:
            returnValue('Already set')

        elif self.entity_id is not None:
            raise KeyError('TCONT already assigned: {}'.format(self.entity_id))

        try:
            # TODO: Look up ONU2-G QoS flexibility attribute and only set this
            #       if q-sched-policy  can be supported

            self._free_alloc_id = prev_alloc_id
            frame = TcontFrame(tcont_entity_id, self.alloc_id).set()
            results = yield omci.send(frame)

            status = results.fields['omci_message'].fields['success_code']
            if status == ReasonCodes.Success:
                self._entity_id = tcont_entity_id

            failed_attributes_mask = results.fields['omci_message'].fields['failed_attributes_mask']
            unsupported_attributes_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']

            self.log.debug('set-tcont', status=status,
                           failed_attributes_mask=failed_attributes_mask,
                           unsupported_attributes_mask=unsupported_attributes_mask)

        except Exception as e:
            self.log.exception('tcont-set', e=e)
            raise

        returnValue(results)

    @inlineCallbacks
    def remove_from_hardware(self, omci):
        self.log.debug('remove-from-hardware', tcont_entity_id=self.entity_id)
        if self._is_mock:
            returnValue('mock')
        try:
            frame = TcontFrame(self.entity_id, self._free_alloc_id).set()
            results = yield omci.send(frame)

            status = results.fields['omci_message'].fields['success_code']
            self.log.debug('delete-tcont', status=status)

            if status == ReasonCodes.Success:
                self._entity_id = None

        except Exception as e:
            self.log.exception('tcont-delete', e=e)
            raise

        returnValue(results)
