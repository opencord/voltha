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
from twisted.internet.defer import  inlineCallbacks, returnValue, succeed

from voltha.adapters.adtran_olt.xpon.tcont import TCont
from voltha.adapters.adtran_olt.xpon.traffic_descriptor import TrafficDescriptor
from omci.omci_me import TcontFrame


class OnuTCont(TCont):
    """
    Adtran ONU specific implementation
    """
    def __init__(self, handler, alloc_id, traffic_descriptor, entity_id,
                 name=None, vont_ani=None, is_mock=False):
        super(OnuTCont, self).__init__(alloc_id, traffic_descriptor,
                                       name=name, vont_ani=vont_ani)
        self._handler = handler
        self._is_mock = is_mock
        self._entity_id = entity_id
        self.log = structlog.get_logger(device_id=handler.device_id, alloc_id=alloc_id)

    @property
    def entity_id(self):
        return self._entity_id

    @staticmethod
    def create(handler, tcont, td, is_mock=False):
        assert isinstance(tcont, dict), 'TCONT should be a dictionary'
        assert isinstance(td, TrafficDescriptor), 'Invalid Traffic Descriptor data type'

        # TODO: Pass in a unique TCONT Entity ID from the ONU's PON Object
        entity_id = 0x8001

        return OnuTCont(handler,
                        tcont['alloc-id'],
                        td,
                        entity_id,
                        name=tcont['name'],
                        vont_ani=tcont['vont-ani'],
                        is_mock=is_mock)

    @inlineCallbacks
    def add_to_hardware(self, omci):
        if self._is_mock:
            returnValue('mock')

        try:
            # TODO: What is a valid Entity ID (compute and save if needed)
            #
            # NOTE: Entity ID should be computed. For NGPON2, they were starting
            #       at 256 and incrementing.
            results = None
            # results = yield self._handler.omci.send_set_tcont(self._entity_id,  # Entity ID
            #                                                   self.alloc_id)    # Alloc ID

            # response = yield omci.send(TcontFrame(self._entity_id,
            #                                       alloc_id=self.alloc_id).get())

        except Exception as e:
            self.log.exception('tcont-set', e=e)
            raise

        returnValue(results)

    @inlineCallbacks
    def remove_from_hardware(self, omci):
        if self._is_mock:
            returnValue('mock')

        results = None
        # results = yield omci.send(TcontFrame(self._entity_id).delete())
        returnValue(results)











