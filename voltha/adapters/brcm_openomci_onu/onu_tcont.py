#
# Copyright 2018 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import structlog
from common.frameio.frameio import hexify
from twisted.internet.defer import  inlineCallbacks, returnValue, succeed
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.omci_defs import *

RC = ReasonCodes


class OnuTCont(object):
    """
    Broadcom ONU specific implementation
    """
    def __init__(self, handler, alloc_id, traffic_descriptor,
                 name=None, vont_ani=None):

        self.log = structlog.get_logger(device_id=handler.device_id, alloc_id=alloc_id)
        self.log.debug('function-entry')

        self.alloc_id = alloc_id
        self.traffic_descriptor = traffic_descriptor
        self.name = name
        self.vont_ani = vont_ani        # (string) reference

        self._handler = handler
        self._entity_id = None

    @property
    def entity_id(self):
        self.log.debug('function-entry')
        return self._entity_id

    @staticmethod
    def create(handler, tcont, td):
        log = structlog.get_logger(tcont=tcont, td=td)
        log.debug('function-entry', tcont=tcont)

        return OnuTCont(handler,
                        tcont['alloc-id'],
                        td,
                        name=tcont['name'],
                        vont_ani=tcont['vont-ani'])

    @inlineCallbacks
    def add_to_hardware(self, omci, tcont_entity_id):
        self.log.debug('function-entry', omci=omci, tcont_entity_id=tcont_entity_id)
        self.log.debug('add-to-hardware', tcont_entity_id=tcont_entity_id)

        self._entity_id = tcont_entity_id

        try:
            msg = TcontFrame(self.entity_id, self.alloc_id)
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci.send(frame)
            self.check_status_and_state(results, 'set-tcont')

        except Exception as e:
            self.log.exception('tcont-set', e=e)
            raise

        returnValue(results)

    @inlineCallbacks
    def remove_from_hardware(self, omci):
        self.log.debug('function-entry', omci=omci)
        self.log.debug('remove-from-hardware', tcont_entity_id=self.entity_id)

        # Release tcont by setting alloc_id=0xFFFF
        # TODO: magic number, create a named variable

        try:
            msg = TcontFrame(self.entity_id, 0xFFFF)
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci.send(frame)
            self.check_status_and_state(results, 'delete-tcont')

        except Exception as e:
            self.log.exception('tcont-delete', e=e)
            raise

        returnValue(results)


    def check_status_and_state(self, results, operation=''):
        self.log.debug('function-entry')
        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')

        self.log.debug("OMCI Result: %s", operation, omci_msg=omci_msg,
                       status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            return True

        elif status == RC.InstanceExists:
            return False
