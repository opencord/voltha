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
#
from task import Task
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, failure
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciDelete

RC = ReasonCodes
OP = EntityOperations


class DeletePMException(Exception):
    pass


class OmciDeletePMRequest(Task):
    """
    OpenOMCI routine to delete the requested PM Interval MEs
    """
    task_priority = Task.DEFAULT_PRIORITY
    name = "ONU OMCI Delete PM ME Task"

    def __init__(self, omci_agent, device_id, me_set, exclusive=False):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param me_set: (set) Tuples of class_id / entity_id to create
        :param exclusive: (bool) True if this Create request Task exclusively own the
                                 OMCI-CC while running. Default: False
        """
        super(OmciDeletePMRequest, self).__init__(OmciDeletePMRequest.name,
                                                  omci_agent,
                                                  device_id,
                                                  priority=OmciDeletePMRequest.task_priority,
                                                  exclusive=exclusive)
        self._device = omci_agent.get_device(device_id)
        self._me_tuples = me_set
        self._local_deferred = None

    def cancel_deferred(self):
        super(OmciDeletePMRequest, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """ Start task """
        super(OmciDeletePMRequest, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_delete)

    @inlineCallbacks
    def perform_delete(self):
        """ Perform the delete requests """
        self.log.debug('perform-delete')

        try:
            for me in self._me_tuples:
                class_id = me[0]
                entity_id = me[1]

                frame = OmciFrame(
                    transaction_id=None,
                    message_type=OmciDelete.message_id,
                    omci_message=OmciDelete(
                        entity_class=class_id,
                        entity_id=entity_id
                    )
                )
                self.strobe_watchdog()
                results = yield self._device.omci_cc.send(frame)

                status = results.fields['omci_message'].fields['success_code']
                self.log.debug('perform-delete-status', status=status)

                # Did it fail, it instance does not exist, not an error
                if status != RC.Success.value and status != RC.UnknownInstance.value:
                    msg = 'ME: {}, entity: {} failed with status {}'.format(class_id,
                                                                            entity_id,
                                                                            status)
                    raise DeletePMException(msg)

                self.log.debug('delete-pm-success', class_id=class_id,
                               entity_id=entity_id)
            self.deferred.callback(self)

        except Exception as e:
            self.log.exception('perform-create', e=e)
            self.deferred.errback(failure.Failure(e))
