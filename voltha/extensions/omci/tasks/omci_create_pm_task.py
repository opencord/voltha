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
from twisted.internet.defer import inlineCallbacks, failure, TimeoutError
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciCreate

RC = ReasonCodes
OP = EntityOperations


class CreatePMException(Exception):
    pass


class OmciCreatePMRequest(Task):
    """
    OpenOMCI routine to create the requested PM Interval MEs

    TODO: Support of thresholding crossing alarms will be in a future VOLTHA release
    """
    task_priority = Task.DEFAULT_PRIORITY
    name = "ONU OMCI Create PM ME Task"

    def __init__(self, omci_agent, device_id, me_dict, exclusive=False):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param me_dict: (dict) (pm cid, pm eid) -> (me cid, me eid, upstream)
        :param exclusive: (bool) True if this Create request Task exclusively own the
                                 OMCI-CC while running. Default: False
        """
        super(OmciCreatePMRequest, self).__init__(OmciCreatePMRequest.name,
                                                  omci_agent,
                                                  device_id,
                                                  priority=OmciCreatePMRequest.task_priority,
                                                  exclusive=exclusive)
        self._device = omci_agent.get_device(device_id)
        self._me_dict = me_dict
        self._local_deferred = None

    def cancel_deferred(self):
        super(OmciCreatePMRequest, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """ Start task """
        super(OmciCreatePMRequest, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_create)

    @inlineCallbacks
    def perform_create(self):
        """ Perform the create requests """

        try:
            for pm, me in self._me_dict.items():
                pm_class_id = pm[0]
                pm_entity_id = pm[1]
                me_class_id = me[0]
                me_entity_id = me[1]
                upstream = me[2]
                self.log.debug('create-pm-me', class_id=pm_class_id, entity_id=pm_entity_id)

                if me_class_id == 0:
                    # Typical/common PM interval format
                    frame = OmciFrame(
                        transaction_id=None,  # OMCI-CC will set
                        message_type=OmciCreate.message_id,
                        omci_message=OmciCreate(
                            entity_class=pm_class_id,
                            entity_id=pm_entity_id,
                            data=dict()
                        )
                    )
                else:
                    # Extended PM interval format. See ITU-T G.988 Section 9.3.32.
                    #    Bit 1 - continuous accumulation if set, 15-minute interval if unset
                    #    Bit 2 - directionality (0=upstream, 1=downstream)
                    #    Bit 3..14 - Reserved
                    #    Bit 15 - Use P bits of TCI field to filter
                    #    Bit 16 - Use VID bits of TCI field to filter
                    bitmap = 0 if upstream else 1 << 1

                    data = {'control_block': [
                        0,             # Threshold data 1/2 ID
                        me_class_id,   # Parent ME Class
                        me_entity_id,  # Parent ME Instance
                        0,             # Accumulation disable
                        0,             # TCA Disable
                        bitmap,        # Control fields bitmap
                        0,             # TCI
                        0              # Reserved
                    ]}
                    frame = OmciFrame(
                        transaction_id=None,  # OMCI-CC will set
                        message_type=OmciCreate.message_id,
                        omci_message=OmciCreate(
                            entity_class=pm_class_id,
                            entity_id=pm_entity_id,
                            data=data
                        )
                    )
                self.strobe_watchdog()
                try:
                    results = yield self._device.omci_cc.send(frame)
                except TimeoutError:
                    self.log.warning('perform-create-timeout', me_class_id=me_class_id, me_entity_id=me_entity_id,
                                     pm_class_id=pm_class_id, pm_entity_id=pm_entity_id)
                    raise

                status = results.fields['omci_message'].fields['success_code']
                self.log.debug('perform-create-status', status=status)

                # Did it fail
                if status != RC.Success.value and status != RC.InstanceExists.value:
                    msg = 'ME: {}, entity: {} failed with status {}'.format(pm_class_id,
                                                                            pm_entity_id,
                                                                            status)
                    raise CreatePMException(msg)

                self.log.debug('create-pm-success', class_id=pm_class_id,
                               entity_id=pm_entity_id)

            self.deferred.callback(self)

        except Exception as e:
            self.log.exception('perform-create', e=e)
            self.deferred.errback(failure.Failure(e))
