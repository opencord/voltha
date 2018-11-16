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
from twisted.internet.defer import inlineCallbacks, failure, returnValue
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_me import MEFrame
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciCreate, OmciSet, OmciDelete
from voltha.extensions.omci.omci_entities import EntityClass

RC = ReasonCodes
OP = EntityOperations


class ModifyException(Exception):
    pass


class OmciModifyRequest(Task):
    """
    OpenOMCI Generic Create, Set, or Delete Frame support Task.

    This task allows an ONU to send a Create, Set, or Delete request from any point in their
    code while properly using the OMCI-CC channel.  Direct access to the OMCI-CC object
    to send requests by an ONU is highly discouraged.
    """
    task_priority = 128
    name = "ONU OMCI Modify Task"

    def __init__(self, omci_agent, device_id, frame, priority=task_priority, exclusive=False):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param frame: (OmciFrame) Frame to send
        :param priority: (int) OpenOMCI Task priority (0..255) 255 is the highest
        :param exclusive: (bool) True if this GET request Task exclusively own the
                                 OMCI-CC while running. Default: False
        """
        super(OmciModifyRequest, self).__init__(OmciModifyRequest.name,
                                                omci_agent,
                                                device_id,
                                                priority=priority,
                                                exclusive=exclusive)
        self._device = omci_agent.get_device(device_id)
        self._frame = frame
        self._results = None
        self._local_deferred = None

        # Validate message type
        self._msg_type = frame.fields['message_type']
        if self._msg_type not in (OmciCreate.message_id, OmciSet.message_id, OmciDelete.message_id):
            raise TypeError('Invalid Message type: {}, must be Create, Set, or Delete'.
                            format(self._msg_type))

    def cancel_deferred(self):
        super(OmciModifyRequest, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    @property
    def success_code(self):
        """
        Return the OMCI success/reason code for the Get Response.
        """
        if self._results is None:
            return None

        return self._results.fields['omci_message'].fields['success_code']

    @property
    def illegal_attributes_mask(self):
        """
        For Create & Set requests, a failure may indicate that one or more
        attributes have an illegal value.  This property returns any illegal
        attributes

        :return: None if not a create/set request, otherwise the attribute mask
                 of illegal attributes
        """
        if self._results is None:
            return None

        omci_msg = self._results.fields['omci_message'].fields

        if self._msg_type == OmciCreate.message_id:
            if self.success_code != RC.ParameterError:
                return 0
            return omci_msg['parameter_error_attributes_mask']

        elif self._msg_type == OmciSet.message_id:
            if self.success_code != RC.AttributeFailure:
                return 0
            return omci_msg['failed_attributes_mask']

        return None

    @property
    def unsupported_attributes_mask(self):
        """
        For Set requests, a failure may indicate that one or more attributes
        are not supported by this ONU. This property returns any those unsupported attributes

        :return: None if not a set request, otherwise the attribute mask of any illegal
                 parameters
        """
        if self._msg_type != OmciSet.message_id or self._results is None:
            return None

        if self.success_code != RC.AttributeFailure:
            return 0

        return self._results.fields['omci_message'].fields['unsupported_attributes_mask']

    @property
    def raw_results(self):
        """
        Return the raw Response OMCIFrame
        """
        return self._results

    def start(self):
        """
        Start MIB Capabilities task
        """
        super(OmciModifyRequest, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_omci)

    @inlineCallbacks
    def perform_omci(self):
        """
        Perform the request
        """
        self.log.debug('perform-request')

        try:
            self.strobe_watchdog()
            self._results = yield self._device.omci_cc.send(self._frame)

            status = self._results.fields['omci_message'].fields['success_code']
            self.log.debug('response-status', status=status)

            # Success?
            if status in (RC.Success.value, RC.InstanceExists):
                self.deferred.callback(self)
            else:
                raise ModifyException('Failed with status {}'.format(status))

        except Exception as e:
            self.log.exception('perform-modify', e=e)
            self.deferred.errback(failure.Failure(e))
