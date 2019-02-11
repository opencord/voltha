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
from binascii import hexlify
from twisted.internet.defer import inlineCallbacks, failure, returnValue
from twisted.internet import reactor
from voltha.extensions.omci.omci_defs import ReasonCodes
from voltha.extensions.omci.omci_me import OmciFrame
from voltha.extensions.omci.omci import EntityOperations
from voltha.extensions.omci.tasks.omci_get_request import OmciGetRequest
from voltha.extensions.omci.omci_entities import Omci


class GetNextException(Exception):
    pass


class GetCapabilitiesFailure(Exception):
    pass


class OnuCapabilitiesTask(Task):
    """
    OpenOMCI MIB Capabilities Task

    This task requests information on supported MEs via the OMCI (ME#287)
    Managed entity.

    This task should be ran after MIB Synchronization and before any MIB
    Downloads to the ONU.

    Upon completion, the Task deferred callback is invoked with dictionary
    containing the supported managed entities and message types.

    results = {
                'supported-managed-entities': {set of supported managed entities},
                'supported-message-types': {set of supported message types}
              }
    """
    task_priority = 240
    name = "ONU Capabilities Task"

    max_mib_get_next_retries = 3
    mib_get_next_delay = 5
    DEFAULT_OCTETS_PER_MESSAGE = 29

    def __init__(self, omci_agent, device_id, omci_pdu_size=DEFAULT_OCTETS_PER_MESSAGE):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param omci_pdu_size: (int) OMCI Data payload size (not counting any trailers)
        """
        super(OnuCapabilitiesTask, self).__init__(OnuCapabilitiesTask.name,
                                                  omci_agent,
                                                  device_id,
                                                  exclusive=False,
                                                  priority=OnuCapabilitiesTask.task_priority,
                                                  watchdog_timeout=2*Task.DEFAULT_WATCHDOG_SECS)
        self._local_deferred = None
        self._device = omci_agent.get_device(device_id)
        self._pdu_size = omci_pdu_size
        self._supported_entities = set()
        self._supported_msg_types = set()

    def cancel_deferred(self):
        super(OnuCapabilitiesTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    @property
    def supported_managed_entities(self):
        """
        Return a set of the Managed Entity class IDs supported on this ONU

        None is returned if no MEs have been discovered

        :return: (set of ints)
        """
        return frozenset(self._supported_entities) if len(self._supported_entities) else None

    @property
    def supported_message_types(self):
        """
        Return a set of the Message Types supported on this ONU

        None is returned if no message types have been discovered

        :return: (set of EntityOperations)
        """
        return frozenset(self._supported_msg_types) if len(self._supported_msg_types) else None

    def start(self):
        """
        Start MIB Capabilities task
        """
        super(OnuCapabilitiesTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_get_capabilities)

    def stop(self):
        """
        Shutdown MIB Capabilities task
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        self._device = None
        super(OnuCapabilitiesTask, self).stop()

    @inlineCallbacks
    def perform_get_capabilities(self):
        """
        Perform the MIB Capabilities sequence.

        The sequence is to perform a Get request with the attribute mask equal
        to 'me_type_table'.  The response to this request will carry the size
        of (number of get-next sequences).

        Then a loop is entered and get-next commands are sent for each sequence
        requested.
        """
        self.log.debug('perform-get')

        try:
            self.strobe_watchdog()
            self._supported_entities = yield self.get_supported_entities()
            self.strobe_watchdog()
            self._supported_msg_types = yield self.get_supported_message_types()
            self.strobe_watchdog()

            self.log.debug('get-success',
                           supported_entities=self.supported_managed_entities,
                           supported_msg_types=self.supported_message_types)
            results = {
                'supported-managed-entities': self.supported_managed_entities,
                'supported-message-types': self.supported_message_types
            }
            self.deferred.callback(results)

        except Exception as e:
            self.log.exception('perform-get', e=e)
            self.deferred.errback(failure.Failure(e))

    def get_count_from_data_buffer(self, data):
        """
        Extract the 4 octet buffer length from the OMCI PDU contents
        """
        self.log.debug('get-count-buffer', data=hexlify(data))
        return int(hexlify(data[:4]), 16)

    @inlineCallbacks
    def get_supported_entities(self):
        """
        Get the supported Message Types (actions) for this ONU.
        """
        try:
            # Use the GetRequest Task to perform table retrieval
            get_request = OmciGetRequest(self.omci_agent, self.device_id, Omci, 0,
                                         ["me_type_table"], exclusive=False)

            results = yield self._device.task_runner.queue_task(get_request)

            if results.success_code != ReasonCodes.Success.value:
                raise GetCapabilitiesFailure('Get supported managed entities table failed with status code: {}'.
                                             format(results.success_code))

            returnValue({attr.fields['me_type'] for attr in results.attributes['me_type_table']})

        except Exception as e:
            self.log.exception('get-entities', e=e)
            raise

    @inlineCallbacks
    def get_supported_message_types(self):
        """
        Get the supported Message Types (actions) for this ONU.
        """
        try:
            # Use the GetRequest Task to perform table retrieval
            get_request = OmciGetRequest(self.omci_agent, self.device_id, Omci, 0,
                                         ["message_type_table"], exclusive=False)

            results = yield self._device.task_runner.queue_task(get_request)

            if results.success_code != ReasonCodes.Success.value:
                raise GetCapabilitiesFailure('Get supported msg types table failed with status code: {}'.
                                             format(results.success_code))

            returnValue({attr.fields['msg_type'] for attr in results.attributes['message_type_table']})

        except Exception as e:
            self.log.exception('get-msg-types', e=e)
            raise
