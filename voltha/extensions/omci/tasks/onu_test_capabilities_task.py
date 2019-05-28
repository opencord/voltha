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
from twisted.internet.defer import inlineCallbacks, failure, returnValue
from twisted.internet import reactor
from voltha.extensions.omci.omci_entities import AniG
from voltha.extensions.omci.tasks.omci_test_request import OmciTestRequest


class TestCapabilitiesFailure(Exception):
    pass


class OnuTestCapabilitiesTask(Task):
    """
    OpenOMCI MIB Capabilities Task

    This task requests information on supported MEs via the OMCI (ME#263)
    Managed entity.

    results = {
                'supported-managed-entities': {set of supported managed entities},
                'supported-message-types': {set of supported message types}
              }
    """
    task_priority = 240
    name = "ONU Test Capabilities Task"

    max_mib_get_next_retries = 3
    mib_get_next_delay = 5
    DEFAULT_OCTETS_PER_MESSAGE = 29

    def __init__(self, omci_agent, device_id,
                 omci_pdu_size=DEFAULT_OCTETS_PER_MESSAGE):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param omci_pdu_size: (int) OMCI Data payload size
        (not counting any trailers)
        """
        super(OnuTestCapabilitiesTask, self).__init__(
            OnuTestCapabilitiesTask.name,
            omci_agent,
            device_id,
            exclusive=False,
            priority=OnuTestCapabilitiesTask.task_priority,
            watchdog_timeout=6 * Task.DEFAULT_WATCHDOG_SECS)
        self._local_deferred = None
        self._local_deferred_test = None
        self._device = omci_agent.get_device(device_id)
        self._pdu_size = omci_pdu_size
        self._supported_entities = set()
        self._supported_msg_types = set()

    def cancel_deferred(self):
        """

        :return: None
        """
        super(OnuTestCapabilitiesTask, self).cancel_deferred()

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
        return frozenset(self._supported_entities) if len(
            self._supported_entities) else None

    @property
    def supported_message_types(self):
        """
        Return a set of the Message Types supported on this ONU

        None is returned if no message types have been discovered

        :return: (set of EntityOperations)
        """
        return frozenset(self._supported_msg_types) if len(
            self._supported_msg_types) else None

    def start(self):
        """
        Start MIB Capabilities task
        """
        super(OnuTestCapabilitiesTask, self).start()
        self._local_deferred_test = reactor.callLater(
            0, self.perform_test_capabilities)

    def stop(self):
        """
        Shutdown MIB Capabilities task
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        self._device = None
        super(OnuTestCapabilitiesTask, self).stop()

    @inlineCallbacks
    def test_supported_message_types(self):
        """
                Get the supported Message Types (actions) for this ONU.
        """
        try:
            ani_g_entities = self._device.configuration.ani_g_entities
            ani_g_entities_ids = ani_g_entities.keys() \
                if ani_g_entities is not None else None
            test_request = OmciTestRequest(self.omci_agent, self.device_id,
                                           AniG, ani_g_entities_ids[0],
                                           [], exclusive=False)
            results = yield self._device.task_runner.queue_task(test_request)
            returnValue(results)

        except Exception as e:
            self.log.exception('test-msg-types', e=e)
            raise

    @inlineCallbacks
    def test_supported_entities(self):
        """
        Get the supported Message Types (actions) for this ONU.
        """
        try:
            ani_g_entities = self._device.configuration.ani_g_entities
            ani_g_entities_ids = ani_g_entities.keys() if ani_g_entities \
                                                          is not None else None
            test_request = OmciTestRequest(self.omci_agent, self.device_id,
                                           AniG, ani_g_entities_ids[0],
                                           [], exclusive=False)
            results = yield self._device.task_runner.queue_task(test_request)
            returnValue(results)

        except Exception as e:
            self.log.exception('test-entities', e=e)
            raise

    @inlineCallbacks
    def perform_test_capabilities(self):
        """
         start the initial omci test capabilites.
        """
        self.log.debug('perform-test')

        try:
            self.strobe_watchdog()
            self._supported_entities = yield self.test_supported_entities()
            self.strobe_watchdog()
            self._supported_msg_types = yield self.test_supported_message_types()
            self.strobe_watchdog()
            self.log.debug('test-success',
                           supported_entities=self.supported_managed_entities,
                           supported_msg_types=self.supported_message_types)
            results = {
                'supported-managed-entities': self.supported_managed_entities,
                'supported-message-types': self.supported_message_types
            }
            self.deferred.callback(results)

        except Exception as e:
            self.log.exception('perform-test', e=e)
            self.deferred.errback(failure.Failure(e))
