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
from voltha.extensions.omci.tasks.onu_test_capabilities_task import \
    OnuTestCapabilitiesTask
from twisted.internet.defer import failure


class BrcmTestCapabilitiesTask(OnuTestCapabilitiesTask):
    """
    OpenOMCI MIB Capabilities Task - BROADCOM ONUs

    This task requests information on supported MEs via the OMCI (ME#263)
    Managed entity.

    This task should be ran after MIB Synchronization.
    results = {
                'supported-managed-entities': {set of supported managed entities},
                'supported-message-types': {set of supported message types}
              }
    """

    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        self.log = structlog.get_logger(device_id=device_id)
        self.log.debug('function-entry')

        super(BrcmTestCapabilitiesTask, self).__init__(omci_agent, device_id)
        self._omci_managed = False  # TODO: Look up capabilities/model number

    def perform_test_capabilities(self):
        """
         start the initial omci test capabilites.
        """
        self.log.debug('function-entry')

        self.log.info('perform-test')
        self._omci_managed = True
        if self._omci_managed:
            # Return generator deferred/results
            return super(BrcmTestCapabilitiesTask,
                         self).perform_test_capabilities()

        # Fixed values, no need to query
        try:
            self._supported_entities = frozenset(list([263]))
            from voltha.extensions.omci.omci_entities import EntityOperations
            self._supported_msg_types = frozenset(
                [EntityOperations.Test, EntityOperations.TestResult])

            self.log.debug('Test-success',
                           supported_entities=self._supported_entities,
                           supported_msg_types=self._supported_msg_types)
            results = {
                'supported-managed-entities': self._supported_entities,
                'supported-message-types': self._supported_msg_types
            }
            self.deferred.callback(results)

        except Exception as e:
            self.log.exception('test-failed', e=e)
            self.deferred.errback(failure.Failure(e))
