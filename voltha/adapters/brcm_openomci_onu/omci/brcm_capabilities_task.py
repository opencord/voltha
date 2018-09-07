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
from voltha.extensions.omci.tasks.onu_capabilities_task import OnuCapabilitiesTask
from twisted.internet.defer import failure


class BrcmCapabilitiesTask(OnuCapabilitiesTask):
    """
    OpenOMCI MIB Capabilities Task - BROADCOM ONUs

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
    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        self.log = structlog.get_logger(device_id=device_id)
        self.log.debug('function-entry')

        super(BrcmCapabilitiesTask, self).__init__(omci_agent, device_id)
        self._omci_managed = False      # TODO: Look up capabilities/model number

    @property
    def supported_managed_entities(self):
        """
        Return a set of the Managed Entity class IDs supported on this ONU

        None is returned if not MEs have been discovered

        :return: (set of ints)
        """
        self.log.debug('function-entry')

        if self._omci_managed:
            return super(BrcmCapabilitiesTask, self).supported_managed_entities

        # TODO: figure out why broadcom wont answer for ME 287 to get this.  otherwise manually fill in
        me_1287800f1 = [
            2, 5, 6, 7, 11, 24, 45, 46, 47, 48, 49, 50, 51, 52, 78, 79, 84, 89, 130,
            131, 133, 134, 135, 136, 137, 148, 157, 158, 159, 162, 163, 164, 171, 240,
            241, 242, 256, 257, 262, 263, 264, 266, 268, 272, 273, 274, 276, 277, 278,
            279, 280, 281, 287, 296, 297, 298, 307, 308, 309, 310, 311, 312, 321, 322,
            329, 330, 332, 334, 336, 340, 341, 342, 343, 347, 348, 425, 426
        ]
        return frozenset(list(me_1287800f1))

    @property
    def supported_message_types(self):
        """
        Return a set of the Message Types supported on this ONU

        None is returned if no message types have been discovered

        :return: (set of EntityOperations)
        """
        self.log.debug('function-entry')

        if self._omci_managed:
            return super(BrcmCapabilitiesTask, self).supported_message_types

        # TODO: figure out why broadcom wont answer for ME 287 to get this.  otherwise manually fill in
        from voltha.extensions.omci.omci_entities import EntityOperations
        op_11287800f1 = [
            EntityOperations.Create,
            EntityOperations.CreateComplete,
            EntityOperations.Delete,
            EntityOperations.Set,
            EntityOperations.Get,
            EntityOperations.GetComplete,
            EntityOperations.GetAllAlarms,
            EntityOperations.GetAllAlarmsNext,
            EntityOperations.MibUpload,
            EntityOperations.MibUploadNext,
            EntityOperations.MibReset,
            EntityOperations.AlarmNotification,
            EntityOperations.AttributeValueChange,
            EntityOperations.Test,
            EntityOperations.StartSoftwareDownload,
            EntityOperations.DownloadSection,
            EntityOperations.EndSoftwareDownload,
            EntityOperations.ActivateSoftware,
            EntityOperations.CommitSoftware,
            EntityOperations.SynchronizeTime,
            EntityOperations.Reboot,
            EntityOperations.GetNext,
        ]
        return frozenset(op_11287800f1)

    def perform_get_capabilities(self):
        """
        Perform the MIB Capabilities sequence.

        The sequence is to perform a Get request with the attribute mask equal
        to 'me_type_table'.  The response to this request will carry the size
        of (number of get-next sequences).

        Then a loop is entered and get-next commands are sent for each sequence
        requested.
        """
        self.log.debug('function-entry')

        self.log.info('perform-get')

        if self._omci_managed:
            # Return generator deferred/results
            return super(BrcmCapabilitiesTask, self).perform_get_capabilities()

        # Fixed values, no need to query
        try:
            self._supported_entities = self.supported_managed_entities
            self._supported_msg_types = self.supported_message_types

            self.log.debug('get-success',
                           supported_entities=self.supported_managed_entities,
                           supported_msg_types=self.supported_message_types)
            results = {
                'supported-managed-entities': self.supported_managed_entities,
                'supported-message-types': self.supported_message_types
            }
            self.deferred.callback(results)

        except Exception as e:
            self.log.exception('get-failed', e=e)
            self.deferred.errback(failure.Failure(e))


