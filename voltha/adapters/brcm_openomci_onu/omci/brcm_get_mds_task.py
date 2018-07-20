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
from voltha.extensions.omci.tasks.get_mds_task import GetMdsTask


class BrcmGetMdsTask(GetMdsTask):
    """
    OpenOMCI Get MIB Data Sync value task - Broadcom ONU

    On successful completion, this task will call the 'callback' method of the
    deferred returned by the start method and return the value of the MIB
    Data Sync attribute of the ONT Data ME
    """
    name = "BRCM: Get MDS Task"

    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        self.log = structlog.get_logger(device_id=device_id)
        self.log.debug('function-entry')

        super(BrcmGetMdsTask, self).__init__(omci_agent, device_id)

        self.name = BrcmGetMdsTask.name
        self._device = omci_agent.get_device(device_id)
        self._omci_managed = False      # TODO: Look up capabilities/model number/check handler

    def perform_get_mds(self):
        """
        Get the 'mib_data_sync' attribute of the ONU
        """
        self.log.debug('function-entry')
        self.log.info('perform-get-mds')

        if self._omci_managed:
            return super(BrcmGetMdsTask, self).perform_get_mds()

        # Non-OMCI managed BRCM ONUs always return 0 for MDS, use the MIB
        # sync value and depend on an accelerated mib resync to do the
        # proper comparison

        self.deferred.callback(self._device.mib_synchronizer.mib_data_sync)

