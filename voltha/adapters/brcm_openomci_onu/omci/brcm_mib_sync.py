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
from twisted.internet import reactor
from voltha.extensions.omci.state_machines.mib_sync import MibSynchronizer

log = structlog.get_logger()

class BrcmMibSynchronizer(MibSynchronizer):
    """
    OpenOMCI MIB Synchronizer state machine for Broadcom ONUs
    """

    def __init__(self, agent, device_id, mib_sync_tasks, db,
                 advertise_events=False):
        """
        Class initialization

        :param agent: (OpenOmciAgent) Agent
        :param device_id: (str) ONU Device ID
        :param db: (MibDbVolatileDict) MIB Database
        :param mib_sync_tasks: (dict) Tasks to run
        :param advertise_events: (bool) Advertise events on OpenOMCI Event Bus
        """
        self.log = structlog.get_logger(device_id=device_id)
        self.log.debug('function-entry')

        super(BrcmMibSynchronizer, self).__init__(agent, device_id, mib_sync_tasks, db,
                                                  advertise_events=advertise_events)

    def on_enter_starting(self):
        """
        Given resync and mib update is questionable (see below) flag the ONU as a new device which forces a mib
        reset and a mib upload
        """
        self.log.warn('db-sync-not-supported-forcing-reset')
        self._last_mib_db_sync_value = None
        super(BrcmMibSynchronizer, self).on_enter_starting()

    def on_enter_auditing(self):
        """
        Perform a MIB Audit.  Currently this is broken on BRCM based onu and its never in sync and continuously
        retries. On disable/enable it never enables becaues its never in sync.  Effectively disable the function so
        disable/enable works and we can figure out whats going on

        Oddly enough this is only an issue with MibVolatileDict
        """
        # TODO: Actually fix resync
        self.log.warn('audit-resync-not-supported')

        self._deferred = reactor.callLater(0, self.success)

    def on_enter_examining_mds(self):
        """
        Examine MIB difference counter between onu and voltha.  Currently same problem as on_enter_auditing.
        examine mds is always mismatched and causing disable/enable to fail

        Oddly enough this is only an issue with MibVolatileDict
        """
        # TODO: Actually fix resync
        self.log.warn('examine-mds-resync-not-supported')

        self._deferred = reactor.callLater(0, self.success)

