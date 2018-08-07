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
from voltha.extensions.omci.state_machines.mib_sync import MibSynchronizer

log = structlog.get_logger()

class BrcmMibSynchronizer(MibSynchronizer):
    """
    OpenOMCI MIB Synchronizer state machine for Broadcom ONUs
    """
    # broadcom takes a while to sync.  going too often causes errors
    BRCM_RESYNC_DELAY = 300 # Periodically force a resync
    BRCM_TIMEOUT_RETRY = 60
    BRCM_AUDIT_DELAY = 0   # disable audit as if its out of sync nothing can fix it anyway

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
                                                  advertise_events=advertise_events,
                                                  # states=MibSynchronizer.DEFAULT_STATES,
                                                  # transitions=MibSynchronizer.DEFAULT_TRANSITIONS,
                                                  # initial_state='disabled',
                                                  timeout_delay=BrcmMibSynchronizer.BRCM_TIMEOUT_RETRY,
                                                  audit_delay=BrcmMibSynchronizer.BRCM_AUDIT_DELAY,
                                                  resync_delay=BrcmMibSynchronizer.BRCM_RESYNC_DELAY)
        self._omci_managed = False      # TODO: Look up model number/check handler

    def on_enter_auditing(self):
        """
        Perform a MIB Audit.  If our last MIB resync was too long in the
        past, perform a resynchronization anyway
        """
        self.log.debug('function-entry')

        # TODO: currently the audit/resync state machine cannot reconcile and re-add differences causing
        # it to loop forever
        self.log.info('audit-resync-not-supported')

        if self._omci_managed:
            super(BrcmMibSynchronizer, self).on_enter_auditing()

