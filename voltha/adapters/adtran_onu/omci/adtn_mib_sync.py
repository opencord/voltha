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
from voltha.extensions.omci.state_machines.mib_sync import MibSynchronizer


class AdtnMibSynchronizer(MibSynchronizer):
    """
    OpenOMCI MIB Synchronizer state machine for Adtran ONUs
    """
    ADTN_RESYNC_DELAY = 120     # Periodically force a resync (lower for debugging)
    ADTN_AUDIT_DELAY = 60

    def __init__(self, agent, device_id, mib_sync_tasks, db, advertise_events=False):
        """
        Class initialization

        :param agent: (OpenOmciAgent) Agent
        :param device_id: (str) ONU Device ID
        :param db: (MibDbVolatileDict) MIB Database
        :param mib_sync_tasks: (dict) Tasks to run
        :param advertise_events: (bool) Advertise events on OpenOMCI Event Bus
        """
        super(AdtnMibSynchronizer, self).__init__(agent, device_id, mib_sync_tasks, db,
                                                  advertise_events=advertise_events,
                                                  audit_delay=AdtnMibSynchronizer.ADTN_AUDIT_DELAY,
                                                  resync_delay=AdtnMibSynchronizer.ADTN_RESYNC_DELAY)
        self._first_in_sync = True
        self._omci_managed = False      # TODO: Look up model number/check handler

    def increment_mib_data_sync(self):
        if self._omci_managed:
            super(AdtnMibSynchronizer, self).increment_mib_data_sync()

        # IBONT 602 does not support MDS
        self._mib_data_sync = 0

    def on_enter_in_sync(self):
        """ Early first sync """
        if not self._omci_managed:
            # IBONT 602 does not support MDS, accelerate first forced resync
            # after a MIB reset occurs or on first startup
            if self._first_in_sync:
                self._first_in_sync = False
                # self._audit_delay = 10            # Re-enable after BBWF
                # self._resync_delay = 10
            else:
                self._audit_delay = MibSynchronizer.DEFAULT_AUDIT_DELAY
                self._resync_delay = AdtnMibSynchronizer.ADTN_RESYNC_DELAY

        super(AdtnMibSynchronizer, self).on_enter_in_sync()

    def on_enter_auditing(self):
        """
        Perform a MIB Audit.  If our last MIB resync was too long in the
        past, perform a resynchronization anyway
        """
        # Is this a model that supports full OMCI management. If so, use standard
        # forced resync delay

        if not self._omci_managed and self._check_if_mib_data_sync_supported():
            self._omci_managed = True
            # Revert to standard timeouts
            self._resync_delay = MibSynchronizer.DEFAULT_RESYNC_DELAY

        super(AdtnMibSynchronizer, self).on_enter_auditing()

    def _check_if_mib_data_sync_supported(self):
        return False    # TODO: Look up to see if we are/check handler

    def on_mib_reset_response(self, topic, msg):
        self._first_in_sync = True
        super(AdtnMibSynchronizer, self).on_mib_reset_response(topic, msg)
