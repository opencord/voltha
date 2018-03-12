#
# Copyright 2017 the original author or authors.
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

import structlog
from voltha.extensions.omci.omci_defs import EntityOperations, ReasonCodes
import voltha.extensions.omci.omci_entities as omci_entities
from voltha.extensions.omci.omci_cc import OMCI_CC
from common.event_bus import EventBusClient
from voltha.extensions.omci.tasks.task_runner import TaskRunner

from twisted.internet import reactor
from enum import IntEnum

OP = EntityOperations
RC = ReasonCodes

IN_SYNC_KEY = 'in-sync'
LAST_IN_SYNC_KEY = 'last-in-sync-time'


class OnuDeviceEvents(IntEnum):
    # Events of interest to Device Adapters and OpenOMCI State Machines
    DeviceStatusEvent = 0       # OnuDeviceEntry running status changed
    MibDatabaseSyncEvent = 1    # MIB database sync changed
    # TODO: Add other events here as needed


class OnuDeviceEntry(object):
    """
    An ONU Device entry in the MIB
    """
    def __init__(self, omci_agent, device_id, adapter_agent, custom_me_map,
                 mib_synchronizer_info, mib_db):
        """
        Class initializer

        :param device_id: (str) ONU Device ID
        :param custom_me_map: (dict) Additional/updated ME to add to class map
        """
        self.log = structlog.get_logger(device_id=device_id)

        self._started = False
        self._omci_agent = omci_agent         # OMCI AdapterAgent
        self._device_id = device_id           # ONU Device ID
        self._runner = TaskRunner(device_id)  # OMCI_CC Task runner
        self._deferred = None

        try:
            self._mib_db_in_sync = False
            self.mib_sync = mib_synchronizer_info['state-machine'](self._omci_agent,
                                                                   device_id,
                                                                   mib_synchronizer_info['tasks'],
                                                                   mib_db)
        except Exception as e:
            self.log.exception('mib-sync-create-failed', e=e)
            raise

        self._state_machines = [self.mib_sync]
        self._custom_me_map = custom_me_map
        self._me_map = omci_entities.entity_id_to_class_map.copy()

        if custom_me_map is not None:
            self._me_map.update(custom_me_map)

        self.event_bus = EventBusClient()

        # Create OMCI communications channel
        self._omci_cc = OMCI_CC(adapter_agent, self.device_id, self._me_map)

    @staticmethod
    def event_bus_topic(device_id, event):
        """
        Get the topic name for a given event for this ONU Device
        :param device_id: (str) ONU Device ID
        :param event: (OnuDeviceEvents) Type of event
        :return: (str) Topic string
        """
        assert event in OnuDeviceEvents, \
            'Event {} is not an ONU Device Event'.format(event.Name)
        return 'omci-device:{}:{}'.format(device_id, event.name)

    @property
    def device_id(self):
        return self._device_id

    @property
    def omci_cc(self):
        return self._omci_cc

    @property
    def task_runner(self):
        return self._runner

    @property
    def mib_synchronizer(self):
        return self.mib_sync

    @property
    def active(self):
        """
        Is the ONU device currently active/running
        """
        return self._started

    @property
    def custom_me_map(self):
        """ Custom Managed Entity Map for this device"""
        return self._custom_me_map

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    @property
    def mib_db_in_sync(self):
        return self._mib_db_in_sync

    @mib_db_in_sync.setter
    def mib_db_in_sync(self, value):
        if self._mib_db_in_sync != value:
            # Save value
            self._mib_db_in_sync = value

            # Notify any event listeners

            topic = OnuDeviceEntry.event_bus_topic(self.device_id,
                                                   OnuDeviceEvents.MibDatabaseSyncEvent)
            msg = {
                IN_SYNC_KEY: self._mib_db_in_sync,
                LAST_IN_SYNC_KEY: self.mib_synchronizer.last_mib_db_sync
            }
            self.event_bus.publish(topic=topic, msg=msg)

    def start(self):
        if self._started:
            return

        self._started = True
        self._omci_cc.enabled = True
        self._runner.start()

        # Start MIB Sync and other state machines. Start 'later' so that any
        # ONU Device, OMCI DB, OMCI Agent, and others are fully started before
        # performing the start.

        def start_state_machines(machines):
            for sm in machines:
                sm.start()

        self._deferred = reactor.callLater(0, start_state_machines,
                                           self._state_machines)
        # Notify any event listeners
        self._publish_device_status_event()

    def stop(self):
        if not self._started:
            return

        self._started = False
        self._cancel_deferred()
        self._omci_cc.enabled = False

        # Halt MIB Sync and other state machines
        for sm in self._state_machines:
            sm.stop()

        # Stop task runner
        self._runner.stop()

        # Notify any event listeners
        self._publish_device_status_event()

    def _publish_device_status_event(self):
        """
        Publish the ONU Device start/start status.
        """
        topic = OnuDeviceEntry.event_bus_topic(self.device_id,
                                               OnuDeviceEvents.DeviceStatusEvent)
        msg = {'active': self._started}
        self.event_bus.publish(topic=topic, msg=msg)

    def delete(self):
        self.stop()

    def query_mib(self, class_id=None, instance_id=None, attributes=None):
        """
        Get MIB database information.

        This method can be used to request information from the database to the detailed
        level requested

        :param class_id:  (int) Managed Entity class ID
        :param instance_id: (int) Managed Entity instance
        :param attributes: (list or str) Managed Entity instance's attributes

        :return: (dict) The value(s) requested. If class/inst/attribute is
                        not found, an empty dictionary is returned
        :raises DatabaseStateError: If the database is not enabled
        """
        self.log.debug('query', class_id=class_id, instance_id=instance_id,
                       attributes=attributes)

        return self.mib_synchronizer.query_mib(class_id=class_id, instance_id=instance_id,
                                               attributes=attributes)

    def query_mib_single_attribute(self, class_id, instance_id, attribute):
        """
        Get MIB database information for a single specific attribute

        This method can be used to request information from the database to the detailed
        level requested

        :param class_id:  (int) Managed Entity class ID
        :param instance_id: (int) Managed Entity instance
        :param attribute: (str) Managed Entity instance's attribute

        :return: (varies) The value requested. If class/inst/attribute is
                          not found, None is returned
        :raises DatabaseStateError: If the database is not enabled
        """
        self.log.debug('query-single', class_id=class_id,
                       instance_id=instance_id, attributes=attribute)
        assert isinstance(attribute, basestring), \
            'Only a single attribute value can be retrieved'

        entry = self.mib_synchronizer.query_mib(class_id=class_id,
                                                instance_id=instance_id,
                                                attributes=attribute)

        return entry[attribute] if attribute in entry else None
