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
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict
from voltha.extensions.omci.database.mib_db_ext import MibDbExternal
from voltha.extensions.omci.state_machines.mib_sync import MibSynchronizer
from voltha.extensions.omci.tasks.mib_upload import MibUploadTask
from voltha.extensions.omci.tasks.get_mds_task import GetMdsTask
from voltha.extensions.omci.tasks.mib_resync_task import MibResyncTask

from voltha.extensions.omci.onu_device_entry import OnuDeviceEntry

OpenOmciAgentDefaults = {
    'mib-synchronizer': {
        'state-machine': MibSynchronizer,  # Implements the MIB synchronization state machine
        # 'database': MibDbVolatileDict,     # Implements volatile ME MIB database
        'database': MibDbExternal,         # Implements persistent ME MIB database
        'tasks': {
            'mib-upload': MibUploadTask,
            'get-mds': GetMdsTask,
            'mib-audit': GetMdsTask,
            'mib-resync': MibResyncTask,
            'mib-reconcile': None        # TODO: post-v1.3.0 (Reconcile out-of-sync MIB DB)
        }
    },
    # TODO: Alarm-synchronizer is a stretch goal for Voltha 1.3.0
    # 'alarm-syncronizer': {
    #     'state-machine': AlarmSynchronizer,  # Implements the MIB synchronization state machine
    #     'database': AlarmDb,                 # For any State storage needs
    #     'tasks': {
    #         'task-1': needToWrite,
    #         'task-2': needToWrite,
    #     }
    # }
}


class OpenOMCIAgent(object):
    """
    OpenOMCI for VOLTHA

    This will become the primary interface into OpenOMCI for ONU Device Adapters
    in VOLTHA v1.3 sprint 3 time frame.
    """
    def __init__(self, core, support_classes=OpenOmciAgentDefaults):
        """
        Class initializer

        :param core: (VolthaCore) VOLTHA Core
        :param support_classes: (Dict) Classes to support OMCI
        """
        self.log = structlog.get_logger()
        self._core = core
        self._started = False
        self._devices = dict()        # device-id -> DeviceEntry

        # MIB Synchronization
        self._mib_db = None
        self._mib_synchronizer_info = support_classes['mib-synchronizer']
        self._mib_database_cls = self._mib_synchronizer_info['database']

        # Alarm Synchronization  # TODO: Stretch goal for VOLTHA v1.3.0
        # self._alarm_db = None
        # self._alarm_synchronizer_info = support_classes['alarm-synchronizer']
        # self._alarm_database_cls = self._alarm_synchronizer_info['database']

    @property
    def core(self):
        """ Return a reference to the VOLTHA Core component"""
        return self._core

    def start(self):
        """
        Start OpenOMCI
        """
        if self._started:
            return

        self.log.debug('start')
        self._started = True

        try:
            # Create all databases as needed. This should be done before
            # State machines are started for the first time

            if self._mib_db is None:
                self._mib_db = self._mib_database_cls(self)

            # TODO Alarm DB

            # Start/restore databases

            self._mib_db.start()

            for device in self._devices.itervalues():
                device.start()

        except Exception as e:
            self.log.exception('startup', e=e)

    def stop(self):
        """
        Shutdown OpenOMCI
        """
        if not self._started:
            return

        self.log.debug('stop')
        self._started = False

        # ONUs OMCI shutdown

        for device in self._devices.itervalues():
            device.stop()

        # DB shutdown
        self._mib_db.stop()

    def add_device(self, device_id, adapter_agent, custom_me_map=None):
        """
        Add a new ONU to be managed.

        To provide vendor-specific or custom Managed Entities, create your own Entity
        ID to class mapping dictionary.

        Since ONU devices can be added at any time (even during Device Handler
        startup), the ONU device handler is responsible for calling start()/stop()
        for this object.

        :param device_id: (str) Device ID of ONU to add
        :param adapter_agent: (AdapterAgent) Adapter agent for ONU
        :param custom_me_map: (dict) Additional/updated ME to add to class map

        :return: (OnuDeviceEntry) The ONU device
        """
        self.log.debug('add-device', device_id=device_id)

        device = self._devices.get(device_id)

        if device is None:
            device = OnuDeviceEntry(self, device_id, adapter_agent, custom_me_map,
                                    self._mib_synchronizer_info, self._mib_db)

            self._devices[device_id] = device

        return device

    def remove_device(self, device_id, cleanup=False):
        """
        Remove a managed ONU

        :param device_id: (str) Device ID of ONU to remove
        :param cleanup: (bool) If true, scrub any state related information
        """
        self.log.debug('remove-device', device_id=device_id, cleanup=cleanup)

        device = self._devices.get(device_id)

        if device is not None:
            device.stop()

            if cleanup:
                del self._devices[device_id]

    def device_ids(self):
        """
        Get an immutable set of device IDs managed by this OpenOMCI instance

        :return: (frozenset) Set of device IDs (str)
        """
        return frozenset(self._devices.keys())

    def get_device(self, device_id):
        """
        Get ONU device entry.  For external (non-OpenOMCI users) the ONU Device
        returned should be used for read-only activity.

        :param device_id: (str) ONU Device ID

        :return: (OnuDeviceEntry) ONU Device entry
        :raises KeyError: If device does not exist
        """
        return self._devices[device_id]
