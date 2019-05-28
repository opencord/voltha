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
from twisted.internet import reactor
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict
from voltha.extensions.omci.database.mib_db_ext import MibDbExternal
from voltha.extensions.omci.state_machines.mib_sync import MibSynchronizer
from voltha.extensions.omci.tasks.mib_upload import MibUploadTask
from voltha.extensions.omci.tasks.get_mds_task import GetMdsTask
from voltha.extensions.omci.tasks.mib_resync_task import MibResyncTask
from voltha.extensions.omci.tasks.mib_reconcile_task import MibReconcileTask
from voltha.extensions.omci.tasks.sync_time_task import SyncTimeTask
from voltha.extensions.omci.state_machines.alarm_sync import AlarmSynchronizer
from voltha.extensions.omci.tasks.alarm_resync_task import AlarmResyncTask
from voltha.extensions.omci.database.alarm_db_ext import AlarmDbExternal
from voltha.extensions.omci.tasks.interval_data_task import IntervalDataTask
from voltha.extensions.omci.onu_device_entry import OnuDeviceEntry
from voltha.extensions.omci.state_machines.omci_onu_capabilities import OnuOmciCapabilities
from voltha.extensions.omci.tasks.onu_capabilities_task import OnuCapabilitiesTask
from voltha.extensions.omci.state_machines.performance_intervals import PerformanceIntervals
from voltha.extensions.omci.tasks.omci_create_pm_task import OmciCreatePMRequest
from voltha.extensions.omci.tasks.omci_delete_pm_task import OmciDeletePMRequest
from voltha.extensions.omci.state_machines.image_agent import ImageDownloadeSTM, OmciSoftwareImageDownloadSTM
from voltha.extensions.omci.tasks.file_download_task import FileDownloadTask
from voltha.extensions.omci.tasks.omci_sw_image_upgrade_task import OmciSwImageUpgradeTask

OpenOmciAgentDefaults = {
    'mib-synchronizer': {
        'state-machine': MibSynchronizer,  # Implements the MIB synchronization state machine
        'database': MibDbVolatileDict,     # Implements volatile ME MIB database
        # 'database': MibDbExternal,         # Implements persistent ME MIB database
        'advertise-events': True,          # Advertise events on OpenOMCI event bus
        'tasks': {
            'mib-upload': MibUploadTask,
            'get-mds': GetMdsTask,
            'mib-audit': GetMdsTask,
            'mib-resync': MibResyncTask,
            'mib-reconcile': MibReconcileTask
        }
    },
    'omci-capabilities': {
        'state-machine': OnuOmciCapabilities,   # Implements OMCI capabilities state machine
        'advertise-events': False,              # Advertise events on OpenOMCI event bus
        'tasks': {
            'get-capabilities': OnuCapabilitiesTask # Get supported ME and Commands
        }
    },
    'performance-intervals': {
        'state-machine': PerformanceIntervals,  # Implements PM Intervals State machine
        'advertise-events': False,              # Advertise events on OpenOMCI event bus
        'tasks': {
            'sync-time': SyncTimeTask,
            'collect-data': IntervalDataTask,
            'create-pm': OmciCreatePMRequest,
            'delete-pm': OmciDeletePMRequest,
        },
    },
    'alarm-synchronizer': {
        'state-machine': AlarmSynchronizer,    # Implements the Alarm sync state machine
        'database': AlarmDbExternal,           # For any State storage needs
        'advertise-events': True,              # Advertise events on OpenOMCI event bus
        'tasks': {
            'alarm-resync': AlarmResyncTask
        }
     },
    'image_downloader': {
        'state-machine': ImageDownloadeSTM,
        'advertise-event': True,
        'tasks': {
            'download-file': FileDownloadTask
        }
    },
    'image_upgrader': {
        'state-machine': OmciSoftwareImageDownloadSTM,
        'advertise-event': True,
        'tasks': {
            'omci_upgrade_task': OmciSwImageUpgradeTask
        }
    }
    # 'image_activator': {
    #     'state-machine': OmciSoftwareImageActivateSTM,
    #     'advertise-event': True,
    # }
}


class OpenOMCIAgent(object):
    """
    OpenOMCI for VOLTHA

    This will become the primary interface into OpenOMCI for ONU Device Adapters
    in VOLTHA v1.3 sprint 3 time frame.
    """
    def __init__(self, core, support_classes=OpenOmciAgentDefaults, clock=None):
        """
        Class initializer

        :param core: (VolthaCore) VOLTHA Core
        :param support_classes: (Dict) Classes to support OMCI
        """
        self.log = structlog.get_logger()
        self._core = core
        self.reactor = clock if clock is not None else reactor
        self._started = False
        self._devices = dict()       # device-id -> DeviceEntry
        self._event_bus = None

        # OMCI related databases are on a per-agent basis. State machines and tasks
        # are per ONU Vendore
        #
        # MIB Synchronization Database
        self._mib_db = None
        self._mib_database_cls = support_classes['mib-synchronizer']['database']

        # Alarm Synchronization Database
        self._alarm_db = None
        self._alarm_database_cls = support_classes['alarm-synchronizer']['database']

    @property
    def core(self):
        """ Return a reference to the VOLTHA Core component"""
        return self._core

    @property
    def database_class(self):
        return self._mib_database_cls

    # TODO: Need to deprecate this. ImageAgent is using it and should not
    @property
    def database(self):
        return self._mib_db
        
    def start(self):
        """
        Start OpenOMCI
        """
        if self._started:
            return

        self.log.debug('OpenOMCIAgent.start')
        self._started = True

        try:
            # Create all databases as needed. This should be done before
            # State machines are started for the first time

            if self._mib_db is None:
                self._mib_db = self._mib_database_cls(self)

            if self._alarm_db is None:
                self._alarm_db = self._alarm_database_cls(self)

            # Start/restore databases

            self._mib_db.start()
            self._alarm_db.start()

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
        self._event_bus = None

        # ONUs OMCI shutdown
        for device in self._devices.itervalues():
            device.stop()

        # DB shutdown
        self._mib_db.stop()
        self._alarm_db.stop()

    def mk_event_bus(self):
        """ Get the event bus for OpenOMCI"""
        if self._event_bus is None:
            from voltha.extensions.omci.openomci_event_bus import OpenOmciEventBus
            self._event_bus = OpenOmciEventBus()

        return self._event_bus

    def advertise(self, event_type, data):
        """
        Advertise an OpenOMCU event on the kafka bus
        :param event_type: (int) Event Type (enumberation from OpenOMCI protobuf definitions)
        :param data: (Message, dict, ...) Associated data (will be convert to a string)
        """
        if self._started:
            try:
                self.mk_event_bus().advertise(event_type, data)

            except Exception as e:
                self.log.exception('advertise-failure', e=e)

    def add_device(self, device_id, adapter_agent, custom_me_map=None,
                   support_classes=OpenOmciAgentDefaults):
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
        :param support_classes: (dict) State machines and tasks for this ONU

        :return: (OnuDeviceEntry) The ONU device
        """
        self.log.debug('OpenOMCIAgent.add-device', device_id=device_id)

        device = self._devices.get(device_id)

        if device is None:
            device = OnuDeviceEntry(self, device_id, adapter_agent, custom_me_map,
                                    self._mib_db, self._alarm_db, support_classes, clock=self.reactor)

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
