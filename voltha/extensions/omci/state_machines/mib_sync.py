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
from datetime import datetime, timedelta
from transitions import Machine
from twisted.internet import reactor
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.database.mib_db_api import MDS_KEY
from voltha.extensions.omci.omci_defs import EntityOperations, ReasonCodes, \
    AttributeAccess
from voltha.extensions.omci.omci_cc import OmciCCRxEvents, OMCI_CC, TX_REQUEST_KEY, \
    RX_RESPONSE_KEY
from voltha.extensions.omci.onu_device_entry import OnuDeviceEvents, OnuDeviceEntry, \
    SUPPORTED_MESSAGE_ENTITY_KEY, SUPPORTED_MESSAGE_TYPES_KEY
from voltha.extensions.omci.omci_entities import OntData, Omci
from common.event_bus import EventBusClient
from voltha.protos.omci_mib_db_pb2 import OpenOmciEventType

RxEvent = OmciCCRxEvents
DevEvent = OnuDeviceEvents
OP = EntityOperations
RC = ReasonCodes
AA = AttributeAccess


class MibSynchronizer(object):
    """
    OpenOMCI MIB Synchronizer state machine
    """
    DEFAULT_STATES = ['disabled', 'starting', 'uploading', 'examining_mds',
                      'in_sync', 'out_of_sync', 'auditing', 'resynchronizing']

    DEFAULT_TRANSITIONS = [
        {'trigger': 'start', 'source': 'disabled', 'dest': 'starting'},

        {'trigger': 'upload_mib', 'source': 'starting', 'dest': 'uploading'},
        {'trigger': 'examine_mds', 'source': 'starting', 'dest': 'examining_mds'},

        {'trigger': 'success', 'source': 'uploading', 'dest': 'in_sync'},

        {'trigger': 'success', 'source': 'examining_mds', 'dest': 'in_sync'},
        {'trigger': 'mismatch', 'source': 'examining_mds', 'dest': 'resynchronizing'},

        {'trigger': 'audit_mib', 'source': 'in_sync', 'dest': 'auditing'},

        {'trigger': 'success', 'source': 'out_of_sync', 'dest': 'in_sync'},
        {'trigger': 'audit_mib', 'source': 'out_of_sync', 'dest': 'auditing'},

        {'trigger': 'success', 'source': 'auditing', 'dest': 'in_sync'},
        {'trigger': 'mismatch', 'source': 'auditing', 'dest': 'resynchronizing'},
        {'trigger': 'force_resync', 'source': 'auditing', 'dest': 'resynchronizing'},

        {'trigger': 'success', 'source': 'resynchronizing', 'dest': 'in_sync'},
        {'trigger': 'diffs_found', 'source': 'resynchronizing', 'dest': 'out_of_sync'},

        # Do wildcard 'timeout' trigger that sends us back to start
        {'trigger': 'timeout', 'source': '*', 'dest': 'starting'},

        # Do wildcard 'stop' trigger last so it covers all previous states
        {'trigger': 'stop', 'source': '*', 'dest': 'disabled'},
    ]
    DEFAULT_TIMEOUT_RETRY = 5     # Seconds to delay after task failure/timeout
    DEFAULT_AUDIT_DELAY = 60      # Periodic tick to audit the MIB Data Sync
    DEFAULT_RESYNC_DELAY = 300    # Periodically force a resync

    def __init__(self, agent, device_id, mib_sync_tasks, db,
                 advertise_events=False,
                 states=DEFAULT_STATES,
                 transitions=DEFAULT_TRANSITIONS,
                 initial_state='disabled',
                 timeout_delay=DEFAULT_TIMEOUT_RETRY,
                 audit_delay=DEFAULT_AUDIT_DELAY,
                 resync_delay=DEFAULT_RESYNC_DELAY):
        """
        Class initialization

        :param agent: (OpenOmciAgent) Agent
        :param device_id: (str) ONU Device ID
        :param db: (MibDbVolatileDict) MIB Database
        :param advertise_events: (bool) Advertise events on OpenOMCI Event Bus
        :param mib_sync_tasks: (dict) Tasks to run
        :param states: (list) List of valid states
        :param transitions: (dict) Dictionary of triggers and state changes
        :param initial_state: (str) Initial state machine state
        :param timeout_delay: (int/float) Number of seconds after a timeout to attempt
                                          a retry (goes back to starting state)
        :param audit_delay: (int) Seconds between MIB audits while in sync. Set to
                                  zero to disable audit. An operator can request
                                  an audit manually by calling 'self.audit_mib'
        :param resync_delay: (int) Seconds in sync before performing a forced MIB
                                   resynchronization
        """
        self.log = structlog.get_logger(device_id=device_id)

        self._agent = agent
        self._device_id = device_id
        self._device = None
        self._database = db
        self._timeout_delay = timeout_delay
        self._audit_delay = audit_delay
        self._resync_delay = resync_delay

        self._upload_task = mib_sync_tasks['mib-upload']
        self._get_mds_task = mib_sync_tasks['get-mds']
        self._audit_task = mib_sync_tasks['mib-audit']
        self._resync_task = mib_sync_tasks['mib-resync']
        self._reconcile_task = mib_sync_tasks['mib-reconcile']
        self._advertise_events = advertise_events

        self._deferred = None
        self._current_task = None  # TODO: Support multiple running tasks after v.2.0 release
        self._task_deferred = None
        self._mib_data_sync = 0
        self._last_mib_db_sync_value = None
        self._device_in_db = False
        self._next_resync = None

        self._on_olt_only_diffs = None
        self._on_onu_only_diffs = None
        self._attr_diffs = None
        self._audited_olt_db = None
        self._audited_onu_db = None

        self._event_bus = EventBusClient()
        self._omci_cc_subscriptions = {               # RxEvent.enum -> Subscription Object
            RxEvent.MIB_Reset: None,
            RxEvent.AVC_Notification: None,
            RxEvent.MIB_Upload: None,
            RxEvent.MIB_Upload_Next: None,
            RxEvent.Create: None,
            RxEvent.Delete: None,
            RxEvent.Set: None,
            RxEvent.Start_Software_Download: None,
            RxEvent.End_Software_Download: None,
            RxEvent.Activate_Software: None,
            RxEvent.Commit_Software: None,
        }
        self._omci_cc_sub_mapping = {
            RxEvent.MIB_Reset: self.on_mib_reset_response,
            RxEvent.AVC_Notification: self.on_avc_notification,
            RxEvent.MIB_Upload: self.on_mib_upload_response,
            RxEvent.MIB_Upload_Next: self.on_mib_upload_next_response,
            RxEvent.Create: self.on_create_response,
            RxEvent.Delete: self.on_delete_response,
            RxEvent.Set: self.on_set_response,
            RxEvent.Start_Software_Download: self.on_software_event,
            RxEvent.End_Software_Download: self.on_software_event,
            RxEvent.Activate_Software: self.on_software_event,
            RxEvent.Commit_Software: self.on_software_event,
        }
        self._onu_dev_subscriptions = {               # DevEvent.enum -> Subscription Object
            DevEvent.OmciCapabilitiesEvent: None
        }
        self._onu_dev_sub_mapping = {
            DevEvent.OmciCapabilitiesEvent: self.on_capabilities_event
        }

        # Statistics and attributes
        # TODO: add any others if it will support problem diagnosis

        # Set up state machine to manage states
        self.machine = Machine(model=self, states=states,
                               transitions=transitions,
                               initial=initial_state,
                               queued=True,
                               name='{}-{}'.format(self.__class__.__name__,
                                                   device_id))
        try:
            import logging
            logging.getLogger('transitions').setLevel(logging.WARNING)
        except Exception as e:
            self.log.exception('log-level-failed', e=e)

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._task_deferred = self._task_deferred, None

        for d in [d1, d1]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def __str__(self):
        return 'MIBSynchronizer: Device ID: {}, State:{}'.format(self._device_id, self.state)

    def delete(self):
        """
        Cleanup any state information
        """
        self.stop()
        db, self._database = self._database, None

        if db is not None:
            db.remove(self._device_id)

    @property
    def device_id(self):
        return self._device_id

    @property
    def mib_data_sync(self):
        return self._mib_data_sync

    def increment_mib_data_sync(self):
        self._mib_data_sync += 1
        if self._mib_data_sync > 255:
            self._mib_data_sync = 0

        if self._database is not None:
            self._database.save_mib_data_sync(self._device_id,
                                              self._mib_data_sync)
            self.log.info("mds-updated", device=self._device_id, mds=self._mib_data_sync)

    @property
    def last_mib_db_sync(self):
        return self._last_mib_db_sync_value

    @last_mib_db_sync.setter
    def last_mib_db_sync(self, value):
        self._last_mib_db_sync_value = value
        if self._database is not None:
            self._database.save_last_sync(self.device_id, value)

    @property
    def is_new_onu(self):
        """
        Is this a new ONU (has never completed MIB synchronization)
        :return: (bool) True if this ONU should be considered new
        """
        return self.last_mib_db_sync is None

    @property
    def advertise_events(self):
        return self._advertise_events

    @advertise_events.setter
    def advertise_events(self, value):
        if not isinstance(value, bool):
            raise TypeError('Advertise event is a boolean')
        self._advertise_events = value

    def advertise(self, event, info):
        """Advertise an event on the OpenOMCI event bus"""
        if self._advertise_events:
            self._agent.advertise(event,
                                  {
                                      'state-machine': self.machine.name,
                                      'info': info,
                                      'time': str(datetime.utcnow())
                                  })

    def on_enter_disabled(self):
        """
        State machine is being stopped
        """
        self.advertise(OpenOmciEventType.state_change, self.state)

        self._cancel_deferred()
        if self._device is not None:
            self._device.mib_db_in_sync = False

        task, self._current_task = self._current_task, None
        if task is not None:
            task.stop()

        # Drop Response and Autonomous notification subscriptions
        for event, sub in self._omci_cc_subscriptions.iteritems():
            if sub is not None:
                self._omci_cc_subscriptions[event] = None
                self._device.omci_cc.event_bus.unsubscribe(sub)

        for event, sub in self._onu_dev_subscriptions.iteritems():
            if sub is not None:
                self._onu_dev_subscriptions[event] = None
                self._device.event_bus.unsubscribe(sub)

        # TODO: Stop and remove any currently running or scheduled tasks
        # TODO: Anything else?

    def _seed_database(self):
        if not self._device_in_db:
            try:
                try:
                    self._database.start()
                    self._database.add(self._device_id)
                    self.log.debug('seed-db-does-not-exist', device_id=self._device_id)

                except KeyError:
                    # Device already is in database
                    self.log.debug('seed-db-exist', device_id=self._device_id)
                    self._mib_data_sync = self._database.get_mib_data_sync(self._device_id)
                    self._last_mib_db_sync_value = self._database.get_last_sync(self._device_id)

                self._device_in_db = True

            except Exception as e:
                self.log.exception('seed-database-failure', e=e)

    def on_enter_starting(self):
        """
        Determine ONU status and start/re-start MIB Synchronization tasks
        """
        self._device = self._agent.get_device(self._device_id)
        self.advertise(OpenOmciEventType.state_change, self.state)

        # Make sure root of external MIB Database exists
        self._seed_database()

        # Set up Response and Autonomous notification subscriptions
        try:
            for event, sub in self._omci_cc_sub_mapping.iteritems():
                if self._omci_cc_subscriptions[event] is None:
                    self._omci_cc_subscriptions[event] = \
                        self._device.omci_cc.event_bus.subscribe(
                            topic=OMCI_CC.event_bus_topic(self._device_id, event),
                            callback=sub)

        except Exception as e:
            self.log.exception('omci-cc-subscription-setup', e=e)

        # Set up ONU device subscriptions
        try:
            for event, sub in self._onu_dev_sub_mapping.iteritems():
                if self._onu_dev_subscriptions[event] is None:
                    self._onu_dev_subscriptions[event] = \
                        self._device.event_bus.subscribe(
                                topic=OnuDeviceEntry.event_bus_topic(self._device_id, event),
                                callback=sub)

        except Exception as e:
            self.log.exception('dev-subscription-setup', e=e)

        # Clear any previous audit results
        self._on_olt_only_diffs = None
        self._on_onu_only_diffs = None
        self._attr_diffs = None
        self._audited_olt_db = None
        self._audited_onu_db = None

        # Determine if this ONU has ever synchronized
        if self.is_new_onu:
            # Start full MIB upload
            self._deferred = reactor.callLater(0, self.upload_mib)

        else:
            # Examine the MIB Data Sync
            self._deferred = reactor.callLater(0, self.examine_mds)

    def on_enter_uploading(self):
        """
        Begin full MIB data upload, starting with a MIB RESET
        """
        self.advertise(OpenOmciEventType.state_change, self.state)

        def success(results):
            self.log.debug('mib-upload-success', results=results)
            self._current_task = None
            self._next_resync = datetime.utcnow() + timedelta(seconds=self._resync_delay)
            self._deferred = reactor.callLater(0, self.success)

        def failure(reason):
            self.log.info('mib-upload-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        self._device.mib_db_in_sync = False
        self._current_task = self._upload_task(self._agent, self._device_id)

        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_examining_mds(self):
        """
        Create a simple task to fetch the MIB Data Sync value and
        determine if the ONU value matches what is in the MIB database
        """
        self.advertise(OpenOmciEventType.state_change, self.state)

        self._mib_data_sync = self._database.get_mib_data_sync(self._device_id) or 0

        def success(onu_mds_value):
            self.log.debug('examine-mds-success', onu_mds_value=onu_mds_value, olt_mds_value=self.mib_data_sync)
            self._current_task = None

            # Examine MDS value
            if self.mib_data_sync == onu_mds_value:
                self._next_resync = datetime.utcnow() + timedelta(seconds=self._resync_delay)
                self._deferred = reactor.callLater(0, self.success)
            else:
                self._deferred = reactor.callLater(0, self.mismatch)

        def failure(reason):
            self.log.info('examine-mds-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        self._device.mib_db_in_sync = False
        self._current_task = self._get_mds_task(self._agent, self._device_id)

        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_in_sync(self):
        """
        The OLT/OpenOMCI MIB Database is in sync with the ONU MIB Database.
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self.last_mib_db_sync = datetime.utcnow()
        self._device.mib_db_in_sync = True

        if self._audit_delay > 0:
            self._deferred = reactor.callLater(self._audit_delay, self.audit_mib)

    def on_enter_out_of_sync(self):
        """
        The MIB in OpenOMCI and the ONU are out of sync.  This can happen if:

           o the MIB_Data_Sync values are not equal, or
           o the MIBs were compared and differences were found.

        Schedule a task to reconcile the differences
        """
        self.advertise(OpenOmciEventType.state_change, self.state)

        # We are only out-of-sync if there were differences.  If here due to MDS
        # value differences, still run the reconcile so we up date the ONU's MDS
        # value to match ours.

        self._device.mib_db_in_sync = self._attr_diffs is None and \
                                      self._on_onu_only_diffs is None and \
                                      self._on_olt_only_diffs is None

        def success(onu_mds_value):
            self.log.debug('reconcile-success', mds_value=onu_mds_value)
            self._current_task = None
            self._next_resync = datetime.utcnow() + timedelta(seconds=self._resync_delay)
            self._deferred = reactor.callLater(0, self.success)

        def failure(reason):
            self.log.info('reconcile-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        diff_collection = {
            'onu-only': self._on_onu_only_diffs,
            'olt-only': self._on_olt_only_diffs,
            'attributes': self._attr_diffs,
            'olt-db': self._audited_olt_db,
            'onu-db': self._audited_onu_db
        }
        # Clear out results since reconciliation task will be handling them
        self._on_olt_only_diffs = None
        self._on_onu_only_diffs = None
        self._attr_diffs = None
        self._audited_olt_db = None
        self._audited_onu_db = None

        self._current_task = self._reconcile_task(self._agent, self._device_id, diff_collection)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_auditing(self):
        """
        Perform a MIB Audit.  If our last MIB resync was too long in the
        past, perform a resynchronization anyway
        """
        self.advertise(OpenOmciEventType.state_change, self.state)

        if self._next_resync is None:
            self.log.error('next-forced-resync-error', msg='Next Resync should always be valid at this point')
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        if datetime.utcnow() >= self._next_resync:
            self._deferred = reactor.callLater(0, self.force_resync)
        else:
            def success(onu_mds_value):
                self.log.debug('audit-success', onu_mds_value=onu_mds_value, olt_mds_value=self.mib_data_sync)
                self._current_task = None

                # Examine MDS value
                if self.mib_data_sync == onu_mds_value:
                    self._deferred = reactor.callLater(0, self.success)
                else:
                    self._device.mib_db_in_sync = False
                    self._deferred = reactor.callLater(0, self.mismatch)

            def failure(reason):
                self.log.info('audit-failure', reason=reason)
                self._current_task = None
                self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

            self._current_task = self._audit_task(self._agent, self._device_id)
            self._task_deferred = self._device.task_runner.queue_task(self._current_task)
            self._task_deferred.addCallbacks(success, failure)

    def on_enter_resynchronizing(self):
        """
        Perform a resynchronization of the MIB database

        First calculate any differences
        """
        self.advertise(OpenOmciEventType.state_change, self.state)

        def success(results):
            self.log.debug('resync-success', results=results)

            on_olt_only = results.get('on-olt-only')
            on_onu_only = results.get('on-onu-only')
            attr_diffs = results.get('attr-diffs')
            olt_db = results.get('olt-db')
            onu_db = results.get('onu-db')

            self._current_task = None
            self._on_olt_only_diffs = on_olt_only if on_olt_only and len(on_olt_only) else None
            self._on_onu_only_diffs = on_onu_only if on_onu_only and len(on_onu_only) else None
            self._attr_diffs = attr_diffs if attr_diffs and len(attr_diffs) else None
            self._audited_olt_db = olt_db
            self._audited_onu_db = onu_db
            audited_mds = self._audited_onu_db[MDS_KEY]

            mds_equal = self.mib_data_sync == audited_mds

            if mds_equal and all(diff is None for diff in [self._on_olt_only_diffs,
                                                           self._on_onu_only_diffs,
                                                           self._attr_diffs]):
                self._next_resync = datetime.utcnow() + timedelta(seconds=self._resync_delay)
                self._deferred = reactor.callLater(0, self.success)
            else:
                self._deferred = reactor.callLater(0, self.diffs_found)

        def failure(reason):
            self.log.info('resync-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        self._current_task = self._resync_task(self._agent, self._device_id)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_mib_reset_response(self, _topic, msg):
        """
        Called upon receipt of a MIB Reset Response for this ONU

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-mib-reset-response', state=self.state)
        try:
            response = msg[RX_RESPONSE_KEY]

            # Check if expected in current mib_sync state
            if self.state != 'uploading' or self._omci_cc_subscriptions[RxEvent.MIB_Reset] is None:
                self.log.error('rx-in-invalid-state', state=self.state)

            else:
                now = datetime.utcnow()

                if not isinstance(response, OmciFrame):
                    raise TypeError('Response should be an OmciFrame')

                omci_msg = response.fields['omci_message'].fields
                status = omci_msg['success_code']

                assert status == RC.Success, 'Unexpected MIB reset response status: {}'. \
                    format(status)

                self._device.mib_db_in_sync = False
                self._mib_data_sync = 0
                self._device._modified = now
                self._database.on_mib_reset(self._device_id)

        except KeyError:
            pass            # NOP

    def on_avc_notification(self, _topic, msg):
        """
        Process an Attribute Value Change Notification

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-avc-notification', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.AVC_Notification]:
            try:
                notification = msg[RX_RESPONSE_KEY]

                if self.state == 'disabled':
                    self.log.error('rx-in-invalid-state', state=self.state)

                # Inspect the notification
                omci_msg = notification.fields['omci_message'].fields
                class_id = omci_msg['entity_class']
                instance_id = omci_msg['entity_id']
                data = omci_msg['data']
                attributes = [data.keys()]

                # Look up ME Instance in Database. Not-found can occur if a MIB
                # reset has occurred
                info = self._database.query(self.device_id, class_id, instance_id, attributes)
                # TODO: Add old/new info to log message
                self.log.debug('avc-change', class_id=class_id, instance_id=instance_id)

                # Save the changed data to the MIB.
                self._database.set(self.device_id, class_id, instance_id, data)

            except KeyError:
                pass            # NOP

    def on_mib_upload_response(self, _topic, msg):
        """
        Process a MIB Upload response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-mib-upload-next-response', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.MIB_Upload]:
            # Check if expected in current mib_sync state
            if self.state == 'resynchronizing':
                # The resync task handles this
                # TODO: Remove this subscription if we never do anything with the response
                return

            if self.state != 'uploading':
                self.log.error('rx-in-invalid-state', state=self.state)

    def on_mib_upload_next_response(self, _topic, msg):
        """
        Process a MIB Upload Next response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-mib-upload-next-response', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.MIB_Upload_Next]:
            try:
                if self.state == 'resynchronizing':
                    # The resync task handles this
                    return

                # Check if expected in current mib_sync state
                if self.state != 'uploading':
                    self.log.error('rx-in-invalid-state', state=self.state)

                else:
                    response = msg[RX_RESPONSE_KEY]

                    # Extract entity instance information
                    omci_msg = response.fields['omci_message'].fields

                    class_id = omci_msg['object_entity_class']
                    entity_id = omci_msg['object_entity_id']

                    # Filter out the 'mib_data_sync' and 'omci' from the database. We save
                    # that at the device level and do not want it showing up during a
                    # re-sync during data compares

                    if class_id in {OntData.class_id, Omci.class_id}:
                        return

                    attributes = {k: v for k, v in omci_msg['object_data'].items()}

                    # Save to the database
                    self._database.set(self._device_id, class_id, entity_id, attributes)

            except KeyError:
                pass            # NOP
            except Exception as e:
                self.log.exception('upload-next', e=e)

    def on_create_response(self, _topic, msg):
        """
        Process a Set response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-create-response', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.Create]:
            if self.state in ['disabled', 'uploading']:
                self.log.error('rx-in-invalid-state', state=self.state)
                return
            try:
                request = msg[TX_REQUEST_KEY]
                response = msg[RX_RESPONSE_KEY]
                status = response.fields['omci_message'].fields['success_code']

                if status != RC.Success and status != RC.InstanceExists:
                    # TODO: Support offline ONTs in post VOLTHA v1.3.0
                    omci_msg = response.fields['omci_message']
                    self.log.warn('set-response-failure',
                                  class_id=omci_msg.fields['entity_class'],
                                  instance_id=omci_msg.fields['entity_id'],
                                  status=omci_msg.fields['success_code'],
                                  status_text=self._status_to_text(omci_msg.fields['success_code']),
                                  parameter_error_attributes_mask=omci_msg.fields['parameter_error_attributes_mask'])

                elif status != RC.InstanceExists:
                    omci_msg = request.fields['omci_message'].fields
                    class_id = omci_msg['entity_class']
                    entity_id = omci_msg['entity_id']
                    attributes = {k: v for k, v in omci_msg['data'].items()}

                    # Save to the database
                    self._database.set(self._device_id, class_id, entity_id, attributes)
                    self.increment_mib_data_sync()

                    # If the ME contains set-by-create or writeable values that were
                    # not specified in the create command, the ONU will have
                    # initialized those fields

                    if class_id in self._device.me_map:
                        sbc_w_set = {attr.field.name for attr in self._device.me_map[class_id].attributes
                                     if (AA.SBC in attr.access or AA.W in attr.access)
                                     and attr.field.name != 'managed_entity_id'}

                        missing = sbc_w_set - {k for k in attributes.iterkeys()}

                        if len(missing):
                            # Request the missing attributes
                            self.update_sbc_w_items(class_id, entity_id, missing)

            except KeyError as e:
                pass            # NOP

            except Exception as e:
                self.log.exception('create', e=e)

    def update_sbc_w_items(self, class_id, entity_id, missing_attributes):
        """
        Perform a get-request for Set-By-Create (SBC) or writable (w) attributes
        that were not specified in the original Create request.

        :param class_id: (int) Class ID
        :param entity_id: (int) Instance ID
        :param missing_attributes: (set) Missing SBC or Writable attribute
        """
        if len(missing_attributes) and class_id in self._device.me_map:
            from voltha.extensions.omci.tasks.omci_get_request import OmciGetRequest

            def success(results):
                self._database.set(self._device_id, class_id, entity_id, results.attributes)

            def failure(reason):
                self.log.warn('update-sbc-w-failed', reason=reason, class_id=class_id,
                              entity_id=entity_id, attributes=missing_attributes)

            d = self._device.task_runner.queue_task(OmciGetRequest(self._agent, self._device_id,
                                                                   self._device.me_map[class_id],
                                                                   entity_id, missing_attributes,
                                                                   allow_failure=True))
            d.addCallbacks(success, failure)

    def on_delete_response(self, _topic, msg):
        """
        Process a Delete response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-delete-response', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.Delete]:
            if self.state in ['disabled', 'uploading']:
                self.log.error('rx-in-invalid-state', state=self.state)
                return
            try:
                request = msg[TX_REQUEST_KEY]
                response = msg[RX_RESPONSE_KEY]

                if response.fields['omci_message'].fields['success_code'] != RC.Success:
                    # TODO: Support offline ONTs in post VOLTHA v1.3.0
                    omci_msg = response.fields['omci_message']
                    self.log.warn('set-response-failure',
                                  class_id=omci_msg.fields['entity_class'],
                                  instance_id=omci_msg.fields['entity_id'],
                                  status=omci_msg.fields['success_code'],
                                  status_text=self._status_to_text(omci_msg.fields['success_code']))
                else:
                    omci_msg = request.fields['omci_message'].fields
                    class_id = omci_msg['entity_class']
                    entity_id = omci_msg['entity_id']

                    # Remove from the database
                    self._database.delete(self._device_id, class_id, entity_id)
                    self.increment_mib_data_sync()

            except KeyError as e:
                pass            # NOP
            except Exception as e:
                self.log.exception('delete', e=e)

    def on_set_response(self, _topic, msg):
        """
        Process a Set response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-set-response', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.Set]:
            if self.state in ['disabled', 'uploading']:
                self.log.error('rx-in-invalid-state', state=self.state)
                return
            try:
                request = msg[TX_REQUEST_KEY]
                response = msg[RX_RESPONSE_KEY]
                tx_omci_msg = request.fields['omci_message'].fields
                rx_omci_msg = response.fields['omci_message'].fields

                rx_status = rx_omci_msg['success_code']
                class_id = rx_omci_msg['entity_class']
                entity_id = rx_omci_msg['entity_id']
                attributes = dict()

                tx_mask = tx_omci_msg['attributes_mask']
                rx_fail_mask = 0
                if rx_status == RC.AttributeFailure:
                    rx_fail_mask = rx_omci_msg['unsupported_attributes_mask'] | rx_omci_msg['failed_attributes_mask']

                if rx_status == RC.Success:
                    attributes = {k: v for k, v in tx_omci_msg['data'].items()}

                elif RC.AttributeFailure and tx_mask != rx_fail_mask:
                    # Partial success, set only those that were good
                    entity = self._device.me_map[class_id]
                    good_mask = tx_mask & ~rx_fail_mask
                    good_attr_indexes = entity.attribute_indices_from_mask(good_mask)
                    good_attr_names = {attr.field.name for index, attr in enumerate(entity.attributes)
                                       if index in good_attr_indexes}

                    attributes = {k: v for k, v in tx_omci_msg['data'].items()
                                  if k in good_attr_names}
                else:
                    self.log.warn('set-response-failure',
                                  class_id=rx_omci_msg['entity_class'],
                                  instance_id=rx_omci_msg['entity_id'],
                                  status=rx_status,
                                  status_text=self._status_to_text(rx_status),
                                  unsupported_attribute_mask=rx_omci_msg['unsupported_attributes_mask'],
                                  failed_attribute_mask=rx_omci_msg['failed_attributes_mask'])

                # Save to the database. A set of MDS in the OntData class results in
                # an increment. However, we do not save that within the class/entity
                # portion of the database.
                if class_id == OntData.class_id and len(attributes) > 0:
                    self.increment_mib_data_sync()

                elif len(attributes) > 0:
                    self._database.set(self._device_id, class_id, entity_id, attributes)
                    self.increment_mib_data_sync()

            except KeyError as _e:
                pass            # NOP
            except Exception as e:
                self.log.exception('set', e=e)

    def on_software_event(self, _topic, msg):
        """
        Process a Software Start, End, Activate, and Commit

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-software-event', state=self.state)

        # All events for software run this method, checking for one is good enough
        if self._omci_cc_subscriptions[RxEvent.Start_Software_Download]:
            if self.state in ['disabled', 'uploading']:
                self.log.error('rx-in-invalid-state', state=self.state)
                return
            try:
                # Note: all download responses we subscribe to have a 'result' field
                response = msg[RX_RESPONSE_KEY]
                if response.fields['omci_message'].fields['success_code'] == RC.Success:
                    self.increment_mib_data_sync()

            except KeyError as _e:
                pass            # NOP
            except Exception as e:
                self.log.exception('set', e=e)

    def on_capabilities_event(self, _topic, msg):
        """
        Process a OMCI capabilties event
        :param _topic: (str) OnuDeviceEntry Capabilities event
        :param msg: (dict) Message Entities & Message Types supported
        """
        self._database.update_supported_managed_entities(self.device_id,
                                                         msg[SUPPORTED_MESSAGE_ENTITY_KEY])
        self._database.update_supported_message_types(self.device_id,
                                                      msg[SUPPORTED_MESSAGE_TYPES_KEY])

    def _status_to_text(self, success_code):
        return {
                RC.Success: "Success",
                RC.ProcessingError: "Processing Error",
                RC.NotSupported: "Not Supported",
                RC.ParameterError: "Paremeter Error",
                RC.UnknownEntity: "Unknown Entity",
                RC.UnknownInstance: "Unknown Instance",
                RC.DeviceBusy: "Device Busy",
                RC.InstanceExists: "Instance Exists"
            }.get(success_code, 'Unknown status code: {}'.format(success_code))

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
        :raises DatabaseStateError: If the database is not enabled or does not exist
        """
        from voltha.extensions.omci.database.mib_db_api import DatabaseStateError

        self.log.debug('query', class_id=class_id,
                       instance_id=instance_id, attributes=attributes)
        if self._database is None:
            raise DatabaseStateError('Database does not yet exist')

        return self._database.query(self._device_id, class_id=class_id,
                                    instance_id=instance_id,
                                    attributes=attributes)

    def mib_set(self, class_id, entity_id, attributes):
        """
        Set attributes of an existing ME Class instance

        This method is primarily used by other state machines to save ME specific
        information to the persistent database. Access by objects external to the
        OpenOMCI library is discouraged.

        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME Class entity ID
        :param attributes: (dict) attribute -> value pairs to set
        """
        # It must exist first (but attributes can be new)
        if isinstance(attributes, dict) and len(attributes) and\
                self.query_mib(class_id, entity_id) is not None:
            self._database.set(self._device_id, class_id, entity_id, attributes)

    def mib_delete(self, class_id, entity_id):
        """
        Delete an existing ME Class instance

        This method is primarily used by other state machines to delete an ME
        from the MIB database

        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME Class entity ID

        :raises KeyError: If device does not exist
        :raises DatabaseStateError: If the database is not enabled
        """
        self._database.delete(self._device_id, class_id, entity_id)
