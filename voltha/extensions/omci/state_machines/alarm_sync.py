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
from datetime import datetime
from transitions import Machine
from twisted.internet import reactor
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_cc import OmciCCRxEvents, OMCI_CC, RX_RESPONSE_KEY
from voltha.extensions.omci.omci_messages import OmciGetAllAlarmsResponse
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.database.alarm_db_ext import AlarmDbExternal
from voltha.extensions.omci.database.mib_db_api import ATTRIBUTES_KEY
from voltha.extensions.omci.omci_entities import CircuitPack, PptpEthernetUni, OntG, AniG

from common.event_bus import EventBusClient
from voltha.protos.omci_alarm_db_pb2 import AlarmOpenOmciEventType

RxEvent = OmciCCRxEvents
RC = ReasonCodes
OP = EntityOperations


class AlarmSynchronizer(object):
    """
    OpenOMCI Alarm Synchronizer state machine
    """
    DEFAULT_STATES = ['disabled', 'starting', 'auditing', 'in_sync']

    DEFAULT_TRANSITIONS = [
        {'trigger': 'start', 'source': 'disabled', 'dest': 'starting'},

        {'trigger': 'audit_alarm', 'source': 'starting', 'dest': 'auditing'},
        {'trigger': 'sync_alarm', 'source': 'starting', 'dest': 'in_sync'},

        {'trigger': 'success', 'source': 'auditing', 'dest': 'in_sync'},
        {'trigger': 'audit_alarm', 'source': 'auditing', 'dest': 'auditing'},
        {'trigger': 'failure', 'source': 'auditing', 'dest': 'auditing'},

        {'trigger': 'audit_alarm', 'source': 'in_sync', 'dest': 'auditing'},

        # Do wildcard 'stop' trigger last so it covers all previous states
        {'trigger': 'stop', 'source': '*', 'dest': 'disabled'},
    ]
    DEFAULT_TIMEOUT_RETRY = 15     # Seconds to delay after task failure/timeout
    DEFAULT_AUDIT_DELAY = 180      # Periodic tick to audit the ONU's alarm table

    def __init__(self, agent, device_id, alarm_sync_tasks, db,
                 advertise_events=False,
                 states=DEFAULT_STATES,
                 transitions=DEFAULT_TRANSITIONS,
                 initial_state='disabled',
                 timeout_delay=DEFAULT_TIMEOUT_RETRY,
                 audit_delay=DEFAULT_AUDIT_DELAY):
        """
        Class initialization

        :param agent: (OpenOmciAgent) Agent
        :param device_id: (str) ONU Device ID
        :param db: (MibDbApi) MIB/Alarm Database
        :param advertise_events: (bool) Advertise events on OpenOMCI Event Bus
        :param alarm_sync_tasks: (dict) Tasks to run
        :param states: (list) List of valid states
        :param transitions: (dict) Dictionary of triggers and state changes
        :param initial_state: (str) Initial state machine state
        :param timeout_delay: (int/float) Number of seconds after a timeout to attempt
                                          a retry (goes back to starting state)
        :param audit_delay: (int) Seconds between Alarm audits while in sync. Set to
                                  zero to disable audit. An operator can request
                                  an audit manually by calling 'self.audit_alarm'
        """

        self.log = structlog.get_logger(device_id=device_id)

        self._agent = agent
        self._device_id = device_id
        self._device = None
        self._database = db
        self._timeout_delay = timeout_delay
        self._audit_delay = audit_delay
        self._resync_task = alarm_sync_tasks['alarm-resync']
        self._advertise_events = advertise_events
        self._alarm_manager = None
        self._onu_id = None
        self._uni_ports = list()
        self._ani_ports = list()

        self._deferred = None
        self._current_task = None
        self._task_deferred = None
        self._last_alarm_sequence_value = 0
        self._device_in_db = False

        self._event_bus = EventBusClient()
        self._omci_cc_subscriptions = {               # RxEvent.enum -> Subscription Object
            RxEvent.Get_ALARM_Get: None,
            RxEvent.Alarm_Notification: None
        }
        self._omci_cc_sub_mapping = {
            RxEvent.Get_ALARM_Get: self.on_alarm_update_response,
            RxEvent.Alarm_Notification: self.on_alarm_notification
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
        return 'Alarm Synchronizer: Device ID: {}, State:{}'.format(self._device_id, self.state)

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
    def last_alarm_sequence(self):
        return self._last_alarm_sequence_value

    def reset_alarm_sequence(self):
        if self._last_alarm_sequence_value != 0:
            self._last_alarm_sequence_value = 0

    def increment_alarm_sequence(self):
        self._last_alarm_sequence_value += 1
        if self._last_alarm_sequence_value > 255:
            self._last_alarm_sequence_value = 1

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

    def set_alarm_params(self, mgr=None, onu_id=None, uni_ports=None, ani_ports=None):
        if mgr is not None:
            self._alarm_manager = mgr

        if onu_id is not None:
            self._onu_id = onu_id

        if uni_ports is not None:
            assert isinstance(uni_ports, list)
            self._uni_ports = uni_ports

        if ani_ports is not None:
            assert isinstance(ani_ports, list)
            self._ani_ports = ani_ports

    def on_enter_disabled(self):
        """
        State machine is being stopped
        """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        self._cancel_deferred()

        task, self._current_task = self._current_task, None
        if task is not None:
            task.stop()

        # Drop Response and Autonomous notification subscriptions
        for event, sub in self._omci_cc_subscriptions.iteritems():
            if sub is not None:
                self._omci_cc_subscriptions[event] = None
                self._device.omci_cc.event_bus.unsubscribe(sub)

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

                self._device_in_db = True

            except Exception as e:
                self.log.exception('seed-database-failure', e=e)

    def on_enter_starting(self):
        """
        Determine ONU status and start Alarm Synchronization tasks
        """
        self._device = self._agent.get_device(self._device_id)
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        # Make sure root of external Alarm Database exists
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

        # Schedule first audit if enabled
        if self._audit_delay > 0:
            # Note using the shorter timeout delay here since this is the first
            # audit after startup
            self._deferred = reactor.callLater(self._timeout_delay, self.audit_alarm)
        else:
            self._deferred = reactor.callLater(0, self.sync_alarm)

    def on_enter_in_sync(self):
        """
        Schedule a tick to occur to in the future to request an audit
        """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        if self._audit_delay > 0:
            # Note using the shorter timeout delay here since this is the first
            # audit after startup
            self._deferred = reactor.callLater(self._audit_delay, self.audit_alarm)

    def on_enter_auditing(self):
        """
         Begin full Alarm data sync, Comparing the all alarms
         """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        def success(results):
            self.log.debug('alarm-diff-success')
            self._current_task = None

            # Any differences found between ONU and OpenOMCI Alarm tables?
            if results is None:
                self._device.alarm_db_in_sync = True
                self._deferred = reactor.callLater(0, self.success)
            else:
                # Reconcile the alarm table and re-run audit
                self.reconcile_alarm_table(results)
                self._deferred = reactor.callLater(5, self.audit_alarm)

        def failure(reason):
            self.log.info('alarm-update-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.failure)

        self._current_task = self._resync_task(self._agent, self._device_id)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def reconcile_alarm_table(self, results):
        self.log.debug('alarm-reconcile', state=self.state, results=results)

        onu_only = results['onu-only']
        olt_only = results['olt-only']
        attr_diffs = results['attr-diffs']
        onu_db = results['onu-db']
        olt_db = results['olt-db']

        if any(item is not None for item in (onu_only, olt_only, attr_diffs)):
            self._device.alarm_db_in_sync = False

        # Compare the differences.  During upload, if there are no alarms at all,
        # then the ONU alarm table retrieved may be empty (instead of MEs with all
        # bits cleared) depending upon the ONU's OMCI Stack.

        if onu_only is not None:
            self.process_onu_only_diffs(onu_only, onu_db)

        if olt_only is not None:
            self.process_olt_only_diffs(olt_only)

        if attr_diffs is not None:
            self.process_attr_diffs(attr_diffs, olt_db, onu_db)

    def process_onu_only_diffs(self, onu_only, onu_db):
        """
        ONU only alarms will typically occur when doing the first audit as our
        database is clear and we are seeding the alarm table. Save the entries
        and if any are set, we need to raise that alarm.

        :param onu_only: (list) Tuples with [0]=class ID, [1]=entity ID
        :param onu_db: (dict) ONU Alarm database from the alarm audit upload
        """
        for cid_eid in onu_only:
            class_id = cid_eid[0]
            entity_id = cid_eid[1]
            try:
                bitmap = onu_db[class_id][entity_id][ATTRIBUTES_KEY][AlarmDbExternal.ALARM_BITMAP_KEY]
                self.process_alarm_data(class_id, entity_id, bitmap, -1)

            except KeyError as e:
                self.log.error('alarm-not-found', class_id=class_id, entity_id=entity_id, e=e)

    def process_olt_only_diffs(self, olt_only):
        """
        OLT only alarms may occur if the alarm(s) are no longer active on the ONU
        and the notification was missed. Process this by sending a cleared bitmap
        for any alarm in the OLT database only

        :param olt_only: (list) Tuples with [0]=class ID, [1]=entity ID
        """
        for cid_eid in olt_only:
            # First process the alarm clearing
            self.process_alarm_data(cid_eid[0], cid_eid[1], 0, -1)
            # Now remove from alarm DB so we match the ONU alarm table
            self._database.delete(self._device_id, cid_eid[0], cid_eid[1])

    def process_attr_diffs(self, attr_diffs, onu_db):
        """
        Mismatch in alarm settings. Note that the attribute should always be the
        alarm bitmap attribute (long).  For differences, the ONU is always right

        :param attr_diffs: (list(int,int,str)) [0]=class ID, [1]=entity ID, [1]=attr
        :param olt_db: (dict) OLT Alarm database snapshot from the alarm audit
        :param onu_db: (dict) ONU Alarm database from the alarm audit upload
        """
        for cid_eid_attr in attr_diffs:
            class_id = cid_eid_attr[0]
            entity_id = cid_eid_attr[1]

            try:
                assert AlarmDbExternal.ALARM_BITMAP_KEY == cid_eid_attr[2]
                bitmap = onu_db[class_id][entity_id][ATTRIBUTES_KEY][AlarmDbExternal.ALARM_BITMAP_KEY]
                self.process_alarm_data(class_id, entity_id, bitmap, -1)

            except KeyError as e:
                self.log.error('alarm-not-found', class_id=class_id, entity_id=entity_id, e=e)

    def on_alarm_update_response(self, _topic, msg):
        """
        Process a Get All Alarms response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-alarm-update-response', state=self.state, msg=msg)

        if self._omci_cc_subscriptions[RxEvent.Get_ALARM_Get]:
            if self.state == 'disabled':
                self.log.error('rx-in-invalid-state', state=self.state)
                return

            try:
                response = msg.get(RX_RESPONSE_KEY)

                if isinstance(response, OmciFrame) and \
                        isinstance(response.fields.get('omci_message'), OmciGetAllAlarmsResponse):
                    # ONU will reset its last alarm sequence number to 0 on receipt of the
                    # Get All Alarms request
                    self.log.debug('received-alarm-response')
                    self.reset_alarm_sequence()

            except Exception as e:
                self.log.exception('upload-alarm-failure', e=e)

    def on_alarm_notification(self, _topic, msg):
        """
        Process an alarm Notification

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with keys:
                    TX_REQUEST_KEY  -> None (this is an autonomous msg)
                    RX_RESPONSE_KEY -> OmciMessage (Alarm notification frame)
        """
        self.log.debug('on-alarm-update-response', state=self.state, msg=msg)

        alarm_msg = msg.get(RX_RESPONSE_KEY)
        if alarm_msg is not None:
            omci_msg = alarm_msg.fields['omci_message'].fields
            class_id = omci_msg['entity_class']
            seq_no = omci_msg['alarm_sequence_number']

            # Validate that this ME supports alarm notifications
            if class_id not in self._device.me_map or \
                    OP.AlarmNotification not in self._device.me_map[class_id].notifications or \
                    len(self._device.me_map[class_id].alarms) == 0:
                self.log.warn('invalid-alarm-notification', class_id=class_id)
                return

            self.process_alarm_data(class_id,
                                    omci_msg['entity_id'],
                                    omci_msg['alarm_bit_map'],
                                    seq_no)

    def process_alarm_data(self, class_id, entity_id, bitmap, msg_seq_no):
        """
        Process new alarm data

        :param class_id: (int)  Class ID of alarm
        :param entity_id: (int) Entity ID of alarm
        :param bitmap: (long) Alarm bitmap value
        :param msg_seq_no: (int) Alarm sequence number. -1 if generated during an audit
        """
        if msg_seq_no > 0:
            # increment alarm number & compare to alarm # in message
            # Signal early audit if no match and audits are enabled
            self.increment_alarm_sequence()

            if self.last_alarm_sequence != msg_seq_no and self._audit_delay > 0:
                self._deferred = reactor.callLater(0, self.audit_alarm)

        key = AlarmDbExternal.ALARM_BITMAP_KEY
        prev_entry = self._database.query(self._device_id, class_id, entity_id)
        try:
            # Need to access the bit map structure which is nested in dict attributes
            prev_bitmap = 0 if len(prev_entry) == 0 else long(prev_entry['attributes'][key])
        except Exception as e:
            self.log.exception('alarm-prev-entry-collection-failure', class_id=class_id,
                               device_id=self._device_id, entity_id=entity_id, value=bitmap, e=e)
        # Save current entry before going on
        try:
            self._database.set(self._device_id, class_id, entity_id, {key: bitmap})

        except Exception as e:
            self.log.exception('alarm-save-failure', class_id=class_id,
                               device_id=self._device_id, entity_id=entity_id, value=bitmap, e=e)

        if self._alarm_manager is not None:
            # Generate a set of alarm number that are raised in current and previous
            previously_raised = {alarm_no for alarm_no in xrange(224)
                                 if prev_bitmap & (1L << (223-alarm_no)) != 0L}

            currently_raised = {alarm_no for alarm_no in xrange(224)
                                if bitmap & (1L << (223-alarm_no)) != 0L}

            newly_cleared = previously_raised - currently_raised
            newly_raised = currently_raised - previously_raised

            # Generate the set/clear alarms now
            for alarm_number in newly_cleared:
                reactor.callLater(0, self.clear_alarm, class_id, entity_id, alarm_number)

            for alarm_number in newly_raised:
                reactor.callLater(0, self.raise_alarm, class_id, entity_id, alarm_number)

    def get_alarm_description(self, class_id, alarm_number):
        """
        Get the alarm description, both as a printable-string and also a CamelCase value
        """
        if alarm_number in self._device.me_map[class_id].alarms:
            description = self._device.me_map[class_id].alarms[alarm_number]
        elif alarm_number <= 207:
            description = 'Reserved alarm {}'.format(alarm_number)
        else:
            description = 'Vendor specific alarm {}'.format(alarm_number)

        # For CamelCase, replace hyphens with spaces before camel casing the string
        return description, description.replace('-', ' ').title().replace(' ', '')

    def raise_alarm(self, class_id, entity_id, alarm_number):
        """
        Raise an alarm on the ONU

        :param class_id: (int)  Class ID of the Alarm ME
        :param entity_id: (int) Entity ID of the Alarm
        :param alarm_number: (int) Alarm number (bit) that is alarmed
        """
        description, name = self.get_alarm_description(class_id, alarm_number)

        self.log.warn('alarm-set', class_id=class_id, entity_id=entity_id,
                      alarm_number=alarm_number, name=name, description=description)

        if self._alarm_manager is not None:
            alarm = self.omci_alarm_to_onu_alarm(class_id, entity_id, alarm_number)
            if alarm is not None:
                alarm.raise_alarm()

    def clear_alarm(self, class_id, entity_id, alarm_number):
        """
        Lower/clear an alarm on the ONU

        :param class_id: (int)  Class ID of the Alarm ME
        :param entity_id: (int) Entity ID of the Alarm
        :param alarm_number: (int) Alarm number (bit) that is alarmed
        """
        description, name = self.get_alarm_description(class_id, alarm_number)

        self.log.info('alarm-cleared', class_id=class_id, entity_id=entity_id,
                      alarm_number=alarm_number, name=name, description=description)

        if self._alarm_manager is not None:
            alarm = self.omci_alarm_to_onu_alarm(class_id, entity_id, alarm_number)
            if alarm is not None:
                alarm.clear_alarm()

    def query_mib(self, class_id=None, instance_id=None):
        """
        Get Alarm database information.

        This method can be used to request information from the database to the detailed
        level requested

        :param class_id:  (int) Managed Entity class ID
        :param instance_id: (int) Managed Entity instance

        :return: (dict) The value(s) requested. If class/inst/attribute is
                        not found, an empty dictionary is returned
        :raises DatabaseStateError: If the database is not enabled or does not exist
        """
        from voltha.extensions.omci.database.mib_db_api import DatabaseStateError

        self.log.debug('query', class_id=class_id, instance_id=instance_id)
        if self._database is None:
            raise DatabaseStateError('Database does not yet exist')

        return self._database.query(self._device_id, class_id=class_id, instance_id=instance_id)

    def omci_alarm_to_onu_alarm(self, class_id, entity_id, alarm_number):
        """
        Map an OMCI Alarm Notification alarm to the proper ONU Alarm Library alarm

        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME Class instance ID
        :param alarm_number: (int) Alarm Number
        :return: (AlarmBase) Alarm library alarm or None if not supported/found
        """
        from voltha.extensions.alarms.onu.onu_dying_gasp_alarm import OnuDyingGaspAlarm
        from voltha.extensions.alarms.onu.onu_los_alarm import OnuLosAlarm
        from voltha.extensions.alarms.onu.onu_equipment_alarm import OnuEquipmentAlarm
        from voltha.extensions.alarms.onu.onu_selftest_failure_alarm import OnuSelfTestFailureAlarm
        from voltha.extensions.alarms.onu.onu_laser_eol_alarm import OnuLaserEolAlarm
        from voltha.extensions.alarms.onu.onu_laser_bias_current_alarm import OnuLaserBiasAlarm
        from voltha.extensions.alarms.onu.onu_temp_yellow_alarm import OnuTempYellowAlarm
        from voltha.extensions.alarms.onu.onu_temp_red_alarm import OnuTempRedAlarm
        from voltha.extensions.alarms.onu.onu_voltage_yellow_alarm import OnuVoltageYellowAlarm
        from voltha.extensions.alarms.onu.onu_voltage_red_alarm import OnuVoltageRedAlarm
        from voltha.extensions.alarms.onu.onu_low_rx_optical_power_alarm import OnuLowRxOpticalAlarm
        from voltha.extensions.alarms.onu.onu_high_rx_optical_power_alarm import OnuHighRxOpticalAlarm
        from voltha.extensions.alarms.onu.onu_low_tx_optical_power_alarm import OnuLowTxOpticalAlarm
        from voltha.extensions.alarms.onu.onu_high_tx_optical_power_alarm import OnuHighTxOpticalAlarm

        mgr = self._alarm_manager
        if class_id in (CircuitPack.class_id, PptpEthernetUni.class_id):
            intf_id = self.select_uni_port(class_id, entity_id)

        elif class_id in (AniG.class_id, OntG.class_id):
            intf_id = self.select_ani_port(class_id, entity_id)

        else:
            self.log.error('unsupported-class-id', class_id=class_id, alarm_number=alarm_number)
            return

        alarm_map = {
            (CircuitPack.class_id, 0): OnuEquipmentAlarm,
            (CircuitPack.class_id, 2): OnuSelfTestFailureAlarm,
            (CircuitPack.class_id, 3): OnuLaserEolAlarm,
            (CircuitPack.class_id, 4): OnuTempYellowAlarm,
            (CircuitPack.class_id, 5): OnuTempRedAlarm,

            (PptpEthernetUni.class_id, 0): OnuLosAlarm,

            (OntG.class_id, 0): OnuEquipmentAlarm,
            (OntG.class_id, 6): OnuSelfTestFailureAlarm,
            (OntG.class_id, 7): OnuDyingGaspAlarm,
            (OntG.class_id, 8): OnuTempYellowAlarm,
            (OntG.class_id, 9): OnuTempRedAlarm,
            (OntG.class_id, 10): OnuVoltageYellowAlarm,
            (OntG.class_id, 11): OnuVoltageRedAlarm,

            (AniG.class_id, 0): OnuLowRxOpticalAlarm,
            (AniG.class_id, 1): OnuHighRxOpticalAlarm,
            (AniG.class_id, 4): OnuLowTxOpticalAlarm,
            (AniG.class_id, 5): OnuHighTxOpticalAlarm,
            (AniG.class_id, 6): OnuLaserBiasAlarm,
        }
        alarm_cls = alarm_map.get((class_id, alarm_number))

        return alarm_cls(mgr, self._onu_id, intf_id) if alarm_cls is not None else None

    def select_uni_port(self, class_id, entity_id):
        """
        Select the best possible UNI Port (logical) interface number for this ME class and
        entity ID.

        This base implementation will assume that a UNI Port object has been registered
        on startup and supports both an 'entity_id' and also 'logical_port_number'
        property.  See both the Adtran and BroadCom OpenOMCI ONU DA for an example
        of this UNI port object.

        :param class_id: (int)  ME Class ID for which the alarms belongs to
        :param entity_id: (int) Instance ID

        :return: (int) Logical Port number for the UNI port
        """
        # NOTE: Of the three class ID's supported in this version of code, only the CircuitPack,
        #       and PptpEthernetUni MEs will map to the UNI port
        assert class_id in (CircuitPack.class_id, PptpEthernetUni.class_id)

        return next((uni.logical_port_number for uni in self._uni_ports if
                     uni.entity_id == entity_id), None)

    def select_ani_port(self, class_id, _entity_id):
        """
        Select the best possible ANI Port (physical) interface number for this ME class and
        entity ID.

        Currently the base implementation assumes only a single PON port and it will be
        chosen.  A future implementation may want to have a PON Port object (similar to
        the BroadCom Open OMCI and Adtran ONU's UNI Port object) that provides a match
        for entity ID.  This does assume that the PON port object supports a property
        of 'port_number' to return the physical port number.

        :param class_id: (int)  ME Class ID for which the alarms belongs to
        :param _entity_id: (int) Instance ID

        :return: (int) Logical Port number for the UNI port
        """
        # NOTE: Of the three class ID's supported in this version of code, only the AniG
        #       MEs will map to the ANI port. For some the OntG alarms (Dying Gasp) the
        #       PON interface will also be selected.
        assert class_id in (AniG.class_id, OntG.class_id)

        return self._ani_ports[0].port_number if len(self._ani_ports) else None
