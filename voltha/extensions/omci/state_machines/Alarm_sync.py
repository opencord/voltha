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
from voltha.extensions.omci.omci_defs import EntityOperations, ReasonCodes, \
    AttributeAccess
from voltha.extensions.omci.omci_cc import OmciCCRxEvents, OMCI_CC, TX_REQUEST_KEY, \
    RX_RESPONSE_KEY
from voltha.extensions.omci.omci_entities import OntData
import voltha.extensions.omci.omci_entities as omci_entities
from common.event_bus import EventBusClient
from voltha.protos.omci_alarm_db_pb2 import AlarmOpenOmciEventType

RxEvent = OmciCCRxEvents
RC = ReasonCodes


class AlarmSynchronizer(object):
    """
    OpenOMCI Alarm Synchronizer state machine
    """
    DEFAULT_STATES = ['disabled', 'starting', 'updating', 'syncing_alarm',
                      'in_sync', 'out_of_sync', 'auditing', 'resynchronizing']

    DEFAULT_TRANSITIONS = [
        {'trigger': 'start', 'source': 'disabled', 'dest': 'starting'},

        {'trigger': 'update_alarm', 'source': 'starting', 'dest': 'updating'},
        {'trigger': 'sync_alarm', 'source': 'starting', 'dest': 'syncing_alarm'},

        {'trigger': 'success', 'source': 'updating', 'dest': 'in_sync'},
        {'trigger': 'timeout', 'source': 'updating', 'dest': 'starting'},

        {'trigger': 'success', 'source': 'syncing_alarm', 'dest': 'in_sync'},
        {'trigger': 'timeout', 'source': 'syncing_alarm', 'dest': 'starting'},
        {'trigger': 'mismatch', 'source': 'syncing_alarm', 'dest': 'updating'},

        {'trigger': 'audit_alarm', 'source': 'in_sync', 'dest': 'auditing'},
        {'trigger': 'audit_alarm', 'source': 'out_of_sync', 'dest': 'auditing'},

        {'trigger': 'success', 'source': 'auditing', 'dest': 'in_sync'},
        {'trigger': 'timeout', 'source': 'auditing', 'dest': 'starting'},
        {'trigger': 'mismatch', 'source': 'auditing', 'dest': 'resynchronizing'},
        {'trigger': 'force_resync', 'source': 'auditing', 'dest': 'resynchronizing'},

        {'trigger': 'timeout', 'source': 'resynchronizing', 'dest': 'out_of_sync'},
        {'trigger': 'success', 'source': 'resynchronizing', 'dest': 'in_sync'},

        # Do wildcard 'stop' trigger last so it covers all previous states
        {'trigger': 'stop', 'source': '*', 'dest': 'disabled'},
    ]
    DEFAULT_TIMEOUT_RETRY = 60      # Seconds to delay after task failure/timeout
    DEFAULT_AUDIT_DELAY = 15       # Periodic tick to audit the MIB Data Sync
    DEFAULT_RESYNC_DELAY = 300     # Periodically force a resync

    def __init__(self, agent, device_id, alarm_sync_tasks, db,
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
        :param db: (MibDbVolatileDict) MIB/Alarm Database
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
        :param resync_delay: (int) Seconds in sync before performing a forced Alarm
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

        self._update_task = alarm_sync_tasks['alarm-sync']
        self._check_task = alarm_sync_tasks['alarm-check']
        self._resync_task = alarm_sync_tasks['alarm-resync']
        self._audit_task = alarm_sync_tasks['alarm-audit']
        self._advertise_events = advertise_events

        self._deferred = None
        self._current_task = None   # TODO: Support multiple running tasks after v.1.3.0 release
        self._task_deferred = None
        self._last_alarm_sync_time = None
        self._last_alarm_sequence_value = None
        self._device_in_db = False
        self._alarm_class_id = None
        self._alarm_entity_id = None
        self._commands_retrieved = None
        self._alarm_table = None

        self._event_bus = EventBusClient()
        self._omci_cc_subscriptions = {               # RxEvent.enum -> Subscription Object
            RxEvent.Get_ALARM_Get: None,
            RxEvent.Get_ALARM_Get_Next: None
        }
        self._omci_cc_sub_mapping = {
            RxEvent.Get_ALARM_Get: self.on_alarm_update_response,
            RxEvent.Get_ALARM_Get_Next: self.on_alarm_update_next_response
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

    @last_alarm_sequence.setter
    def last_alarm_seuence(self, value):
        self._last_alarm_sequence_value = value
        if self._database is not None:
            self._database.save_alarm_last_sync(self.device_id, value)

    @property
    def last_alarm_sync_time(self):
        return self._last_alarm_sync_time

    @last_alarm_sync_time.setter
    def last_alarm_sync_time(self, value):
        self._last_alarm_sync_time = value
        if self._database is not None:
            self._database.save_last_sync_time(self.device_id, value)

    @property
    def is_updated_alarm(self):
        """
        Is this a new ONU (has never completed Alarm synchronization)
        :return: (bool) True if this ONU should be considered new
        """
        return self.last_alarm_sequence is None

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
                    self.last_alarm_sequence = \
                        self._database.get_alarm_last_sync(self._device_id)

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

        except Exception as e:
            self.log.exception('dev-subscription-setup', e=e)

        if self.is_updated_alarm:
            self._deferred = reactor.callLater(0, self.update_alarm)
        # Determine if this ONU has ever synchronized
        else:
            self._deferred = reactor.callLater(0, self.sync_alarm)

    def on_enter_updating(self):
        """
        Begin full Alarm data sync, starting with a Alarm RESET
        """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        def success(results):
            self.log.debug('alarm-update-success', results='the sequence_number is {}'.
                                                           format(results))
            self._current_task = None
            # The new ONU is up, save the first updated alarm sequence number
            self.last_alarm_sequence = results
            self._deferred = reactor.callLater(0, self.success)

        def failure(reason):
            self.log.info('alarm-update-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        self._current_task = self._update_task(self._agent, self._device_id)

        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_syncing_alarm(self):
        """
        Create a simple task to fetch the Alarm value
        """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        self.last_alarm_sequence = self._database.get_alarm_last_sync(self._device_id) or 0

        def success(sequence):
            self.log.debug('sync-alarm-success', sequence_value=sequence)
            self._current_task = None

            # Examine Alarm value
            if self.last_alarm_sequence == sequence:
                self._deferred = reactor.callLater(0, self.success)
            else:
                self._deferred = reactor.callLater(0, self.mismatch)

        def failure(reason):
            self.log.info('sync-alarm-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        self._current_task = self._check_task(self._agent, self._device_id)

        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_in_sync(self):
        """
        Schedule a tick to occur to in the future to request an audit
        """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)
        self.last_alarm_sync_time = datetime.utcnow()
        self._device.alarm_db_in_sync = True

        if self._audit_delay > 0:
            self._deferred = reactor.callLater(self._audit_delay, self.audit_alarm)

    def on_enter_out_of_sync(self):
        """
        The Alarm re-synchronization state does not match alarm status currently.
        The condition would happen the following as below:
            1. The alarm sequence is not equal the last alarm status.
            2. The ONU alarm does not happen right now.

        Condition 1: Something happen on the alarm table does not match the sequence.
                     Opening display of message to examine the alarm table.
        Condition 2: In this state, why happen this situation?
                     Has ONU recover the alarm table in this meanwhile?

        Schedule a tick to occur to in the future to request an audit
        """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)
        self._device.alarm_db_in_sync = False

        step = 'Nothing'
        class_id = 0
        entity_id = 0
        attribute = self._alarm_table

        try:
            if self._commands_retrieved is not self.last_alarm_sequence :
                # The alarm sequence does not match last saving value. Has happen Alarm?
                step = 'alarm-table'
                for sequence in xrange(self._commands_retrieved):
                    self.log.info(step, class_id=self._alarm_class_id[sequence],
                                  entity_id=self._alarm_entity_id[sequence],
                                  alarm_sequence=self._alarm_table[sequence])
                pass
            elif self._commands_retrieved is None:
                # The alarm sequence does not get alarm at present.
                # TODO: need to update the database here ?
                step = 'None_of_alarm'
                self._alarm_table = None
                pass

            self._deferred = reactor.callLater(1, self.audit_alarm)

        except Exception as e:
            self.log.exception('alarm-out-of-update', e=e, step=step, class_id=class_id,
                               entity_id=entity_id, attribute=attribute)
            # Retry the Audit process
            self._deferred = reactor.callLater(1, self.audit_alarm)

    def on_enter_auditing(self):
        """
        Perform a Alarm Audit.  If our last Alarm resync was too long in the
        past, perform a resynchronization anyway
        """
        next_resync = self.last_alarm_sync_time + timedelta(seconds=self._resync_delay)\
            if self.last_alarm_sync_time is not None else datetime.utcnow()

        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        if datetime.utcnow() >= next_resync:
            self._deferred = reactor.callLater(0, self.force_resync)
        else:
            def success(sequence):
                self.log.debug('get-alarm-success', alarm_sequence=sequence)
                self._current_task = None

                # Examine alarm sequence value
                if self.last_alarm_sequence == sequence:
                    self._deferred = reactor.callLater(0, self.success)
                else:
                    self._device.alarm_db_in_sync = False
                    self._deferred = reactor.callLater(0, self.mismatch)

            def failure(reason):
                self.log.info('get-alarm-failure', reason=reason)
                self._current_task = None
                self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

            self._current_task = self._audit_task(self._agent, self._device_id)
            self._task_deferred = self._device.task_runner.queue_task(self._current_task)
            self._task_deferred.addCallbacks(success, failure)

    def on_enter_resynchronizing(self):
        """
        Perform a resynchronization of the Alarm database

        First calculate any differences
        """
        self.advertise(AlarmOpenOmciEventType.state_change, self.state)

        def success(results):
            self.log.debug('resync-success', results=results)

            self._alarm_class_id = results.get('alarm_class_id')
            self._alarm_entity_id = results.get('alarm_entity_id')
            self._commands_retrieved = results.get('commands_retrieved')
            self._alarm_table = results.get('alarm_table')

            if self._commands_retrieved is not None and all(self._alarm_table):
                self._deferred = reactor.callLater(0, self.success)
            else:
                self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        def failure(reason):
            self.log.info('resync-failure', reason=reason)
            self._deferred = reactor.callLater(self._timeout_delay, self.timeout)

        self._current_task = self._resync_task(self._agent, self._device_id)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_alarm_update_next_response(self, _topic, msg):
        """
        Process a Alarm update Next response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-alarm-upload-next-response', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.Get_ALARM_Get_Next]:
            try:
                # Check if expected in current alarm_sync state
                if self.state == 'disabled':
                    self.log.error('rx-in-invalid-state', state=self.state)

                else:
                    response = msg[RX_RESPONSE_KEY]

                    # Extract entity instance information
                    omci_msg = response.fields['omci_message'].fields

                    class_id = omci_msg['entity_class']
                    entity_id = omci_msg['entity_id']
                    alarm_entity_class = omci_msg['alarmed_entity_class']
                    alarm_entity_id = omci_msg['alarmed_entity_id']
                    alarm_bit_map = omci_msg['alarm_bit_map']

                    self.log.info('set-response-failure',
                                  class_id=class_id, entity_id=entity_id,
                                  alarm_entity_class=alarm_entity_class,
                                  alarm_entity_id=alarm_entity_id,
                                  alarm_bit_map=alarm_bit_map)

                    if class_id == OntData.class_id:
                        return

                    # Save to the database
                    self._database.set(self._device_id, class_id, entity_id, alarm_bit_map)

            except KeyError:
                pass            # NOP
            except Exception as e:
                self.log.exception('upload-next', e=e)

    def on_alarm_update_response(self, _topic, msg):
        """
        Process a Set response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-alarm-update-response', state=self.state)

        if self._omci_cc_subscriptions[RxEvent.Get_ALARM_Get]:
            if self.state == 'disabled':
                self.log.error('rx-in-invalid-state', state=self.state)
                return
            try:
                response = msg[RX_RESPONSE_KEY]
                omci_msg = response.fields['omci_message'].fields
                class_id = omci_msg['entity_class']
                entity_id = omci_msg['entity_id']
                number_of_commands = omci_msg.fields['number_of_commands']


                self.last_alarm_sequence = number_of_commands

                self.log.info('received alarm response',
                              class_id=class_id,
                              instance_id=entity_id,
                              number_of_commands=number_of_commands)

                if class_id == OntData.class_id:
                    return

                # Save to the database
                self._database.set(self._device_id, class_id, entity_id, number_of_commands)


            except KeyError:
                pass  # NOP