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
from voltha.extensions.omci.omci_defs import ReasonCodes
from voltha.extensions.omci.omci_cc import OmciCCRxEvents, OMCI_CC, RX_RESPONSE_KEY
from voltha.extensions.omci.omci_messages import OmciGetAllAlarmsResponse
from voltha.extensions.omci.omci_frame import OmciFrame
from common.event_bus import EventBusClient
from voltha.protos.omci_alarm_db_pb2 import AlarmOpenOmciEventType

RxEvent = OmciCCRxEvents
RC = ReasonCodes


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
    DEFAULT_AUDIT_DELAY = 0        # 300      # Periodic tick to audit the ONU's alarm table

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

        self._deferred = None
        self._current_task = None
        self._task_deferred = None
        self._last_alarm_sequence_value = None
        self._device_in_db = False
        # self._alarm_bit_map_notification = dict()
        # self._alarm_sequence_number_notification = dict()

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
        self.log.info('alarm-reconcile', state=self.state, results=results)

        onu_only = results['onu-only']
        olt_only = results['olt-only']
        attr_diffs = results['attr-diffs']

        # Compare the differences.  During upload, if there are no alarms at all,
        # then the ONU alarm table retrieved may be empty (instead of MEs with all
        # bits cleared) depending upon the ONU's OMCI Stack.

        if onu_only is not None:
            pass
            # ONU only alarms will typically occur when doing the first audit as our
            # database is clear and we are seeding the alarm table. Save the entries
            # and if any are set, we need to raise that alarm.
            #
            # self._database.set(self._device_id, class_id, entity_id, alarm_bit_map)

        if olt_only is not None:
            pass

        if attr_diffs is not None:
            pass

    def on_alarm_update_response(self, _topic, msg):
        """
        Process a Get All Alarms response

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.info('on-alarm-update-response', state=self.state, msg=msg)

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
                    self.log.info('received alarm response')
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
        self.log.info('on-alarm-update-response', state=self.state, msg=msg)

        alarm_msg = msg.get(RX_RESPONSE_KEY)
        if alarm_msg is not None:
            # TODO: Process alarm
            #       decode message, note that the seq number should never
            #       be zero.

            # increment alarm number & compare to alarm # in message
            self.increment_alarm_sequence()

            # Signal early audit if no match and audits are enabled
            # if self.last_alarm_sequence != msg_seq_no and self._audit_delay > 0:
            #     self._deferred = reactor.callLater(0, self.audit_alarm)

            # update alarm table/db (compare current db with alarm msg)
            # notify ONU Device Handler, ...
            pass
            #  Note that right now we do not alarm anyone or save it to the database, so
            #  if we can create (or clear) an alarm on the ONU, then the audit logic
            #  should detect the difference. So we can test the audit that way.

    def raise_alarm(self, class_id, entity_id, alarm_number):
        """
        Raise an alarm on the ONU

        :param class_id: (int)  Class ID of the Alarm ME
        :param entity_id: (int) Entity ID of the Alarm
        :param alarm_number: (int) Alarm number (bit) that is alarmed
        """
        pass            # TODO: Implement this

    def clear_alarm(self, class_id, entity_id, alarm_number):
        """
        Lower/clear an alarm on the ONU

        :param class_id: (int)  Class ID of the Alarm ME
        :param entity_id: (int) Entity ID of the Alarm
        :param alarm_number: (int) Alarm number (bit) that is alarmed
        """
        pass            # TODO: Implement this

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
