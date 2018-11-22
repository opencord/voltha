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
import structlog
import arrow
from transitions import Machine
from datetime import datetime, timedelta
from random import uniform, shuffle
from twisted.internet import reactor
from common.utils.indexpool import IndexPool
from voltha.protos.omci_mib_db_pb2 import OpenOmciEventType
from voltha.extensions.omci.omci_defs import EntityOperations, ReasonCodes
from voltha.extensions.omci.omci_cc import OmciCCRxEvents, OMCI_CC, TX_REQUEST_KEY, \
    RX_RESPONSE_KEY
from voltha.extensions.omci.database.mib_db_api import ATTRIBUTES_KEY
from voltha.extensions.omci.tasks.omci_get_request import OmciGetRequest
from voltha.extensions.omci.omci_entities import MacBridgePortConfigurationData
from voltha.extensions.omci.omci_entities import EthernetPMMonitoringHistoryData, \
    FecPerformanceMonitoringHistoryData, \
    XgPonTcPerformanceMonitoringHistoryData, \
    XgPonDownstreamPerformanceMonitoringHistoryData, \
    XgPonUpstreamPerformanceMonitoringHistoryData, \
    EthernetFrameUpstreamPerformanceMonitoringHistoryData, \
    EthernetFrameDownstreamPerformanceMonitoringHistoryData, \
    EthernetFrameExtendedPerformanceMonitoring, \
    EthernetFrameExtendedPerformanceMonitoring64Bit, AniG


RxEvent = OmciCCRxEvents
OP = EntityOperations
RC = ReasonCodes


class PerformanceIntervals(object):
    """
    OpenOMCI ONU Performance Monitoring Intervals State machine

    This state machine focuses on L2 Internet Data Service and Classical
    PM (for the v2.0 release).
    """
    DEFAULT_STATES = ['disabled', 'starting', 'synchronize_time', 'idle', 'create_pm_me',
                      'collect_data', 'threshold_exceeded']

    DEFAULT_TRANSITIONS = [
        {'trigger': 'start', 'source': 'disabled', 'dest': 'starting'},
        {'trigger': 'tick', 'source': 'starting', 'dest': 'synchronize_time'},

        {'trigger': 'success', 'source': 'synchronize_time', 'dest': 'idle'},
        {'trigger': 'failure', 'source': 'synchronize_time', 'dest': 'synchronize_time'},

        {'trigger': 'tick', 'source': 'idle', 'dest': 'collect_data'},
        {'trigger': 'add_me', 'source': 'idle', 'dest': 'create_pm_me'},
        {'trigger': 'delete_me', 'source': 'idle', 'dest': 'delete_pm_me'},

        {'trigger': 'success', 'source': 'create_pm_me', 'dest': 'idle'},
        {'trigger': 'failure', 'source': 'create_pm_me', 'dest': 'idle'},

        {'trigger': 'success', 'source': 'delete_pm_me', 'dest': 'idle'},
        {'trigger': 'failure', 'source': 'delete_pm_me', 'dest': 'idle'},

        {'trigger': 'success', 'source': 'collect_data', 'dest': 'idle'},
        {'trigger': 'failure', 'source': 'collect_data', 'dest': 'idle'},

        # TODO: Add rebooted event transitions to disabled or synchronize_time
        # TODO: Need to capture Threshold Crossing Alarms appropriately

        # Do wildcard 'stop' trigger last so it covers all previous states
        {'trigger': 'stop', 'source': '*', 'dest': 'disabled'},
        {'trigger': 'reboot', 'source': '*', 'dest': 'rebooted'},
    ]
    DEFAULT_RETRY = 10               # Seconds to delay after task failure/timeout/poll
    DEFAULT_TICK_DELAY = 15          # Seconds between checks for collection tick
    DEFAULT_INTERVAL_SKEW = 10 * 60  # Seconds to skew past interval boundary
    DEFAULT_COLLECT_ATTEMPTS = 3     # Maximum number of collection fetch attempts
    DEFAULT_CREATE_ATTEMPTS = 15     # Maximum number of attempts to create a PM Managed Entities

    def __init__(self, agent, device_id, tasks,
                 advertise_events=False,
                 states=DEFAULT_STATES,
                 transitions=DEFAULT_TRANSITIONS,
                 initial_state='disabled',
                 timeout_delay=DEFAULT_RETRY,
                 tick_delay=DEFAULT_TICK_DELAY,
                 interval_skew=DEFAULT_INTERVAL_SKEW,
                 collect_attempts=DEFAULT_COLLECT_ATTEMPTS,
                 create_attempts=DEFAULT_CREATE_ATTEMPTS):
        """
        Class initialization

        :param agent: (OpenOmciAgent) Agent
        :param device_id: (str) ONU Device ID
        :param tasks: (dict) Tasks to run
        :param advertise_events: (bool) Advertise events on OpenOMCI Event Bus
        :param states: (list) List of valid states
        :param transitions: (dict) Dictionary of triggers and state changes
        :param initial_state: (str) Initial state machine state
        :param timeout_delay: (int/float) Number of seconds after a timeout to pause
        :param tick_delay: (int/float) Collection poll check delay while idle
        :param interval_skew: (int/float) Seconds to randomly skew the next interval
                              collection to spread out requests for PM intervals
        :param collect_attempts: (int) Max requests for a single PM interval before fail
        :param create_attempts: (int) Max attempts to create PM Managed entities before stopping state machine
        """
        self.log = structlog.get_logger(device_id=device_id)

        self._agent = agent
        self._device_id = device_id
        self._device = None
        self._pm_config = None
        self._timeout_delay = timeout_delay
        self._tick_delay = tick_delay
        self._interval_skew = interval_skew
        self._collect_attempts = collect_attempts
        self._create_attempts = create_attempts

        self._sync_time_task = tasks['sync-time']
        self._get_interval_task = tasks['collect-data']
        self._create_pm_task = tasks['create-pm']
        self._delete_pm_task = tasks['delete-pm']
        self._advertise_events = advertise_events

        self._omci_cc_subscriptions = {               # RxEvent.enum -> Subscription Object
            RxEvent.MIB_Reset: None,
            RxEvent.Create: None,
            RxEvent.Delete: None
        }
        self._omci_cc_sub_mapping = {
            RxEvent.MIB_Reset: self.on_mib_reset_response,
            RxEvent.Create: self.on_create_response,
            RxEvent.Delete: self.on_delete_response,
        }
        self._me_watch_list = {
            MacBridgePortConfigurationData.class_id: {
                'create-delete': self.add_remove_enet_frame_pm,
                'instances': dict()  # BP entity_id -> (PM class_id, PM entity_id)
            }
        }
        self._deferred = None
        self._task_deferred = None
        self._current_task = None
        self._add_me_deferred = None
        self._delete_me_deferred = None
        self._next_interval = None
        self._enet_entity_id = IndexPool(1024, 1)
        self._add_pm_me_retry = 0

        # (Class ID, Instance ID) -> Collect attempts remaining
        self._pm_me_collect_retries = dict()
        self._pm_me_extended_info = dict()
        self._add_pm_me = dict()        # (pm cid, pm eid) -> (me cid, me eid, upstream)
        self._del_pm_me = set()

        # Pollable PM items
        # Note that some items the KPI extracts are not listed below. These are the
        # administrative states, operational states, and sensed ethernet type. The values
        # in the MIB database should be accurate for these items.

        self._ani_g_items = ["optical_signal_level", "transmit_optical_level"]
        self._next_poll_time = datetime.utcnow()
        self._poll_interval = 60                    # TODO: Fixed at once a minute

        # Statistics and attributes
        # TODO: add any others if it will support problem diagnosis

        # Set up state machine to manage states
        self.machine = Machine(model=self, states=states,
                               transitions=transitions,
                               initial=initial_state,
                               queued=True,
                               ignore_invalid_triggers=True,
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
        d3, self._add_me_deferred = self._add_me_deferred, None
        d4, self._delete_me_deferred = self._delete_me_deferred, None

        for d in [d1, d2, d3, d4]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def _cancel_tasks(self):
        task, self._current_task = self._current_task, None
        if task is not None:
            task.stop()

    def __str__(self):
        return 'PerformanceIntervals: Device ID: {}, State:{}'.format(self._device_id,
                                                                      self.state)

    def delete(self):
        """
        Cleanup any state information
        """
        self.stop()

    @property
    def device_id(self):
        return self._device_id

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
                                      'time': str(datetime.utcnow()),
                                      'next': str(self._next_interval)
                                  })

    def set_pm_config(self, pm_config):
        """
        Set PM interval configuration

        :param pm_config: (OnuPmIntervalMetrics) PM Interval configuration
        :return:
        """
        self._pm_config = pm_config

    def _me_is_supported(self, class_id):
        """
        Check to see if ONU supports this ME
        :param class_id: (int) ME Class ID
        :return: (bool) If ME is supported
        """
        #
        supported = self._device.omci_capabilities.supported_managed_entities
        return class_id in supported if supported is not None else False

    def add_pm_me(self, pm_class_id, pm_entity_id, cid=0, eid=0, upstream=False):
        """
        Add a new Performance Monitoring ME.

        The ME ID will be added to an internal list and will be added the next
        time the idle state is reached. An 'add_pm_me' trigger will be raised in
        case already in the Idle state.

        :param pm_class_id: (int) ME Class ID (1..0xFFFE)
        :param pm_entity_id: (int) Instance ID (1..0xFFFE)
        :param cid: (int) Class ID of entity monitored, may be None
        :param eid: (int) Instance ID of entity monitored, may be None
        :param upstream: (bool): Flag indicating if PM is for upstream traffic
        """
        if not isinstance(pm_class_id, int):
            raise TypeError('PM ME Instance ID is an integer')
        if not 0 < pm_class_id < 0xFFFF:
            raise ValueError('PM ME Instance ID must be 1..65534')

        # Check to see if ONU supports this ME
        if not self._me_is_supported(pm_class_id):
            self.log.warn('unsupported-PM-me', class_id=pm_class_id)
            return

        key = (pm_class_id, pm_entity_id)
        entry = (cid, eid, upstream)

        if key not in self._pm_me_collect_retries and key not in self._add_pm_me:
            self._add_pm_me[key] = entry

            if self._add_me_deferred is None:
                self._add_me_deferred = reactor.callLater(0, self.add_me)

        if (pm_class_id, pm_entity_id) in self._del_pm_me:
            self._del_pm_me.remove((pm_class_id, pm_entity_id))

    def delete_pm_me(self, class_id, entity_id):
        """
        Remove a new Performance Monitoring ME.

        The ME ID will be added to an internal list and will be removed the next
        time the idle state is reached. An 'delete_pm_me' trigger will be raised in
        case already in the Idle state.

        :param class_id: (int) ME Class ID (1..0xFFFE)
        :param entity_id: (int) Instance ID (1..0xFFFE)
        """
        if not isinstance(class_id, int):
            raise TypeError('PM ME Class ID is an integer')
        if not 0 < class_id < 0xFFFF:
            raise ValueError('PM ME Class ID must be 1..65534')

        # Check to see if ONU supports this ME
        if not self._me_is_supported(class_id):
            self.log.warn('unsupported-PM-me', class_id=class_id)
            return

        key = (class_id, entity_id)

        if key in self._pm_me_collect_retries and key not in self._del_pm_me:
            self._del_pm_me.add(key)

            if self._delete_me_deferred is None:
                self._delete_me_deferred = reactor.callLater(0, self.delete_me)

        if key in self._add_pm_me:
            self._add_pm_me.pop(key)

    def on_enter_disabled(self):
        """
        State machine is being stopped
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        self._cancel_tasks()
        self._next_interval = None

        # Drop OMCI ME Response subscriptions
        for event, sub in self._omci_cc_subscriptions.iteritems():
            if sub is not None:
                self._omci_cc_subscriptions[event] = None
                self._device.omci_cc.event_bus.unsubscribe(sub)

        # Manually remove ani ANI/PON and UNI PM interval MEs
        config = self._device.configuration
        anis = config.ani_g_entities
        unis = config.uni_g_entities

        if anis is not None:
            for entity_id in anis.iterkeys():
                self.delete_pm_me(FecPerformanceMonitoringHistoryData.class_id, entity_id)
                self.delete_pm_me(XgPonTcPerformanceMonitoringHistoryData.class_id, entity_id)
                self.delete_pm_me(XgPonDownstreamPerformanceMonitoringHistoryData.class_id, entity_id)
                self.delete_pm_me(XgPonUpstreamPerformanceMonitoringHistoryData.class_id, entity_id)

        if unis is not None:
            for entity_id in config.uni_g_entities.iterkeys():
                self.delete_pm_me(EthernetPMMonitoringHistoryData.class_id, entity_id)

    def on_enter_starting(self):
        """ Add the PON/ANI and UNI PM intervals"""
        self.advertise(OpenOmciEventType.state_change, self.state)

        self._device = self._agent.get_device(self._device_id)
        self._cancel_deferred()

        # Set up OMCI ME Response subscriptions
        try:
            for event, sub in self._omci_cc_sub_mapping.iteritems():
                if self._omci_cc_subscriptions[event] is None:
                    self._omci_cc_subscriptions[event] = \
                        self._device.omci_cc.event_bus.subscribe(
                            topic=OMCI_CC.event_bus_topic(self._device_id, event),
                            callback=sub)

        except Exception as e:
            self.log.exception('omci-cc-subscription-setup', e=e)

        try:
            # Manually start some ANI/PON and UNI PM interval MEs
            config = self._device.configuration
            anis = config.ani_g_entities
            unis = config.uni_g_entities

            if anis is not None:
                for entity_id in anis.iterkeys():
                    self.add_pm_me(FecPerformanceMonitoringHistoryData.class_id,
                                   entity_id)
                    self.add_pm_me(XgPonTcPerformanceMonitoringHistoryData.class_id,
                                   entity_id)
                    self.add_pm_me(XgPonDownstreamPerformanceMonitoringHistoryData.class_id,
                                   entity_id)
                    self.add_pm_me(XgPonUpstreamPerformanceMonitoringHistoryData.class_id,
                                   entity_id)

            if unis is not None:
                for entity_id in config.uni_g_entities.iterkeys():
                    self.add_pm_me(EthernetPMMonitoringHistoryData.class_id, entity_id)

            # Look for existing instances of dynamically created ME's that have PM
            # associated with them and add them now
            for class_id in self._me_watch_list.iterkeys():
                instances = {k: v for k, v in
                             self._device.query_mib(class_id=class_id).items()
                             if isinstance(k, int)}

                for entity_id, data in instances.items():
                    method = self._me_watch_list[class_id]['create-delete']
                    cid, eid = method(None, class_id, entity_id,
                                      add=True, attributes=data[ATTRIBUTES_KEY])
                    if cid > 0:
                        # BP entity_id -> (PM class_id, PM entity_id)
                        instances = self._me_watch_list[class_id]['instances']
                        instances[entity_id] = (cid, eid)

        except Exception as e:
            self.log.exception('pm-me-setup', class_id=class_id, e=e)

        # Got to synchronize_time state
        self._deferred = reactor.callLater(0, self.tick)

    def on_enter_synchronize_time(self):
        """
        State machine has just transitioned to the synchronize_time state
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()

        def success(_results):
            self.log.debug('sync-time-success')
            self._current_task = None
            self._deferred = reactor.callLater(0, self.success)
            # Calculate next interval time
            self._next_interval = self.get_next_interval

        def failure(reason):
            self.log.info('sync-time-failure', reason=reason)
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.failure)

        # Schedule a task to set the ONU time
        self._current_task = self._sync_time_task(self._agent, self._device_id)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_idle(self):
        """
        State machine has just transitioned to the idle state

        In this state, any added PM MEs that need to be created will be.
        TODO: some non-interval PM stats (if there are any) are collected here
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()

        if len(self._del_pm_me) and self._delete_me_deferred is None:
            self._delete_me_deferred = reactor.callLater(0, self.delete_me)

        elif len(self._add_pm_me) and self._add_me_deferred is None:
            self._add_me_deferred = reactor.callLater(0, self.add_me)

        elif datetime.utcnow() >= self._next_poll_time:
            def success(results):
                self._device.timestamp = arrow.utcnow().float_timestamp
                self._device.mib_synchronizer.mib_set(results.me_class.class_id,
                                                      results.entity_id,
                                                      results.attributes)
                self._next_poll_time = datetime.utcnow() + timedelta(seconds=self._poll_interval)

            def failure(reason):
                self.log.info('poll-failure', reason=reason)
                self._device.timestamp = None
                return None

            # Scan all ANI-G ports
            ani_g_entities = self._device.configuration.ani_g_entities
            ani_g_entities_ids = ani_g_entities.keys() if ani_g_entities is not None else None

            if ani_g_entities_ids is not None and len(ani_g_entities_ids):
                for entity_id in ani_g_entities_ids:
                    task = OmciGetRequest(self._agent, self.device_id,
                                          AniG, entity_id,
                                          self._ani_g_items, allow_failure=True)
                    self._task_deferred = self._device.task_runner.queue_task(task)
                    self._task_deferred.addCallbacks(success, failure)
            else:
                self.log.warn('poll-pm-no-anis')
                self._next_poll_time = datetime.utcnow() + timedelta(seconds=self._poll_interval)

        # TODO: Compute a better mechanism than just polling here, perhaps based on
        #       the next time to fetch data for 'any' interval
        self._deferred = reactor.callLater(self._tick_delay, self.tick)

    def on_enter_create_pm_me(self):
        """
        State machine has just transitioned to the create_pm_me state
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        self._cancel_tasks()
        mes, self._add_pm_me = self._add_pm_me, dict()

        def success(results):
            self.log.debug('create-me-success', results=results)

            # Check if already here. The create request could have received
            # an already-exists status code which we consider successful
            for pm, me in mes.items():
                self._pm_me_collect_retries[pm] = self.pm_collected(pm)
                self._pm_me_extended_info[pm] = me

            self._current_task = None
            self._deferred = reactor.callLater(0, self.success)

        def failure(reason):
            self.log.info('create-me-failure', reason=reason, retries=self._add_pm_me_retry)
            self._current_task = None
            if self._add_pm_me_retry <= self._create_attempts:
              for pm, me in mes.items():
                  self._add_pm_me[pm] = me
              self._add_pm_me_retry += 1
              self._deferred = reactor.callLater(self._timeout_delay, self.failure)
            else:
              # we cant seem to create any collection me, no point in doing anything
              self.log.warn('unable-to-create-pm-me-disabling-collection', reason=reason, device_id=self._device_id)
              self._deferred = reactor.callLater(self._timeout_delay, self.stop)

        self._current_task = self._create_pm_task(self._agent, self._device_id, mes)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_delete_pm_me(self):
        """
        State machine has just transitioned to the delete_pm_me state
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        self._cancel_tasks()

        mes, self._del_pm_me = self._del_pm_me, set()

        def success(results):
            self.log.debug('delete-me-success', results=results)
            self._current_task = None
            for me in mes:
                self._pm_me_collect_retries.pop(me)

            self._deferred = reactor.callLater(0, self.success)

        def failure(reason):
            self.log.info('delete-me-failure', reason=reason)
            self._current_task = None
            for me in mes:
                self._del_pm_me.add(me)

            self._deferred = reactor.callLater(self._timeout_delay, self.failure)

        self._current_task = self._delete_pm_task(self._agent, self._device_id, mes)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_collect_data(self):
        """
        State machine has just transitioned to the collect_data state
        """

        if self._next_interval is not None and self._next_interval > datetime.utcnow():
            self.log.debug('wait-next-interval')
            # Not ready for next interval, transition back to idle and we should get
            # called again after a short delay
            reactor.callLater(0, self.success)
            return

        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        self._cancel_tasks()
        keys = self._pm_me_collect_retries.keys()
        shuffle(keys)

        for key in keys:
            class_id = key[0]
            entity_id = key[1]

            self.log.debug("in-enter-collect-data", data_key=key,
                           retries=self._pm_me_collect_retries[key])

            # Collect the data ?
            if self._pm_me_collect_retries[key] > 0:
                def success(results):
                    self.log.debug('collect-success', results=results,
                                   class_id=results.get('class_id'),
                                   entity_id=results.get('entity_id'))
                    self._current_task = None
                    self._pm_me_collect_retries[key] = 0
                    self._deferred = reactor.callLater(0, self.success)
                    return results

                def failure(reason):
                    self.log.info('collect-failure', reason=reason)
                    self._current_task = None
                    self._pm_me_collect_retries[key] -= 1
                    self._deferred = reactor.callLater(self._timeout_delay, self.failure)
                    return reason   # Halt callback processing

                # start the task
                if key in self._pm_me_extended_info:
                    self.log.debug('collect-extended-info-found', data_key=key,
                                   extended_info=self._pm_me_extended_info[key])
                    parent_class_id = self._pm_me_extended_info[key][0]
                    parent_entity_id = self._pm_me_extended_info[key][1]
                    upstream = self._pm_me_extended_info[key][2]
                else:
                    self.log.debug('collect-extended-info-not-found', data_key=key)
                    parent_class_id = None
                    parent_entity_id = None
                    upstream = None

                self._current_task = self._get_interval_task(self._agent, self._device_id,
                                                             class_id, entity_id,
                                                             parent_class_id=parent_class_id,
                                                             parent_entity_id=parent_entity_id,
                                                             upstream=upstream)
                self._task_deferred = self._device.task_runner.queue_task(self._current_task)
                self._task_deferred.addCallbacks(success, failure)
                self._task_deferred.addCallback(self.publish_data)
                return

        # Here if all intervals have been collected (we are up to date)
        self._next_interval = self.get_next_interval
        self.log.debug('collect-calculate-next', next=self._next_interval)

        self._pm_me_collect_retries = dict.fromkeys(self._pm_me_collect_retries, self._collect_attempts)
        reactor.callLater(0, self.success)

    def on_enter_threshold_exceeded(self):
        """
        State machine has just transitioned to the threshold_exceeded state
        """
        pass  # TODO: Not sure if we want this state. Need to get alarm synchronizer working first

    @property
    def get_next_interval(self):
        """
        Determine the time for the next interval collection for all of this
        ONUs PM Intervals. Earliest fetch time is at least 1 minute into the
        next interval.

        :return: (datetime) UTC time to get the next interval
        """
        now = datetime.utcnow()

        # Get delta seconds to at least 1 minute into next interval
        next_delta_secs = (16 - (now.minute % 15)) * 60
        next_interval = now + timedelta(seconds=next_delta_secs)

        # NOTE: For debugging, uncomment next section to perform collection
        #       right after initial code startup/mib-sync
        if self._next_interval is None:
            return now     # Do it now  (just for debugging purposes)

        # Skew the next time up to the maximum specified
        # TODO: May want to skew in a shorter range and select the minute
        #       based off some device property value to make collection a
        #       little more predictable on a per-ONU basis.
        return next_interval + timedelta(seconds=uniform(0, self._interval_skew))

    def pm_collected(self, key):
        """
        Query database and determine if PM data needs to be collected for this ME
        """
        class_id = key[0]
        entity_id = key[1]

        return self._collect_attempts        # TODO: Implement persistent storage

    def publish_data(self, results):
        """
        Publish the PM interval results on the appropriate bus.  The results are
        a dictionary with the following format.

            'class-id':          (int) ME Class ID,
            'entity-id':         (int) ME Entity ID,
            'me-name':           (str) ME Class name,   # Mostly for debugging...
            'interval-end-time': None,
            'interval-utc-time': (DateTime) UTC time when retrieved from ONU,

            Counters added here as they are retrieved with the format of
            'counter-attribute-name': value (int)

        :param results: (dict) PM results
        """
        self.log.debug('collect-publish', results=results)

        if self._pm_config is not None:
            self._pm_config.publish_metrics(results)

        pass  # TODO: Save off last time interval fetched to persistent storage?

    def on_mib_reset_response(self, _topic, msg):
        """
        Called upon receipt of a MIB Reset Response for this ONU

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-mib-reset-response', state=self.state)
        try:
            response = msg[RX_RESPONSE_KEY]
            omci_msg = response.fields['omci_message'].fields
            status = omci_msg['success_code']

            if status == RC.Success:
                for class_id in self._me_watch_list.iterkeys():
                    # BP entity_id -> (PM class_id, PM entity_id)
                    instances = self._me_watch_list[class_id]['instances']
                    for _, me_pair in instances.items():
                        self._me_watch_list[class_id]['create-delete'](None, me_pair[0],
                                                                       me_pair[1], add=False)
                    self._me_watch_list[class_id]['instances'] = dict()

        except KeyError:
            pass            # NOP

    def on_create_response(self, _topic, msg):
        """
        Called upon receipt of a Create Response for this ONU.

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-create-response', state=self.state)

        def valid_request(stat, c_id, e_id):
            return self._omci_cc_subscriptions[RxEvent.Delete] is not None\
                and stat in (RC.Success, RC.InstanceExists) \
                and c_id in self._me_watch_list.keys() \
                and e_id not in self._me_watch_list[c_id]['instances']

        response = msg[RX_RESPONSE_KEY]
        omci = response.fields['omci_message'].fields
        class_id = omci['entity_class']
        entity_id = omci['entity_id']
        status = omci['success_code']

        if valid_request(status, class_id, entity_id):
            request = msg[TX_REQUEST_KEY]
            method = self._me_watch_list[class_id]['create-delete']
            cid, eid = method(request, class_id, entity_id, add=True)

            if cid > 0:
                # BP entity_id -> (PM class_id, PM entity_id)
                instances = self._me_watch_list[class_id]['instances']
                instances[entity_id] = (cid, eid)

    def on_delete_response(self, _topic, msg):
        """
        Called upon receipt of a Delete Response for this ONU

        :param _topic: (str) OMCI-RX topic
        :param msg: (dict) Dictionary with 'rx-response' and 'tx-request' (if any)
        """
        self.log.debug('on-delete-response', state=self.state)

        def valid_request(stat, cid, eid):
            return self._omci_cc_subscriptions[RxEvent.Delete] is not None\
                and stat in (RC.Success, RC.UnknownInstance) \
                and cid in self._me_watch_list.keys() \
                and eid in self._me_watch_list[cid]['instances']

        response = msg[RX_RESPONSE_KEY]
        omci = response.fields['omci_message'].fields
        class_id = omci['entity_class']
        entity_id = omci['entity_id']
        status = omci['success_code']

        if valid_request(status, class_id, entity_id):
            request = msg[TX_REQUEST_KEY]
            method = self._me_watch_list[class_id]['create-delete']

            method(request, class_id, entity_id, add=False)
            # BP entity_id -> (PM class_id, PM entity_id)
            instances = self._me_watch_list[class_id]['instances']
            del instances[entity_id]

    def get_pm_entity_id_for_add(self, pm_cid, eid):
        """
        Select the Entity ID to use for a specific PM Class ID.  For extended
        PM ME's, an entity id (>0) is allocated

        :param pm_cid: (int) PM ME Class ID to create/get entry ID for
        :param eid: (int) Reference class's entity ID. Used as PM entity ID for non-
                    extended PM history PMs
        :return: (int) Entity ID to use
        """
        if pm_cid in (EthernetFrameExtendedPerformanceMonitoring.class_id,
                      EthernetFrameExtendedPerformanceMonitoring64Bit.class_id):
            return self._enet_entity_id.get_next()
        return eid

    def release_pm_entity_id(self, pm_cid, eid):
        if pm_cid in (EthernetFrameExtendedPerformanceMonitoring.class_id,
                      EthernetFrameExtendedPerformanceMonitoring64Bit.class_id):
            try:
                self._enet_entity_id.release(eid)
            except:
                pass

    def add_remove_enet_frame_pm(self, request, class_id, entity_id,
                                 add=True,
                                 attributes=None):
        """
        Add/remove PM for the dynamic MAC Port configuration data.

        This can be called in a variety of ways:

           o If from an Response event from OMCI_CC, the request will contain
             the original create/delete request. The class_id and entity_id will
             be the MAC Data Configuration Data class and instance ID.
             add = True if create, False if delete

           o If starting up (and the associated ME is already created), the MAC
             Data Configuration Data class and instance ID, and attributes are
             provided. request = None and add = True

           o If cleaning up (stopping), the PM ME class_id, entity_id are provided.
             request = None and add = False

        :return: (int, int) PM ME class_id and entity_id for add/remove was performed.
                            class and entity IDs are non-zero on success
        """
        pm_entity_id = 0
        cid = 0
        eid = 0
        upstream = False

        def tp_type_to_pm(tp):
            # TODO: Support 64-bit extended Monitoring MEs.
            # This will result in the need to maintain entity IDs of PMs differently
            upstream_types = [  # EthernetFrameExtendedPerformanceMonitoring64Bit.class_id,
                              EthernetFrameExtendedPerformanceMonitoring.class_id,
                              EthernetFrameUpstreamPerformanceMonitoringHistoryData.class_id], True
            downstream_types = [  # EthernetFrameExtendedPerformanceMonitoring64Bit.class_id,
                                EthernetFrameExtendedPerformanceMonitoring.class_id,
                                EthernetFrameDownstreamPerformanceMonitoringHistoryData.class_id], False
            return {
                1: downstream_types,
                3: upstream_types,
                5: downstream_types,
                6: downstream_types,
            }.get(tp, None)

        if request is not None:
            assert class_id == MacBridgePortConfigurationData.class_id

            # Is this associated with the ANI or the UNI side of the bridge?
            # For VOLTHA v2.0, only high-speed internet data service is
            attributes = request.fields['omci_message'].fields['data']
            pm_class_ids, upstream = tp_type_to_pm(attributes['tp_type'])
            cid = request.fields['omci_message'].fields['entity_class']
            eid = request.fields['omci_message'].fields['entity_id']
            if not add:
                instances = self._me_watch_list[cid]['instances']
                _, pm_entity_id = instances.get(eid, (None, None))

        elif add:
            assert class_id == MacBridgePortConfigurationData.class_id
            assert isinstance(attributes, dict)

            # Is this associated with the ANI or the UNI side of the bridge?
            pm_class_ids, upstream = tp_type_to_pm(attributes.get('tp_type'))
            cid = class_id
            eid = entity_id

        else:
            assert class_id in (EthernetFrameUpstreamPerformanceMonitoringHistoryData.class_id,
                                EthernetFrameDownstreamPerformanceMonitoringHistoryData.class_id,
                                EthernetFrameExtendedPerformanceMonitoring.class_id,
                                EthernetFrameExtendedPerformanceMonitoring64Bit.class_id)
            pm_class_ids = [class_id]

        if pm_class_ids is None:
            return False     # Unable to select a supported ME for this ONU

        if add:
            for pm_class_id in pm_class_ids:
                if self._me_is_supported(pm_class_id):
                    pm_entity_id = self.get_pm_entity_id_for_add(pm_class_id, eid)
                    self.add_pm_me(pm_class_id, pm_entity_id, cid=cid, eid=eid,
                                   upstream=upstream)
                    return pm_class_id, pm_entity_id
        else:
            for pm_class_id in pm_class_ids:
                if self._me_is_supported(pm_class_id):
                    self.delete_pm_me(pm_class_id, pm_entity_id)
                    self.release_pm_entity_id(pm_class_id, pm_entity_id)
                    return pm_class_id, pm_entity_id

        return 0, 0
