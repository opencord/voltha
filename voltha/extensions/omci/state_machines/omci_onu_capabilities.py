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
from transitions import Machine
from twisted.internet import reactor
from voltha.extensions.omci.onu_device_entry import OnuDeviceEntry, OnuDeviceEvents, IN_SYNC_KEY
from voltha.protos.omci_mib_db_pb2 import OpenOmciEventType


class OnuOmciCapabilities(object):
    """
    OpenOMCI ONU OMCI Capabilities State machine
    """
    DEFAULT_STATES = ['disabled', 'out_of_sync', 'in_sync', 'idle']

    DEFAULT_TRANSITIONS = [
        {'trigger': 'start', 'source': 'disabled', 'dest': 'out_of_sync'},
        {'trigger': 'synchronized', 'source': 'out_of_sync', 'dest': 'in_sync'},

        {'trigger': 'success', 'source': 'in_sync', 'dest': 'idle'},
        {'trigger': 'failure', 'source': 'in_sync', 'dest': 'out_of_sync'},

        {'trigger': 'not_synchronized', 'source': 'idle', 'dest': 'out_of_sync'},

        # Do wildcard 'stop' trigger last so it covers all previous states
        {'trigger': 'stop', 'source': '*', 'dest': 'disabled'},
    ]
    DEFAULT_RETRY = 10      # Seconds to delay after task failure/timeout/poll

    def __init__(self, agent, device_id, tasks,
                 advertise_events=False,
                 states=DEFAULT_STATES,
                 transitions=DEFAULT_TRANSITIONS,
                 initial_state='disabled',
                 timeout_delay=DEFAULT_RETRY):
        """
        Class initialization

        :param agent: (OpenOmciAgent) Agent
        :param device_id: (str) ONU Device ID
        :param tasks: (dict) Tasks to run
        :param advertise_events: (bool) Advertise events on OpenOMCI Event Bus
        :param states: (list) List of valid states
        :param transitions: (dict) Dictionary of triggers and state changes
        :param initial_state: (str) Initial state machine state
        :param timeout_delay: (int/float) Number of seconds after a timeout or poll
        """
        self.log = structlog.get_logger(device_id=device_id)

        self._agent = agent
        self._device_id = device_id
        self._device = None
        self._timeout_delay = timeout_delay

        self._get_capabilities_task = tasks['get-capabilities']
        self._advertise_events = advertise_events

        self._deferred = None
        self._current_task = None
        self._task_deferred = None
        self._supported_entities = frozenset()
        self._supported_msg_types = frozenset()

        self._subscriptions = {               # RxEvent.enum -> Subscription Object
            OnuDeviceEvents.MibDatabaseSyncEvent: None
        }
        self._sub_mapping = {
            OnuDeviceEvents.MibDatabaseSyncEvent: self.on_mib_sync_event
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

        for d in [d1, d2]:
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
        return 'OnuOmciCapabilities: Device ID: {}, State:{}'.format(self._device_id, self.state)

    def delete(self):
        """
        Cleanup any state information
        """
        self.stop()

    @property
    def device_id(self):
        return self._device_id

    @property
    def supported_managed_entities(self):
        """
        Return a set of the Managed Entity class IDs supported on this ONU
        None is returned if no MEs have been discovered

        :return: (set of ints)
        """
        return self._supported_entities if len(self._supported_entities) else None

    @property
    def supported_message_types(self):
        """
        Return a set of the Message Types supported on this ONU
        None is returned if no message types have been discovered

        :return: (set of EntityOperations)
        """
        return self._supported_msg_types if len(self._supported_msg_types) else None

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
        from datetime import datetime

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
        self._cancel_tasks()

        self._supported_entities = frozenset()
        self._supported_msg_types = frozenset()

        # Drop Response and Autonomous notification subscriptions
        for event, sub in self._subscriptions.iteritems():
            if sub is not None:
                self._subscriptions[event] = None
                self._device.event_bus.unsubscribe(sub)

    def on_enter_out_of_sync(self):
        """
        State machine has just started or the MIB database has transitioned
        to an out-of-synchronization state
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        self._device = self._agent.get_device(self._device_id)

        # Subscribe to events of interest
        try:
            for event, sub in self._sub_mapping.iteritems():
                if self._subscriptions[event] is None:
                    self._subscriptions[event] = \
                        self._device.event_bus.subscribe(
                            topic=OnuDeviceEntry.event_bus_topic(self._device_id,
                                                                 event),
                            callback=sub)

        except Exception as e:
            self.log.exception('subscription-setup', e=e)

        # Periodically check/poll for in-sync in case subscription was missed or
        # already in sync
        self._deferred = reactor.callLater(0, self.check_in_sync)

    def check_in_sync(self):
        if self._device.mib_db_in_sync:
            self.synchronized()
        else:
            self._deferred = reactor.callLater(self._timeout_delay,
                                               self.check_in_sync)

    def on_enter_in_sync(self):
        """
        State machine has just transitioned to an in-synchronization state
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()

        def success(results):
            self.log.debug('capabilities-success', results=results)
            self._supported_entities = self._current_task.supported_managed_entities
            self._supported_msg_types = self._current_task.supported_message_types
            self._current_task = None
            self._deferred = reactor.callLater(0, self.success)

        def failure(reason):
            self.log.info('capabilities-failure', reason=reason)
            self._supported_entities = frozenset()
            self._supported_msg_types = frozenset()
            self._current_task = None
            self._deferred = reactor.callLater(self._timeout_delay, self.failure)

        # Schedule a task to read the ONU's OMCI capabilities
        self._current_task = self._get_capabilities_task(self._agent, self._device_id)
        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

    def on_enter_idle(self):
        """
        Notify any subscribers for a capabilities event and wait until
        stopped or ONU MIB database goes out of sync
        """
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        self._device.publish_omci_capabilities_event()

    def on_mib_sync_event(self, _topic, msg):
        """
        Handle In-Sync/Out-of-Sync for the MIB database
        :param _topic: (str) Subscription topic
        :param msg: (dict) In-Sync event data
        """
        if self._subscriptions.get(OnuDeviceEvents.MibDatabaseSyncEvent) is None:
            return

        if msg[IN_SYNC_KEY]:
            self.synchronized()
        else:
            self.not_synchronized()
