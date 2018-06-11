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

"""
A simple internal pub/sub event bus with topics and filter-based registration.
"""
import re

import structlog


log = structlog.get_logger()


class _Subscription(object):

    __slots__ = ('bus', 'predicate', 'callback', 'topic')
    def __init__(self, bus, predicate, callback, topic=None):
        self.bus = bus
        self.predicate = predicate
        self.callback = callback
        self.topic = topic


class EventBus(object):

    def __init__(self):
        self.subscriptions = {}  # topic -> list of _Subscription objects
                                 # topic None holds regexp based topic subs.
        self.subs_topic_map = {} # to aid fast lookup when unsubscribing

    def list_subscribers(self, topic=None):
        if topic is None:
            return sum(self.subscriptions.itervalues(), [])
        else:
            if topic in self.subscriptions:
                return self.subscriptions[topic]
            else:
                return []

    @staticmethod
    def _get_topic_key(topic):
        if isinstance(topic, str):
            return topic
        elif hasattr(topic, 'match'):
            return None
        else:
            raise AttributeError('topic not a string nor a compiled regex')

    def subscribe(self, topic, callback, predicate=None):
        """
        Subscribe to given topic with predicate and register the callback
        :param topic: String topic (explicit) or regexp based topic filter.
        :param callback: Callback method with signature def func(topic, msg)
        :param predicate: Optional method/function signature def predicate(msg)
        :return: Subscription object which can be used to unsubscribe
        """
        subscription = _Subscription(self, predicate, callback, topic)
        topic_key = self._get_topic_key(topic)
        self.subscriptions.setdefault(topic_key, []).append(subscription)
        self.subs_topic_map[subscription] = topic_key
        return subscription

    def unsubscribe(self, subscription):
        """
        Remove given subscription
        :param subscription: subscription object as was returned by subscribe
        :return: None
        """
        topic_key = self.subs_topic_map[subscription]
        self.subscriptions[topic_key].remove(subscription)

    def publish(self, topic, msg):
        """
        Publish given message to all subscribers registered with topic taking
        the predicate functions into account.
        :param topic: String topic
        :param msg: Arbitrary python data as message
        :return: None
        """
        from copy import copy

        def passes(msg, predicate):
            try:
                return predicate(msg)
            except Exception, e:
                return False  # failed predicate function treated as no match

        # lookup subscribers with explicit topic subscriptions
        subscribers = self.subscriptions.get(topic, [])

        # add matching regexp topic subscribers
        subscribers.extend(s for s in self.subscriptions.get(None, [])
                           if s.topic.match(topic))

        # iterate over a shallow-copy of subscribers
        for candidate in copy(subscribers):
            predicate = candidate.predicate
            if predicate is None or passes(msg, predicate):
                try:
                    candidate.callback(topic, msg)
                except Exception, e:
                    log.exception('callback-failed', e=repr(e), topic=topic)



default_bus = EventBus()


class EventBusClient(object):
    """
    Primary interface to the EventBus. Usage:

    Publish:
    >>> events = EventBusClient()
    >>> msg = dict(a=1, b='foo')
    >>> events.publish('a.topic', msg)

    Subscribe to get all messages on specific topic:
    >>> def got_event(topic, msg):
    >>>     print topic, ':', msg
    >>> events = EventBusClient()
    >>> events.subscribe('a.topic', got_event)

    Subscribe to get messages matching predicate on specific topic:
    >>> def got_event(topic, msg):
    >>>     print topic, ':', msg
    >>> events = EventBusClient()
    >>> events.subscribe('a.topic', got_event, lambda msg: msg.len() < 100)

    Use a DeferredQueue to buffer incoming messages
    >>> queue = DeferredQueue()
    >>> events = EventBusClient()
    >>> events.subscribe('a.topic', lambda _, msg: queue.put(msg))

    """
    def __init__(self, bus=None):
        """
        Obtain a client interface for the pub/sub event bus.
        :param bus: An optional specific event bus. Inteded for mainly test
        use. If not provided, the process default bus will be used, which is
        the preferred use (a process shall not need more than one bus).
        """
        self.bus = bus or default_bus

    def publish(self, topic, msg):
        """
        Publish given msg to given topic.
        :param topic: String topic
        :param msg: Arbitrary python data as message
        :return: None
        """
        self.bus.publish(topic, msg)

    def subscribe(self, topic, callback, predicate=None):
        """
        Subscribe to given topic with predicate and register the callback
        :param topic: String topic (explicit) or regexp based topic filter.
        :param callback: Callback method with signature def func(topic, msg)
        :param predicate: Optional method/function with signature
        def predicate(msg)
        :return: Subscription object which can be used to unsubscribe
        """
        return self.bus.subscribe(topic, callback, predicate)

    def unsubscribe(self, subscription):
        """
        Remove given subscription
        :param subscription: subscription object as was returned by subscribe
        :return: None
        """
        return self.bus.unsubscribe(subscription)

    def list_subscribers(self, topic=None):
        """
        Return list of subscribers. If topci is provided, it is filtered for
        those subscribing to the topic.
        :param topic: Optional topic
        :return: List of subscriptions
        """
        return self.bus.list_subscribers(topic)
