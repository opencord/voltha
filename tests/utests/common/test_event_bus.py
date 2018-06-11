#
# Copyright 2016 the original author or authors.
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
import re

from mock import Mock
from mock import call
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.trial.unittest import TestCase

from common.event_bus import EventBusClient, EventBus


class TestEventBus(TestCase):

    def test_subscribe(self):

        ebc = EventBusClient()
        sub = ebc.subscribe('news', lambda msg, topic: None)
        self.assertEqual(len(ebc.list_subscribers()), 1)
        self.assertEqual(len(ebc.list_subscribers('news')), 1)
        self.assertEqual(len(ebc.list_subscribers('other')), 0)

    def test_unsubscribe(self):

        ebc = EventBusClient(EventBus())
        sub = ebc.subscribe('news', lambda msg, topic: None)
        ebc.unsubscribe(sub)
        self.assertEqual(ebc.list_subscribers(), [])
        self.assertEqual(ebc.list_subscribers('news'), [])

    def test_simple_publish(self):

        ebc = EventBusClient(EventBus())

        mock = Mock()
        ebc.subscribe('news', mock)

        ebc.publish('news', 'message')

        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with('news', 'message')

    def test_topic_filtering(self):

        ebc = EventBusClient(EventBus())

        mock = Mock()
        ebc.subscribe('news', mock)

        ebc.publish('news', 'msg1')
        ebc.publish('alerts', 'msg2')
        ebc.publish('logs', 'msg3')

        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with('news', 'msg1')

    def test_multiple_subscribers(self):

        ebc = EventBusClient(EventBus())

        mock1 = Mock()
        ebc.subscribe('news', mock1)

        mock2 = Mock()
        ebc.subscribe('alerts', mock2)

        mock3 = Mock()
        ebc.subscribe('logs', mock3)

        mock4 = Mock()
        ebc.subscribe('logs', mock4)

        ebc.publish('news', 'msg1')
        ebc.publish('alerts', 'msg2')
        ebc.publish('logs', 'msg3')

        self.assertEqual(mock1.call_count, 1)
        mock1.assert_called_with('news', 'msg1')

        self.assertEqual(mock2.call_count, 1)
        mock2.assert_called_with('alerts', 'msg2')

        self.assertEqual(mock3.call_count, 1)
        mock3.assert_called_with('logs', 'msg3')

        self.assertEqual(mock4.call_count, 1)
        mock4.assert_called_with('logs', 'msg3')

    def test_predicates(self):

        ebc = EventBusClient(EventBus())

        get_foos = Mock()
        ebc.subscribe('', get_foos, lambda msg: msg.startswith('foo'))

        get_bars = Mock()
        ebc.subscribe('', get_bars, lambda msg: msg.endswith('bar'))

        get_all = Mock()
        ebc.subscribe('', get_all)

        get_none = Mock()
        ebc.subscribe('', get_none, lambda msg: msg.find('zoo') >= 0)

        errored = Mock()
        ebc.subscribe('', errored, lambda msg: 1/0)

        ebc.publish('', 'foo')
        ebc.publish('', 'foobar')
        ebc.publish('', 'bar')

        c = call

        self.assertEqual(get_foos.call_count, 2)
        get_foos.assert_has_calls([c('', 'foo'), c('', 'foobar')])

        self.assertEqual(get_bars.call_count, 2)
        get_bars.assert_has_calls([c('', 'foobar'), c('', 'bar')])

        self.assertEqual(get_all.call_count, 3)
        get_all.assert_has_calls([c('', 'foo'), c('', 'foobar'), c('', 'bar')])

        get_none.assert_not_called()

        errored.assert_not_called()

    def test_wildcard_topic(self):

        ebc = EventBusClient(EventBus())
        subs = []

        wildcard_sub = Mock()
        subs.append(ebc.subscribe(re.compile(r'.*'), wildcard_sub))

        prefix_sub = Mock()
        subs.append(ebc.subscribe(re.compile(r'ham.*'), prefix_sub))

        contains_sub = Mock()
        subs.append(ebc.subscribe(re.compile(r'.*burg.*'), contains_sub))

        ebc.publish('news', 1)
        ebc.publish('hamsters', 2)
        ebc.publish('hamburgers', 3)
        ebc.publish('nonsense', 4)

        c = call

        self.assertEqual(wildcard_sub.call_count, 4)
        wildcard_sub.assert_has_calls([
            c('news', 1),
            c('hamsters', 2),
            c('hamburgers', 3),
            c('nonsense', 4)])

        self.assertEqual(prefix_sub.call_count, 2)
        prefix_sub.assert_has_calls([
            c('hamsters', 2),
            c('hamburgers', 3)])

        self.assertEqual(contains_sub.call_count, 1)
        contains_sub.assert_has_calls([c('hamburgers', 3)])

        for sub in subs:
            ebc.unsubscribe(sub)

        self.assertEqual(ebc.list_subscribers(), [])

    @inlineCallbacks
    def test_deferred_queue_receiver(self):

        ebc = EventBus()

        queue = DeferredQueue()

        ebc.subscribe('', lambda _, msg: queue.put(msg))

        for i in xrange(10):
            ebc.publish('', i)

        self.assertEqual(len(queue.pending), 10)
        for i in xrange(10):
            msg = yield queue.get()
            self.assertEqual(msg, i)
        self.assertEqual(len(queue.pending), 0)

    def test_subscribers_that_unsubscribe_when_called(self):
        # VOL-943 bug fix check
        ebc = EventBusClient(EventBus())

        class UnsubscribeWhenCalled(object):
            def __init__(self):
                self.subscription = ebc.subscribe('news', self.unsubscribe)
                self.called = False

            def unsubscribe(self, _topic, _msg):
                self.called = True
                ebc.unsubscribe(self.subscription)

        ebc1 = UnsubscribeWhenCalled()
        ebc2 = UnsubscribeWhenCalled()
        ebc3 = UnsubscribeWhenCalled()

        ebc.publish('news', 'msg1')

        self.assertTrue(ebc1.called)
        self.assertTrue(ebc2.called)
        self.assertTrue(ebc3.called)
