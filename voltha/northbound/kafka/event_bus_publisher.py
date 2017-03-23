#!/usr/bin/env python
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
A gateway between the internal event bus and the Kafka publisher proxy
to publish select topics and messages posted to the Voltha-internal event
bus toward the external world.
"""
import structlog
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message
from simplejson import dumps

from common.event_bus import EventBusClient

log = structlog.get_logger()


class EventBusPublisher(object):

    def __init__(self, kafka_proxy, config):
        self.kafka_proxy = kafka_proxy
        self.config = config
        self.topic_mappings = config.get('topic_mappings', {})
        self.event_bus = EventBusClient()
        self.subscriptions = None

    def start(self):
        log.debug('starting')
        self.subscriptions = list()
        self._setup_subscriptions(self.topic_mappings)
        log.info('started')
        return self

    def stop(self):
        try:
            log.debug('stopping-event-bus')
            if self.subscriptions:
                for subscription in self.subscriptions:
                    self.event_bus.unsubscribe(subscription)
            log.info('stopped-event-bus')
        except Exception, e:
            log.exception('failed-stopping-event-bus', e=e)
            return

    def _setup_subscriptions(self, mappings):

        for event_bus_topic, mapping in mappings.iteritems():

            kafka_topic = mapping.get('kafka_topic', None)

            if kafka_topic is None:
                log.error('no-kafka-topic-in-config',
                          event_bus_topic=event_bus_topic,
                          mapping=mapping)
                continue

            self.subscriptions.append(self.event_bus.subscribe(
                event_bus_topic,
                # to avoid Python late-binding to the last registered
                # kafka_topic, we force instant binding with the default arg
                lambda _, m, k=kafka_topic: self.forward(k, m)))

            log.info('event-to-kafka', kafka_topic=kafka_topic,
                     event_bus_topic=event_bus_topic)

    def forward(self, kafka_topic, msg):
        try:
            # convert to JSON string if msg is a protobuf msg
            if isinstance(msg, Message):
                msg = dumps(MessageToDict(msg, True, True))
            log.debug('forward-event-bus-publisher')
            self.kafka_proxy.send_message(kafka_topic, msg)
        except Exception, e:
            log.exception('failed-forward-event-bus-publisher', e=e)

