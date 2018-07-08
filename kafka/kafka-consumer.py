#!/usr/bin/env python
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -*- coding: utf-8 -*-
# Copyright (C) 2015 Cyan, Inc.

import logging
from argparse import ArgumentParser

from afkak.client import KafkaClient
from afkak.common import (
    KafkaUnavailableError,
    OFFSET_LATEST)
from afkak.consumer import Consumer
from twisted.internet import reactor
from twisted.internet.defer import DeferredList, inlineCallbacks
from twisted.python.failure import Failure

from common.utils.consulhelpers import get_endpoint_from_consul

log = logging.getLogger(__name__)


class ConsumerExample(object):
    def __init__(self, consul_endpoint, topic="voltha.heartbeat", runtime=60):
        self.topic = topic
        self.runtime = runtime
        self.kafka_endpoint = get_endpoint_from_consul(consul_endpoint,
                                                       'kafka')

        self._client = KafkaClient(self.kafka_endpoint)
        self._consumer_list = []  # List of consumers
        # List of deferred returned from consumers' start() methods
        self._consumer_d_list = []

    @inlineCallbacks
    def start(self):
        partitions = []
        try:
            while not partitions:
                yield self._client.load_metadata_for_topics(self.topic)
                e = self._client.metadata_error_for_topic(self.topic)
                if e:
                    log.warning('no-metadata-for-topic', error=e,
                                topic=self.topic)
                else:
                    partitions = self._client.topic_partitions[self.topic]
        except KafkaUnavailableError:
            log.error("unable-to-communicate-with-Kafka-brokers")
            self.stop()

        def _note_consumer_stopped(result, consumer):
            log.info('consumer-stopped', consumer=consumer,
                     result=result)

        for partition in partitions:
            c = Consumer(self._client, self.topic, partition,
                         self.msg_processor)
            self._consumer_list.append(c)
            # log.info('consumer-started', topic=self.topic, partition=partition)
            d = c.start(OFFSET_LATEST)
            d.addBoth(_note_consumer_stopped, c)
            self._consumer_d_list.append(d)

        # Stop ourselves after we've run the allotted time
        reactor.callLater(self.runtime, self.stop)

    def stop(self):
        log.info("\n")
        log.info('end-of-execution-stopping-consumers')
        # Ask each of our consumers to stop. When a consumer fully stops, it
        # fires the deferred returned from its start() method. We saved all
        # those deferreds away (above, in start()) in self._consumer_d_list,
        # so now we'll use a DeferredList to wait for all of them...
        for consumer in self._consumer_list:
            consumer.stop()
        dl = DeferredList(self._consumer_d_list)

        # Once the consumers are all stopped, then close our client
        def _stop_client(result):
            if isinstance(result, Failure):
                log.error('error', result=result)
            else:
                log.info('all-consumers-stopped', client=self._client)
            self._client.close()
            return result

        dl.addBoth(_stop_client)

        # And once the client is shutdown, stop the reactor
        def _stop_reactor(result):
            reactor.stop()
            return result

        dl.addBoth(_stop_reactor)

    def msg_processor(self, consumer, msglist):
        for msg in msglist:
            log.info(msg)


def parse_options():
    parser = ArgumentParser("Consume kafka messages")
    parser.add_argument("-c", "--consul",
                        help="consul ip and port",
                        default='10.100.198.220:8500')

    parser.add_argument("-t", "--topic",
                        help="topic to listen from",
                        default="voltha.heartbeat")

    parser.add_argument("-r", "--runtime",
                        help="total runtime",
                        default=1000)

    return parser.parse_args()

def main():
    logging.basicConfig(
        format='%(asctime)s:%(name)s:' +
               '%(levelname)s:%(process)d:%(message)s',
        level=logging.INFO
    )

    args = parse_options()

    consumer_example = ConsumerExample(args.consul, args.topic,
                                       int(args.runtime))
    reactor.callWhenRunning(consumer_example.start)
    reactor.run()
    log.info("completed!")


if __name__ == "__main__":
    main()
