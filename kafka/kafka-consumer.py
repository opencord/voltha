#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2015 Cyan, Inc.

import logging
from argparse import ArgumentParser

from twisted.internet import reactor
from twisted.internet.defer import DeferredList, inlineCallbacks
from twisted.python.failure import Failure
from afkak.client import KafkaClient
from afkak.consumer import Consumer
from voltha.consulhelpers import get_endpoint_from_consul
from afkak.common import (
    KafkaUnavailableError,
    OFFSET_EARLIEST,
    OFFSET_LATEST)

log = logging.getLogger(__name__)


class ConsumerExample(object):
    def __init__(self, consul_endpoint, topic='voltha-heartbeat', runtime=60):
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
                    log.warning("Error: %r getting metadata for topic: %s",
                                e, self.topic)
                else:
                    partitions = self._client.topic_partitions[self.topic]
        except KafkaUnavailableError:
            log.error("Unable to communicate with any Kafka brokers")
            self.stop()

        def _note_consumer_stopped(result, consumer):
            log.info("Consumer: %r stopped with result: %r", consumer, result)

        for partition in partitions:
            c = Consumer(self._client, self.topic, partition,
                         self.msg_processor)
            self._consumer_list.append(c)
            d = c.start(OFFSET_LATEST)
            d.addBoth(_note_consumer_stopped, c)
            self._consumer_d_list.append(d)

        # Stop ourselves after we've run the allotted time
        reactor.callLater(self.runtime, self.stop)

    def stop(self):
        log.info("\n")
        log.info("Time is up, stopping consumers...")
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
                log.error("Error stopping consumers: %r", result)
            else:
                log.info("All consumers stopped. Stopping client: %r",
                         self._client)
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
            log.info("proc: msg: %r", msg)

def parse_options():
    parser = ArgumentParser("Consume kafka messages")
    parser.add_argument("-c", "--consul",
                        help="consul ip and port",
                        default='10.100.198.220:8500')

    parser.add_argument("-t", "--topic",
                        help="topic to listen from",
                        default='voltha-heartbeat')

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
    log.info("All Done!")


if __name__ == "__main__":
    main()
