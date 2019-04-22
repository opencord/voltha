#!/usr/bin/env python
#
# Copyright 2019 the original author or authors.
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
#

import sys
import getopt
import logging
from structlog import get_logger
from confluent_kafka import Consumer, KafkaError
from voltha.registry import registry

log = get_logger()


class KConsumer(object):
    def __init__(self, callback, *topics):
        kafka_proxy = registry('kafka_proxy')
        if kafka_proxy and not kafka_proxy.is_faulty():
            self.kafka_endpoint = kafka_proxy.kafka_endpoint
            log.debug('kafka-proxy-available', endpoint=self.kafka_endpoint)
        else:
            log.error('kafka-proxy-unavailable')

        conf = {'bootstrap.servers': self.kafka_endpoint,
                'group.id': "mygroup"}

        logger = logging.getLogger('openolt-kafka-consumer')
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)-15s %(levelname)-8s %(message)s'))
        logger.addHandler(handler)

        # Create Consumer instance
        # Hint: try debug='fetch' to generate some log messages
        # self._c = Consumer(conf, logger=logger, debug='fetch')
        log.debug('creating kafka consumer', conf=conf)
        self._c = Consumer(conf, logger=logger)

        # Subscribe to topics
        log.debug('subscribe to topics', topics=topics)
        self.topics = list(topics)
        self._c.subscribe(self.topics)

        # Read messages from Kafka and hand it to to callback
        try:
            while True:
                log.debug('polling kafka for messages', topics=self.topics)
                msg = self._c.poll(timeout=1.0)
                if msg is None:
                    continue
                elif not msg.error():
                    log.debug('got a kafka message', topic=msg.topic())
                    callback(msg.topic(), msg.value())
                elif msg.error().code() == KafkaError._PARTITION_EOF:
                    pass
                else:
                    log.error('Error occured: {0}'.format(msg.error().str()))

        except KeyboardInterrupt:
            pass

        finally:
            # Close down consumer to commit final offsets.
            self._c.close()


def print_usage_and_exit(program_name):
    sys.stderr.write(
        'Usage: %s <bootstrap-brokers> <group> <topic1> <topic2> ..\n'
        % program_name)
    sys.exit(1)


if __name__ == '__main__':
    """
    Usage:
        python openolt_kafka_consumer.py $(kubectl get pod -o wide \
        | grep cord-kafka-0 | awk '{print $6}'):9092 \
        mygroup openolt.ind.olt openolt.ind.pkt
    """
    optlist, argv = getopt.getopt(sys.argv[1:], 'T:')
    if len(argv) < 3:
        print_usage_and_exit(sys.argv[0])

    broker = argv[0]
    group = argv[1]
    topics = argv[2:]
    # Consumer configuration
    # See https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
    conf = {'bootstrap.servers': broker,
            'group.id': group}

    logger = logging.getLogger('openolt-kafka-consumer')
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)-15s %(levelname)-8s %(message)s'))
    logger.addHandler(handler)

    # Create Consumer instance
    # Hint: try debug='fetch' to generate some log messages
    # c = Consumer(conf, logger=logger, debug='fetch')
    c = Consumer(conf, logger=logger)

    # Subscribe to topics
    c.subscribe(topics)

    # Read messages from Kafka, print to stdout
    try:
        while True:
            msg = c.poll(timeout=1.0)
            if msg is None:
                continue
            elif not msg.error():
                print('got a kafka message, topic: {0}'.format(msg.topic()))
                print(msg.value())
            elif msg.error().code() == KafkaError._PARTITION_EOF:
                # print('End of partition reached {0}/{1}'
                #       .format(msg.topic(), msg.partition()))
                pass
            else:
                print('Error occured: {0}'.format(msg.error().str()))

    except KeyboardInterrupt:
        pass

    finally:
        # Close down consumer to commit final offsets.
        c.close()
