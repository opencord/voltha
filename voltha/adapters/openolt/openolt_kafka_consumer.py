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
from voltha.northbound.kafka.kafka_proxy import get_kafka_proxy

log = get_logger()


class KConsumer(object):
    def __init__(self, *topics):
        kafka_proxy = get_kafka_proxy()
        if kafka_proxy and not kafka_proxy.is_faulty():
            log.debug('kafka-proxy-available')
            self.kafka_endpoint = kafka_proxy.kafka_endpoint
        else:
            self.log.error('kafka-proxy-unavailable')

        conf = {'bootstrap.servers': self.kafka_endpoint,
                'group.id': "mygroup",
                'session.timeout.ms': 60000}

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
        self._c.subscribe(list(topics))

    def read(self, callback):
        # Read messages from Kafka and hand it to to callback
        try:
            while True:
                log.debug('polling kafka for alarms')
                msg = self._c.poll(timeout=1.0)
                if msg is None:
                    continue
                elif not msg.error():
                    print(msg.value())
                    callback(msg.value())
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
            | grep cord-kafka-0 | awk '{print $6}'):9092 foo voltha.heartbeat
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
            'group.id': group,
            'session.timeout.ms': 60000}

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

    def print_assignment(consumer, partitions):
        print('Assignment:', partitions)

    # Subscribe to topics
    c.subscribe(topics, on_assign=print_assignment)

    # Read messages from Kafka, print to stdout
    try:
        while True:
            msg = c.poll(timeout=1.0)
            if msg is None:
                continue
            elif not msg.error():
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
