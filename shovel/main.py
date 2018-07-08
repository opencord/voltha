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

"""
A simple process to read time-series samples from a kafka topic and shove
the data into graphite/carbon as pickled input.

The code is based on a github/gist by phobos182
(https://gist.github.com/phobos182/3931936).

As all GitHib gists, it is covered by the MIT license.

"""

from optparse import OptionParser

import simplejson
import structlog
from kafka import KafkaConsumer
import pickle
import struct
import socket
import sys
import time

from kafka.consumer.fetcher import ConsumerRecord
from kafka.errors import KafkaError

from common.utils.consulhelpers import get_endpoint_from_consul


log = structlog.get_logger()


class Graphite:

    def __init__(self, host='localhost', port=2004, retry=5, delay=3,
                 backoff=2, timeout=10):
        self.host = host
        self.port = port
        self.retry = retry
        self.delay = delay
        self.backoff = backoff
        self.timeout = timeout

        # Create initial socket
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.settimeout(self.timeout)
        # Initiate connection
        self.connect()


    def _backoff(self, retry, delay, backoff):
        """Exponential backoff."""
        retry -= 1
        if retry == 0:
            raise Exception('Timeout')
        time.sleep(delay)
        delay *= backoff
        return retry, delay, backoff


    def _retry(self, exception, func, *args):
        """
        Retry calling the func catching a tuple of exceptions with backoff.
        """
        retry = self.retry
        delay = self.delay
        backoff = self.backoff
        while retry > 0:
            try:
                return func(*args)
            except exception, e:
                retry, delay, backoff = self._backoff(retry, delay, backoff)


    def connect(self):
        """Connect to graphite."""
        retry = self.retry
        backoff = self.backoff
        delay = self.delay
        while retry > 0:
            try:
                # Attempt to connect to Graphite, break if success
                self.conn.connect((self.host, self.port))
                break
            except socket.error, e:
                # Ditch this socket. Create a new one
                self.conn.close()
                self.conn.connect()
                retry, delay, backoff = self._backoff(retry, delay, backoff)


    def close(self):
        """Close connection go Graphite."""
        self.conn.close()


    def send(self, data, retry=3):
        """Send data to graphite."""
        retry = self.retry
        backoff = self.backoff
        delay = self.delay
        # Attempt to send any data in the queue
        while retry > 0:
            # Check socket
            if not self.conn:
                # Attempt to restablish connection
                self.close()
                self.connect()
                retry, delay, backoff = self._backoff(retry, delay, backoff)
                continue
            try:
                # Send data to socket
                self.conn.sendall(data)
                break
            except socket.error, e:
                self.close()
                self.connect()
                retry, delay, backoff = self._backoff(retry, delay, backoff)
                continue


def _pickle(batch):
    """Pickle metrics into graphite format."""
    payload = pickle.dumps(batch)
    header = struct.pack("!L", len(payload))
    message = header + payload
    return message


def _convert(msg):
    """Convert a graphite key value string to pickle."""

    def extract_slice(ts, prefixes):
        for object_path, metrics in prefixes.iteritems():
            for metric_name, value in metrics['metrics'].iteritems():
                path = '.'.join((object_path, metric_name))
                yield (path, ts, value)

    assert isinstance(msg, dict)
    type = msg.get('type')
    if type == 'slice':
        extractor, kw = extract_slice, dict(ts=msg['ts'],
                                            prefixes=msg['prefixes'])
    else:
        raise Exception('Unknown format')

    batch = []
    for path, timestamp, value in extractor(**kw):
        batch.append((path, (timestamp, value)))
    return batch


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-K", "--kafka", dest="kafka",
                      default="localhost:9092", help="Kafka bootstrap server")
    parser.add_option("-c", "--consul", dest="consul",
                      default="localhost:8500",
                      help="Consul server (needed if kafak server is specifed"
                           "with '@kafka' value)")
    parser.add_option("-t", "--topic", dest="topic", help="Kafka topic")
    parser.add_option("-H", "--host", dest="graphite_host",
                      default="localhost", help="Graphite host")
    parser.add_option("-p", "--port", dest="graphite_port", type=int,
                      default=2004, help="Graphite port")

    (options, args) = parser.parse_args()

    # Assign OptParse variables
    kafka = options.kafka
    consul = options.consul
    topic = options.topic
    host = options.graphite_host
    port = options.graphite_port

    # Connect to Graphite
    try:
        graphite = Graphite(host, port)
    except socket.error, e:
        print "Could not connect to graphite host %s:%s" % (host, port)
        sys.exit(1)
    except socket.gaierror, e:
        print "Invalid hostname for graphite host %s" % (host)
        sys.exit(1)
    log.info('Connected to graphite at {}:{}'.format(host, port))

    # Resolve Kafka value if it is based on consul lookup
    if kafka.startswith('@'):
        kafka = get_endpoint_from_consul(consul, kafka[1:])

    # Connect to Kafka
    try:
        log.info('connect-to-kafka', kafka=kafka)
        consumer = KafkaConsumer(topic, bootstrap_servers=kafka)
    except KafkaError, e:
        log.error('failed-to-connect-to-kafka', kafka=kafka, e=e)
        sys.exit(1)

    # Consume Kafka topic
    log.info('start-loop', topic=topic)
    for record in consumer:
        assert isinstance(record, ConsumerRecord)
        msg = record.value

        try:
            batch = _convert(simplejson.loads(msg))
        except Exception, e:
            log.warn('unknown-format', msg=msg)
            continue

        pickled = _pickle(batch)
        graphite.send(pickled)
        log.debug('sent', batch_len=len(batch))

    log.info('exited')
