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


from structlog import get_logger
from simplejson import dumps
from google.protobuf.json_format import MessageToJson
from zope.interface import implementer
from confluent_kafka import Producer

from voltha.registry import registry, IComponent

log = get_logger()


@implementer(IComponent)
class OpenoltKafkaProxy(object):
    """
    This is a singleton proxy kafka class to hide the kafka client details.
    This proxy uses confluent-kafka-python as the kafka client.
    """
    _kafka_instance = None

    def __init__(self, kafka_endpoint='localhost:9092'):

        # return an exception if the object already exist
        if OpenoltKafkaProxy._kafka_instance:
            raise Exception('Singleton exist for :{}'.format(
                OpenoltKafkaProxy))

        log.debug('initializing', endpoint=kafka_endpoint)
        self.kafka_endpoint = kafka_endpoint
        self.kproducer = None
        self.stopping = False
        self.faulty = False
        log.debug('initialized', endpoint=kafka_endpoint)

    def start(self):
        log.debug('starting')
        self._get_kafka_producer()
        OpenoltKafkaProxy._kafka_instance = self
        log.info('started')
        self.stopping = False
        return self

    def stop(self):
        pass

    def _get_kafka_producer(self):
        conf = {'bootstrap.servers': self.kafka_endpoint}
        self.kproducer = Producer(**conf)

    def send_message(self, topic, msg, key=None):
        try:
            self.kproducer.produce(topic, msg)
        except BufferError:
            log.error('Local producer queue is full')

    def is_faulty(self):
        return self.faulty


def kafka_send_pb(topic, msg):
    try:
        log.debug('send protobuf to kafka', topic=topic, msg=msg)
        kafka_proxy = registry('openolt_kafka_proxy')
        if kafka_proxy and not kafka_proxy.is_faulty():
            log.debug('kafka-proxy-available')
            kafka_proxy.send_message(
                topic,
                dumps(MessageToJson(
                    msg,
                    including_default_value_fields=True)))
        else:
            log.error('kafka-proxy-unavailable')
    except Exception, e:
        log.exception('failed-sending-protobuf', e=e)
