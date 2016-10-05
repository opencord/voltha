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

import time
from afkak.client import KafkaClient as _KafkaClient
from afkak.producer import Producer as _kafkaProducer
from structlog import get_logger
from voltha.consulhelpers import get_endpoint_from_consul
from twisted.internet.defer import inlineCallbacks
from afkak.common import (
    PRODUCER_ACK_LOCAL_WRITE,
)


class KafkaProxy(object):
    """
    This is a singleton proxy kafka class to hide the kafka client details.
    """
    _kafka_instance = None

    def __init__(self, consul_endpoint='localhost:8500',
                 kafka_endpoint='localhost:9092' ,
                 ack_timeout = 1000, max_req_attempts = 10):

        # return an exception if the object already exist
        if KafkaProxy._kafka_instance:
            raise Exception('Singleton exist for :{}'.format(KafkaProxy))

        self.log = get_logger()

        self.consul_endpoint = consul_endpoint
        self.kafka_endpoint = kafka_endpoint

        # PRODUCER_ACK_LOCAL_WRITE : server will wait till the data is written
        #  to a local log before sending response
        if self.kafka_endpoint.startswith('@'):
            _k_endpoint = get_endpoint_from_consul(self.consul_endpoint,
                                                   self.kafka_endpoint[1:])
        else:
            _k_endpoint = self.kafka_endpoint

        self.log.info('Creating kafka endpoint', endpoint=_k_endpoint)

        self.kclient = _KafkaClient(_k_endpoint)
        self.kproducer = _kafkaProducer(self.kclient,
                                        req_acks=PRODUCER_ACK_LOCAL_WRITE,
                                        ack_timeout=ack_timeout,
                                        max_req_attempts=max_req_attempts)

        self.log.info('initializing-KafkaProxy:{}'.format(_k_endpoint))
        KafkaProxy._kafka_instance = self


    @inlineCallbacks
    def send_message(self, topic, msg):
        assert topic is not None
        assert msg is not None
        self.log.info('Sending message {} to kafka topic {}'.format(msg,
                                                                    topic))
        try:
            msg_list = []
            msg_list.append(msg)
            yield self.kproducer.send_messages(topic, msgs=msg_list)
            self.log.debug('Successfully sent message {} to kafka topic '
                           '{}'.format(msg, topic))
        except Exception as e:
            self.log.info('Failure to send message {} to kafka topic {}: '
                          '{}'.format(msg, topic, repr(e)))


# Common method to get the singleton instance of the kafka proxy class
def get_kafka_proxy():
    return KafkaProxy._kafka_instance
