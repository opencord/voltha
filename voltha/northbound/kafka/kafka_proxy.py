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


import threading
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads import deferToThread
from zope.interface import implementer
from confluent_kafka import Producer as _kafkaProducer
from confluent_kafka import Consumer

from common.utils.consulhelpers import get_endpoint_from_consul
from voltha.northbound.kafka.event_bus_publisher import EventBusPublisher
from voltha.registry import IComponent

log = get_logger()


@implementer(IComponent)
class KafkaProxy(object):
    """
    This is a singleton proxy kafka class to hide the kafka client details. This
    proxy uses confluent-kafka-python as the kafka client. Since that client is
    not a Twisted client then requests to that client are wrapped with
    twisted.internet.threads.deferToThread to avoid any potential blocking of
    the Twisted loop.
    """
    _kafka_instance = None

    def __init__(self,
                 consul_endpoint='localhost:8500',
                 kafka_endpoint='localhost:9092',
                 ack_timeout=1000,
                 max_req_attempts=10,
                 consumer_poll_timeout=10,
                 config={}):

        # return an exception if the object already exist
        if KafkaProxy._kafka_instance:
            raise Exception('Singleton exist for :{}'.format(KafkaProxy))

        log.debug('initializing', endpoint=kafka_endpoint)
        self.ack_timeout = ack_timeout
        self.max_req_attempts = max_req_attempts
        self.consul_endpoint = consul_endpoint
        self.kafka_endpoint = kafka_endpoint
        self.config = config
        self.kclient = None
        self.kproducer = None
        self.event_bus_publisher = None
        self.stopping = False
        self.faulty = False
        self.consumer_poll_timeout = consumer_poll_timeout
        self.topic_consumer_map = {}
        self.topic_callbacks_map = {}
        self.topic_any_map_lock = threading.Lock()
        log.debug('initialized', endpoint=kafka_endpoint)

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        self._get_kafka_producer()
        KafkaProxy._kafka_instance = self
        self.event_bus_publisher = yield EventBusPublisher(
            self, self.config.get('event_bus_publisher', {})).start()
        log.info('started')
        KafkaProxy.faulty = False
        self.stopping = False
        returnValue(self)

    @inlineCallbacks
    def stop(self):
        try:
            log.debug('stopping-kafka-proxy')
            self.stopping = True
            try:
                if self.kclient:
                    yield self.kclient.close()
                    self.kclient = None
                    log.debug('stopped-kclient-kafka-proxy')
            except Exception, e:
                log.exception('failed-stopped-kclient-kafka-proxy', e=e)

            try:
                if self.kproducer:
                    yield self.kproducer.flush()
                    self.kproducer = None
                    log.debug('stopped-kproducer-kafka-proxy')
            except Exception, e:
                log.exception('failed-stopped-kproducer-kafka-proxy', e=e)

            # Stop all consumers
            try:
                self.topic_any_map_lock.acquire()
                log.debug('stopping-consumers-kafka-proxy')
                for _, c in self.topic_consumer_map.iteritems():
                    yield deferToThread(c.close)
                self.topic_consumer_map.clear()
                self.topic_callbacks_map.clear()
                log.debug('stopped-consumers-kafka-proxy')
            except Exception, e:
                log.exception('failed-stopped-consumers-kafka-proxy', e=e)
            finally:
                self.topic_any_map_lock.release()
                log.debug('stopping-consumers-kafka-proxy-released-lock')

            # try:
            #    if self.event_bus_publisher:
            #        yield self.event_bus_publisher.stop()
            #        self.event_bus_publisher = None
            #        log.debug('stopped-event-bus-publisher-kafka-proxy')
            # except Exception, e:
            #    log.debug('failed-stopped-event-bus-publisher-kafka-proxy')
            #    pass

            log.debug('stopped-kafka-proxy')

        except Exception, e:
            self.kclient = None
            self.kproducer = None
            # self.event_bus_publisher = None
            log.exception('failed-stopped-kafka-proxy', e=e)
            pass

    def _get_kafka_producer(self):

        try:

            if self.kafka_endpoint.startswith('@'):
                try:
                    _k_endpoint = get_endpoint_from_consul(self.consul_endpoint,
                                                           self.kafka_endpoint[
                                                           1:])
                    log.debug('found-kafka-service', endpoint=_k_endpoint)

                except Exception as e:
                    log.exception('no-kafka-service-in-consul', e=e)

                    self.kproducer = None
                    self.kclient = None
                    return
            else:
                _k_endpoint = self.kafka_endpoint
            self.kproducer = _kafkaProducer(
                {'bootstrap.servers': _k_endpoint,
                 }
            )
            pass
        except Exception, e:
            log.exception('failed-get-kafka-producer', e=e)
            return

    @inlineCallbacks
    def _wait_for_messages(self, consumer, topic):
        while True:
            try:
                msg = yield deferToThread(consumer.poll,
                                          self.consumer_poll_timeout)

                if self.stopping:
                    log.debug("stop-request-recieved", topic=topic)
                    break

                if msg is None:
                    continue
                if msg.error():
                    # This typically is received when there are no more messages
                    # to read from kafka. Ignore.
                    continue

                # Invoke callbacks
                for cb in self.topic_callbacks_map[topic]:
                    yield cb(msg)
            except Exception as e:
                log.debug("exception-receiving-msg", topic=topic, e=e)

    @inlineCallbacks
    def subscribe(self, topic, callback, groupId, offset='latest'):
        """
        subscribe allows a caller to subscribe to a given kafka topic.  This API
        always create a group consumer.
        :param topic - the topic to subscribe to
        :param callback - the callback to invoke whenever a message is received
        on that topic
        :param groupId - the groupId for this consumer.  In the current
        implementation there is a one-to-one mapping between a topic and a
        groupId.  In other words, once a groupId is used for a given topic then
        we won't be able to create another groupId for the same topic.
        :param offset:  the kafka offset from where the consumer will start
        consuming messages
        """
        try:
            self.topic_any_map_lock.acquire()
            if topic in self.topic_consumer_map:
                # Just add the callback
                if topic in self.topic_callbacks_map:
                    self.topic_callbacks_map[topic].append(callback)
                else:
                    self.topic_callbacks_map[topic] = [callback]
                return

            # Create consumer for that topic
            c = Consumer({
                'bootstrap.servers': self.kafka_endpoint,
                'group.id': groupId,
                'auto.offset.reset': offset
            })
            yield deferToThread(c.subscribe, [topic])
            # c.subscribe([topic])
            self.topic_consumer_map[topic] = c
            self.topic_callbacks_map[topic] = [callback]
            # Start the consumer
            reactor.callLater(0, self._wait_for_messages, c, topic)
        except Exception, e:
            log.exception("topic-subscription-error", e=e)
        finally:
            self.topic_any_map_lock.release()

    @inlineCallbacks
    def unsubscribe(self, topic, callback):
        """
        Unsubscribe to a given topic.  Since there they be multiple callers
        consuming from the same topic then to ensure only the relevant caller
        gets unsubscribe then the callback is used as a differentiator.   The
        kafka consumer will be closed when there are no callbacks required.
        :param topic: topic to unsubscribe
        :param callback: callback the caller used when subscribing to the topic.
        If multiple callers have subscribed to a topic using the same callback
        then the first callback on the list will be removed.
        :return:None
        """
        try:
            self.topic_any_map_lock.acquire()
            log.debug("unsubscribing-to-topic", topic=topic)
            if topic in self.topic_callbacks_map:
                index = 0
                for cb in self.topic_callbacks_map[topic]:
                    if cb == callback:
                        break
                    index += 1
                if index < len(self.topic_callbacks_map[topic]):
                    self.topic_callbacks_map[topic].pop(index)

                if len(self.topic_callbacks_map[topic]) == 0:
                    # Stop the consumer
                    if topic in self.topic_consumer_map:
                        yield deferToThread(
                            self.topic_consumer_map[topic].close)
                        del self.topic_consumer_map[topic]
                    del self.topic_callbacks_map[topic]
                    log.debug("unsubscribed-to-topic", topic=topic)
                else:
                    log.debug("consumers-for-topic-still-exist", topic=topic,
                              num=len(self.topic_callbacks_map[topic]))
        except Exception, e:
            log.exception("topic-unsubscription-error", e=e)
        finally:
            self.topic_any_map_lock.release()
            log.debug("unsubscribing-to-topic-release-lock", topic=topic)

    @inlineCallbacks
    def send_message(self, topic, msg, key=None):
        assert topic is not None
        assert msg is not None

        # first check whether we have a kafka producer.  If there is none
        # then try to get one - this happens only when we try to lookup the
        # kafka service from consul
        try:
            if self.faulty is False:

                if self.kproducer is None:
                    self._get_kafka_producer()
                    # Lets the next message request do the retry if still a failure
                    if self.kproducer is None:
                        log.error('no-kafka-producer',
                                  endpoint=self.kafka_endpoint)
                        return

                log.debug('sending-kafka-msg', topic=topic, kafka_msg=msg)
                msgs = [msg]

                if self.kproducer is not None and self.event_bus_publisher and self.faulty is False:
                    d = deferToThread(self.kproducer.produce, topic, msg, key)
                    yield d
                    log.debug('sent-kafka-msg', topic=topic, kafka_msg=msg)
                    # send a lightweight poll to avoid an exception after 100k messages.
                    d1 = deferToThread(self.kproducer.poll, 0)
                    yield d1
                else:
                    return

        except Exception, e:
            self.faulty = True
            log.error('failed-to-send-kafka-msg', topic=topic, kafka_msg=msg,
                      e=e)

            # set the kafka producer to None.  This is needed if the
            # kafka docker went down and comes back up with a different
            # port number.
            if self.stopping is False:
                log.debug('stopping-kafka-proxy')
                try:
                    self.stopping = True
                    self.stop()
                    self.stopping = False
                    self.faulty = False
                    log.debug('stopped-kafka-proxy')
                except Exception, e:
                    log.exception('failed-stopping-kafka-proxy', e=e)
                    pass
            else:
                log.info('already-stopping-kafka-proxy')

            return

    def is_faulty(self):
        return self.faulty
