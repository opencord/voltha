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
import structlog
import grpc
from multiprocessing import Process
from confluent_kafka import Producer
from simplejson import dumps
from google.protobuf.json_format import MessageToJson

from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2


log = structlog.get_logger()


def kafka_send_pb(p, topic, ind):
    p.produce(topic, dumps(MessageToJson(
        ind, including_default_value_fields=True)))


def process_indications(broker, host_and_port):
    channel = grpc.insecure_channel(host_and_port)
    stub = openolt_pb2_grpc.OpenoltStub(channel)
    stream = stub.EnableIndication(openolt_pb2.Empty())

    default_topic = 'openolt.ind-{}'.format(host_and_port.split(':')[0])
    # pktin_topic = 'openolt.pktin-{}'.format(host_and_port.split(':')[0])

    conf = {'bootstrap.servers': broker}

    p = Producer(**conf)

    while True:
        try:
            # get the next indication from olt
            print('waiting for indication...')
            ind = next(stream)
        except Exception as e:
            log.warn('openolt grpc connection lost', error=e)
            ind = openolt_pb2.Indication()
            ind.olt_ind.oper_state = 'down'
            kafka_send_pb(p, default_topic, ind)
            break
        else:
            log.debug("openolt grpc rx indication", indication=ind)
            kafka_send_pb(p, default_topic, ind)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: %s <olt hostname or ip>\n\n' % sys.argv[0])
        sys.exit(1)

    broker = sys.argv[1]
    host = sys.argv[2]

    try:
        # Start indications_process
        log.debug('openolt grpc starting')
        indications_process = Process(
            target=process_indications,
            args=(broker, host,))
        indications_process.start()
    except Exception as e:
        log.exception('indication start failed', e=e)
    else:
        log.debug('openolt grpc started')

    try:
        indications_process.join()
    except KeyboardInterrupt:
        indications_process.terminate()
