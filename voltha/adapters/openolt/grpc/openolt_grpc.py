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
import time
import yaml
import grpc
import threading

from common.structlog_setup import setup_logging
from voltha.registry import registry
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2
from voltha.adapters.openolt.openolt_kafka_proxy import OpenoltKafkaProxy, \
    kafka_send_pb


class OpenoltGrpc(object):
    def __init__(self, host_and_port, device):
        super(OpenoltGrpc, self).__init__()
        log.debug('openolt grpc init')
        self.device = device
        self.host_and_port = host_and_port
        self.channel = grpc.insecure_channel(self.host_and_port)
        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

    def start(self):
        try:
            # Start indications thread
            log.debug('openolt grpc starting')
            self.indications_thread_handle = threading.Thread(
                target=process_indications,
                args=(self.host_and_port,))
            self.indications_thread_handle.setDaemon(True)
            self.indications_thread_handle.start()
        except Exception as e:
            log.exception('indication start failed', e=e)
        else:
            log.debug('openolt grpc started')


def process_indications(host_and_port):
    channel = grpc.insecure_channel(host_and_port)
    stub = openolt_pb2_grpc.OpenoltStub(channel)
    stream = stub.EnableIndication(openolt_pb2.Empty())

    topic = 'openolt.ind-{}'.format(host_and_port.split(':')[0])

    while True:
        try:
            # get the next indication from olt
            ind = next(stream)
        except Exception as e:
            log.warn('openolt grpc connection lost', error=e)
            ind = openolt_pb2.Indication()
            ind.olt_ind.oper_state = 'down'
            kafka_send_pb(topic, ind)
            break
        else:
            log.debug("openolt grpc rx indication", indication=ind)
            kafka_send_pb(topic, ind)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: %s <olt hostname or ip>\n\n' % sys.argv[0])
        sys.exit(1)

    broker = sys.argv[1]
    host = sys.argv[2]

    log = setup_logging(yaml.load(open('./logconfig.yml', 'r')),
                        host,
                        verbosity_adjust=0,
                        cache_on_use=True)

    kafka_proxy = registry.register(
        'openolt_kafka_proxy',
        OpenoltKafkaProxy(broker)
    ).start()

    while True:
        process_indications(host)
        time.sleep(5)
