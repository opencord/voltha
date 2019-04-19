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

import structlog
import grpc
import threading
from voltha.northbound.kafka.kafka_proxy import kafka_send_pb
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2


class OpenoltGrpc(object):
    def __init__(self, host_and_port, device):
        super(OpenoltGrpc, self).__init__()
        self.log = structlog.get_logger()
        self.log.debug('openolt grpc init')
        self.device = device
        self.host_and_port = host_and_port
        self.channel = grpc.insecure_channel(self.host_and_port)
        self.channel_ready_future = grpc.channel_ready_future(self.channel)
        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

    def start(self):
        try:
            # Start indications thread
            self.log.debug('openolt grpc starting')
            self.indications_thread_handle = threading.Thread(
                target=self.indications_thread)
            # Old getter/setter API for daemon; use it directly as a
            # property instead. The Jinkins error will happon on the reason of
            # Exception in thread Thread-1 (most likely raised # during
            # interpreter shutdown)
            self.indications_thread_handle.setDaemon(True)
            self.indications_thread_handle.start()
        except Exception as e:
            self.log.exception('indication start failed', e=e)
        else:
            self.log.debug('openolt grpc started')

    def indications_thread(self):

        self.indications = self.stub.EnableIndication(openolt_pb2.Empty())

        topic = 'openolt.ind-{}'.format(
            self.device.host_and_port.split(':')[0])

        while True:
            try:
                # get the next indication from olt
                ind = next(self.indications)
            except Exception as e:
                self.log.warn('openolt grpc connection lost', error=e)
                ind = openolt_pb2.Indication()
                ind.olt_ind.oper_state = 'down'
                kafka_send_pb(topic, ind)
                break
            else:
                self.log.debug("openolt grpc rx indication", indication=ind)

                topic = 'openolt.ind-{}'.format(
                    self.device.host_and_port.split(':')[0])
                kafka_send_pb(topic, ind)
