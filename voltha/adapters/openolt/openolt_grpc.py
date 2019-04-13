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
import time
from twisted.internet import reactor
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

        self.log.debug('openolt grpc connecting to olt')

        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

        timeout = 60*60
        delay = 1
        exponential_back_off = False
        while True:
            try:
                self.device.device_info \
                    = self.stub.GetDeviceInfo(openolt_pb2.Empty())
                break
            except Exception as e:
                if delay > timeout:
                    self.log.error("openolt grpc timed out connecting to olt")
                    return
                else:
                    self.log.warn(
                        "openolt grpc retry connecting to olt in %ds: %s"
                        % (delay, repr(e)))
                    time.sleep(delay)
                    if exponential_back_off:
                        delay += delay
                    else:
                        delay += 1

        self.log.info('openolt grpc connected to olt',
                      device_info=self.device.device_info)

        self.device.go_state_connected()

        self.indications = self.stub.EnableIndication(openolt_pb2.Empty())

        while True:
            try:
                # get the next indication from olt
                ind = next(self.indications)
            except Exception as e:
                self.log.warn('openolt grpc connection lost', error=e)
                reactor.callFromThread(self.device.go_state_down)
                reactor.callFromThread(self.device.go_state_init)
                break
            else:
                self.log.debug("openolt grpc rx indication", indication=ind)

                if self.device.admin_state is "down":
                    if ind.HasField('intf_oper_ind') \
                            and (ind.intf_oper_ind.type == "nni"):
                        self.log.warn('olt is admin down, allow nni ind',
                                      admin_state=self.device.admin_state,
                                      indications=ind)
                    else:
                        self.log.warn('olt is admin down, ignore indication',
                                      admin_state=self.admin_state,
                                      indications=ind)
                        continue

                topic = 'openolt.ind-{}'.format(
                    self.device.host_and_port.split(':')[0])
                kafka_send_pb(topic, ind)
