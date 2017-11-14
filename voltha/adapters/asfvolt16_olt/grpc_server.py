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

from Queue import Queue, Empty
import os

import grpc
from concurrent import futures
from grpc import StatusCode
from grpc._channel import _Rendezvous
from structlog import get_logger
from common.utils.grpc_utils import twisted_async
from twisted.internet import threads

#log = get_logger()

class GrpcServer(object):

    def __init__(self, port, adapter, log):
        self.port = port
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=10)
        self.server = grpc.server(self.thread_pool)
        self.services = []
        self.adapter = adapter
        self.log = log

    def start(self, activation_func, service):
        self.log.debug('Asfvolt16-GRPC-server-starting')
        self.services.append(service)
        activation_func(service, self.server)
        self.server.add_insecure_port('[::]:%s' % self.port)
        self.server.start()
        self.log.info('Asfvolt16-GRPC-server-started')

    def stop(self, grace=0):
        self.log.info('Asfvolt16-stopping-GRPC-Server')
        self.server.stop(grace)
        self.thread_pool.shutdown(False)
        self.log.debug('Asfvolt16-stopped-GRPC-Server')
