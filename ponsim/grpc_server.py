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
import grpc
import structlog
import os
from concurrent import futures

from voltha.protos import third_party
from voltha.protos.ponsim_pb2_grpc import add_PonSimServicer_to_server
from voltha.protos.ponsim_pb2_grpc import add_XPonSimServicer_to_server
from voltha.adapters.asfvolt16_olt.protos.bal_pb2_grpc import add_BalServicer_to_server
from ponsim_servicer import FlowUpdateHandler, XPonHandler
from bal_servicer import BalHandler

_ = third_party

log = structlog.get_logger()

class GrpcServer(object):

    def __init__(self, port, ponsim, x_pon_sim, device_type):
        self.port = port
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=10)
        self.server = grpc.server(self.thread_pool)
        self.ponsim = ponsim
        self.x_pon_sim = x_pon_sim
        self.device_type = device_type

    def start(self):
        if self.device_type == 'ponsim':
            handler = FlowUpdateHandler(self.thread_pool, self.ponsim)
            add_PonSimServicer_to_server(handler, self.server)
            x_pon_handler = XPonHandler(self.thread_pool, self.x_pon_sim)
            add_XPonSimServicer_to_server(x_pon_handler, self.server)
        else:
            handler = BalHandler(self.thread_pool, self.ponsim)
            add_BalServicer_to_server(handler, self.server)

        # read in key and certificate
        try:
           voltha_key = os.path.join(os.environ.get('VOLTHA_BASE'),"pki/voltha.key")
           with open(voltha_key) as f:
               private_key = f.read()

           voltha_cert = os.path.join(os.environ.get('VOLTHA_BASE'),"pki/voltha.crt")
           with open(voltha_cert) as f:
               certificate_chain = f.read()
        except Exception as e:
           log.error('failed-to-read-cert-keys', reason=e)

        # create server credentials
        if self.device_type == 'ponsim':
            server_credentials = grpc.ssl_server_credentials(((private_key, certificate_chain,),))
            self.server.add_secure_port('[::]:%s' % self.port, server_credentials)
        else:
            self.server.add_insecure_port('[::]:%s' % self.port)

        self.server.start()
        log.info('started')

    def stop(self, grace=0):
        log.debug('stopping')
        self.server.stop(grace)
        log.info('stopped')
