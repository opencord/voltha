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

_ = third_party

log = structlog.get_logger()

class GrpcServer(object):

    def __init__(self, port, ponsim, x_pon_sim):
        self.port = port
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=10)
        self.server = grpc.server(self.thread_pool)
        self.ponsim = ponsim
        self.x_pon_sim = x_pon_sim

    '''
    service_list: a list of (add_xyzSimServicer_to_server, xyzServicerClass)
    e.g. [(add_PonSimServicer_to_server, FlowUpdateHandler),
          (add_XPonSimServicer_to_server, XPonHandler)]
    '''
    def start(self, service_list):
        log.debug('starting')
        for add_x_to_server, xServiceClass in service_list:
            x_handler = xServiceClass(self.thread_pool, self.ponsim)
            add_x_to_server(x_handler, self.server)

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
        server_credentials = grpc.ssl_server_credentials(((private_key, certificate_chain,),))
        self.server.add_secure_port('[::]:%s' % self.port, server_credentials)
        self.server.start()
        log.info('started')

    def stop(self, grace=0):
        log.debug('stopping')
        self.server.stop(grace)
        log.info('stopped')
