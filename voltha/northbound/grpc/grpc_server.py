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

"""gRPC server endpoint"""
import grpc
from concurrent import futures
from structlog import get_logger

from voltha.northbound.grpc import pb2_loader
from voltha.core.protos import voltha_pb2

log = get_logger()


class HealthService(voltha_pb2.HealthServiceServicer):

    def __init__(self, thread_pool):
        self.thread_pool = thread_pool

    def GetHealthStatus(self, request, context):
        """Return current health status of a Voltha instance
        """
        log.info('get-health-status', request=request)
        hs = voltha_pb2.HealthStatus()
        hs.state = voltha_pb2.HealthStatus.HEALTHY
        return hs


class VolthaGrpcServer(object):

    def __init__(self, port=50055):
        self.port = port
        log.info('init-grpc-server', port=self.port)
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=10)
        self.server = grpc.server(self.thread_pool)

        voltha_pb2.add_HealthServiceServicer_to_server(
            HealthService(self.thread_pool), self.server)

        self.server.add_insecure_port('[::]:%s' % self.port)

    def run(self):
        log.info('starting-grpc-server')
        self.server.start()
        return self

    def shutdown(self, grace=0):
        self.server.stop(grace)


# This is to allow running the GRPC server in stand-alone mode

if __name__ == '__main__':

    server = VolthaGrpcServer().run()

    import time
    _ONE_DAY_IN_SECONDS = 60 * 60 * 24
    try:
        while 1:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.shutdown()


