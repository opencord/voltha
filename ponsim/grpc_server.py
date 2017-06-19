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
from concurrent import futures

from common.utils.grpc_utils import twisted_async
from voltha.protos import third_party
from voltha.protos.ponsim_pb2 import PonSimServicer, \
    add_PonSimServicer_to_server, PonSimDeviceInfo
from google.protobuf.empty_pb2 import Empty

from voltha.protos.ponsim_pb2 import XPonSimServicer, add_XPonSimServicer_to_server

_ = third_party

log = structlog.get_logger()


class FlowUpdateHandler(PonSimServicer):

    def __init__(self, thread_pool, ponsim):
        self.thread_pool = thread_pool
        self.ponsim = ponsim

    @twisted_async
    def GetDeviceInfo(self, request, context):
        log.info('get-device-info')
        ports = self.ponsim.get_ports()
        return PonSimDeviceInfo(
            nni_port=ports[0],
            uni_ports=ports[1:]
        )

    @twisted_async
    def UpdateFlowTable(self, request, context):
        log.info('flow-table-update', request=request, port=request.port)
        if request.port == 0:
            # by convention this is the olt port
            self.ponsim.olt_install_flows(request.flows)
        else:
            self.ponsim.onu_install_flows(request.port, request.flows)
        return Empty()

    def GetStats(self, request, context):
        return self.ponsim.get_stats()

class XPonHandler(XPonSimServicer):

    def __init__(self, thread_pool, x_pon_sim):
        self.thread_pool = thread_pool
        self.x_pon_sim = x_pon_sim

    def CreateInterface(self, request, context):
        self.x_pon_sim.CreateInterface(request)
        return Empty()

    def UpdateInterface(self, request, context):
        self.x_pon_sim.UpdateInterface(request)
        return Empty()

    def RemoveInterface(self, request, context):
        self.x_pon_sim.RemoveInterface(request)
        return Empty()

class GrpcServer(object):

    def __init__(self, port, ponsim, x_pon_sim):
        self.port = port
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=10)
        self.server = grpc.server(self.thread_pool)
        self.ponsim = ponsim
        self.x_pon_sim = x_pon_sim

    def start(self):
        log.debug('starting')
        handler = FlowUpdateHandler(self.thread_pool, self.ponsim)
        add_PonSimServicer_to_server(handler, self.server)
        x_pon_handler = XPonHandler(self.thread_pool, self.x_pon_sim)
        add_XPonSimServicer_to_server(x_pon_handler, self.server)
        self.server.add_insecure_port('[::]:%s' % self.port)
        self.server.start()
        log.info('started')

    def stop(self, grace=0):
        log.debug('stopping')
        self.server.stop(grace)
        log.info('stopped')
