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
import structlog
from common.utils.grpc_utils import twisted_async
from voltha.protos import third_party
from voltha.protos.ponsim_pb2_grpc import PonSimServicer, XPonSimServicer
from voltha.protos.ponsim_pb2 import PonSimDeviceInfo
from google.protobuf.empty_pb2 import Empty

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

    def CreateTcont(self, request, context):
        self.x_pon_sim.CreateTcont(
            request.tconts_config_data,
            request.traffic_descriptor_profile_config_data)
        return Empty()

    def UpdateTcont(self, request, context):
        self.x_pon_sim.UpdateTcont(
            request.tconts_config_data,
            request.traffic_descriptor_profile_config_data)
        return Empty()

    def RemoveTcont(self, request, context):
        self.x_pon_sim.RemoveTcont(
            request.tconts_config_data,
            request.traffic_descriptor_profile_config_data)
        return Empty()

    def CreateGemport(self, request, context):
        self.x_pon_sim.CreateGemport(request)
        return Empty()

    def UpdateGemport(self, request, context):
        self.x_pon_sim.UpdateGemport(request)
        return Empty()

    def RemoveGemport(self, request, context):
        self.x_pon_sim.RemoveGemport(request)
        return Empty()

    def CreateMulticastGemport(self, request, context):
        self.x_pon_sim.CreateMulticastGemport(request)
        return Empty()

    def UpdateMulticastGemport(self, request, context):
        self.x_pon_sim.UpdateMulticastGemport(request)
        return Empty()

    def RemoveMulticastGemport(self, request, context):
        self.x_pon_sim.RemoveMulticastGemport(request)
        return Empty()

    def CreateMulticastDistributionSet(self, request, context):
        self.x_pon_sim.CreateMulticastDistributionSet(request)
        return Empty()

    def UpdateMulticastDistributionSet(self, request, context):
        self.x_pon_sim.UpdateMulticastDistributionSet(request)
        return Empty()

    def RemoveMulticastDistributionSet(self, request, context):
        self.x_pon_sim.RemoveMulticastDistributionSet(request)
        return Empty()
