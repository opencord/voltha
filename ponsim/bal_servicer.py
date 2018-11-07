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
from voltha.protos.ponsim_pb2 import PonSimDeviceInfo
from google.protobuf.empty_pb2 import Empty
from voltha.adapters.asfvolt16_olt.protos.bal_pb2_grpc import BalServicer
from voltha.adapters.asfvolt16_olt.protos.bal_pb2 BalErr
from voltha.adapters.asfvolt16_olt.protos.bal_errno_pb2 import BAL_ERR_OK

_ = third_party

log = structlog.get_logger()

class BalHandler(BalServicer):

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

    def BalApiInit(self, request, context):
        log.info('olt-connection-successful', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalApiFinish(self, request, context):
        log.info('BalApi', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalCfgSet(self, request, context):
        log.info('olt-activation-successful', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalAccessTerminalCfgSet(self, request, context):
        log.info('olt-activation-successful', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalCfgClear(self, request, context):
        log.info('BalCfClear', request=request)
        return BalErr(err=BAL_ERR_OK)
