#
# Copyright 2018 the original author or authors.
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

"""
Openolt device handler
"""
import structlog
import threading
import grpc

from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS
from voltha.registry import registry
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2

class OpenoltDevice(object):

    def __init__(self, **kwargs):
        super(OpenoltDevice, self).__init__()
        self.adapter_agent = kwargs['adapter_agent']
        self.device= kwargs['device']
        self.log = structlog.get_logger(id=self.device.id, ip=self.device.host_and_port)
        self.interface = registry('main').get_args().interface
        self.channel = None
        self.stub = None
        self.indications = None
        self.indications_thread = None
        self.logical_device = self.createLogicalDevice()
        self.channel = grpc.insecure_channel(self.device.host_and_port)
        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)
        self.enableInd()
        self.enable()

    def enable(self):
        self.log.info('Enabling OpenOLT device', device_id=self.device.id)

        try:
            self.stub.SetOltAdminState(openolt_pb2.State(State="up"))
        except grpc.RpcError as error:
            self.log.error('Failed to set OLT admin state', state=state, error=error)

    def enableInd(self):
        try:
            self.indications = self.stub.StreamOltInd(openolt_pb2.Empty())
        except grpc.RpcError as error:
            self.log.error('Failed to start indications', error=error)
        self.indications_thread = threading.Thread(target=self.processInd)
        self.indications_thread.daemon = True
        self.indications_thread.start()

    def processInd(self):
        while 1:
            state = next(self.indications)
            self.log.debug("rx indication", state=state)
            if state.State == "up":
                self.device.connect_status = ConnectStatus.REACHABLE
                self.device.oper_status = OperStatus.ACTIVE
                self.device.reason = 'OLT activated successfully'
                self.adapter_agent.update_device(self.device)

    def createLogicalDevice(self):
        ld = LogicalDevice(
            # FIXME
            desc=ofp_desc(mfr_desc='FIXME',
                          hw_desc='FIXME',
                          sw_desc='FIXME',
                          serial_num='FIXME',
                          dp_desc='n/a'),
            switch_features=ofp_switch_features(n_buffers=256,
                                                n_tables=2,
                                                capabilities=(
                                                    OFPC_FLOW_STATS |
                                                    OFPC_TABLE_STATS |
                                                    OFPC_GROUP_STATS |
                                                    OFPC_PORT_STATS)),
            root_device_id=self.device.id)
        # FIXME
        return self.adapter_agent.create_logical_device(ld,
                                                        dpid='00:13:95:00:00:00')
