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

import structlog
import threading
import grpc

from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_switch_features, \
    OFPC_PORT_STATS, OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS
from voltha.registry import registry
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2

"""
OpenoltDevice represents an OLT.
"""
class OpenoltDevice(object):

    def __init__(self, **kwargs):
        super(OpenoltDevice, self).__init__()
        self.adapter_agent = kwargs['adapter_agent']
        self.device= kwargs['device']

        self.log = structlog.get_logger(id=self.device.id, ip=self.device.host_and_port)
        self.interface = registry('main').get_args().interface

        self.log.debug('Create logical device', device_id=self.device.id)
        self.logical_device = self.create_device()
        self.channel = grpc.insecure_channel(self.device.host_and_port)
        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

        self.log.debug('Enable indications', device_id=self.device.id)
        self.indications = self.stub.GetIndication(openolt_pb2.Empty())
        self.indications_thread = threading.Thread(target=self.process_indication)
        self.indications_thread.daemon = True
        self.indications_thread.start()

        self.log.debug('Enable OpenOLT device', device_id=self.device.id)
        self.stub.SetOltAdminState(openolt_pb2.State(State="up"))

        self.log.debug('Enable PON interfaces', device_id=self.device.id)
        self.num_pon_interfaces = self.stub.GetNumPonIf(openolt_pb2.Empty()).num_pon_if
        for i in range(1, self.num_pon_interfaces):
            self.enable_pon_interface(i)

    def process_indication(self):
        while 1:
            ind = next(self.indications)
            self.log.debug("rx indication", indication=ind)
            if ind.HasField('olt_ind'):
                self.log.debug("rx olt_ind", olt_ind=ind.olt_ind)
                if ind.olt_ind.oper_state == 'up':
                    self.log.debug("olt up", oper_state=ind.olt_ind.oper_state)
                    self.update_device(
                        connect_status = ConnectStatus.REACHABLE,
                        oper_status = OperStatus.ACTIVE,
                        reason = 'OLT activated successfully')
                    self.adapter_agent.update_device(self.device)
                else:
                    self.log.debug("ERROR 1", indication=ind)
            else:
                self.log.debug("ERROR 2", indication=ind)

    def create_device(self):
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

    def update_device(self, connect_status=None, oper_status=None, reason=None):
        if connect_status is not None:
            self.device.connect_status = connect_status
        if oper_status is not None:
            self.device.oper_status = oper_status
        if reason is not None:
            self.device.reason = reason
        self.adapter_agent.update_device(self.device)

    def enable_pon_interface(iface):
        pass
