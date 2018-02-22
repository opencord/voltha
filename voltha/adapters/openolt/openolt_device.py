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

from voltha.protos.device_pb2 import Port
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

        self.oper_state = 'unknown'

        self.onu_id_counter = 0

        self.log.debug('Create logical device', device_id=self.device.id)
        self.logical_device = self.create_device()
        self.channel = grpc.insecure_channel(self.device.host_and_port)
        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

        self.log.debug('Enable indications', device_id=self.device.id)
        self.indications = self.stub.EnableIndication(openolt_pb2.Empty())
        self.indications_thread = threading.Thread(target=self.process_indication)
        self.indications_thread.daemon = True
        self.indications_thread.start()

        self.log.debug('Enable OLT device', device_id=self.device.id)
        self.stub.Enable(openolt_pb2.Empty())

    def set_oper_state(self, new_state):
        if self.oper_state != new_state:
	    if new_state == 'up':
	        self.update_device(
		    connect_status = ConnectStatus.REACHABLE,
		    oper_status = OperStatus.ACTIVE,
		    reason = 'OLT indication - operation state up')
	        self.adapter_agent.update_device(self.device)
	    elif new_state == 'down':
	        self.update_device(
		    connect_status = ConnectStatus.REACHABLE,
		    oper_status = OperStatus.FAILED,
		    reason = 'OLT indication - operation state down')
	        self.adapter_agent.update_device(self.device)
            else:
	        raise ValueError('Invalid oper_state in olt_indication')

            self.oper_state = new_state

    def process_olt_indication(self, olt_indication):
	self.log.debug("rx olt_indication", olt_ind=olt_indication)
        self.set_oper_state(olt_indication.oper_state)

    def onu_discovery(self, onu_disc_indication):
	self.log.debug("Discovered ONU", intf_id=onu_disc_indication.intf_id,
            serial_number=onu_disc_indication.serial_number)
        # FIXME - onu_id_counter per PON interface
        self.onu_id_counter += 1
        onuConfig = openolt_pb2.OnuConfig(
                        intf_id=onu_disc_indication.intf_id,
                        onu_id=self.onu_id_counter,
                        serial_number=onu_disc_indication.serial_number)
	self.log.debug("EnableOnu", intf_id=onu_disc_indication.intf_id,
            serial_number=onu_disc_indication.serial_number)
        self.stub.EnableOnu(onuConfig)

    def add_port(self, port_no, port_type, label, oper_status):
        self.log.info('adding-port', port_no=port_no, port_type=port_type)
        port = Port(
            port_no=port_no,
            label=label,
            type=port_type,
            admin_state=AdminState.ENABLED,
            oper_status=oper_status
        )
        self.adapter_agent.add_port(self.device.id, port)

    def make_pon_label(self, intf_id):
        return "pon_" + self.device.id + "/" + str(intf_id)

    def intf_indication(self, intf_indication):
	self.log.debug("Received interface indication", intf_id=intf_indication.intf_id,
            oper_state=intf_indication.oper_state)
        # Interface Ids (reported by device) are zero-based indexed,
        # while OpenFlow port numbering is one-based.
        label = self.make_pon_label(intf_indication.intf_id+1)
        self.add_port(intf_indication.intf_id+1, Port.PON_OLT, label, OperStatus.ACTIVE)

    def process_indication(self):
        while 1:
            ind = next(self.indications)
            self.log.debug("rx indication", indication=ind)
            if ind.HasField('olt_ind'):
                self.process_olt_indication(ind.olt_ind)
            elif ind.HasField('onu_disc_ind'):
                self.onu_discovery(ind.onu_disc_ind)
            elif ind.HasField('intf_ind'):
                self.intf_indication(ind.intf_ind)

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

    def enable_pon_interface(self, intf_id):
        self.stub.EnablePonIf(openolt_pb2.Number(val=intf_id))
