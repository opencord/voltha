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
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPS_LINK_DOWN, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, ofp_switch_features, ofp_desc, ofp_port, \
    OFPXMC_OPENFLOW_BASIC
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.core.logical_device_agent import mac_str_to_tuple
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

        self.nni_oper_state = dict() #intf_id -> oper_state
        self.onus = {} # (intf_id, onu_id) -> {vendor_id, vendor_specific}
        self.serial_numbers = {} # (vendor_id, vendor_specific) => {intf_id, onu_id}
        self.registration_ids = {} # registration_id => {intf_id, onu_id}

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

    def alloc_onu_id(self, intf_id, serial_number=None, registration_id=None):
        onu_id = None

        # onu_id is unique per PON.
        # FIXME - Remove hardcoded limit on ONUs per PON (64)
        for i in range(1, 64):
            if (intf_id, i) not in self.onus:
                onu_id = i
                break

        if onu_id is not None:
            onu_rec = {'intf_id': intf_id, 'onu_id': onu_id,
                       'serial_number': serial_number,
                       'registration_id': registration_id}
            if serial_number is not None:
                self.serial_numbers[(serial_number.vendor_id, serial_number.vendor_specific)] = onu_rec
            if registration_id is not None:
                self.registration_ids[registration_id] = onu_rec
            self.onus[(intf_id, onu_id)] = onu_rec
        else:
	    raise Exception('ONU Id allocation failed')

        return onu_id

    def decode_vendor_specific(self, serial_number):
        temp = [ord(onu_disc_indication.serial_number.vendor_specific[0])>>4 & 0x0f,
            ord(onu_disc_indication.serial_number.vendor_specific[0]) & 0x0f,
            ord(onu_disc_indication.serial_number.vendor_specific[1])>>4 & 0x0f,
            ord(onu_disc_indication.serial_number.vendor_specific[1]) & 0x0f,
            ord(onu_disc_indication.serial_number.vendor_specific[2])>>4 & 0x0f,
            ord(onu_disc_indication.serial_number.vendor_specific[2]) & 0x0f,
            ord(onu_disc_indication.serial_number.vendor_specific[3])>>4 & 0x0f,
            ord(onu_disc_indication.serial_number.vendor_specific[3]) & 0x0f]
        return ''.join(str(i) for i in vendor_specific)

    def lookup_onu(self, serial_number=None, registration_id=None):
        if serial_number is not None:
            vendor_id = serial_number.vendor_id
            vendor_specific = serial_number.vendor_specific
            if (vendor_id, vendor_specific) in self.serial_numbers:
                return self.serial_numbers[(vendor_id, vendor_specific)]
            else:
                return (None, None, None, None)

    def onu_discovery(self, onu_disc_indication):
	self.log.debug("Discovered ONU", intf_id=onu_disc_indication.intf_id,
            serial_number=onu_disc_indication.serial_number)

        (_, onu_id, _, _) = self.lookup_onu(serial_number=onu_disc_indication.serial_number)

        if onu_id is None:
            onu_id = self.alloc_onu_id(onu_disc_indication.intf_id,
                                       serial_number=onu_disc_indication.serial_number)
            onuConfig = openolt_pb2.OnuConfig(
                        intf_id=onu_disc_indication.intf_id,
                        onu_id=onu_id,
                        serial_number=onu_disc_indication.serial_number)
	    self.log.info("Enabling ONU", intf_id=onu_disc_indication.intf_id, onu_id=onu_id,
                serial_number=onu_disc_indication.serial_number)
            self.stub.EnableOnu(onuConfig)
        else:
	    self.log.info("onu activation in progress",
                intf_id=onu_disc_indication.intf_id, onu_id=onu_id)

    def make_intf_label(self, intf_id, type):
        if type is Port.ETHERNET_NNI:
            prefix = "nni"
        elif type is Port.PON_OLT:
            prefix = "pon"
        return prefix + "_" + self.device.id + "/" + str(intf_id)

    def intf_indication(self, intf_indication):
	self.log.debug("Received interface indication", intf_id=intf_indication.intf_id,
            oper_state=intf_indication.oper_state)

        if intf_indication.oper_state == "up":
            oper_status = OperStatus.ACTIVE
        else:
            oper_status = OperStatus.DISCOVERED

        # FIXME - If port exists, update oper state
        self.add_port(intf_indication.intf_id, Port.PON_OLT, oper_status)

    def intf_oper_indication(self, intf_oper_indication):
	self.log.debug("Received interface oper state change indication", intf_id=intf_oper_indication.intf_id,
            type=intf_oper_indication.type, oper_state=intf_oper_indication.oper_state)

        if intf_oper_indication.oper_state == "up":
            oper_state = OperStatus.ACTIVE
        else:
            oper_state = OperStatus.DISCOVERED

        if intf_oper_indication.type == "nni":
            if intf_oper_indication.intf_id not in self.nni_oper_state:
                # NNI discovery
                self.nni_oper_state[intf_oper_indication.intf_id] = oper_state
                port_no, label = self.add_port(intf_oper_indication.intf_id, Port.ETHERNET_NNI, oper_state)
                self.add_logical_port(port_no, Port.ETHERNET_NNI, self.device.id, self.logical_device.id)
            elif intf_oper_indication.intf_id != self.nni_oper_state:
                # FIXME - handle subsequent NNI oper state change
                pass
        elif intf_oper_indication.type == "pon":
            # FIXME - handle PON oper state change
            pass

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
            elif ind.HasField('intf_oper_ind'):
                self.intf_oper_indication(ind.intf_oper_ind)

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

    def add_logical_port(self, port_no, port_type,
                         device_id, logical_device_id):
        self.log.info('adding-logical-port', port_no=port_no,
                      port_type=port_type, device_id=device_id)
        if port_type is Port.ETHERNET_NNI:
            label = 'nni'
            cap = OFPPF_1GB_FD | OFPPF_FIBER
            curr_speed = OFPPF_1GB_FD
            max_speed = OFPPF_1GB_FD
        else:
            self.log.error('invalid-port-type', port_type=port_type)
            return

        ofp = ofp_port(
            port_no=port_no,  # is 0 OK?
            hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
            name=label,
            config=0,
            #state=OFPPS_LIVE,
            state=OFPPS_LINK_DOWN,
            curr=cap,
            advertised=cap,
            peer=cap,
            curr_speed=curr_speed,
            max_speed=max_speed)

        logical_port = LogicalPort(
            id=label,
            ofp_port=ofp,
            device_id=device_id,
            device_port_no=port_no,
            root_port=True
        )

        self.adapter_agent.add_logical_port(logical_device_id, logical_port)

    def add_port(self, intf_id, type, oper_status):

        # FIXME - Add a per-interface object.
        if type is Port.ETHERNET_NNI:
            # FIXME - Remove hardcoded '129'
            port_no = intf_id + 129
        elif type is Port.PON_OLT:
            # Interface Ids (reported by device) are zero-based indexed
            # OpenFlow port numbering is one-based.
            port_no = intf_id + 1
        else:
	    raise Exception('Invalid port type')

        label = self.make_intf_label(port_no, type)

        self.log.info('adding-port', port_no=port_no, label=label, type=type)
        port = Port(
            port_no=port_no,
            label=label,
            type=type,
            admin_state=AdminState.ENABLED,
            oper_status=oper_status
        )
        self.adapter_agent.add_port(self.device.id, port)
        return port_no, label
