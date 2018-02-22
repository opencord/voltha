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

from voltha.protos.device_pb2 import Port, Device
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
        device = kwargs['device']
        self.device_id = device.id
        self.host_and_port = device.host_and_port
        self.log = structlog.get_logger(id=self.device_id, ip=self.host_and_port)
        self.oper_state = 'unknown'
        self.nni_oper_state = dict() #intf_id -> oper_state
        self.onus = {} # (intf_id, onu_id) -> {vendor_id, vendor_specific}
        self.serial_numbers = {} # (vendor_id, vendor_specific) => {intf_id, onu_id}
        self.registration_ids = {} # registration_id => {intf_id, onu_id}

        self.create_logical_device()
        self.connect_olt()
        self.init_device()

    def connect_olt(self):
        self.channel = grpc.insecure_channel(self.host_and_port)
        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

        self.indications = self.stub.EnableIndication(openolt_pb2.Empty())
        self.indications_thread = threading.Thread(target=self.process_indication)
        self.indications_thread.daemon = True
        self.indications_thread.start()

        self.stub.Enable(openolt_pb2.Empty())

    def init_device(self):
        device = self.adapter_agent.get_device(self.device_id)
        device.root = True
        device.vendor = 'Edgecore'
        device.model = 'ASFvOLT16'
        device.serial_number = self.host_and_port # FIXME
        device.parent_id = self.logical_device_id
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

    def set_oper_state(self, new_state):
        if self.oper_state != new_state:
	    if new_state == 'up':
	        self.update_device_status(
		    connect_status=ConnectStatus.REACHABLE,
		    oper_status=OperStatus.ACTIVE,
		    reason='OLT indication - operation state up')
	    elif new_state == 'down':
	        self.update_device_status(
		    connect_status=ConnectStatus.REACHABLE,
		    oper_status=OperStatus.FAILED,
		    reason='OLT indication - operation state down')
            else:
	        raise ValueError('Invalid oper_state in olt_indication')

            self.oper_state = new_state

    def olt_indication(self, olt_indication):
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

    def stringify_vendor_specific(self, vendor_specific):
        return ''.join(str(i) for i in [
		    ord(vendor_specific[0])>>4 & 0x0f,
		    ord(vendor_specific[0]) & 0x0f,
		    ord(vendor_specific[1])>>4 & 0x0f,
		    ord(vendor_specific[1]) & 0x0f,
		    ord(vendor_specific[2])>>4 & 0x0f,
		    ord(vendor_specific[2]) & 0x0f,
		    ord(vendor_specific[3])>>4 & 0x0f,
		    ord(vendor_specific[3]) & 0x0f])

    def lookup_onu(self, serial_number=None, registration_id=None):
        if serial_number is not None:
            vendor_id = serial_number.vendor_id
            vendor_specific = serial_number.vendor_specific
            if (vendor_id, vendor_specific) in self.serial_numbers:
                return self.serial_numbers[(vendor_id, vendor_specific)]
            else:
                return (None, None, None, None)

    def activate_onu(self, intf_id, serial_number=None, registration_id=None):
        onu_id = self.alloc_onu_id(
            intf_id, serial_number=serial_number,
            registration_id=registration_id)
        onuConfig = openolt_pb2.OnuConfig(
            intf_id=intf_id, onu_id=onu_id, serial_number=serial_number)
        self.log.info("Enabling ONU", intf_id=intf_id, onu_id=onu_id,
                      serial_number=serial_number)
        self.stub.EnableOnu(onuConfig)
        return onu_id

    def add_onu(self, port_no, onu_id, serial_number):

        self.log.info("Adding ONU", port_no=port_no, onu_id=onu_id,
                      serial_number=serial_number)

        proxy_address = Device.ProxyAddress(
            device_id=self.device_id,
            channel_id=port_no,
            onu_id=onu_id,
            onu_session_id=onu_id)

        self.log.info("Adding ONU", proxy_address=proxy_address)

        serial_number_str = ''.join([
            serial_number.vendor_id,
            self.stringify_vendor_specific(serial_number.vendor_specific)])

        self.adapter_agent.add_onu_device(
            parent_device_id=self.device_id, parent_port_no=port_no,
            vendor_id=serial_number.vendor_id, proxy_address=proxy_address,
            root=True, serial_number=serial_number_str,
            admin_state=AdminState.ENABLED) # FIXME

    def intf_id_to_port_no(self, intf_id, intf_type):
        if intf_type is Port.ETHERNET_NNI:
            # FIXME - Remove hardcoded '129'
            return intf_id + 129
        elif intf_type is Port.PON_OLT:
            # Interface Ids (reported by device) are zero-based indexed
            # OpenFlow port numbering is one-based.
            return intf_id + 1
        else:
	    raise Exception('Invalid port type')

    def onu_discovery_indication(self, onu_disc_indication):
	self.log.debug("Discovered ONU", intf_id=onu_disc_indication.intf_id,
            serial_number=onu_disc_indication.serial_number)

        (_, onu_id, _, _) = self.lookup_onu(serial_number=onu_disc_indication.serial_number)

        if onu_id is None:
            self.add_onu(
                self.intf_id_to_port_no(onu_disc_indication.intf_id, Port.PON_OLT),
                onu_id, onu_disc_indication.serial_number)

            self.activate_onu(
                onu_disc_indication.intf_id,
                serial_number=onu_disc_indication.serial_number)
        else:
	    self.log.info("onu activation in progress",
                intf_id=onu_disc_indication.intf_id, onu_id=onu_id)

    def make_intf_label(self, intf_id, intf_type, device_id):
        if intf_type is Port.ETHERNET_NNI:
            prefix = "nni"
        elif intf_type is Port.PON_OLT:
            prefix = "pon"
        return prefix + "-" + device_id + "-" + str(intf_id)

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
	        self.log.debug("int_oper_indication", port_no=port_no, label=label)
                self.add_logical_port(port_no) # FIXME - add oper_state
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
                self.olt_indication(ind.olt_ind)
            elif ind.HasField('onu_disc_ind'):
                self.onu_discovery_indication(ind.onu_disc_ind)
            elif ind.HasField('intf_ind'):
                self.intf_indication(ind.intf_ind)
            elif ind.HasField('intf_oper_ind'):
                self.intf_oper_indication(ind.intf_oper_ind)

    def create_logical_device(self):
        self.log.info('create logical device', device_id=self.device_id)
        serial_num = self.host_and_port

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
            root_device_id=self.device_id)
        # FIXME
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        self.logical_device_id = ld_initialized.id

    def update_device_status(self, connect_status=None, oper_status=None, reason=None):
        device = self.adapter_agent.get_device(self.device_id)
        if connect_status is not None:
            device.connect_status = connect_status
        if oper_status is not None:
            device.oper_status = oper_status
        if reason is not None:
            device.reason = reason
        self.adapter_agent.update_device(device)

    def enable_pon_interface(self, intf_id):
        self.stub.EnablePonIf(openolt_pb2.Number(val=intf_id))

    def add_logical_port(self, port_no):
        self.log.info('adding-logical-port', port_no=port_no)

        label = self.make_intf_label(port_no, Port.ETHERNET_NNI, self.device_id)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        curr_speed = OFPPF_1GB_FD
        max_speed = OFPPF_1GB_FD

        ofp = ofp_port(
            port_no=port_no,
            hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
            name=label,
            config=0,
            state=OFPPS_LIVE,
            curr=cap,
            advertised=cap,
            peer=cap,
            curr_speed=curr_speed,
            max_speed=max_speed)

        logical_port = LogicalPort(
            id=label,
            ofp_port=ofp,
            device_id=self.device_id,
            device_port_no=port_no,
            root_port=True
        )

        self.adapter_agent.add_logical_port(self.logical_device_id, logical_port)

    def add_port(self, intf_id, port_type, oper_status):
        port_no = self.intf_id_to_port_no(intf_id, port_type)

        label = self.make_intf_label(port_no, port_type, self.device_id)

        self.log.info('adding-port', port_no=port_no, label=label, port_type=port_type)
        port = Port(
            port_no=port_no,
            label=label,
            type=port_type,
            admin_state=AdminState.ENABLED,
            oper_status=oper_status
        )
        self.adapter_agent.add_port(self.device_id, port)
        return port_no, label
