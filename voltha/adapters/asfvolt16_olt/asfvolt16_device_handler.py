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

"""
Asfvolt16 OLT adapter
"""

from uuid import uuid4
from common.frameio.frameio import BpfProgramFilter
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.protos.device_pb2 import Port
from voltha.protos.common_pb2 import AdminState
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, ofp_switch_features, ofp_desc, ofp_port
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.adapters.asfvolt16_olt.bal import Bal
from voltha.adapters.device_handler import OltDeviceHandler

# TODO: VLAN ID needs to come from some sort of configuration.
PACKET_IN_VLAN = 4091
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))

#TODO: hardcoded NNI port ID to be removed once port enumeration is supported.
nni_port_no = 1

# TODO - hardcoded OLT ID to be removed once multiple OLT devices is supported.
olt_id = 1

class Asfvolt16Handler(OltDeviceHandler):
    def __init__(self, adapter, device_id):
        super(Asfvolt16Handler, self).__init__(adapter, device_id)
        self.filter = is_inband_frame
        self.bal = Bal(self, self.log)
        self.host_and_port = None
        self.olt_id = 0

    def __del__(self):
        super(Asfvolt16Handler, self).__del__()

    def __str__(self):
        return "Asfvolt16Handler: {}".format(self.host_and_port)

    def activate(self, device):

        self.log.info('activating-asfvolt16-olt', device=device)

        if self.logical_device_id is None:

            if not device.host_and_port:
                device.oper_status = OperStatus.FAILED
                device.reason = 'No host_and_port field provided'
                self.adapter_agent.update_device(device)
                return

            self.host_and_port = device.host_and_port
            device.root = True
            device.vendor = 'Edgecore'
            device.model = 'ASFvOLT16'
            device.serial_number = device.host_and_port
            self.adapter_agent.update_device(device)
    
            self.add_port(port_no=1, port_type=Port.ETHERNET_NNI)
            self.logical_device_id = self.add_logical_device(device_id=device.id)
            self.add_logical_port(port_no=1,
                                  port_type=Port.ETHERNET_NNI,
                                  device_id=device.id,
                                  logical_device_id=self.logical_device_id)

            self.bal.connect_olt(device.host_and_port, self.device_id)

        self.bal.activate_olt()

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = self.logical_device_id
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

        # Open the frameio port to receive in-band packet_in messages
        self.activate_io_port()

    def add_port(self, port_no, port_type):
        self.log.info('adding-port', port_no=port_no, port_type=port_type)
        if port_type is Port.ETHERNET_NNI:
            label='NNI facing Ethernet port'
            oper_status=OperStatus.ACTIVE
        elif port_type is Port.PON_OLT:
            label='PON port'
            #To-Do The pon port status should be ACTIVATING.
            #For now make the status as Active.
            oper_status=OperStatus.ACTIVE
        else :
            self.log.erro('invalid-port-type', port_type=port_type)
            return

        port = Port(
            port_no=port_no,
            label=label,
            type=port_type,
            admin_state=AdminState.ENABLED,
            oper_status=oper_status
        )
        self.adapter_agent.add_port(self.device_id, port)

    def add_logical_device(self, device_id):
        self.log.info('adding-logical-device', device_id=device_id)
        ld = LogicalDevice(
            # not setting id and datapth_id will let the adapter
            # agent pick id
            desc=ofp_desc(
                mfr_desc='cord project',
                hw_desc='n/a',
                sw_desc='logical device for Edgecore ASFvOLT16 OLT',
                serial_num=uuid4().hex,
                dp_desc='n/a'
            ),
            switch_features=ofp_switch_features(
                n_buffers=256,  # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    OFPC_FLOW_STATS
                    | OFPC_TABLE_STATS
                    | OFPC_PORT_STATS
                    | OFPC_GROUP_STATS
                )
            ),
            root_device_id=device_id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        return ld_initialized.id

    def add_logical_port(self, port_no, port_type, device_id, logical_device_id):
        self.log.info('adding-logical-port', port_no=port_no, port_type=port_type, device_id=device_id)
        if port_type is Port.ETHERNET_NNI:
            label='nni'
            cap = OFPPF_1GB_FD | OFPPF_FIBER
            curr_speed=OFPPF_1GB_FD
            max_speed=OFPPF_1GB_FD
        else:
            self.log.erro('invalid-port-type', port_type=port_type)
            return

        ofp=ofp_port(
            port_no=0,  # is 0 OK?
            hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
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
            device_id=device_id,
            device_port_no=port_no,
            root_port=True
        )

        self.adapter_agent.add_logical_port(logical_device_id, logical_port)

    def handle_access_term_ind(self, ind_info):
        #import pdb; pdb.set_trace()
        device = self.adapter_agent.get_device(self.device_id)
        if ind_info['actv_status'] == 'success':
            self.log.info('successful access terminal Indication',
                                  olt_id=self.olt_id)
            device.connect_status = ConnectStatus.REACHABLE
            device.oper_status = OperStatus.ACTIVE
            device.reason = 'OLT activated successfully'
            status = self.adapter_agent.update_device(device)
            self.log.info('OLT activation complete')
            try:
               #Here we have to add pon_port to OLT device.
               #Since the create_interface is not called, below code is
               #added to achive functionality.
               #self.send_connect_olt(self.olt_id)
               port_no = 100
               self.add_port(port_no, port_type=Port.PON_OLT)
               #import pdb; pdb.set_trace()
               self.bal.activate_pon_port(self.olt_id, port_no);
            except Exception as e:
               return
        else:
            device.oper_status = OperStatus.FAILED
            device.reason = 'Failed to Intialize OLT'
            self.adapter_agent.update_device(device)
            reactor.callLater(5, self.activate, device)
        return

    def handle_subscriber_term_ind(self, ind_info):
        #import pdb; pdb.set_trace()
        self.log.info('To-DO Need to handle ONU Indication')
       

def disable(self):
        super(Asfvolt16Handler, self).disable()

def delete(self):
        super(Asfvolt16Handler, self).delete()
