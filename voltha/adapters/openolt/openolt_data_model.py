#
# Copyright 2019 the original author or authors.
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
import socket
from voltha.adapters.openolt.openolt_utils import OpenoltUtils
from voltha.protos.device_pb2 import Port
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPS_LINK_DOWN, OFPPF_1GB_FD, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, OFPC_GROUP_STATS, ofp_port, ofp_port_stats, ofp_desc, \
    ofp_switch_features
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.registry import registry


class OpenOltDataModel(object):
    log = structlog.get_logger()

    def __init__(self, adapter_agent):
        self.adapter_agent = adapter_agent
        self.log = structlog.get_logger()

    def create_logical_device(self, device_id, device_info):
        dpid = device_info.device_id
        serial_number = device_info.device_serial_number

        device = self.adapter_agent.get_device(device_id)
        host_and_port = device.host_and_port

        if dpid is None or dpid == '':
            uri = host_and_port.split(":")[0]
            try:
                socket.inet_pton(socket.AF_INET, uri)
                dpid = '00:00:' + OpenoltUtils.ip_hex(uri)
            except socket.error:
                # this is not an IP
                dpid = OpenoltUtils.str_to_mac(uri)

        self.log.info('creating-openolt-logical-device', dp_id=dpid,
                      serial_number=serial_number)

        hw_desc = device_info.model
        if device_info.hardware_version:
            hw_desc += '-' + device_info.hardware_version

        # Create logical OF device
        ld = LogicalDevice(
            root_device_id=device_id,
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
            desc=ofp_desc(
                serial_num=serial_number
            )
        )
        ld_init = self.adapter_agent.create_logical_device(ld,
                                                           dpid=dpid)

        device = self.adapter_agent.get_device(device_id)
        device.serial_number = serial_number
        self.adapter_agent.update_device(device)

        self.log.info('created-openolt-logical-device',
                      logical_device_id=ld_init.id)

        return ld_init.id

    def disable_logical_device(self, device_id):

        oper_state = OperStatus.UNKNOWN
        connect_state = ConnectStatus.UNREACHABLE

        device = self.adapter_agent.get_device(device_id)

        logical_device_id = device.parent_id

        child_devices = self.adapter_agent.get_child_devices(device_id)
        for onu_device in child_devices:
            onu_adapter_agent = \
                registry('adapter_loader').get_agent(onu_device.adapter)
            onu_adapter_agent.update_interface(onu_device,
                                               {'oper_state': 'down'})
            self.onu_ports_down(onu_device, oper_state)

        # Children devices
        self.adapter_agent.update_child_devices_state(
            device_id, oper_status=oper_state,
            connect_status=connect_state)
        # Device Ports
        device_ports = self.adapter_agent.get_ports(device_id,
                                                    Port.ETHERNET_NNI)
        logical_ports_ids = [port.label for port in device_ports]
        device_ports += self.adapter_agent.get_ports(device_id,
                                                     Port.PON_OLT)

        for port in device_ports:
            port.oper_status = oper_state
            self.adapter_agent.add_port(device_id, port)

        # Device logical port
        for logical_port_id in logical_ports_ids:
            logical_port = self.adapter_agent.get_logical_port(
                logical_device_id, logical_port_id)
            logical_port.ofp_port.state = OFPPS_LINK_DOWN
            self.adapter_agent.update_logical_port(self.logical_device_id,
                                                   logical_port)
        device.oper_status = oper_state
        device.connect_status = connect_state
        self.adapter_agent.update_device(device)

    def add_logical_port(self, logical_device_id, device_id, port_no, intf_id,
                         oper_state):
        self.log.info('adding-logical-port', port_no=port_no)

        label = OpenoltUtils.port_name(port_no, Port.ETHERNET_NNI)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        curr_speed = OFPPF_1GB_FD
        max_speed = OFPPF_1GB_FD

        if oper_state == OperStatus.ACTIVE:
            of_oper_state = OFPPS_LIVE
        else:
            of_oper_state = OFPPS_LINK_DOWN

        ofp = ofp_port(
            port_no=port_no,
            hw_addr=mac_str_to_tuple(
                OpenoltUtils.make_mac_from_port_no(port_no)),
            name=label, config=0, state=of_oper_state, curr=cap,
            advertised=cap, peer=cap, curr_speed=curr_speed,
            max_speed=max_speed)

        ofp_stats = ofp_port_stats(port_no=port_no)

        logical_port = LogicalPort(
            id=label, ofp_port=ofp, device_id=device_id,
            device_port_no=port_no, root_port=True,
            ofp_port_stats=ofp_stats)

        self.adapter_agent.add_logical_port(logical_device_id, logical_port)
