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
from voltha.protos.device_pb2 import Port, Device
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPS_LINK_DOWN, OFPPF_1GB_FD, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, OFPC_GROUP_STATS, ofp_port, ofp_port_stats, ofp_desc, \
    ofp_switch_features
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.registry import registry


class OpenOltDataModel(object):

    def __init__(self, device, adapter_agent, platform):
        self.log = structlog.get_logger()

        self.device = device
        self.adapter_agent = adapter_agent
        self.platform = platform
        self.logical_device_id = None

        self.device.root = True
        self.device.connect_status = ConnectStatus.UNREACHABLE
        self.device.oper_status = OperStatus.ACTIVATING

        self.adapter_agent.update_device(device)

    def reconcile(self):
        assert self.logical_device_id is not None
        self.adapter_agent.reconcile_logical_device(
            self.logical_device_id)

    def olt_create(self, device_info):
        if self.logical_device_id is not None:
            return

        dpid = device_info.device_id
        serial_number = device_info.device_serial_number

        if dpid is None or dpid == '':
            uri = self.device.host_and_port.split(":")[0]
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
            root_device_id=self.device.id,
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
        self.logical_device_id = \
            self.adapter_agent.create_logical_device(ld, dpid=dpid).id

        self.device.vendor = device_info.vendor
        self.device.model = device_info.model
        self.device.hardware_version = device_info.hardware_version
        self.device.firmware_version = device_info.firmware_version
        self.device.connect_status = ConnectStatus.REACHABLE
        self.device.serial_number = serial_number

        self.adapter_agent.update_device(self.device)

        self.log.info('created-openolt-logical-device',
                      logical_device_id=self.logical_device_id)

        return self.logical_device_id

    def disable_logical_device(self):

        oper_state = OperStatus.UNKNOWN
        connect_state = ConnectStatus.UNREACHABLE

        child_devices = self.adapter_agent.get_child_devices(self.device.id)
        for onu_device in child_devices:
            onu_adapter_agent = \
                registry('adapter_loader').get_agent(onu_device.adapter)
            onu_adapter_agent.update_interface(onu_device,
                                               {'oper_state': 'down'})
            self.onu_ports_down(onu_device, oper_state)

        # Children devices
        self.adapter_agent.update_child_devices_state(
            self.device.id, oper_status=oper_state,
            connect_status=connect_state)
        # Device Ports
        device_ports = self.adapter_agent.get_ports(self.device.id,
                                                    Port.ETHERNET_NNI)
        logical_ports_ids = [port.label for port in device_ports]
        device_ports += self.adapter_agent.get_ports(self.device.id,
                                                     Port.PON_OLT)

        for port in device_ports:
            port.oper_status = oper_state
            self.adapter_agent.add_port(self.device.id, port)

        # Device logical port
        for logical_port_id in logical_ports_ids:
            logical_port = self.adapter_agent.get_logical_port(
                self.logical_device_id, logical_port_id)
            logical_port.ofp_port.state = OFPPS_LINK_DOWN
            self.adapter_agent.update_logical_port(self.logical_device_id,
                                                   logical_port)
        self.device.oper_status = oper_state
        self.device.connect_status = connect_state
        self.adapter_agent.update_device(self.device)

    def add_logical_port(self, port_no, intf_id, oper_state):
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
            id=label, ofp_port=ofp, device_id=self.device.id,
            device_port_no=port_no, root_port=True,
            ofp_port_stats=ofp_stats)

        self.adapter_agent.add_logical_port(self.logical_device_id,
                                            logical_port)

    def olt_oper_up(self):
        self.device.parent_id = self.logical_device_id
        self.device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(self.device)

    def olt_oper_down(self):
        self.disable_logical_device()

    def onu_create(self, intf_id, onu_id, serial_number):

        onu_device = self.adapter_agent.get_child_device(
            self.device.id,
            serial_number=serial_number)

        if onu_device:
            self.log.debug("data_model onu update", intf_id=intf_id,
                           onu_id=onu_id, serial_number=serial_number)
            onu_device.oper_status = OperStatus.DISCOVERED
            onu_device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(onu_device)
            return

        self.log.debug("data_model onu create", intf_id=intf_id,
                       onu_id=onu_id, serial_number=serial_number)

        # NOTE - channel_id of onu is set to intf_id
        proxy_address = Device.ProxyAddress(device_id=self.device.id,
                                            channel_id=intf_id, onu_id=onu_id,
                                            onu_session_id=onu_id)
        port_no = self.platform.intf_id_to_port_no(intf_id, Port.PON_OLT)
        vendor_id = serial_number[:4]
        self.adapter_agent.add_onu_device(
            parent_device_id=self.device.id, parent_port_no=port_no,
            vendor_id=vendor_id, proxy_address=proxy_address,
            root=False, serial_number=serial_number,
            admin_state=AdminState.ENABLED,
            connect_status=ConnectStatus.REACHABLE
        )

    def onu_id(self, serial_number):
        onu_device = self.adapter_agent.get_child_device(
            self.device.id,
            serial_number=serial_number)

        if onu_device:
            return onu_device.proxy_address.onu_id
        else:
            return 0  # Invalid onu id
