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

    def __del__(self):
        pass

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

    def olt_oper_up(self):
        self.device.parent_id = self.logical_device_id
        self.device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(self.device)

    def olt_oper_down(self):
        self._disable_logical_device()

    def olt_delete(self):
        ld = self.adapter_agent.get_logical_device(self.logical_device_id)
        self.adapter_agent.delete_logical_device(ld)

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

    def onu_delete(self, serial_number):
        onu_device = self.adapter_agent.get_child_device(
            self.device.id,
            serial_number=serial_number)
        try:
            self.adapter_agent.delete_child_device(self.device_id,
                                                   onu_device.id, onu_device)
        except Exception as e:
            self.log.error('adapter_agent error', error=e)

        ofp_port_name = self._get_uni_ofp_port_name(onu_device)
        if ofp_port_name is None:
            self.log.exception("uni-ofp-port-not-found")
            return

        try:
            self._delete_logical_port(onu_device)
        except Exception as e:
            self.log.error('logical_port delete error', error=e)
        try:
            self.delete_port(onu_device.serial_number)
        except Exception as e:
            self.log.error('port delete error', error=e)

    def onu_id(self, serial_number):
        onu_device = self.adapter_agent.get_child_device(
            self.device.id,
            serial_number=serial_number)

        if onu_device:
            return onu_device.proxy_address.onu_id
        else:
            return 0  # Invalid onu id

    def onu_oper_down(self, intf_id, onu_id):

        onu_device = self.adapter_agent.get_child_device(
            self.device.id,
            parent_port_no=self.platform.intf_id_to_port_no(intf_id,
                                                            Port.PON_OLT),
            onu_id=onu_id)

        if onu_device is None:
            self.log.error('onu not found', intf_id=intf_id, onu_id=onu_id)
            return

        onu_adapter_agent = \
            registry('adapter_loader').get_agent(onu_device.adapter)
        if onu_adapter_agent is None:
            self.log.error('onu_adapter_agent-could-not-be-retrieved',
                           onu_device=onu_device)
            return

        if onu_device.connect_status != ConnectStatus.UNREACHABLE:
            onu_device.connect_status = ConnectStatus.UNREACHABLE
            self.adapter_agent.update_device(onu_device)

        # Move to discovered state
        self.log.debug('onu-oper-state-is-down')

        if onu_device.oper_status != OperStatus.DISCOVERED:
            onu_device.oper_status = OperStatus.DISCOVERED
            self.adapter_agent.update_device(onu_device)
        # Set port oper state to Discovered
        self.data_model._onu_ports_down(onu_device)

        onu_adapter_agent.update_interface(onu_device,
                                           {'oper_state': 'down'})

    def onu_oper_up(self, intf_id, onu_id):

        class _OnuIndication:
            def __init__(self, intf_id, onu_id):
                self.intf_id = intf_id
                self.onu_id = onu_id

        onu_device = self.adapter_agent.get_child_device(
            self.device.id,
            parent_port_no=self.platform.intf_id_to_port_no(intf_id,
                                                            Port.PON_OLT),
            onu_id=onu_id)

        if onu_device is None:
            self.log.error('onu not found', intf_id=intf_id, onu_id=onu_id)
            return

        onu_adapter_agent = \
            registry('adapter_loader').get_agent(onu_device.adapter)
        if onu_adapter_agent is None:
            self.log.error('onu_adapter_agent-could-not-be-retrieved',
                           onu_device=onu_device)
            return
        if onu_device.connect_status != ConnectStatus.REACHABLE:
            onu_device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(onu_device)

        if onu_device.oper_status != OperStatus.DISCOVERED:
            self.log.debug("ignore onu indication",
                           intf_id=intf_id,
                           onu_id=onu_id,
                           state=onu_device.oper_status,
                           msg_oper_state="up")
            return

        onu_adapter_agent.create_interface(onu_device,
                                           _OnuIndication(intf_id, onu_id))

    def olt_port_add_update(self, intf_id, intf_type, oper):
        if oper == "up":
            oper_status = OperStatus.ACTIVE
        else:
            oper_status = OperStatus.DISCOVERED

        if intf_type == "nni":
            port_type = Port.ETHERNET_NNI
        elif intf_type == "pon":
            port_type = Port.PON_OLT

        port_no, label = self._add_port(intf_id, port_type, oper_status)

        if intf_type == "nni":
            self._add_logical_port(port_no, intf_id, oper)

    # #################
    # Private functions
    # #################

    def _disable_logical_device(self):
        oper_state = OperStatus.UNKNOWN
        connect_state = ConnectStatus.UNREACHABLE

        onu_devices = self.adapter_agent.get_child_devices(self.device.id)
        for onu_device in onu_devices:
            onu_adapter_agent = \
                registry('adapter_loader').get_agent(onu_device.adapter)
            onu_adapter_agent.update_interface(onu_device,
                                               {'oper_state': 'down'})
            self.onu_ports_down(onu_device)

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

    def _add_logical_port(self, port_no, intf_id, oper_state):
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

    def _delete_logical_port(self, child_device):
        logical_ports = self.proxy.get('/logical_devices/{}/ports'.format(
            self.data_model.logical_device_id))
        for logical_port in logical_ports:
            if logical_port.device_id == child_device.id:
                self.log.debug('delete-logical-port',
                               onu_device_id=child_device.id,
                               logical_port=logical_port)
                self.flow_mgr.clear_flows_and_scheduler_for_logical_port(
                    child_device, logical_port)
                self.adapter_agent.delete_logical_port(
                    self.data_model.logical_device_id, logical_port)
                return

    def _onu_ports_down(self, onu_device):
        onu_ports = self.proxy.get('devices/{}/ports'.format(onu_device.id))
        for onu_port in onu_ports:
            self.log.debug('onu-ports-down', onu_port=onu_port)
            onu_port_id = onu_port.label
            try:
                onu_logical_port = self.adapter_agent.get_logical_port(
                    logical_device_id=self.data_model.logical_device_id,
                    port_id=onu_port_id)
                onu_logical_port.ofp_port.state = OFPPS_LINK_DOWN
                self.adapter_agent.update_logical_port(
                    logical_device_id=self.data_model.logical_device_id,
                    port=onu_logical_port)
                self.log.debug('cascading-oper-state-to-port-and-logical-port')
            except KeyError as e:
                self.log.error('matching-onu-port-label-invalid',
                               onu_id=onu_device.id, olt_id=self.device.id,
                               onu_ports=onu_ports, onu_port_id=onu_port_id,
                               error=e)

    def _add_port(self, intf_id, port_type, oper_status):
        port_no = self.platform.intf_id_to_port_no(intf_id, port_type)

        label = OpenoltUtils.port_name(port_no, port_type, intf_id)

        self.log.debug('adding-port', port_no=port_no, label=label,
                       port_type=port_type)

        port = Port(port_no=port_no, label=label, type=port_type,
                    admin_state=AdminState.ENABLED, oper_status=oper_status)

        self.adapter_agent.add_port(self.device.id, port)

        return port_no, label

    def _get_uni_ofp_port_name(self, child_device):
        logical_ports = self.proxy.get('/logical_devices/{}/ports'.format(
            self.data_model.logical_device_id))
        for logical_port in logical_ports:
            if logical_port.device_id == child_device.id:
                return logical_port.ofp_port.name
        return None
