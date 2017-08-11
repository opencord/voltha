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
from scapy.layers.l2 import Ether, Dot1Q
from voltha.registry import registry
from voltha.protos.common_pb2 import OperStatus, ConnectStatus, AdminState


class DeviceHandler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.logical_device_id = None

    def disable(self):
        self.log.info('disabling', device_id=self.device_id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        # Update the operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)


class OltDeviceHandler(DeviceHandler):
    def __init__(self, adapter, device_id):
        super(OltDeviceHandler, self).__init__(adapter, device_id)
        self.filter = None
        self.io_port = None
        self.interface = registry('main').get_args().interface

    def __del__(self):
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)

    def disable(self):
        super(OltDeviceHandler, self).disable()

        # Remove the logical device
        logical_device = self.adapter_agent.get_logical_device(
            self.logical_device_id)
        self.adapter_agent.delete_logical_device(logical_device)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      admin_state=AdminState.DISABLED)

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        #  Update the logice device mapping
        if self.logical_device_id in \
                self.adapter.logical_device_id_to_root_device_id:
            del self.adapter.logical_device_id_to_root_device_id[
                self.logical_device_id]

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('disabled', device_id=self.device_id)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        # Remove all child devices
        self.adapter_agent.delete_all_child_devices(self.device_id)

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('deleted', device_id=self.device_id)

    def activate_io_port(self):
        if self.io_port is None:
            self.log.info('registering-frameio')
            self.io_port = registry('frameio').open_port(
                self.interface, self.rcv_io, self.filter)

    def deactivate_io_port(self):
        io, self.io_port = self.io_port, None

        if io is not None:
            registry('frameio').close_port(io)

    def rcv_io(self, port, frame):
        self.log.info('received', iface_name=port.iface_name,
                      frame_len=len(frame))
        pkt = Ether(frame)
        if pkt.haslayer(Dot1Q):
            outer_shim = pkt.getlayer(Dot1Q)
            if isinstance(outer_shim.payload, Dot1Q):
                inner_shim = outer_shim.payload
                cvid = inner_shim.vlan
                logical_port = cvid
                popped_frame = (
                    Ether(src=pkt.src, dst=pkt.dst, type=inner_shim.type) /
                    inner_shim.payload
                )
                kw = dict(
                    logical_device_id=self.logical_device_id,
                    logical_port_no=logical_port,
                )
                self.log.info('sending-packet-in', **kw)
                self.adapter_agent.send_packet_in(
                    packet=str(popped_frame), **kw)
            '''
            # TODO: handle non dot1q pkts
            elif pkt.haslayer(Raw):
                raw_data = json.loads(pkt.getlayer(Raw).load)
                self.alarms.send_alarm(self, raw_data)
            '''

    def packet_out(self, egress_port, msg):
        raise NotImplementedError()


class OnuDeviceHandler(DeviceHandler):
    pass
