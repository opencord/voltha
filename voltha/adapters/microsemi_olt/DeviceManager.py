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
from uuid import uuid4
import structlog

from voltha.adapters.microsemi_olt.PAS5211 import CHANNELS, PORTS
from voltha.protos.common_pb2 import ConnectStatus, OperStatus, AdminState
from voltha.protos.device_pb2 import Device, Port, Image
from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_switch_features, OFPC_FLOW_STATS, OFPC_TABLE_STATS, \
    OFPC_PORT_STATS, OFPC_GROUP_STATS, ofp_port, OFPPS_LIVE, OFPPF_10GB_FD, OFPPF_FIBER

log = structlog.get_logger()


def mac_str_to_tuple(mac):
    """
    Convert 'xx:xx:xx:xx:xx:xx' MAC address string to a tuple of integers.
    Example: mac_str_to_tuple('00:01:02:03:04:05') == (0, 1, 2, 3, 4, 5)
    """
    return tuple(int(d, 16) for d in mac.split(':'))


class DeviceManager(object):

    def __init__(self, device, adapter_agent):
        self.device = device
        self.adapter_agent = adapter_agent
        self.logical_device = None

    def update_device_info_from_pkt(self, pkt):

        self.device.root = True
        self.device.vendor = 'Celestica Inc.'
        self.device.model = 'Ruby'
        self.device.hardware_version = \
            '{}.{}'.format(hex(pkt.major_hardware_version),
                           pkt.minor_hardware_version)
        self.device.firmware_version = '{}.{}.{}'.format(pkt.major_firmware_version,
                                                         pkt.minor_firmware_version,
                                                         pkt.build_firmware_version)

        # There could be multiple software version on the device,
        # active, standby etc. Choose the active or running software
        # below. See simulated_olt for example implementation
        self.device.images.image.extend([
            Image(version="0.0.1")
        ])
        self.device.serial_number = self.device.mac_address
        self.device.oper_status = ConnectStatus.REACHABLE
        # self.adapter_agent.update_device(self.device)

        for i in PORTS:
            self.adapter_agent.add_port(self.device.id, Port(
                port_no=i,
                label='PON port',
                type=Port.PON_OLT,
                admin_state=AdminState.ENABLED,
                oper_status=OperStatus.ACTIVE
            ))

        self.create_logical_device()
        self.add_upstream_port(129)
        self.add_logical_upstream_port(129)

        self.device.parent_id = self.logical_device.id
        self.adapter_agent.update_device(self.device)

    def create_logical_device(self):
        log.debug('create-logical-device')
        # then shortly after we create the logical device with one port
        # that will correspond to the NNI port
        ld = LogicalDevice(
            desc=ofp_desc(
                hw_desc=self.device.hardware_version,
                sw_desc=self.device.firmware_version,
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
            root_device_id=self.device.id
        )

        self.logical_device = self.adapter_agent.create_logical_device(ld, dpid=self.device.mac_address)

    def add_upstream_port(self, port):
        nni_port = Port(
            port_no=port,
            label='NNI',
            type=Port.ETHERNET_NNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.adapter_agent.add_port(self.device.id, nni_port)

    def add_logical_upstream_port(self, port):
    
        cap = OFPPF_10GB_FD | OFPPF_FIBER

        self.adapter_agent.add_logical_port(self.logical_device.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=port,
                # hw_addr=mac_str_to_tuple(self.device.serial_number)[2:8],
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port),
                name='nni',
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_10GB_FD,
                max_speed=OFPPF_10GB_FD
            ),
            device_id=self.device.id,
            device_port_no=port,
            root_port=True
        ))

    def add_port(self, port):
        self.adapter_agent.add_port(self.device.id, port)

        cap = OFPPF_10GB_FD | OFPPF_FIBER
        logical_port = LogicalPort(
            id='uni',
            ofp_port=ofp_port(
                port_no=port.port_no,
                hw_addr=mac_str_to_tuple(self.device.mac_address),
                name='{}-{}'.format(port.label, port.port_no),
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_10GB_FD,
                max_speed=OFPPF_10GB_FD
            )
        )
        self.adapter_agent.add_logical_port(self.logical_device.id,
                                            logical_port)

    def onu_detected(self, parent_port_no=None,
                     child_device_type=None,
                     onu_id=None,
                     serial_number=None,
                     onu_session_id=None,
                     channel_id=None):
        log.debug('onu-detected') 
        try:
            self.adapter_agent.child_device_detected(
                parent_device_id=self.device.id,
                parent_port_no=parent_port_no,
                child_device_type=child_device_type,
                serial_number=serial_number,
                proxy_address=Device.ProxyAddress(
                    device_id=self.device.id,
                    channel_id=channel_id,  # happens to be the channel id as well
                    onu_id=onu_id,
                    onu_session_id=onu_session_id
                ),
                admin_state=AdminState.ENABLED,
                vlan=0)
        except Exception as e:
            log.exception('onu-detected-failed', e=e) 
            raise e

    def deactivate_onu(self, onu_id=None, channel_id=None, onu_session_id=None):
        try:
            child_device = self.adapter_agent.get_child_device_with_proxy_address(Device.ProxyAddress(
                device_id=self.device.id,
                channel_id=channel_id,
                onu_id=onu_id,
                onu_session_id=onu_session_id
            ))
            if child_device:
                # self.adapter_agent.update_child_device_state(child_device, admin_state=AdminState.DISABLED)
                child_device.admin_state=AdminState.DISABLED
                self.adapter_agent.update_device(child_device)
        except KeyError:
            log.debug("ONU {} cannot be deactivated".format(onu_id))

    def activate(self):
        # self.device = self.adapter_agent.get_device(self.device.id)
        # self.device.parent_id = self.logical_device.id
        self.device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(self.device)


    def publish_alarm(self, alarm):
        new_alarm = self.adapter_agent.create_alarm(
            # id = alarm["id"],
            resource_id = alarm["resource_id"],
            description = alarm["description"],
            type = alarm["type"],
            # category = alarm["category"],
            # severity = alarm["severity"],
            # state = alarm["state"],
            context = alarm["context"]
        )
        self.adapter_agent.submit_alarm(self.device.id, new_alarm)
        log.debug("[publish_alarm]")