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
Fully simulated OLT/ONU adapter.
"""

import structlog
from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from zope.interface import implementer
from common.utils.asleep import asleep

from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, OFPPC_NO_RECV
from voltha.protos.openflow_13_pb2 import ofp_port
from voltha.protos.ponsim_pb2 import FlowTable

_ = third_party
log = structlog.get_logger()


@implementer(IAdapterInterface)
class PonSimOnuAdapter(object):
    name = 'ponsim_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Voltha project',
            version='0.4',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.devices_handlers = dict()  # device_id -> PonSimOltHandler()

    def start(self):
        log.debug('starting')
        log.info('started')

    def stop(self):
        log.debug('stopping')
        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def adopt_device(self, device):
        self.devices_handlers[device.id] = PonSimOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        log.info('disable-device', device_id=device.id)
        reactor.callLater(0, self.devices_handlers[device.id].disable)
        return device

    def reenable_device(self, device):
        log.info('reenable-device', device_id=device.id)
        reactor.callLater(0, self.devices_handlers[device.id].reenable)
        return device

    def reboot_device(self, device):
        log.info('rebooting', device_id=device.id)
        reactor.callLater(0, self.devices_handlers[device.id].reboot)
        return device

    def delete_device(self, device):
        log.info('delete-device', device_id=device.id)
        reactor.callLater(0, self.devices_handlers[device.id].delete)
        return device

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.info('receive-proxied-message', proxy_address=proxy_address,
                 device_id=proxy_address.device_id, msg=msg)
        handler = self.devices_handlers[proxy_address.device_id]
        handler.receive_message(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()


class PonSimOnuHandler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue()
        self.proxy_address = None
        # reference of uni_port is required when re-enabling the device if
        # it was disabled previously
        self.uni_port = None
        self.pon_port = None

    def receive_message(self, msg):
        self.incoming_messages.put(msg)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # populate device info
        device.root = True
        device.vendor = 'ponsim'
        device.model = 'n/a'
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # register physical ports
        self.uni_port = Port(
            port_no=2,
            label='UNI facing Ethernet port',
            type=Port.ETHERNET_UNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.pon_port = Port(
            port_no=1,
            label='PON port',
            type=Port.PON_ONU,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE,
            peers=[
                Port.PeerPort(
                    device_id=device.parent_id,
                    port_no=device.parent_port_no
                )
            ]
        )
        self.adapter_agent.add_port(device.id, self.uni_port)
        self.adapter_agent.add_port(device.id, self.pon_port)

        # add uni port to logical device
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
            id='uni-{}'.format(port_no),
            ofp_port=ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name='uni-{}'.format(port_no),
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=device.id,
            device_port_no=self.uni_port.port_no
        ))

        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

    @inlineCallbacks
    def update_flow_table(self, flows):

        # we need to proxy through the OLT to get to the ONU

        # reset response queue
        while self.incoming_messages.pending:
            yield self.incoming_messages.get()

        msg = FlowTable(
            port=self.proxy_address.channel_id,
            flows=flows
        )
        self.adapter_agent.send_proxied_message(self.proxy_address, msg)

        yield self.incoming_messages.get()

    @inlineCallbacks
    def reboot(self):
        self.log.info('rebooting', device_id=self.device_id)

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE
        device = self.adapter_agent.get_device(self.device_id)
        previous_oper_status = device.oper_status
        previous_conn_status = device.connect_status
        device.oper_status = OperStatus.ACTIVATING
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Sleep 10 secs, simulating a reboot
        # TODO: send alert and clear alert after the reboot
        yield asleep(10)

        # Change the operational status back to its previous state.  With a
        # real OLT the operational state should be the state the device is
        # after a reboot.
        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)
        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        self.adapter_agent.update_device(device)
        self.log.info('rebooted', device_id=self.device_id)

    def disable(self):
        self.log.info('disabling', device_id=self.device_id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        # Update the device operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the uni logical port from the OLT, if still present
        parent_device = self.adapter_agent.get_device(device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
        port_id = 'uni-{}'.format(port_no)
        try:
            port = self.adapter_agent.get_logical_port(logical_device_id,
                                                       port_id)
            self.adapter_agent.delete_logical_port(logical_device_id, port)
        except KeyError:
            self.log.info('logical-port-not-found', device_id=self.device_id,
                          portid=port_id)

        # Remove pon port from parent
        self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                             self.pon_port)

        # Just updating the port status may be an option as well
        # port.ofp_port.config = OFPPC_NO_RECV
        # yield self.adapter_agent.update_logical_port(logical_device_id,
        #                                             port)
        # Unregister for proxied message
        self.adapter_agent.unregister_for_proxied_messages(
            device.proxy_address)

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('disabled', device_id=device.id)

    def reenable(self):
        self.log.info('re-enabling', device_id=self.device_id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # First we verify that we got parent reference and proxy info
        assert self.uni_port
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # Re-register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # Re-enable the ports on that device
        self.adapter_agent.enable_all_ports(self.device_id)

        # Add the pon port reference to the parent
        self.adapter_agent.add_port_reference_to_parent(device.id,
                                                        self.pon_port)

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # re-add uni port to logical device
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
            id='uni-{}'.format(port_no),
            ofp_port=ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name='uni-{}'.format(port_no),
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=device.id,
            device_port_no=self.uni_port.port_no
        ))

        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        self.log.info('re-enabled', device_id=device.id)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        # A delete request may be received when an OLT is dsiabled

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('deleted', device_id=self.device_id)
