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
from common.utils.asleep import asleep

from voltha.adapters.iadapter import IAdapter
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, ConnectStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD
from voltha.protos.openflow_13_pb2 import ofp_port
from voltha.protos.ponsim_pb2 import FlowTable

_ = third_party
log = structlog.get_logger()


class PonSimOnuAdapter(IAdapter):
    def __init__(self, adapter_agent, config):
        super(PonSimOnuAdapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class = PonSimOnuHandler,
                                               name='ponsim_onu',
                                               vendor='Voltha project',
                                               version='0.4')

    def get_device_details(self, device):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.info('receive-proxied-message', proxy_address=proxy_address,
                 device_id=proxy_address.device_id, msg=msg)
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.receive_message(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

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

    def _get_uni_port(self):
        ports = self.adapter_agent.get_ports(self.device_id, Port.ETHERNET_UNI)
        if ports:
            # For now, we use on one uni port
            return ports[0]

    def _get_pon_port(self):
        ports = self.adapter_agent.get_ports(self.device_id, Port.PON_ONU)
        if ports:
            # For now, we use on one uni port
            return ports[0]

    def reconcile(self, device):
        self.log.info('reconciling-ONU-device-starts')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # Set the connection status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # TODO: Verify that the uni, pon and logical ports exists

        # Mark the device as REACHABLE and ACTIVE
        device = self.adapter_agent.get_device(device.id)
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        self.log.info('reconciling-ONU-device-ends')

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
        self.pon_port = self._get_pon_port()
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
        try:
            # Get the latest device reference
            device = self.adapter_agent.get_device(self.device_id)

            # First we verify that we got parent reference and proxy info
            assert device.parent_id
            assert device.proxy_address.device_id
            assert device.proxy_address.channel_id

            # Re-register for proxied messages right away
            self.proxy_address = device.proxy_address
            self.adapter_agent.register_for_proxied_messages(
                device.proxy_address)

            # Re-enable the ports on that device
            self.adapter_agent.enable_all_ports(self.device_id)

            # Refresh the port reference
            self.uni_port = self._get_uni_port()
            self.pon_port = self._get_pon_port()

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
        except Exception, e:
            self.log.exception('error-reenabling', e=e)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        # A delete request may be received when an OLT is dsiabled

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('deleted', device_id=self.device_id)
