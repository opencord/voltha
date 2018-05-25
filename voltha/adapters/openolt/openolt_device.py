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
import collections
import time

from twisted.internet import reactor
from scapy.layers.l2 import Ether, Dot1Q
import binascii
from transitions import Machine

from voltha.protos.device_pb2 import Port, Device
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPS_LINK_DOWN, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, ofp_switch_features, ofp_port
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.registry import registry
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_base_pb2 import VEnetConfig
import voltha.core.flow_decomposer as fd

import openolt_platform as platform
from openolt_flow_mgr import OpenOltFlowMgr

MAX_HEARTBEAT_MISS = 3
HEARTBEAT_PERIOD = 1
GRPC_TIMEOUT = 5

"""
OpenoltDevice represents an OLT.
"""
class OpenoltDevice(object):

    states = ['up', 'down']
    transitions = [
            { 'trigger': 'olt_up', 'source': 'down', 'dest': 'up', 'before': 'olt_indication_up' },
            { 'trigger': 'olt_down', 'source': 'up', 'dest': 'down', 'before': 'olt_indication_down' }
    ]

    def __init__(self, **kwargs):
        super(OpenoltDevice, self).__init__()

        self.adapter_agent = kwargs['adapter_agent']
        self.device_num = kwargs['device_num']
        device = kwargs['device']
        self.device_id = device.id
        self.host_and_port = device.host_and_port
        self.log = structlog.get_logger(id=self.device_id, ip=self.host_and_port)
        self.nni_oper_state = dict() #intf_id -> oper_state
        self.proxy = registry('core').get_proxy('/')

        # Update device
        device.root = True
        device.serial_number = self.host_and_port # FIXME
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

        # Initialize the OLT state machine
        self.machine = Machine(model=self, states=OpenoltDevice.states,
                transitions=OpenoltDevice.transitions,
                send_event=True, initial='down', ignore_invalid_triggers=True)
        self.machine.add_transition(trigger='olt_ind_up', source='down', dest='up')
        self.machine.add_transition(trigger='olt_ind_loss', source='up', dest='down')

        # Initialize gRPC
        self.channel = grpc.insecure_channel(self.host_and_port)
        self.channel_ready_future = grpc.channel_ready_future(self.channel)
        self.channel_ready_future.result()  # blocks till gRPC connection is complete
        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

        self.flow_mgr = OpenOltFlowMgr(self.log, self.stub)

        # Start indications thread
        self.indications_thread = threading.Thread(target=self.process_indications)
        self.indications_thread.setDaemon(True)
        self.indications_thread_active = True
        self.indications_thread.start()

        # Start heartbeat thread
        self.heartbeat_thread = threading.Thread(target=self.heartbeat)
        self.heartbeat_thread.setDaemon(True)
        self.heartbeat_thread_active = True
        self.heartbeat_miss = 0
        self.heartbeat_signature = None
        self.heartbeat_thread.start()

    def process_indications(self):

        self.log.debug('starting-indications-thread')

        self.indications = self.stub.EnableIndication(openolt_pb2.Empty())

        while self.indications_thread_active:
            try:
                # get the next indication from olt
                ind = next(self.indications)
            except Exception as e:
                self.log.warn('GRPC-connection-lost-stoping-indications-thread', error=e)
                self.indications_thread_active = False
            else:
                self.log.debug("rx indication", indication=ind)

                # indication handlers run in the main event loop
                if ind.HasField('olt_ind'):
                    reactor.callFromThread(self.olt_indication, ind.olt_ind)
                elif ind.HasField('intf_ind'):
                    reactor.callFromThread(self.intf_indication, ind.intf_ind)
                elif ind.HasField('intf_oper_ind'):
                    reactor.callFromThread(self.intf_oper_indication, ind.intf_oper_ind)
                elif ind.HasField('onu_disc_ind'):
                    reactor.callFromThread(self.onu_discovery_indication, ind.onu_disc_ind)
                elif ind.HasField('onu_ind'):
                    reactor.callFromThread(self.onu_indication, ind.onu_ind)
                elif ind.HasField('omci_ind'):
                    reactor.callFromThread(self.omci_indication, ind.omci_ind)
                elif ind.HasField('pkt_ind'):
                    reactor.callFromThread(self.packet_indication, ind.pkt_ind)

        self.log.debug('stopping-indications-thread', device_id=self.device_id)

    def olt_indication(self, olt_indication):
        if olt_indication.oper_state == "up":
            self.olt_up(ind=olt_indication)
        elif olt_indication.oper_state == "down":
            self.olt_down(ind=olt_indication)

    def olt_indication_up(self, event):
        olt_indication = event.kwargs.get('ind', None)
        self.log.debug("olt indication", olt_ind=olt_indication)

        device = self.adapter_agent.get_device(self.device_id)

        # If logical device does not exist create it
        if len(device.parent_id) == 0:

            dpid = '00:00:' + self.ip_hex(self.host_and_port.split(":")[0])

            # Create logical OF device
            ld = LogicalDevice(
                root_device_id=self.device_id,
                switch_features=ofp_switch_features(
                    n_buffers=256,  # TODO fake for now
                    n_tables=2,  # TODO ditto
                    capabilities=(  # TODO and ditto
                        OFPC_FLOW_STATS
                        | OFPC_TABLE_STATS
                        | OFPC_PORT_STATS
                        | OFPC_GROUP_STATS
                    )
                )
            )
            ld_initialized = self.adapter_agent.create_logical_device(ld, dpid=dpid)
            self.logical_device_id = ld_initialized.id

        # Update phys OF device
        device.parent_id = self.logical_device_id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

    def olt_indication_down(self, event):
        olt_indication = event.kwargs.get('ind', None)
        new_admin_state = event.kwargs.get('admin_state', None)
        new_oper_state = event.kwargs.get('oper_state', None)
        new_connect_state = event.kwargs.get('connect_state', None)
        self.log.debug("olt indication", olt_ind=olt_indication, admin_state=new_admin_state, oper_state=new_oper_state,
                       connect_state=new_connect_state)

        device = self.adapter_agent.get_device(self.device_id)
        if new_admin_state is not  None:
            device.admin_state = new_admin_state
        if new_oper_state is not None:
            device.oper_status = new_oper_state
        if new_connect_state is not None:
            device.connect_status = new_connect_state

        self.adapter_agent.update_device(device)
        #Propagating to the children
        self.adapter_agent.update_child_devices_state(self.device_id, oper_status=new_oper_state,
                                              connect_status=ConnectStatus.UNREACHABLE, admin_state=new_admin_state)

        child_devices = self.adapter_agent.get_child_devices(self.device_id)
        for onu_device in child_devices:
            uni_no = platform.mk_uni_port_num(onu_device.proxy_address.channel_id, onu_device.proxy_address.onu_id)
            uni_name = self.port_name(uni_no, Port.ETHERNET_UNI, serial_number=onu_device.serial_number)

            self.onu_ports_down(onu_device, uni_no, uni_name, new_oper_state)


    def intf_indication(self, intf_indication):
        self.log.debug("intf indication", intf_id=intf_indication.intf_id,
            oper_state=intf_indication.oper_state)

        if intf_indication.oper_state == "up":
            oper_status = OperStatus.ACTIVE
        else:
            oper_status = OperStatus.DISCOVERED

        # add_port update the port if it exists
        self.add_port(intf_indication.intf_id, Port.PON_OLT, oper_status)

    def intf_oper_indication(self, intf_oper_indication):
        self.log.debug("Received interface oper state change indication", intf_id=intf_oper_indication.intf_id,
            type=intf_oper_indication.type, oper_state=intf_oper_indication.oper_state)

        if intf_oper_indication.oper_state == "up":
            oper_state = OperStatus.ACTIVE
        else:
            oper_state = OperStatus.DISCOVERED

        if intf_oper_indication.type == "nni":

            # FIXME - creating logical port for 2nd interface throws exception!
            if intf_oper_indication.intf_id != 0:
                return

            if intf_oper_indication.intf_id not in self.nni_oper_state:
                self.nni_oper_state[intf_oper_indication.intf_id] = oper_state
                port_no, label = self.add_port(intf_oper_indication.intf_id, Port.ETHERNET_NNI, oper_state)
                self.log.debug("int_oper_indication", port_no=port_no, label=label)
                self.add_logical_port(port_no, intf_oper_indication.intf_id) # FIXME - add oper_state
            elif intf_oper_indication.intf_id != self.nni_oper_state:
                # FIXME - handle subsequent NNI oper state change
                pass

        elif intf_oper_indication.type == "pon":
            # FIXME - handle PON oper state change
            pass

    def onu_discovery_indication(self, onu_disc_indication):
        intf_id = onu_disc_indication.intf_id
        serial_number=onu_disc_indication.serial_number

        serial_number_str = self.stringify_serial_number(serial_number)

        self.log.debug("onu discovery indication", intf_id=intf_id, serial_number=serial_number_str)

        onu_device = self.adapter_agent.get_child_device(self.device_id, serial_number=serial_number_str)

        if onu_device is None:
            onu_id = self.new_onu_id(intf_id)
            try:
                self.add_onu_device(intf_id,
                        platform.intf_id_to_port_no(intf_id, Port.PON_OLT),
                        onu_id, serial_number)
                self.log.info("activate-onu", intf_id=intf_id, onu_id=onu_id,
                        serial_number=serial_number_str)
                onu = openolt_pb2.Onu(intf_id=intf_id, onu_id=onu_id,serial_number=serial_number)
                self.stub.ActivateOnu(onu)
            except Exception as e:
                self.log.exception('onu-activation-failed', e=e)

        else:
            if onu_device.connect_status != ConnectStatus.REACHABLE:
                    onu_device.connect_status = ConnectStatus.REACHABLE
                    self.adapter_agent.update_device(onu_device)

            onu_id = onu_device.proxy_address.onu_id
            if onu_device.oper_status == OperStatus.DISCOVERED or onu_device.oper_status == OperStatus.ACTIVATING:
                self.log.debug("ignore onu discovery indication, the onu has been discovered and should be \
                              activating shorlty", intf_id=intf_id, onu_id=onu_id, state=onu_device.oper_status)
            elif onu_device.oper_status== OperStatus.ACTIVE:
                self.log.warn("onu discovery indication whereas onu is supposed to be active",
                              intf_id=intf_id, onu_id=onu_id, state=onu_device.oper_status)
            elif onu_device.oper_status == OperStatus.UNKNOWN:
                self.log.info("onu-in-unknow-state-recovering-form-olt-reboot-activate-onu", intf_id=intf_id, onu_id=onu_id,
                              serial_number=serial_number_str)

                onu_device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(onu_device)

                onu = openolt_pb2.Onu(intf_id=intf_id, onu_id=onu_id, serial_number=serial_number)
                self.stub.ActivateOnu(onu)
            else:
                self.log.warn('unexpected state', onu_id=onu_id, onu_device_oper_state=onu_device.oper_status)

    def onu_indication(self, onu_indication):
        self.log.debug("onu-indication", intf_id=onu_indication.intf_id,
                onu_id=onu_indication.onu_id, serial_number=onu_indication.serial_number,
                    oper_state=onu_indication.oper_state, admin_state=onu_indication.admin_state)

        serial_number_str = self.stringify_serial_number(onu_indication.serial_number)

        if serial_number_str == '000000000000':
            self.log.debug('serial-number-was-not-provided-or-default-serial-number-provided-identifying-onu-by-onu_id')
            #FIXME: if multiple PON ports onu_id is not a sufficient key
            onu_device = self.adapter_agent.get_child_device(
                self.device_id,
                onu_id=onu_indication.onu_id)
        else :
            onu_device = self.adapter_agent.get_child_device(
                self.device_id,
                serial_number=serial_number_str)

        self.log.debug('onu-device', olt_device_id=self.device_id, device=onu_device)

        # FIXME - handle serial_number mismatch
        # assert key is not None
        # assert onu_device is not None
        if onu_device is None:
            self.log.warn('onu-device-is-none-invalid-message')
            return

        if onu_device.connect_status != ConnectStatus.REACHABLE:
            onu_device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(onu_device)

        if platform.intf_id_from_pon_port_no(onu_device.parent_port_no) != onu_indication.intf_id:
            self.log.warn('ONU-is-on-a-different-intf-id-now',
                          previous_intf_id=platform.intf_id_from_pon_port_no(onu_device.parent_port_no),
                          current_intf_id=onu_indication.intf_id)
            # FIXME - handle intf_id mismatch (ONU move?)


        if onu_device.proxy_address.onu_id != onu_indication.onu_id:
            # FIXME - handle onu id mismatch
            self.log.warn('ONU-id-mismatch', expected_onu_id=onu_device.proxy_address.onu_id,
                          received_onu_id=onu_indication.onu_id)

        uni_no = platform.mk_uni_port_num(onu_indication.intf_id, onu_indication.onu_id)
        uni_name = self.port_name(uni_no, Port.ETHERNET_UNI, serial_number=serial_number_str)

        self.log.debug('port-number-ready', uni_no=uni_no, uni_name=uni_name)

        #Admin state
        if onu_indication.admin_state == 'down':
            if onu_indication.oper_state != 'down':
                self.log.error('ONU-admin-state-down-and-oper-status-not-down', oper_state=onu_indication.oper_state)
                onu_indication.oper_state = 'down' # Forcing the oper state change code to execute

            if onu_device.admin_state != AdminState.DISABLED:
                onu_device.admin_state = AdminState.DISABLED
                self.adapter_agent.update(onu_device)
                self.log.debug('putting-onu-in-disabled-state', onu_serial_number=onu_device.serial_number)

            #Port and logical port update is taken care of by oper state block

        elif onu_indication.admin_state == 'up':
            if onu_device.admin_state != AdminState.ENABLED:
                onu_device.admin_state = AdminState.ENABLED
                self.adapter_agent.update(onu_device)
                self.log.debug('putting-onu-in-enabled-state', onu_serial_number=onu_device.serial_number)

        else:
            self.log.warn('Invalid-or-not-implemented-admin-state', received_admin_state=onu_indication.admin_state)

        self.log.debug('admin-state-dealt-with')

        #Operating state
        if onu_indication.oper_state == 'down':
            #Move to discovered state
            self.log.debug('onu-oper-state-is-down')

            if onu_device.oper_status != OperStatus.DISCOVERED:
                onu_device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(onu_device)
            #Set port oper state to Discovered

            self.onu_ports_down(onu_device, uni_no, uni_name, OperStatus.DISCOVERED)

        elif onu_indication.oper_state == 'up':

            if onu_device.oper_status != OperStatus.DISCOVERED:
                self.log.debug("ignore onu indication", intf_id=onu_indication.intf_id,
                               onu_id=onu_indication.onu_id, state=onu_device.oper_status,
                               msg_oper_state=onu_indication.oper_state)
                return

            #Device was in Discovered state, setting it to active



            onu_adapter_agent = registry('adapter_loader').get_agent(onu_device.adapter)
            if onu_adapter_agent is None:
                self.log.error('onu_adapter_agent-could-not-be-retrieved', onu_device=onu_device)
                return

            #Prepare onu configuration

            # onu initialization, base configuration (bridge setup ...)
            def onu_initialization():

                #FIXME: that's definitely cheating
                if onu_device.adapter == 'broadcom_onu':
                    onu_adapter_agent.adapter.devices_handlers[onu_device.id].message_exchange()
                    self.log.debug('broadcom-message-exchange-started')

            # tcont creation (onu)
            tcont = TcontsConfigData()
            tcont.alloc_id = platform.mk_alloc_id(onu_indication.onu_id)

            # gem port creation
            gem_port = GemportsConfigData()
            gem_port.gemport_id = platform.mk_gemport_id(onu_indication.onu_id)

            #ports creation/update
            def port_config():

                # "v_enet" creation (olt)

                #add_port update port when it exists
                self.adapter_agent.add_port(
                    self.device_id,
                    Port(
                        port_no=uni_no,
                        label=uni_name,
                        type=Port.ETHERNET_UNI,
                        admin_state=AdminState.ENABLED,
                        oper_status=OperStatus.ACTIVE))

                # v_enet creation (onu)

                venet = VEnetConfig(name=uni_name)
                venet.interface.name = uni_name
                onu_adapter_agent.create_interface(onu_device, venet)

            # ONU device status update in the datastore
            def onu_update_oper_status():
                onu_device.oper_status = OperStatus.ACTIVE
                onu_device.connect_status = ConnectStatus.REACHABLE
                self.adapter_agent.update_device(onu_device)

            # FIXME : the asynchronicity has to be taken care of properly
            onu_initialization()
            reactor.callLater(10, onu_adapter_agent.create_tcont, device=onu_device,
                                                            tcont_data=tcont, traffic_descriptor_data=None)
            reactor.callLater(11, onu_adapter_agent.create_gemport, onu_device, gem_port)
            reactor.callLater(12, port_config)
            reactor.callLater(12, onu_update_oper_status)

        else:
            self.log.warn('Not-implemented-or-invalid-value-of-oper-state', oper_state=onu_indication.oper_state)

    def onu_ports_down(self, onu_device, uni_no, uni_name, oper_state):
        # Set port oper state to Discovered
        # add port will update port if it exists
        self.adapter_agent.add_port(
            self.device_id,
            Port(
                port_no=uni_no,
                label=uni_name,
                type=Port.ETHERNET_UNI,
                admin_state=onu_device.admin_state,
                oper_status=oper_state))

        # Disable logical port
        openolt_device = self.adapter_agent.get_device(self.device_id)
        onu_ports = self.proxy.get('devices/{}/ports'.format(onu_device.id))
        onu_port_id = None
        for onu_port in onu_ports:
            if onu_port.port_no == uni_no:
                onu_port_id = onu_port.label
        if onu_port_id is None:
            self.log.error('matching-onu-port-label-not-found', onu_id=onu_device.id, olt_id=self.device_id,
                           onu_ports=onu_ports)
            return
        try:
            onu_logical_port = self.adapter_agent.get_logical_port(logical_device_id=openolt_device.parent_id,
                                                                   port_id=onu_port_id)
            onu_logical_port.ofp_port.state = OFPPS_LINK_DOWN
            self.adapter_agent.update_logical_port(logical_device_id=openolt_device.parent_id, port=onu_logical_port)
            self.log.debug('cascading-oper-state-to-port-and-logical-port')
        except KeyError as e:
            self.log.error('matching-onu-port-label-invalid', onu_id=onu_device.id, olt_id=self.device_id,
                           onu_ports=onu_ports, onu_port_id=onu_port_id, error=e)

    def omci_indication(self, omci_indication):

        self.log.debug("omci indication", intf_id=omci_indication.intf_id,
                onu_id=omci_indication.onu_id)

        onu_device = self.adapter_agent.get_child_device(self.device_id,
                onu_id=omci_indication.onu_id)

        self.adapter_agent.receive_proxied_message(onu_device.proxy_address,
                omci_indication.pkt)

    def packet_indication(self, pkt_indication):

        self.log.debug("packet indication", intf_id=pkt_indication.intf_id,
                gemport_id=pkt_indication.gemport_id,
                flow_id=pkt_indication.flow_id)

        onu_id = platform.onu_id_from_gemport_id(pkt_indication.gemport_id)
        logical_port_num = platform.mk_uni_port_num(pkt_indication.intf_id, onu_id)

        pkt = Ether(pkt_indication.pkt)
        kw = dict(logical_device_id=self.logical_device_id,
                logical_port_no=logical_port_num)
        self.adapter_agent.send_packet_in(packet=str(pkt), **kw)

    def olt_reachable(self):
        device = self.adapter_agent.get_device(self.device_id)
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)
        # Not changing its child devices state, we cannot guaranty that

    def heartbeat(self):

        while self.heartbeat_thread_active:

            try:
                heartbeat = self.stub.HeartbeatCheck(openolt_pb2.Empty(), timeout=GRPC_TIMEOUT)
            except Exception as e:
                self.heartbeat_miss += 1
                self.log.warn('heartbeat-miss', missed_heartbeat=self.heartbeat_miss, error=e)
                if self.heartbeat_miss == MAX_HEARTBEAT_MISS:
                    self.log.error('lost-connectivity-to-olt')
                    #TODO : send alarm/notify monitoring system
                    # Using reactor to synchronize update
                    # flagging it as unreachable and in unknow state
                    reactor.callLater(0, self.olt_down, oper_state=OperStatus.UNKNOWN,
                                      connect_state=ConnectStatus.UNREACHABLE)

            else:
                # heartbeat received
                if self.heartbeat_signature is None:
                    # Initialize heartbeat signature
                    self.heartbeat_signature = heartbeat.heartbeat_signature
                    self.log.debug('heartbeat-signature', device_id=self.device_id,
                                   heartbeat_signature=self.heartbeat_signature)
                # Check if signature is different
                if self.heartbeat_signature != heartbeat.heartbeat_signature:
                    # OLT has rebooted
                    self.log.warn('OLT-was-rebooted', device_id=self.device_id)
                    #TODO: notify monitoring system
                    self.heartbeat_signature = heartbeat.heartbeat_signature

                else:
                    self.log.debug('valid-heartbeat-received')

                if self.heartbeat_miss > MAX_HEARTBEAT_MISS:
                    self.log.info('OLT-connection-restored')
                    #TODO : suppress alarm/notify monitoring system
                    # flagging it as reachable again
                    reactor.callLater(0, self.olt_reachable)

                if not self.indications_thread_active:
                    self.log.info('restarting-indications-thread')
                    # reset indications thread
                    self.indications_thread = threading.Thread(target=self.process_indications)
                    self.indications_thread.setDaemon(True)
                    self.indications_thread_active = True
                    self.indications_thread.start()

                self.heartbeat_miss = 0

            time.sleep(HEARTBEAT_PERIOD)

        self.log.debug('stopping-heartbeat-thread', device_id=self.device_id)



    def packet_out(self, egress_port, msg):
        pkt = Ether(msg)
        self.log.info('packet out', egress_port=egress_port,
                packet=str(pkt).encode("HEX"))

        if pkt.haslayer(Dot1Q):
            outer_shim = pkt.getlayer(Dot1Q)
            if isinstance(outer_shim.payload, Dot1Q):
                #If double tag, remove the outer tag
                payload = (
                    Ether(src=pkt.src, dst=pkt.dst, type=outer_shim.type) /
                    outer_shim.payload
                )
            else:
                payload = pkt
        else:
            payload = pkt

        self.log.info('sending-packet-to-device', egress_port=egress_port,
                packet=str(payload).encode("HEX"))

        send_pkt = binascii.unhexlify(str(payload).encode("HEX"))

        onu_pkt = openolt_pb2.OnuPacket(intf_id=platform.intf_id_from_pon_port_no(egress_port),
                onu_id=platform.onu_id_from_port_num(egress_port), pkt=send_pkt)

        self.stub.OnuPacketOut(onu_pkt)

    def send_proxied_message(self, proxy_address, msg):
        omci = openolt_pb2.OmciMsg(intf_id=proxy_address.channel_id, # intf_id
                onu_id=proxy_address.onu_id, pkt=str(msg))
        self.stub.OmciMsgOut(omci)

    def add_onu_device(self, intf_id, port_no, onu_id, serial_number):
        self.log.info("Adding ONU", port_no=port_no, onu_id=onu_id,
                serial_number=serial_number)

        # NOTE - channel_id of onu is set to intf_id
        proxy_address = Device.ProxyAddress(device_id=self.device_id,
                channel_id=intf_id, onu_id=onu_id, onu_session_id=onu_id)

        self.log.info("Adding ONU", proxy_address=proxy_address)

        serial_number_str = self.stringify_serial_number(serial_number)

        self.adapter_agent.add_onu_device(parent_device_id=self.device_id,
                parent_port_no=port_no, vendor_id=serial_number.vendor_id,
                proxy_address=proxy_address, root=True,
                serial_number=serial_number_str, admin_state=AdminState.ENABLED)

    def port_name(self, port_no, port_type, intf_id=None, serial_number=None):
        if port_type is Port.ETHERNET_NNI:
            return "nni-" + str(port_no)
        elif port_type is Port.PON_OLT:
            return "pon" + str(intf_id)
        elif port_type is Port.ETHERNET_UNI:
            if serial_number is not None:
                return serial_number
            else:
                return "uni-{}".format(port_no)

    def add_logical_port(self, port_no, intf_id):
        self.log.info('adding-logical-port', port_no=port_no)

        label = self.port_name(port_no, Port.ETHERNET_NNI)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        curr_speed = OFPPF_1GB_FD
        max_speed = OFPPF_1GB_FD

        ofp = ofp_port(port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name=label, config=0, state=OFPPS_LIVE, curr=cap,
                advertised=cap, peer=cap, curr_speed=curr_speed,
                max_speed=max_speed)

        logical_port = LogicalPort(id=label, ofp_port=ofp,
                device_id=self.device_id, device_port_no=port_no,
                root_port=True)

        self.adapter_agent.add_logical_port(self.logical_device_id, logical_port)

    def add_port(self, intf_id, port_type, oper_status):
        port_no = platform.intf_id_to_port_no(intf_id, port_type)

        label = self.port_name(port_no, port_type, intf_id)

        self.log.info('adding-port', port_no=port_no, label=label,
                port_type=port_type)

        port = Port(port_no=port_no, label=label, type=port_type,
            admin_state=AdminState.ENABLED, oper_status=oper_status)

        self.adapter_agent.add_port(self.device_id, port)

        return port_no, label

    def new_onu_id(self, intf_id):
        onu_id = None
        onu_devices = self.adapter_agent.get_child_devices(self.device_id)
        for i in range(1, 512):
            id_not_taken = True
            for child_device in onu_devices:
                if child_device.proxy_address.onu_id == i:
                    id_not_taken = False
                    break
            if id_not_taken:
                onu_id = i
                break
        return onu_id

    def stringify_vendor_specific(self, vendor_specific):
        return ''.join(str(i) for i in [
                hex(ord(vendor_specific[0])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[0]) & 0x0f)[2:],
                hex(ord(vendor_specific[1])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[1]) & 0x0f)[2:],
                hex(ord(vendor_specific[2])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[2]) & 0x0f)[2:],
                hex(ord(vendor_specific[3])>>4 & 0x0f)[2:],
                hex(ord(vendor_specific[3]) & 0x0f)[2:]])


    def update_flow_table(self, flows):
        device = self.adapter_agent.get_device(self.device_id)
        self.log.debug('update flow table')
        in_port = None

        for flow in flows:
            is_down_stream = None
            in_port = fd.get_in_port(flow)
            assert in_port is not None
            # Right now there is only one NNI port. Get the NNI PORT and compare
            # with IN_PUT port number. Need to find better way.
            ports = self.adapter_agent.get_ports(device.id, Port.ETHERNET_NNI)

            for port in ports:
                if (port.port_no == in_port):
                    self.log.info('downstream-flow')
                    is_down_stream = True
                    break
            if is_down_stream is None:
                is_down_stream = False
                self.log.info('upstream-flow')

            for flow in flows:
                try:
                    self.flow_mgr.add_flow(flow, is_down_stream)
                except Exception as e:
                    self.log.exception('failed-to-install-flow', e=e, flow=flow)

    # There has to be a better way to do this
    def ip_hex(self, ip):
        octets = ip.split(".")
        hex_ip = []
        for octet in octets:
            octet_hex = hex(int(octet))
            octet_hex = octet_hex.split('0x')[1]
            octet_hex = octet_hex.rjust(2, '0')
            hex_ip.append(octet_hex)
        return ":".join(hex_ip)

    def stringify_serial_number(self, serial_number):
        return ''.join([serial_number.vendor_id,
                                     self.stringify_vendor_specific(serial_number.vendor_specific)])
