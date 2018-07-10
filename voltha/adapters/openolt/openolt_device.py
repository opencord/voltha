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

import threading
import binascii
import grpc

import structlog
from twisted.internet import reactor
from scapy.layers.l2 import Ether, Dot1Q
from transitions import Machine, State

from voltha.protos.device_pb2 import Port, Device
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPS_LINK_DOWN, OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, \
    OFPC_TABLE_STATS, OFPC_FLOW_STATS, ofp_switch_features, ofp_port, \
    ofp_port_stats, ofp_desc
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.registry import registry
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_base_pb2 import VEnetConfig
import voltha.core.flow_decomposer as fd

from voltha.adapters.openolt.openolt_statistics import OpenOltStatisticsMgr
import voltha.adapters.openolt.openolt_platform as platform
from voltha.adapters.openolt.openolt_flow_mgr import OpenOltFlowMgr, \
        DEFAULT_MGMT_VLAN
from voltha.adapters.openolt.openolt_alarms import OpenOltAlarmMgr


class OpenoltDevice(object):
    """
    OpenoltDevice state machine:

        null ----> init ------> connected -----> up -----> down
                   ^ ^             |             ^         | |
                   | |             |             |         | |
                   | +-------------+             +---------+ |
                   |                                         |
                   +-----------------------------------------+
    """
    # pylint: disable=too-many-instance-attributes
    # pylint: disable=R0904
    states = [
        'state_null',
        'state_init',
        'state_connected',
        'state_up',
        'state_down']

    transitions = [
         {'trigger': 'go_state_init',
          'source': ['state_null', 'state_connected', 'state_down'],
          'dest': 'state_init',
          'before': 'do_state_init'},
         {'trigger': 'go_state_connected',
          'source': 'state_init',
          'dest': 'state_connected',
          'before': 'do_state_connected'},
         {'trigger': 'go_state_up',
          'source': ['state_connected', 'state_down'],
          'dest': 'state_up',
          'before': 'do_state_up'},
         {'trigger': 'go_state_down',
          'source': ['state_up'],
          'dest': 'state_down',
          'before': 'do_state_down'}]

    def __init__(self, **kwargs):
        super(OpenoltDevice, self).__init__()

        self.adapter_agent = kwargs['adapter_agent']
        self.device_num = kwargs['device_num']
        device = kwargs['device']
        is_reconciliation = kwargs.get('reconciliation', False)
        self.device_id = device.id
        self.host_and_port = device.host_and_port
        self.log = structlog.get_logger(id=self.device_id,
                                        ip=self.host_and_port)
        self.proxy = registry('core').get_proxy('/')

        # Device already set in the event of reconciliation
        if not is_reconciliation:
            # It is a new device
            # Update device
            device.root = True
            device.serial_number = self.host_and_port  # FIXME
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.ACTIVATING
            self.adapter_agent.update_device(device)

        # If logical device does not exist create it
        if not device.parent_id:

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
                ),
                desc=ofp_desc(
                    serial_num=device.serial_number
                )
            )
            ld_init = self.adapter_agent.create_logical_device(ld,
                                                               dpid=dpid)
            self.logical_device_id = ld_init.id
        else:
            # logical device already exists
            self.logical_device_id = device.parent_id
            if is_reconciliation:
                self.adapter_agent.reconcile_logical_device(
                    self.logical_device_id)

        # Initialize the OLT state machine
        self.machine = Machine(model=self, states=OpenoltDevice.states,
                               transitions=OpenoltDevice.transitions,
                               send_event=True, initial='state_null')
        self.go_state_init()

    def do_state_init(self, event):
        # Initialize gRPC
        self.channel = grpc.insecure_channel(self.host_and_port)
        self.channel_ready_future = grpc.channel_ready_future(self.channel)

        # Start indications thread
        self.indications_thread_handle = threading.Thread(
            target=self.indications_thread)
        self.indications_thread_handle.daemon = True
        self.indications_thread_handle.start()

        '''
        # FIXME - Move to oper_up state without connecting to OLT?
        if is_reconciliation:
            # Put state machine in state up
            reactor.callFromThread(self.go_state_up, reconciliation=True)
        '''

        self.log.debug('openolt-device-created', device_id=self.device_id)

    def do_state_connected(self, event):
        device = self.adapter_agent.get_device(self.device_id)
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)
        self.flow_mgr = OpenOltFlowMgr(self.log, self.stub, self.device_id)
        self.alarm_mgr = OpenOltAlarmMgr(self.log, self.adapter_agent, self.device_id,
                                         self.logical_device_id)
        self.stats_mgr = OpenOltStatisticsMgr(self, self.log)

    def do_state_up(self, event):
        device = self.adapter_agent.get_device(self.device_id)

        # Update phys OF device
        device.parent_id = self.logical_device_id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

    def do_state_down(self, event):
        self.log.debug("do_state_down")
        oper_state = OperStatus.UNKNOWN
        connect_state = ConnectStatus.UNREACHABLE

        # Propagating to the children

        # Children ports
        child_devices = self.adapter_agent.get_child_devices(self.device_id)
        for onu_device in child_devices:
            uni_no = platform.mk_uni_port_num(
                onu_device.proxy_address.channel_id,
                onu_device.proxy_address.onu_id)
            uni_name = self.port_name(uni_no, Port.ETHERNET_UNI,
                                      serial_number=onu_device.serial_number)

            self.onu_ports_down(onu_device, uni_no, uni_name, oper_state)
        # Children devices
        self.adapter_agent.update_child_devices_state(
            self.device_id, oper_status=oper_state,
            connect_status=connect_state)
        # Device Ports
        device_ports = self.adapter_agent.get_ports(self.device_id,
                                                    Port.ETHERNET_NNI)
        logical_ports_ids = [port.label for port in device_ports]
        device_ports += self.adapter_agent.get_ports(self.device_id,
                                                     Port.PON_OLT)

        for port in device_ports:
            port.oper_status = oper_state
            self.adapter_agent.add_port(self.device_id, port)

        # Device logical port
        for logical_port_id in logical_ports_ids:
            logical_port = self.adapter_agent.get_logical_port(
                self.logical_device_id, logical_port_id)
            logical_port.ofp_port.state = OFPPS_LINK_DOWN
            self.adapter_agent.update_logical_port(self.logical_device_id,
                                                   logical_port)

        # Device
        device = self.adapter_agent.get_device(self.device_id)
        device.oper_status = oper_state
        device.connect_status = connect_state

        self.adapter_agent.update_device(device)

    def indications_thread(self):
        self.log.debug('starting-indications-thread')
        self.log.debug('connecting to olt', device_id=self.device_id)
        self.channel_ready_future.result()  # blocking call
        self.log.debug('connected to olt', device_id=self.device_id)
        self.go_state_connected()

        self.indications = self.stub.EnableIndication(openolt_pb2.Empty())

        while True:
            try:
                # get the next indication from olt
                ind = next(self.indications)
            except Exception as e:
                self.log.warn('gRPC connection lost', error=e)
                reactor.callFromThread(self.go_state_down)
                reactor.callFromThread(self.go_state_init)
                break
            else:
                self.log.debug("rx indication", indication=ind)

                # indication handlers run in the main event loop
                if ind.HasField('olt_ind'):
                    reactor.callFromThread(self.olt_indication, ind.olt_ind)
                elif ind.HasField('intf_ind'):
                    reactor.callFromThread(self.intf_indication, ind.intf_ind)
                elif ind.HasField('intf_oper_ind'):
                    reactor.callFromThread(self.intf_oper_indication,
                                           ind.intf_oper_ind)
                elif ind.HasField('onu_disc_ind'):
                    reactor.callFromThread(self.onu_discovery_indication,
                                           ind.onu_disc_ind)
                elif ind.HasField('onu_ind'):
                    reactor.callFromThread(self.onu_indication, ind.onu_ind)
                elif ind.HasField('omci_ind'):
                    reactor.callFromThread(self.omci_indication, ind.omci_ind)
                elif ind.HasField('pkt_ind'):
                    reactor.callFromThread(self.packet_indication, ind.pkt_ind)
                elif ind.HasField('port_stats'):
                    reactor.callFromThread(
                            self.stats_mgr.port_statistics_indication,
                            ind.port_stats)
                elif ind.HasField('flow_stats'):
                    reactor.callFromThread(
                            self.stats_mgr.flow_statistics_indication,
                            ind.flow_stats)
                elif ind.HasField('alarm_ind'):
                    reactor.callFromThread(self.alarm_mgr.process_alarms,
                                           ind.alarm_ind)
                else:
                    self.log.warn('unknown indication type')

    def olt_indication(self, olt_indication):
        if olt_indication.oper_state == "up":
            self.go_state_up()
        elif olt_indication.oper_state == "down":
            self.go_state_down()

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
        self.log.debug("Received interface oper state change indication",
                       intf_id=intf_oper_indication.intf_id,
                       type=intf_oper_indication.type,
                       oper_state=intf_oper_indication.oper_state)

        if intf_oper_indication.oper_state == "up":
            oper_state = OperStatus.ACTIVE
        else:
            oper_state = OperStatus.DISCOVERED

        if intf_oper_indication.type == "nni":

            # FIXME - creating logical port for 2nd interface throws exception!
            if intf_oper_indication.intf_id != 0:
                return

            # add_(logical_)port update the port if it exists
            port_no, label = self.add_port(intf_oper_indication.intf_id,
                                           Port.ETHERNET_NNI, oper_state)
            self.log.debug("int_oper_indication", port_no=port_no, label=label)
            self.add_logical_port(port_no, intf_oper_indication.intf_id,
                                  oper_state)

        elif intf_oper_indication.type == "pon":
            # FIXME - handle PON oper state change
            pass

    def onu_discovery_indication(self, onu_disc_indication):
        intf_id = onu_disc_indication.intf_id
        serial_number = onu_disc_indication.serial_number

        serial_number_str = self.stringify_serial_number(serial_number)

        self.log.debug("onu discovery indication", intf_id=intf_id,
                       serial_number=serial_number_str)

        onu_device = self.adapter_agent.get_child_device(
            self.device_id,
            serial_number=serial_number_str)

        if onu_device is None:
            onu_id = self.new_onu_id(intf_id)
            try:
                self.add_onu_device(
                    intf_id,
                    platform.intf_id_to_port_no(intf_id, Port.PON_OLT),
                    onu_id, serial_number)
                self.log.info("activate-onu", intf_id=intf_id, onu_id=onu_id,
                              serial_number=serial_number_str)
                onu = openolt_pb2.Onu(intf_id=intf_id, onu_id=onu_id,
                                      serial_number=serial_number)
                self.stub.ActivateOnu(onu)
            except Exception as e:
                self.log.exception('onu-activation-failed', e=e)

        else:
            if onu_device.connect_status != ConnectStatus.REACHABLE:
                    onu_device.connect_status = ConnectStatus.REACHABLE
                    self.adapter_agent.update_device(onu_device)

            onu_id = onu_device.proxy_address.onu_id
            if onu_device.oper_status == OperStatus.DISCOVERED \
               or onu_device.oper_status == OperStatus.ACTIVATING:
                self.log.debug("ignore onu discovery indication, \
                               the onu has been discovered and should be \
                               activating shorlty", intf_id=intf_id,
                               onu_id=onu_id, state=onu_device.oper_status)
            elif onu_device.oper_status == OperStatus.ACTIVE:
                self.log.warn("onu discovery indication whereas onu is \
                              supposed to be active",
                              intf_id=intf_id, onu_id=onu_id,
                              state=onu_device.oper_status)
            elif onu_device.oper_status == OperStatus.UNKNOWN:
                self.log.info("onu in unknown state, recovering from olt \
                              reboot, activate onu", intf_id=intf_id,
                              onu_id=onu_id, serial_number=serial_number_str)

                onu_device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(onu_device)

                onu = openolt_pb2.Onu(intf_id=intf_id, onu_id=onu_id,
                                      serial_number=serial_number)
                self.stub.ActivateOnu(onu)
            else:
                self.log.warn('unexpected state', onu_id=onu_id,
                              onu_device_oper_state=onu_device.oper_status)

    def onu_indication(self, onu_indication):
        self.log.debug("onu indication", intf_id=onu_indication.intf_id,
                       onu_id=onu_indication.onu_id,
                       serial_number=onu_indication.serial_number,
                       oper_state=onu_indication.oper_state,
                       admin_state=onu_indication.admin_state)
        try:
            serial_number_str = self.stringify_serial_number(
                onu_indication.serial_number)
        except Exception as e:
            serial_number_str = None

        if serial_number_str is not None:
            onu_device = self.adapter_agent.get_child_device(
                    self.device_id,
                    serial_number=serial_number_str)
        else:
            onu_device = self.adapter_agent.get_child_device(
                    self.device_id,
                    parent_port_no=platform.intf_id_to_port_no(
                            onu_indication.intf_id, Port.PON_OLT),
                    onu_id=onu_indication.onu_id)

        if onu_device is None:
            self.log.error('onu not found', intf_id=onu_indication.intf_id,
                           onu_id=onu_indication.onu_id)
            return

        if onu_device.connect_status != ConnectStatus.REACHABLE:
            onu_device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(onu_device)

        if platform.intf_id_from_pon_port_no(onu_device.parent_port_no) \
           != onu_indication.intf_id:
            self.log.warn('ONU-is-on-a-different-intf-id-now',
                          previous_intf_id=platform.intf_id_from_pon_port_no(
                              onu_device.parent_port_no),
                          current_intf_id=onu_indication.intf_id)
            # FIXME - handle intf_id mismatch (ONU move?)

        if onu_device.proxy_address.onu_id != onu_indication.onu_id:
            # FIXME - handle onu id mismatch
            self.log.warn('ONU-id-mismatch',
                          expected_onu_id=onu_device.proxy_address.onu_id,
                          received_onu_id=onu_indication.onu_id)

        uni_no = platform.mk_uni_port_num(onu_indication.intf_id,
                                          onu_indication.onu_id)
        uni_name = self.port_name(uni_no, Port.ETHERNET_UNI,
                                  serial_number=onu_device.serial_number)

        self.log.debug('port-number-ready', uni_no=uni_no, uni_name=uni_name)

        # Admin state
        if onu_indication.admin_state == 'down':
            if onu_indication.oper_state != 'down':
                self.log.error('ONU-admin-state-down-and-oper-status-not-down',
                               oper_state=onu_indication.oper_state)
                # Forcing the oper state change code to execute
                onu_indication.oper_state = 'down'

            if onu_device.admin_state != AdminState.DISABLED:
                onu_device.admin_state = AdminState.DISABLED
                self.adapter_agent.update(onu_device)
                self.log.debug('putting-onu-in-disabled-state',
                               onu_serial_number=onu_device.serial_number)

            # Port and logical port update is taken care of by oper state block

        elif onu_indication.admin_state == 'up':
            if onu_device.admin_state != AdminState.ENABLED:
                onu_device.admin_state = AdminState.ENABLED
                self.adapter_agent.update(onu_device)
                self.log.debug('putting-onu-in-enabled-state',
                               onu_serial_number=onu_device.serial_number)

        else:
            self.log.warn('Invalid-or-not-implemented-admin-state',
                          received_admin_state=onu_indication.admin_state)

        self.log.debug('admin-state-dealt-with')

        # Operating state
        if onu_indication.oper_state == 'down':
            # Move to discovered state
            self.log.debug('onu-oper-state-is-down')

            if onu_device.oper_status != OperStatus.DISCOVERED:
                onu_device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(onu_device)
            # Set port oper state to Discovered
            self.onu_ports_down(onu_device, uni_no, uni_name,
                                OperStatus.DISCOVERED)

        elif onu_indication.oper_state == 'up':

            if onu_device.oper_status != OperStatus.DISCOVERED:
                self.log.debug("ignore onu indication",
                               intf_id=onu_indication.intf_id,
                               onu_id=onu_indication.onu_id,
                               state=onu_device.oper_status,
                               msg_oper_state=onu_indication.oper_state)
                return

            # Device was in Discovered state, setting it to active
            onu_adapter_agent = \
                registry('adapter_loader').get_agent(onu_device.adapter)
            if onu_adapter_agent is None:
                self.log.error('onu_adapter_agent-could-not-be-retrieved',
                               onu_device=onu_device)
                return

            # Prepare onu configuration

            # onu initialization, base configuration (bridge setup ...)
            def onu_initialization():

                # FIXME: that's definitely cheating
                if onu_device.adapter == 'broadcom_onu':
                    onu_adapter_agent.adapter.devices_handlers[onu_device.id] \
                            .message_exchange(cvid=DEFAULT_MGMT_VLAN)
                    self.log.debug('broadcom-message-exchange-started')

            # tcont creation (onu)
            tcont = TcontsConfigData()
            tcont.alloc_id = platform.mk_alloc_id(onu_indication.onu_id)

            # gem port creation
            gem_port = GemportsConfigData()
            gem_port.gemport_id = platform.mk_gemport_id(onu_indication.onu_id)

            # ports creation/update
            def port_config():

                # "v_enet" creation (olt)

                # add_port update port when it exists
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
            reactor.callLater(10, onu_adapter_agent.create_tcont,
                              device=onu_device, tcont_data=tcont,
                              traffic_descriptor_data=None)
            reactor.callLater(11, onu_adapter_agent.create_gemport, onu_device,
                              gem_port)
            reactor.callLater(12, port_config)
            reactor.callLater(12, onu_update_oper_status)

        else:
            self.log.warn('Not-implemented-or-invalid-value-of-oper-state',
                          oper_state=onu_indication.oper_state)

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
        onu_ports = self.proxy.get('devices/{}/ports'.format(onu_device.id))
        onu_port_id = None
        for onu_port in onu_ports:
            if onu_port.port_no == uni_no:
                onu_port_id = onu_port.label
        if onu_port_id is None:
            self.log.error('matching-onu-port-label-not-found',
                           onu_id=onu_device.id, olt_id=self.device_id,
                           onu_ports=onu_ports)
            return
        try:
            onu_logical_port = self.adapter_agent.get_logical_port(
                logical_device_id=self.logical_device_id, port_id=onu_port_id)
            onu_logical_port.ofp_port.state = OFPPS_LINK_DOWN
            self.adapter_agent.update_logical_port(
                logical_device_id=self.logical_device_id,
                port=onu_logical_port)
            self.log.debug('cascading-oper-state-to-port-and-logical-port')
        except KeyError as e:
            self.log.error('matching-onu-port-label-invalid',
                           onu_id=onu_device.id, olt_id=self.device_id,
                           onu_ports=onu_ports, onu_port_id=onu_port_id,
                           error=e)

    def omci_indication(self, omci_indication):

        self.log.debug("omci indication", intf_id=omci_indication.intf_id,
                       onu_id=omci_indication.onu_id)

        onu_device = self.adapter_agent.get_child_device(
            self.device_id, onu_id=omci_indication.onu_id)

        self.adapter_agent.receive_proxied_message(onu_device.proxy_address,
                                                   omci_indication.pkt)

    def packet_indication(self, pkt_indication):

        self.log.debug("packet indication", intf_id=pkt_indication.intf_id,
                       gemport_id=pkt_indication.gemport_id,
                       flow_id=pkt_indication.flow_id)

        onu_id = platform.onu_id_from_gemport_id(pkt_indication.gemport_id)
        logical_port_num = platform.mk_uni_port_num(pkt_indication.intf_id,
                                                    onu_id)

        pkt = Ether(pkt_indication.pkt)
        kw = dict(logical_device_id=self.logical_device_id,
                  logical_port_no=logical_port_num)
        self.adapter_agent.send_packet_in(packet=str(pkt), **kw)


    def packet_out(self, egress_port, msg):
        pkt = Ether(msg)
        self.log.info('packet out', egress_port=egress_port,
                      packet=str(pkt).encode("HEX"))

        # Find port type
        egress_port_type = self.port_type(egress_port)

        if egress_port_type == Port.ETHERNET_UNI:

            if pkt.haslayer(Dot1Q):
                outer_shim = pkt.getlayer(Dot1Q)
                if isinstance(outer_shim.payload, Dot1Q):
                    # If double tag, remove the outer tag
                    payload = (
                        Ether(src=pkt.src, dst=pkt.dst, type=outer_shim.type) /
                        outer_shim.payload
                    )
                else:
                    payload = pkt
            else:
                payload = pkt

            send_pkt = binascii.unhexlify(str(payload).encode("HEX"))

            self.log.info(
                'sending-packet-to-ONU', egress_port=egress_port,
                intf_id=platform.intf_id_from_uni_port_num(egress_port),
                onu_id=platform.onu_id_from_port_num(egress_port),
                packet=str(payload).encode("HEX"))

            onu_pkt = openolt_pb2.OnuPacket(
                intf_id=platform.intf_id_from_uni_port_num(egress_port),
                onu_id=platform.onu_id_from_port_num(egress_port),
                pkt=send_pkt)

            self.stub.OnuPacketOut(onu_pkt)

        elif egress_port_type == Port.ETHERNET_NNI:
            self.log.info('sending-packet-to-uplink', egress_port=egress_port,
                          packet=str(pkt).encode("HEX"))

            send_pkt = binascii.unhexlify(str(pkt).encode("HEX"))

            uplink_pkt = openolt_pb2.UplinkPacket(
                intf_id=platform.intf_id_from_nni_port_num(egress_port),
                pkt=send_pkt)

            self.stub.UplinkPacketOut(uplink_pkt)

        else:
            self.log.warn('Packet-out-to-this-interface-type-not-implemented',
                          egress_port=egress_port,
                          port_type=egress_port_type)

    def send_proxied_message(self, proxy_address, msg):
        omci = openolt_pb2.OmciMsg(intf_id=proxy_address.channel_id,
                                   onu_id=proxy_address.onu_id, pkt=str(msg))
        self.stub.OmciMsgOut(omci)

    def add_onu_device(self, intf_id, port_no, onu_id, serial_number):
        self.log.info("Adding ONU", port_no=port_no, onu_id=onu_id,
                      serial_number=serial_number)

        # NOTE - channel_id of onu is set to intf_id
        proxy_address = Device.ProxyAddress(device_id=self.device_id,
                                            channel_id=intf_id, onu_id=onu_id,
                                            onu_session_id=onu_id)

        self.log.info("Adding ONU", proxy_address=proxy_address)

        serial_number_str = self.stringify_serial_number(serial_number)

        self.adapter_agent.add_onu_device(
            parent_device_id=self.device_id, parent_port_no=port_no,
            vendor_id=serial_number.vendor_id, proxy_address=proxy_address,
            root=True, serial_number=serial_number_str,
            admin_state=AdminState.ENABLED)

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

    def port_type(self, port_no):
        ports = self.adapter_agent.get_ports(self.device_id)
        for port in ports:
            if port.port_no == port_no:
                return port.type
        return None

    def add_logical_port(self, port_no, intf_id, oper_state):
        self.log.info('adding-logical-port', port_no=port_no)

        label = self.port_name(port_no, Port.ETHERNET_NNI)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        curr_speed = OFPPF_1GB_FD
        max_speed = OFPPF_1GB_FD

        if oper_state == OperStatus.ACTIVE:
            of_oper_state = OFPPS_LIVE
        else:
            of_oper_state = OFPPS_LINK_DOWN

        ofp = ofp_port(
            port_no=port_no,
            hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
            name=label, config=0, state=of_oper_state, curr=cap,
            advertised=cap, peer=cap, curr_speed=curr_speed,
            max_speed=max_speed)

        ofp_stats = ofp_port_stats(port_no=port_no)

        logical_port = LogicalPort(
            id=label, ofp_port=ofp, device_id=self.device_id,
            device_port_no=port_no, root_port=True,
            ofp_port_stats=ofp_stats)

        self.adapter_agent.add_logical_port(self.logical_device_id,
                                            logical_port)

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
                hex(ord(vendor_specific[0]) >> 4 & 0x0f)[2:],
                hex(ord(vendor_specific[0]) & 0x0f)[2:],
                hex(ord(vendor_specific[1]) >> 4 & 0x0f)[2:],
                hex(ord(vendor_specific[1]) & 0x0f)[2:],
                hex(ord(vendor_specific[2]) >> 4 & 0x0f)[2:],
                hex(ord(vendor_specific[2]) & 0x0f)[2:],
                hex(ord(vendor_specific[3]) >> 4 & 0x0f)[2:],
                hex(ord(vendor_specific[3]) & 0x0f)[2:]])

    def update_flow_table(self, flows):
        device = self.adapter_agent.get_device(self.device_id)
        self.log.debug('update flow table', number_of_flows=len(flows))
        in_port = None

        for flow in flows:
            is_down_stream = None
            in_port = fd.get_in_port(flow)
            assert in_port is not None
            # Right now there is only one NNI port. Get the NNI PORT and
            # compare with IN_PUT port number. Need to find better way.
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
                except grpc.RpcError as grpc_e:
                    if grpc_e.code() == grpc.StatusCode.ALREADY_EXISTS:
                        self.log.warn('flow already exists', e=grpc_e,
                                       flow=flow)
                    else:
                        self.log.error('failed to add flow', flow=flow,
                                       e=grpc_e)
                except Exception as e:
                    self.log.error('failed to add flow', flow=flow, e=e)


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
                        self.stringify_vendor_specific(
                            serial_number.vendor_specific)])

    def disable(self):
        self.log.info('sending-deactivate-olt-message',
                      device_id=self.device_id)

        # Send grpc call
        # self.stub.DeactivateOlt(openolt_pb2.Empty())

        # Soft deactivate. Turning down hardware should remove flows,
        # but we are not doing that presently

        # Bring OLT down
        self.go_state_down()

    def delete(self):
        self.log.info('delete-olt', device_id=self.device_id)

        # Stop the grpc communication threads
        self.log.info('stopping-grpc-threads', device_id=self.device_id)

        # Close the grpc channel
        # self.log.info('unsubscribing-grpc-channel', device_id=self.device_id)
        # self.channel.unsubscribe()

        self.log.info('successfully-deleted-olt', device_id=self.device_id)

    def reenable(self):
        self.log.info('reenable-olt', device_id=self.device_id)

        # Bring up OLT
        self.go_state_up()

        # Enable all child devices
        self.log.info('enabling-child-devices', device_id=self.device_id)
        self.log.info('enabling-child-devices', olt_device_id=self.device_id)
        self.adapter_agent.update_child_devices_state(
            parent_device_id=self.device_id,
            admin_state=AdminState.ENABLED)

        # Set all ports to enabled
        self.log.info('enabling-all-ports', device_id=self.device_id)
        self.adapter_agent.enable_all_ports(self.device_id)
