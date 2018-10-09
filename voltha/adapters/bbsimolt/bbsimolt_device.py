#
# Copyright 2018 the original author or authors.
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

from twisted.internet import reactor

from scapy.layers.l2 import Ether
from voltha.adapters.openolt.openolt import OpenoltDevice
from voltha.protos.device_pb2 import Port
from voltha.adapters.openolt.protos import openolt_pb2
from voltha.protos.common_pb2 import ConnectStatus, OperStatus, AdminState
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_base_pb2 import VEnetConfig
from voltha.extensions.alarms.onu.onu_discovery_alarm import OnuDiscoveryAlarm

from voltha.registry import registry

class BBSimOltDevice(OpenoltDevice):
    def __init__(self, **kwargs):
        super(BBSimOltDevice, self).__init__(**kwargs)

    def onu_discovery_indication(self, onu_disc_indication):
        intf_id = onu_disc_indication.intf_id
        serial_number = onu_disc_indication.serial_number

        serial_number_str = self.stringify_serial_number(serial_number)

        self.log.debug("onu discovery indication", intf_id=intf_id,
                       serial_number=serial_number_str)

        # Post ONU Discover alarm  20180809_0805
        try:
            OnuDiscoveryAlarm(self.alarm_mgr.alarms, pon_id=intf_id,
                              serial_number=serial_number_str).raise_alarm()
        except Exception as disc_alarm_error:
            self.log.exception("onu-discovery-alarm-error",
                               errmsg=disc_alarm_error.message)
            # continue for now.

        onu_device = self.adapter_agent.get_child_device(
            self.device_id,
            serial_number=serial_number_str)

        if onu_device is None:
            onu_id = self.new_onu_id(intf_id)
            try:
                self.add_onu_device(
                    intf_id,
                    self.platform.intf_id_to_port_no(intf_id, Port.PON_OLT),
                    onu_id, serial_number)
                self.activate_onu(intf_id, onu_id, serial_number,
                                  serial_number_str)
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
                              reboot probably, activate onu", intf_id=intf_id,
                              onu_id=onu_id, serial_number=serial_number_str)

                onu_device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(onu_device)
                try:
                    self.activate_onu(intf_id, onu_id, serial_number,
                                      serial_number_str)
                except Exception as e:
                    self.log.error('onu-activation-error',
                                   serial_number=serial_number_str, error=e)
            else:
                self.log.warn('unexpected state', onu_id=onu_id,
                              onu_device_oper_state=onu_device.oper_status)

    def packet_indication(self, pkt_indication):

        self.log.debug("packet indication", intf_id=pkt_indication.intf_id,
                       gemport_id=pkt_indication.gemport_id,
                       flow_id=pkt_indication.flow_id)

        onu_id = self.platform.onu_id_from_gemport_id(pkt_indication.gemport_id)
        logical_port_num = self.platform.mk_uni_port_num(pkt_indication.intf_id,
                                                    onu_id)

        pkt = Ether(pkt_indication.pkt)
        kw = dict(logical_device_id=self.logical_device_id,
                  logical_port_no=logical_port_num)
        self.adapter_agent.send_packet_in(packet=str(pkt), **kw)

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
                    parent_port_no=self.platform.intf_id_to_port_no(
                            onu_indication.intf_id, Port.PON_OLT),
                    onu_id=onu_indication.onu_id)

        if onu_device is None:
            self.log.error('onu not found', intf_id=onu_indication.intf_id,
                           onu_id=onu_indication.onu_id)
            return

        if self.platform.intf_id_from_pon_port_no(onu_device.parent_port_no) \
                != onu_indication.intf_id:
            self.log.warn('ONU-is-on-a-different-intf-id-now',
                          previous_intf_id=self.platform.intf_id_from_pon_port_no(
                              onu_device.parent_port_no),
                          current_intf_id=onu_indication.intf_id)
            # FIXME - handle intf_id mismatch (ONU move?)

        if onu_device.proxy_address.onu_id != onu_indication.onu_id:
            # FIXME - handle onu id mismatch
            self.log.warn('ONU-id-mismatch, can happen if both voltha and '
                          'the olt rebooted',
                          expected_onu_id=onu_device.proxy_address.onu_id,
                          received_onu_id=onu_indication.onu_id)

        uni_no = self.platform.mk_uni_port_num(onu_indication.intf_id,
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

            # Port and logical port update is taken care of by oper state block

        elif onu_indication.admin_state == 'up':
            pass

        else:
            self.log.warn('Invalid-or-not-implemented-admin-state',
                          received_admin_state=onu_indication.admin_state)

        self.log.debug('admin-state-dealt-with')

        onu_adapter_agent = \
            registry('adapter_loader').get_agent(onu_device.adapter)
        if onu_adapter_agent is None:
            self.log.error('onu_adapter_agent-could-not-be-retrieved',
                           onu_device=onu_device)
            return

        # Operating state
        if onu_indication.oper_state == 'down':

            if onu_device.connect_status != ConnectStatus.UNREACHABLE:
                onu_device.connect_status = ConnectStatus.UNREACHABLE
                self.adapter_agent.update_device(onu_device)

            # Move to discovered state
            self.log.debug('onu-oper-state-is-down')

            if onu_device.oper_status != OperStatus.DISCOVERED:
                onu_device.oper_status = OperStatus.DISCOVERED
                self.adapter_agent.update_device(onu_device)
            # Set port oper state to Discovered
            self.onu_ports_down(onu_device, uni_no, uni_name,
                                OperStatus.DISCOVERED)

            if onu_device.adapter == 'brcm_openomci_onu':
                self.log.debug('using-brcm_openomci_onu')
                onu_adapter_agent.update_interface(onu_device,
                                                   {'oper_state': 'down'})

        elif onu_indication.oper_state == 'up':

            if onu_device.connect_status != ConnectStatus.REACHABLE:
                onu_device.connect_status = ConnectStatus.REACHABLE
                self.adapter_agent.update_device(onu_device)

            if onu_device.oper_status != OperStatus.DISCOVERED:
                self.log.debug("ignore onu indication",
                               intf_id=onu_indication.intf_id,
                               onu_id=onu_indication.onu_id,
                               state=onu_device.oper_status,
                               msg_oper_state=onu_indication.oper_state)
                return

            # Device was in Discovered state, setting it to active

            # Prepare onu configuration
            # If we are using the old/current broadcom adapter otherwise
            # use the openomci adapter
            if onu_device.adapter == 'broadcom_onu':
                self.log.debug('using-broadcom_onu')

                # onu initialization, base configuration (bridge setup ...)
                def onu_initialization():

                    onu_adapter_agent.adapter.devices_handlers[onu_device.id] \
                                     .message_exchange()
                    self.log.debug('broadcom-message-exchange-started')

                # tcont creation (onu)
                tcont = TcontsConfigData()
                tcont.alloc_id = self.platform.mk_alloc_id(
                    onu_indication.intf_id, onu_indication.onu_id)

                # gem port creation
                gem_port = GemportsConfigData()
                gem_port.gemport_id = self.platform.mk_gemport_id(
                    onu_indication.intf_id,
                    onu_indication.onu_id)

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
                reactor.callLater(11, onu_adapter_agent.create_gemport,
                                  onu_device, gem_port)
                reactor.callLater(12, port_config)
                reactor.callLater(12, onu_update_oper_status)

            else:
                self.log.error('unsupported-openolt-onu-adapter')

        else:
            self.log.warn('Not-implemented-or-invalid-value-of-oper-state',
                          oper_state=onu_indication.oper_state)

    def activate_onu(self, intf_id, onu_id, serial_number,
                     serial_number_str):
        pir = self.bw_mgr.pir(serial_number_str)
        self.log.debug("activating-onu", intf_id=intf_id, onu_id=onu_id,
                       serial_number_str=serial_number_str,
                       serial_number=serial_number, pir=pir)
        onu = openolt_pb2.Onu(intf_id=intf_id, onu_id=onu_id,
                              serial_number=serial_number, pir=pir)
        self.stub.ActivateOnu(onu)
        self.log.info('onu-activated', serial_number=serial_number_str)