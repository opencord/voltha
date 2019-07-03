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
import threading
import binascii
import grpc
import structlog
import time
from twisted.internet import reactor
from scapy.layers.l2 import Ether, Dot1Q
from transitions import Machine

from voltha.protos.device_pb2 import Port
from voltha.adapters.openolt.protos import openolt_pb2_grpc, openolt_pb2
from voltha.adapters.openolt.openolt_utils import OpenoltUtils
from voltha.extensions.alarms.onu.onu_discovery_alarm import OnuDiscoveryAlarm
from voltha.extensions.alarms.olt.olt_conn_lost_alarm import OltConnLostAlarm


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
         'before': 'do_state_init',
         'after': 'post_init'},
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
         'before': 'do_state_down',
         'after': 'post_down'}]

    def __init__(self, **kwargs):
        super(OpenoltDevice, self).__init__()

        self.admin_state = "up"

        adapter_agent = kwargs['adapter_agent']
        self.device_id = kwargs['device_id']

        self.data_model_class = kwargs['support_classes']['data_model']
        self.platform_class = kwargs['support_classes']['platform']
        self.platform = self.platform_class()
        self.resource_mgr_class = kwargs['support_classes']['resource_mgr']
        self.flow_mgr_class = kwargs['support_classes']['flow_mgr']
        self.alarm_mgr_class = kwargs['support_classes']['alarm_mgr']
        self.stats_mgr_class = kwargs['support_classes']['stats_mgr']

        is_reconciliation = kwargs.get('reconciliation', False)
        self.host_and_port = kwargs['host_and_port']
        self.extra_args = kwargs['extra_args']
        self.log = structlog.get_logger(ip=self.host_and_port)

        self.log.info('openolt-device-init')

        self.data_model = self.data_model_class(self.device_id, adapter_agent,
                                                self.platform)
        if is_reconciliation:
            self.log.info('reconcile data model')
            self.data_model.reconcile()

        # Initialize the OLT state machine
        self.machine = Machine(model=self, states=OpenoltDevice.states,
                               transitions=OpenoltDevice.transitions,
                               send_event=True, initial='state_null')

        self.device_info = None

        self.go_state_init()

    def do_state_init(self, event):
        # Initialize gRPC
        self.channel = grpc.insecure_channel(self.host_and_port)
        self.channel_ready_future = grpc.channel_ready_future(self.channel)

        self.log.info('openolt-device-created')

    def post_init(self, event):
        self.log.debug('post_init')

        # We have reached init state, starting the indications thread

        # Catch RuntimeError exception
        try:
            # Start indications thread
            self.indications_thread_handle = threading.Thread(
                target=self.indications_thread)
            # Old getter/setter API for daemon; use it directly as a
            # property instead. The Jinkins error will happon on the reason of
            # Exception in thread Thread-1 (most likely raised # during
            # interpreter shutdown)
            self.indications_thread_handle.setDaemon(True)
            self.indications_thread_handle.start()
        except Exception as e:
            self.log.exception('post_init failed', e=e)

    def do_state_connected(self, event):
        self.log.debug("do_state_connected")

        # Check that device_info was successfully retrieved
        assert(self.device_info is not None
               and self.device_info.device_serial_number is not None
               and self.device_info.device_serial_number != '')

        self.data_model.olt_create(self.device_info)

        self.resource_mgr = self.resource_mgr_class(self.device_id,
                                                    self.host_and_port,
                                                    self.extra_args,
                                                    self.device_info)
        self.flow_mgr = self.flow_mgr_class(self.log, self.stub,
                                            self.device_id,
                                            self.data_model.logical_device_id,
                                            self.platform, self.resource_mgr,
                                            self.data_model)

        self.alarm_mgr = self.alarm_mgr_class(self.log, self.platform,
                                              self.data_model)
        self.stats_mgr = self.stats_mgr_class(self, self.log, self.platform,
                                              self.data_model)

    def do_state_up(self, event):
        self.log.debug("do_state_up")
        self.log.debug("olt-connection-lost-alarm-cleared")
        OltConnLostAlarm(self.alarm_mgr.alarms, serial_number = self.device_info.device_serial_number).clear_alarm()
        self.data_model.olt_oper_up()

    def do_state_down(self, event):
        self.log.debug("do_state_down")
        self.log.debug("olt-connection-lost-alarm-raised")
        OltConnLostAlarm(self.alarm_mgr.alarms, serial_number = self.device_info.device_serial_number).raise_alarm()
        self.data_model.olt_oper_down()

    def post_down(self, event):
        self.log.debug('post_down')
        # We land here on loosing connection with OLT.
        # In such case, reset all data on the KV store for all the associated UNIs,
        # and NNI port. As a result, when the connection is regained with the OLT,
        # the whole configuration is replayed again.

        # Clear the KV store data associated with the all the UNI ports
        # This clears up flow data and also resource map data for various
        # other pon resources like alloc_id and gemport_id
        child_devices = self.data_model.adapter_agent.get_child_devices(self.device_id)
        for child_device in child_devices:
            ports = self.data_model.adapter_agent.get_ports(child_device.id, Port.ETHERNET_UNI)
            for port in ports:
                if port.type == Port.ETHERNET_UNI:
                    self.log.debug("clearing-flows-for-onu-uni", child_device_id=child_device.id)
                    port_no = port.port_no
                    uni_id = self.platform.uni_id_from_port_num(port_no)
                    pon_intf_id = child_device.proxy_address.channel_id
                    onu_id = child_device.proxy_address.onu_id

                    try:
                        self.log.debug("clearing-tp-instance-for-onu",
                                    serial_number=child_device.serial_number, onu_id=onu_id,
                                    uni_id=uni_id, intf_id=pon_intf_id)
                        self.flow_mgr.delete_tech_profile_instance(
                                    pon_intf_id, onu_id, uni_id,
                                    child_device.serial_number)
                    except Exception as e:
                        self.log.exception("error-removing-tp-instance")

                    try:
                        pon_intf_id_onu_id = (pon_intf_id, onu_id, uni_id)
                        # Free any PON resources that were reserved for the ONU
                        # Note: Since the ONU device is not deleted in the voltha core during
                        # OLT post_down handling, we should not reset the ONU ID pool on the
                        # resource manager.
                        # The voltha core is aware of the ONU ID, and we need to ensure that ONU
                        # IDs are not re-used for new ONUs after OLT comes back. If we reset the
                        # ONU ID pool during OLT post_down there is a possibility that newer ONUs
                        # may get the conflicting ONU IDs already assigned for pre-existing ONUs.
                        # Passing the 'reset_onu_id_pool' as False, ensures that the ONU ID pool
                        # is not reset during OLT down scenario.
                        self.resource_mgr.free_pon_resources_for_onu(pon_intf_id_onu_id, False)
                        # Free tech_profile id for ONU
                        self.resource_mgr.remove_tech_profile_id_for_onu(pon_intf_id, onu_id, uni_id)
                        # Free meter_ids for the ONU
                        self.resource_mgr.remove_meter_id_for_onu("upstream",
                                                                  pon_intf_id, onu_id, uni_id)
                        self.resource_mgr.remove_meter_id_for_onu("downstream",
                                                                  pon_intf_id, onu_id, uni_id)
                        self.log.debug('cleared-resource', pon_intf_id_onu_id=pon_intf_id_onu_id)
                    except Exception as e:
                        self.log.exception("error-removing-pon-resources-for-onu")

        # Clear the flows from KV store associated with NNI port.
        # There are mostly trap rules from NNI port (like LLDP)
        ports = self.data_model.adapter_agent.get_ports(self.device_id, Port.ETHERNET_NNI)
        for port in ports:
            self.log.debug('clear-flows-for-nni-in-olt-device', port=port)
            if port.type == Port.ETHERNET_NNI:
                nni_intf_id = self.platform.intf_id_from_nni_port_num(port.port_no)
                flow_ids = self.resource_mgr.get_current_flow_ids(nni_intf_id,
                                                                  -1, -1)
                # Clear the flows on KV store
                if flow_ids is not None and isinstance(flow_ids, list):
                    for flow_id in flow_ids:
                        self.resource_mgr.free_flow_id(nni_intf_id, -1, -1,
                                                       flow_id)
                        self.log.debug('cleared-flows', nni_intf_id=nni_intf_id)

        self.flow_mgr.reset_flows()

    def indications_thread(self):
        self.log.debug('starting-indications-thread')
        self.log.debug('connecting to olt')

        self.stub = openolt_pb2_grpc.OpenoltStub(self.channel)

        timeout = 60*60
        delay = 1
        exponential_back_off = False
        while True:
            try:
                self.device_info = self.stub.GetDeviceInfo(openolt_pb2.Empty())
                break
            except Exception as e:
                if delay > timeout:
                    self.log.error("timed out connecting to olt")
                    return
                else:
                    self.log.warn("retry connecting to olt in %ds: %s"
                                  % (delay, repr(e)))
                    time.sleep(delay)
                    if exponential_back_off:
                        delay += delay
                    else:
                        delay += 1

        self.log.info('connected to olt', device_info=self.device_info)

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

                if self.admin_state is "down":
                    if ind.HasField('intf_oper_ind') \
                            and (ind.intf_oper_ind.type == "nni"):
                        self.log.warn('olt is admin down, allow nni ind',
                                      admin_state=self.admin_state,
                                      indications=ind)
                    else:
                        self.log.warn('olt is admin down, ignore indication',
                                      admin_state=self.admin_state,
                                      indications=ind)
                        continue

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
        # NOTE - BAL only sends interface indications for PON ports,
        # not for NNI ports.
        self.data_model.olt_port_add_update(intf_indication.intf_id,
                                            "pon",
                                            intf_indication.oper_state)

    def intf_oper_indication(self, intf_oper_indication):
        self.log.debug("Received interface oper state change indication",
                       intf_id=intf_oper_indication.intf_id,
                       type=intf_oper_indication.type,
                       oper_state=intf_oper_indication.oper_state)
        self.data_model.olt_port_add_update(intf_oper_indication.intf_id,
                                            intf_oper_indication.type,
                                            intf_oper_indication.oper_state)

    def onu_discovery_indication(self, onu_disc_indication):
        intf_id = onu_disc_indication.intf_id
        serial_number = onu_disc_indication.serial_number
        serial_number_str = OpenoltUtils.stringify_serial_number(serial_number)

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

        try:
            onu_id = self.data_model.onu_id(serial_number=serial_number_str)
        except ValueError:
            # FIXME - resource_mgr.get_onu_id() should raise exception
            onu_id = self.resource_mgr.get_onu_id(intf_id)
            if onu_id is None:
                raise Exception("onu-id-unavailable")

        self.data_model.onu_create(intf_id, onu_id, serial_number_str)

        self.activate_onu(intf_id, onu_id, serial_number, serial_number_str)

    def onu_indication(self, onu_indication):
        self.log.debug("onu indication", intf_id=onu_indication.intf_id,
                       onu_id=onu_indication.onu_id,
                       serial_number=onu_indication.serial_number,
                       oper_state=onu_indication.oper_state,
                       admin_state=onu_indication.admin_state)

        # Admin state
        if onu_indication.admin_state == 'down':
            if onu_indication.oper_state != 'down':
                self.log.error('ONU-admin-state-down-and-oper-status-not-down',
                               oper_state=onu_indication.oper_state)
                # Forcing the oper state change code to execute
                onu_indication.oper_state = 'down'

            # Port and logical port update is taken care of by oper state block

        self.log.debug('admin-state-dealt-with')

        # Operating state
        if onu_indication.oper_state == 'down':
            self.data_model.onu_oper_down(onu_indication.intf_id,
                                          onu_indication.onu_id)

        elif onu_indication.oper_state == 'up':
            self.data_model.onu_oper_up(onu_indication.intf_id,
                                        onu_indication.onu_id)

    def omci_indication(self, omci_indication):

        self.log.debug("omci indication", intf_id=omci_indication.intf_id,
                       onu_id=omci_indication.onu_id)

        self.data_model.onu_omci_rx(omci_indication.intf_id,
                                    omci_indication.onu_id,
                                    omci_indication.pkt)

    def packet_indication(self, pkt_indication):
        self.log.debug("packet-indication",
                       intf_type=pkt_indication.intf_type,
                       intf_id=pkt_indication.intf_id,
                       port_no=pkt_indication.port_no,
                       cookie=pkt_indication.cookie,
                       gemport_id=pkt_indication.gemport_id,
                       flow_id=pkt_indication.flow_id)
        self.data_model.onu_send_packet_in(pkt_indication.intf_type,
                                           pkt_indication.intf_id,
                                           pkt_indication.port_no,
                                           pkt_indication.gemport_id,
                                           pkt_indication.pkt)

    def packet_out(self, egress_port, msg):
        pkt = Ether(msg)
        self.log.debug('packet out', egress_port=egress_port,
                       packet=str(pkt).encode("HEX"))

        # Find port type
        egress_port_type = self.platform.intf_id_to_port_type_name(egress_port)
        if egress_port_type == Port.ETHERNET_UNI:

            if pkt.haslayer(Dot1Q):
                outer_shim = pkt.getlayer(Dot1Q)
                if isinstance(outer_shim.payload, Dot1Q):
                    # If double tag, remove the outer tag
                    payload = (
                            Ether(src=pkt.src, dst=pkt.dst,
                                  type=outer_shim.type) /
                            outer_shim.payload
                    )
                else:
                    payload = pkt
            else:
                payload = pkt

            send_pkt = binascii.unhexlify(str(payload).encode("HEX"))

            self.log.debug(
                'sending-packet-to-ONU', egress_port=egress_port,
                intf_id=self.platform.intf_id_from_uni_port_num(egress_port),
                onu_id=self.platform.onu_id_from_port_num(egress_port),
                uni_id=self.platform.uni_id_from_port_num(egress_port),
                port_no=egress_port,
                packet=str(payload).encode("HEX"))

            intf_id = self.platform.intf_id_from_uni_port_num(egress_port)
            onu_id = self.platform.onu_id_from_port_num(egress_port)
            port_no = egress_port
            gemport_key = (intf_id, onu_id, port_no)
            assert (gemport_key in self.data_model.packet_in_gem_port)
            gemport_id = self.data_model.packet_in_gem_port[gemport_key]
            onu_pkt = openolt_pb2.OnuPacket(
                intf_id=intf_id,
                onu_id=onu_id,
                port_no=port_no,
                gemport_id=gemport_id,
                pkt=send_pkt)

            self.stub.OnuPacketOut(onu_pkt)

        elif egress_port_type == Port.ETHERNET_NNI:
            self.log.debug('sending-packet-to-uplink', egress_port=egress_port,
                           packet=str(pkt).encode("HEX"))

            send_pkt = binascii.unhexlify(str(pkt).encode("HEX"))

            uplink_pkt = openolt_pb2.UplinkPacket(
                intf_id=self.platform.intf_id_from_nni_port_num(egress_port),
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

    def update_flow_table(self, flows):
        self.log.debug('No updates here now, all is done in logical flows '
                       'update')

    def update_logical_flows(self, flows_to_add, flows_to_remove,
                             device_rules_map):
        if not self.is_state_up():
            self.log.info('The OLT is not up, we cannot update flows',
                          flows_to_add=[f.id for f in flows_to_add],
                          flows_to_remove=[f.id for f in flows_to_remove])
            return

        self.flow_mgr.update_logical_flows(flows_to_add, flows_to_remove,
                                           device_rules_map)

    def disable(self):
        self.log.debug('sending-deactivate-olt-message')

        try:
            # Send grpc call
            self.stub.DisableOlt(openolt_pb2.Empty())
            self.admin_state = "down"
            self.log.info('openolt device disabled')
        except Exception as e:
            self.log.error('Failure to disable openolt device', error=e)

    def delete(self):
        self.log.info('deleting-olt')

        # Clears up the data from the resource manager KV store
        # for the device
        del self.resource_mgr

        try:
            # Rebooting to reset the state
            self.reboot()
            self.data_model.olt_delete()
        except Exception as e:
            self.log.error('Failure to delete openolt device', error=e)
            raise e
        else:
            self.log.info('successfully-deleted-olt')

    def reenable(self):
        self.log.debug('reenabling-olt')

        try:
            self.stub.ReenableOlt(openolt_pb2.Empty())
        except Exception as e:
            self.log.error('Failure to reenable openolt device', error=e)
        else:
            self.log.info('openolt device reenabled')
            self.admin_state = "up"

    def activate_onu(self, intf_id, onu_id, serial_number,
                     serial_number_str):
        self.log.debug("activating-onu", intf_id=intf_id, onu_id=onu_id,
                       serial_number_str=serial_number_str,
                       serial_number=serial_number)
        onu = openolt_pb2.Onu(intf_id=intf_id, onu_id=onu_id,
                              serial_number=serial_number)
        try:
            self.stub.ActivateOnu(onu)
        except grpc.RpcError as grpc_e:
            if grpc_e.code() == grpc.StatusCode.ALREADY_EXISTS:
                self.log.info('onu activation in progress',
                              serial_number=serial_number_str,
                              e=grpc_e)
            else:
                self.log.error('onu activation failed',
                               serial_number=serial_number_str,
                               grpc_error=grpc_e)
        else:
            self.log.info('onu-activated', serial_number=serial_number_str)

    # FIXME - instead of passing child_device around, delete_child_device
    # needs to change to use serial_number.
    def delete_child_device(self, child_device):
        serial_number = OpenoltUtils.destringify_serial_number(
                            child_device.serial_number)
        pon_intf_id = child_device.proxy_address.channel_id
        onu_id = child_device.proxy_address.onu_id
        self.log.debug('delete-device',
                       onu_device=child_device,
                       onu_serial_number=serial_number,
                       device_id=child_device.id)

        try:
            self.data_model.onu_delete(self.flow_mgr, child_device)
            onu = openolt_pb2.Onu(
                intf_id=pon_intf_id,
                onu_id=onu_id,
                serial_number=serial_number)
            self.stub.DeleteOnu(onu)
        except Exception as e:
            self.log.exception("error-deleting-the-onu-on-olt-device", error=e)

        # TODO FIXME - For each uni.
        # TODO FIXME - Flows are not deleted
        uni_id = 0  # FIXME
        try:
            self.flow_mgr.delete_tech_profile_instance(
                        pon_intf_id,
                        child_device.proxy_address.onu_id,
                        uni_id, child_device.serial_number)
        except Exception as e:
            self.log.exception("error-removing-tp-instance")

        try:
            pon_intf_id_onu_id = (pon_intf_id,
                                  onu_id,
                                  uni_id)
            # Free any PON resources that were reserved for the ONU
            self.resource_mgr.free_pon_resources_for_onu(pon_intf_id_onu_id)
        except Exception as e:
            self.log.exception("error-removing-pon-resources-for-onu")


    def reboot(self):
        self.log.debug('rebooting openolt device')
        try:
            self.stub.Reboot(openolt_pb2.Empty())
        except Exception as e:
            self.log.error('something went wrong with the reboot', error=e)
        else:
            self.log.info('device rebooted')

    def trigger_statistics_collection(self):
        try:
            self.stub.CollectStatistics(openolt_pb2.Empty())
        except Exception as e:
            self.log.error('Error while triggering statistics collection',
                           error=e)
        else:
            self.log.info('statistics requested')

    def simulate_alarm(self, alarm):
        self.alarm_mgr.simulate_alarm(alarm)
