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
import sys
from uuid import uuid4

import arrow
import voltha.core.flow_decomposer as fd
import grpc
import json
import copy
import structlog
import hashlib
from scapy.layers.l2 import Ether, Dot1Q, Dot1AD
from scapy.layers.inet import IP, Raw
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from grpc._channel import _Rendezvous

from common.frameio.frameio import BpfProgramFilter, hexify
from common.utils.asleep import asleep
from twisted.internet.task import LoopingCall
from voltha.adapters.iadapter import OltAdapter
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos import openflow_13_pb2 as ofp
from voltha.protos import ponsim_pb2, ponsim_pb2_grpc
from voltha.protos.common_pb2 import OperStatus, ConnectStatus, AdminState
from voltha.protos.common_pb2 import OperationResp
from voltha.protos.device_pb2 import Port, Device, PmConfig, PmConfigs
from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs
from google.protobuf.empty_pb2 import Empty
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, \
    OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS, \
    ofp_switch_features, ofp_desc
from voltha.protos.openflow_13_pb2 import ofp_port
from voltha.protos.ponsim_pb2 import FlowTable, PonSimFrame, PonSimMetricsRequest
from voltha.registry import registry

from voltha.protos.bbf_fiber_base_pb2 import \
    ChannelgroupConfig, ChannelpartitionConfig, ChannelpairConfig, \
    ChannelterminationConfig, OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_multicast_gemport_body_pb2 import \
    MulticastGemportsConfigData

from voltha.protos.bbf_fiber_multicast_distribution_set_body_pb2 import \
    MulticastDistributionSetData

from voltha.protos.ponsim_pb2 import InterfaceConfig, TcontInterfaceConfig

from voltha.extensions.alarms.adapter_alarms import AdapterAlarms as VolthaAdapterAlarms
from voltha.extensions.alarms.simulator.simulate_alarms import AdapterAlarmSimulator

_ = third_party
log = structlog.get_logger()

PACKET_IN_VLAN = 4000
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))

EAP_ETH_TYPE = 0x888e

# Classifier
ETH_TYPE = 'eth_type'
TPID = 'tpid'
IP_PROTO = 'ip_proto'
IN_PORT = 'in_port'
VLAN_VID = 'vlan_vid'
VLAN_PCP = 'vlan_pcp'
UDP_DST = 'udp_dst'
UDP_SRC = 'udp_src'
IPV4_DST = 'ipv4_dst'
IPV4_SRC = 'ipv4_src'
METADATA = 'metadata'
OUTPUT = 'output'

class AdapterPmMetrics:
    def __init__(self, device):
        self.pm_names = {'tx_64_pkts', 'tx_65_127_pkts', 'tx_128_255_pkts',
                         'tx_256_511_pkts', 'tx_512_1023_pkts',
                         'tx_1024_1518_pkts', 'tx_1519_9k_pkts',
                         'rx_64_pkts', 'rx_65_127_pkts',
                         'rx_128_255_pkts', 'rx_256_511_pkts',
                         'rx_512_1023_pkts', 'rx_1024_1518_pkts',
                         'rx_1519_9k_pkts'}
        self.device = device
        self.id = device.id
        self.name = 'ponsim_olt'
        # self.id = "abc"
        self.default_freq = 150
        self.grouped = False
        self.freq_override = False
        self.pon_metrics_config = dict()
        self.nni_metrics_config = dict()
        self.lc = None
        for m in self.pm_names:
            self.pon_metrics_config[m] = PmConfig(name=m,
                                                  type=PmConfig.COUNTER,
                                                  enabled=True)
            self.nni_metrics_config[m] = PmConfig(name=m,
                                                  type=PmConfig.COUNTER,
                                                  enabled=True)

    def update(self, pm_config):
        if self.default_freq != pm_config.default_freq:
            # Update the callback to the new frequency.
            self.default_freq = pm_config.default_freq
            self.lc.stop()
            self.lc.start(interval=self.default_freq / 10)
        for m in pm_config.metrics:
            self.pon_metrics_config[m.name].enabled = m.enabled
            self.nni_metrics_config[m.name].enabled = m.enabled

    def make_proto(self):
        pm_config = PmConfigs(
            id=self.id,
            default_freq=self.default_freq,
            grouped=False,
            freq_override=False)
        for m in sorted(self.pon_metrics_config):
            pm = self.pon_metrics_config[m]  # Either will do they're the same
            pm_config.metrics.extend([PmConfig(name=pm.name,
                                               type=pm.type,
                                               enabled=pm.enabled)])
        return pm_config

    def collect_port_metrics(self, channel):
        rtrn_port_metrics = dict()
        stub = ponsim_pb2_grpc.PonSimStub(channel)
        stats = stub.GetStats(ponsim_pb2.PonSimMetricsRequest(port=0))
        rtrn_port_metrics['pon'] = self.extract_pon_metrics(stats)
        rtrn_port_metrics['nni'] = self.extract_nni_metrics(stats)
        return rtrn_port_metrics

    def extract_pon_metrics(self, stats):
        rtrn_pon_metrics = dict()
        for m in stats.metrics:
            if m.port_name == "pon":
                for p in m.packets:
                    if self.pon_metrics_config[p.name].enabled:
                        rtrn_pon_metrics[p.name] = p.value
                return rtrn_pon_metrics

    def extract_nni_metrics(self, stats):
        rtrn_pon_metrics = dict()
        for m in stats.metrics:
            if m.port_name == "nni":
                for p in m.packets:
                    if self.pon_metrics_config[p.name].enabled:
                        rtrn_pon_metrics[p.name] = p.value
                return rtrn_pon_metrics

    def start_collector(self, callback):
        log.info("starting-pm-collection", device_name=self.name,
                 device_id=self.device.id)
        prefix = 'voltha.{}.{}'.format(self.name, self.device.id)
        self.lc = LoopingCall(callback, self.device.id, prefix)
        self.lc.start(interval=self.default_freq / 10)

    def stop_collector(self):
        log.info("stopping-pm-collection", device_name=self.name,
                 device_id=self.device.id)
        self.lc.stop()


class AdapterAlarms:
    def __init__(self, adapter, device):
        self.adapter = adapter
        self.device = device
        self.lc = None

    def send_alarm(self, context_data, alarm_data):
        try:
            current_context = {}
            for key, value in context_data.__dict__.items():
                current_context[key] = str(value)

            alarm_event = self.adapter.adapter_agent.create_alarm(
                resource_id=self.device.id,
                description="{}.{} - {}".format(self.adapter.name,
                                                self.device.id,
                                                alarm_data[
                                                    'description']) if 'description' in alarm_data else None,
                type=alarm_data['type'] if 'type' in alarm_data else None,
                category=alarm_data[
                    'category'] if 'category' in alarm_data else None,
                severity=alarm_data[
                    'severity'] if 'severity' in alarm_data else None,
                state=alarm_data['state'] if 'state' in alarm_data else None,
                raised_ts=alarm_data['ts'] if 'ts' in alarm_data else 0,
                context=current_context
            )

            self.adapter.adapter_agent.submit_alarm(self.device.id,
                                                    alarm_event)

        except Exception as e:
            log.exception('failed-to-send-alarm', e=e)


class PonSimOltAdapter(OltAdapter):
    def __init__(self, adapter_agent, config):
        super(PonSimOltAdapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class=PonSimOltHandler,
                                               name='ponsim_olt',
                                               vendor='Voltha project',
                                               version='0.4',
                                               device_type='ponsim_olt',
                                               accepts_bulk_flow_update=True,
                                               accepts_add_remove_flow_updates=False)

    def update_pm_config(self, device, pm_config):
        log.info("adapter-update-pm-config", device=device,
                 pm_config=pm_config)
        handler = self.devices_handlers[device.id]
        handler.update_pm_config(device, pm_config)

    def create_interface(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('create-interface', device_id=device.id)
            self.devices_handlers[device.id].create_interface(data)

    def update_interface(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('update-interface', device_id=device.id)
            self.devices_handlers[device.id].update_interface(data)

    def remove_interface(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('remove-interface', device_id=device.id)
            self.devices_handlers[device.id].remove_interface(data)

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('create-tcont', device_id=device.id)
            self.devices_handlers[device.id].create_tcont(
                tcont_data, traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('update-tcont', device_id=device.id)
            self.devices_handlers[device.id].update_tcont(
                tcont_data, traffic_descriptor_data)

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('remove-tcont', device_id=device.id)
            self.devices_handlers[device.id].remove_tcont(
                tcont_data, traffic_descriptor_data)

    def create_gemport(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('create-gemport', device_id=device.id)
            self.devices_handlers[device.id].create_gemport(data)

    def update_gemport(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('update-gemport', device_id=device.id)
            self.devices_handlers[device.id].update_gemport(data)

    def remove_gemport(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('remove-gemport', device_id=device.id)
            self.devices_handlers[device.id].remove_gemport(data)

    def create_multicast_gemport(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('create-multicast-gemport', device_id=device.id)
            self.devices_handlers[device.id].create_multicast_gemport(data)

    def update_multicast_gemport(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('update-multicast-gemport', device_id=device.id)
            self.devices_handlers[device.id].update_multicast_gemport(data)

    def remove_multicast_gemport(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('remove-multicast-gemport', device_id=device.id)
            self.devices_handlers[device.id].remove_multicast_gemport(data)

    def create_multicast_distribution_set(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('create-multicast-distribution-set', device_id=device.id)
            self.devices_handlers[device.id].create_multicast_distribution_set(
                data)

    def update_multicast_distribution_set(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('update-multicast-distribution-set', device_id=device.id)
            self.devices_handlers[device.id].update_multicast_distribution_set(
                data)

    def remove_multicast_distribution_set(self, device, data):
        if super(PonSimOltAdapter, self)._get_handler(device):
            log.info('remove-multicast-distribution-set', device_id=device.id)
            self.devices_handlers[device.id].remove_multicast_distribution_set(
                data)

    def simulate_alarm(self, device, alarm):
        handler = self.devices_handlers[device.id]
        handler.simulate_alarm(alarm)
        return OperationResp(code=OperationResp.OPERATION_SUCCESS)

class PonSimOltHandler(object):
    xpon_ponsim_olt_itfs = {
        'create_interface': {
            'method_name': 'CreateInterface',
            'log': 'create-interface'},
        'update_interface': {
            'method_name': 'UpdateInterface',
            'log': 'update-interface'},
        'remove_interface': {
            'method_name': 'RemoveInterface',
            'log': 'remove-interface'},
        'create_tcont': {
            'method_name': 'CreateTcont',
            'log': 'create-tconts-config-data'},
        'update_tcont': {
            'method_name': 'UpdateTcont',
            'log': 'update-tconts-config-data'},
        'remove_tcont': {
            'method_name': 'RemoveTcont',
            'log': 'remove-tconts-config-data'},
        'create_gemport': {
            'method_name': 'CreateGemport',
            'log': 'create-gemports-config-data'},
        'update_gemport': {
            'method_name': 'UpdateGemport',
            'log': 'update-gemports-config-data'},
        'remove_gemport': {
            'method_name': 'RemoveGemport',
            'log': 'remove-gemports-config-data'},
        'create_multicast_gemport': {
            'method_name': 'CreateMulticastGemport',
            'log': 'create-multicast-gemports-config-data'},
        'update_multicast_gemport': {
            'method_name': 'UpdateMulticastGemport',
            'log': 'update-multicast-gemports-config-data'},
        'remove_multicast_gemport': {
            'method_name': 'RemoveMulticastGemport',
            'log': 'remove-multicast-gemports-config-data'},
        'create_multicast_distribution_set': {
            'method_name': 'CreateMulticastDistributionSet',
            'log': 'create-multicast-distribution-set-data'},
        'update_multicast_distribution_set': {
            'method_name': 'UpdateMulticastDistributionSet',
            'log': 'update-multicast-distribution-set-data'},
        'remove_multicast_distribution_set': {
            'method_name': 'RemoveMulticastDistributionSet',
            'log': 'remove-multicast-distribution-set-data'},
    }

    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.channel = None
        self.io_port = None
        self.logical_device_id = None
        self.nni_port = None
        self.ofp_port_no = None
        self.interface = registry('main').get_args().interface
        self.ponsim_comm = registry('main').get_args().ponsim_comm
        self.pm_metrics = None
        self.alarms = None
        self.frames = None
        self.ctag_map = {}

    def __del__(self):
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)

    def get_channel(self):
        if self.channel is None:
            device = self.adapter_agent.get_device(self.device_id)

            self.channel = grpc.insecure_channel(device.host_and_port)

        return self.channel

    def close_channel(self):
        if self.channel is None:
            self.log.info('grpc-channel-already-closed')
            return
        else:
            if self.frames is not None:
                self.frames.cancel()
                self.frames = None
                self.log.info('cancelled-grpc-frame-stream')

            self.channel.unsubscribe(lambda *args: None)
            self.channel = None

            self.log.info('grpc-channel-closed')

    def _get_nni_port(self):
        ports = self.adapter_agent.get_ports(self.device_id, Port.ETHERNET_NNI)
        if ports:
            # For now, we use on one NNI port
            return ports[0]

    # Generate a MAC address based on OLT serial_number (i.e., host_and_port)
    # An example of calculating the same value in the shell:
    #  $ echo -ne olt0.voltha.svc:50060 | md5sum | cut -c -12
    def get_mac_address(self, device):
        hexdig = hashlib.md5(device.serial_number).hexdigest()
        mac_address = "%s:%s:%s:%s:%s:%s" % (hexdig[0:2], hexdig[2:4], hexdig[4:6], hexdig[6:8], hexdig[8:10], hexdig[10:12])
        log.info("generated-mac-address", mac_address=mac_address, serial_number=device.serial_number)
        return mac_address

    def activate(self, device):
        self.log.info('activating')

        if not device.host_and_port:
            device.oper_status = OperStatus.FAILED
            device.reason = 'No host_and_port field provided'
            self.adapter_agent.update_device(device)
            return

        stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())
        info = stub.GetDeviceInfo(Empty())
        log.info('got-info', info=info)

        device.root = True
        device.vendor = 'ponsim'
        device.model = 'n/a'
        device.serial_number = device.host_and_port
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Now set the initial PM configuration for this device
        self.pm_metrics = AdapterPmMetrics(device)
        pm_config = self.pm_metrics.make_proto()
        log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config, init=True)

        # Setup alarm handler
        self.alarms = AdapterAlarms(self.adapter, device)

        nni_port = Port(
            port_no=info.nni_port,
            label='NNI facing Ethernet port',
            type=Port.ETHERNET_NNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.nni_port = nni_port
        self.adapter_agent.add_port(device.id, nni_port)
        self.adapter_agent.add_port(device.id, Port(
            port_no=1,
            label='PON port',
            type=Port.PON_OLT,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        ))

        ld = LogicalDevice(
            # not setting id and datapath_id.  Adapter agent will pick the id
            # and will pick the datapath_id is it is not provided
            desc=ofp_desc(
                hw_desc='simualted pon',
                sw_desc='simualted pon',
                # serial_num=uuid4().hex,
                serial_num=device.serial_number,
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
            root_device_id=device.id
        )

        mac_address = self.get_mac_address(device)
        ld_initialized = self.adapter_agent.create_logical_device(ld,
                                                                  dpid=mac_address)
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.ofp_port_no = info.nni_port
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=info.nni_port,
                hw_addr=mac_str_to_tuple(
                    '00:00:00:00:00:%02x' % info.nni_port),
                name='nni',
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=device.id,
            device_port_no=nni_port.port_no,
            root_port=True
        ))

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)
        self.logical_device_id = ld_initialized.id

        # register ONUS
        for onu in info.onus:
            vlan_id = onu.uni_port
            self.adapter_agent.child_device_detected(
                parent_device_id=device.id,
                parent_port_no=1,
                child_device_type='ponsim_onu',
                proxy_address=Device.ProxyAddress(
                    device_id=device.id,
                    channel_id=vlan_id
                ),
                admin_state=AdminState.ENABLED,
                vlan=vlan_id,
                serial_number=onu.serial_number
            )

        if self.ponsim_comm == 'grpc':
            self.log.info('starting-frame-grpc-stream')
            reactor.callInThread(self.rcv_grpc)
            self.log.info('started-frame-grpc-stream')
        else:
            # finally, open the frameio port to receive in-band packet_in messages
            self.log.info('registering-frameio')
            self.io_port = registry('frameio').open_port(
                self.interface, self.rcv_io, is_inband_frame)
            self.log.info('registered-frameio')

        # Start collecting stats from the device after a brief pause
        self.start_kpi_collection(device.id)

    def reconcile(self, device):
        self.log.info('reconciling-OLT-device-starts')

        if not device.host_and_port:
            device.oper_status = OperStatus.FAILED
            device.reason = 'No host_and_port field provided'
            self.adapter_agent.update_device(device)
            return

        try:
            stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())
            info = stub.GetDeviceInfo(Empty())
            log.info('got-info', info=info)
            # TODO: Verify we are connected to the same device we are
            # reconciling - not much data in ponsim to differentiate at the
            # time
            device.oper_status = OperStatus.ACTIVE
            self.adapter_agent.update_device(device)
            self.ofp_port_no = info.nni_port
            self.nni_port = self._get_nni_port()
        except Exception, e:
            log.exception('device-unreachable', e=e)
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.UNKNOWN
            self.adapter_agent.update_device(device)
            return

        # Now set the initial PM configuration for this device
        self.pm_metrics = AdapterPmMetrics(device)
        pm_config = self.pm_metrics.make_proto()
        log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config, init=True)

        # Setup alarm handler
        self.alarms = AdapterAlarms(self.adapter, device)

        # TODO: Is there anything required to verify nni and PON ports

        # Set the logical device id
        device = self.adapter_agent.get_device(device.id)
        if device.parent_id:
            self.logical_device_id = device.parent_id
            self.adapter_agent.reconcile_logical_device(device.parent_id)
        else:
            self.log.info('no-logical-device-set')

        # Reconcile child devices
        self.adapter_agent.reconcile_child_devices(device.id)

        if self.ponsim_comm == 'grpc':
            reactor.callInThread(self.rcv_grpc)
        else:
            # finally, open the frameio port to receive in-band packet_in messages
            self.io_port = registry('frameio').open_port(
                self.interface, self.rcv_io, is_inband_frame)

        # Start collecting stats from the device after a brief pause
        self.start_kpi_collection(device.id)

        self.log.info('reconciling-OLT-device-ends')

    def _rcv_frame(self, frame):
        pkt = Ether(frame)
        self.log.info('received packet', pkt=pkt)
        if pkt.haslayer(Dot1Q):
            if pkt.haslayer(Dot1AD):
                outer_shim = pkt.getlayer(Dot1AD)
            else:
                outer_shim = pkt.getlayer(Dot1Q)

            if pkt.haslayer(IP) or outer_shim.type == EAP_ETH_TYPE:
                # We don't have any context about the packet at this point.
                # Assume that only downstream traffic is double-tagged.
                if isinstance(outer_shim.payload, Dot1Q):
                    logical_port = int(self.nni_port.port_no)
                else:
                    cvid = outer_shim.vlan
                    logical_port = self.get_subscriber_uni_port(cvid)
                popped_frame = (
                        Ether(src=pkt.src, dst=pkt.dst, type=outer_shim.type) /
                        outer_shim.payload
                )
                kw = dict(
                    logical_device_id=self.logical_device_id,
                    logical_port_no=logical_port,
                )
                self.log.info('sending-packet-in', **kw)
                self.adapter_agent.send_packet_in(
                    packet=str(popped_frame), **kw)

            elif pkt.haslayer(Raw):
                raw_data = json.loads(pkt.getlayer(Raw).load)
                self.alarms.send_alarm(self, raw_data)

    @inlineCallbacks
    def rcv_grpc(self):
        """
        This call establishes a GRPC stream to receive frames.
        """
        stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())

        # Attempt to establish a grpc stream with the remote ponsim service
        self.frames = stub.ReceiveFrames(Empty())

        self.log.info('start-receiving-grpc-frames')

        try:
            for frame in self.frames:
                self.log.info('received-grpc-frame',
                              frame_len=len(frame.payload))
                self._rcv_frame(frame.payload)

        except _Rendezvous, e:
            log.warn('grpc-connection-lost', message=e.message)

        self.log.info('stopped-receiving-grpc-frames')

    def rcv_io(self, port, frame):
        self.log.info('received-io-frame', iface_name=port.iface_name,
                      frame_len=len(frame))
        self._rcv_frame(frame)

    def to_controller(self, flow):
        for action in fd.get_actions(flow):
            if action.type == ofp.OFPAT_OUTPUT:
                action.output.port = ofp.OFPP_CONTROLLER
                self.log.info('sending flow to controller')

    # Lookup UNI port for a particular subscriber ctag
    def get_subscriber_uni_port(self, ctag):
        self.log.debug('get_subscriber_uni_port', ctag=ctag)
        c = int(ctag)
        if c in self.ctag_map:
            return self.ctag_map[c]
        elif self.is_uni_port(c):
            return c
        self.log.debug('get_subscriber_uni_port: no mapping found', ctag=ctag, ctag_map=self.ctag_map)
        return None

    def update_ctag_map(self, ctag, uni_port):
        if ctag is None:
            for (c, u) in self.ctag_map.iteritems():
                if u == int(uni_port):
                    self.log.debug('deleting ctag mapping', ctag=c, uni_port=u)
                    del self.ctag_map[c]
                    return
        else:
            c = int(ctag)
            u = int(uni_port)
            if not self.is_uni_port(u):
                self.log.warning('unknown UNI port', uni_port=u)
            if c in self.ctag_map:
                if self.ctag_map[c] == u:
                    return
                else:
                    self.log.warning('changing UNI port for ctag',
                        ctag=c, old=self.ctag_map[c], new=u)

            self.ctag_map[c] = u
            self.log.debug('added mapping', ctag=c, uni_port=u)

    def is_uni_port(self, vlan_id):
        for onu in self.adapter_agent.get_child_devices(self.device_id):
            if onu.vlan == vlan_id:
                return True
        return False

    def get_classifier_info(self, flow):
        classifier_info = {}
        for field in fd.get_ofb_fields(flow):
            if field.type == fd.ETH_TYPE:
                classifier_info[ETH_TYPE] = field.eth_type
            elif field.type == fd.IP_PROTO:
                classifier_info[IP_PROTO] = field.ip_proto
            elif field.type == fd.IN_PORT:
                classifier_info[IN_PORT] = field.port
            elif field.type == fd.VLAN_VID:
                classifier_info[VLAN_VID] = field.vlan_vid & 0xfff
            elif field.type == fd.VLAN_PCP:
                classifier_info[VLAN_PCP] = field.vlan_pcp
            elif field.type == fd.UDP_DST:
                classifier_info[UDP_DST] = field.udp_dst
            elif field.type == fd.UDP_SRC:
                classifier_info[UDP_SRC] = field.udp_src
            elif field.type == fd.IPV4_DST:
                classifier_info[IPV4_DST] = field.ipv4_dst
            elif field.type == fd.IPV4_SRC:
                classifier_info[IPV4_SRC] = field.ipv4_src
            elif field.type == fd.METADATA:
                classifier_info[METADATA] = field.table_metadata
            else:
                self.log.debug('field-type-unhandled field.type={}'.format(
                    field.type))

        return classifier_info

    # VOLTHA's flow decomposition removes the information about which flows
    # are trap flows where traffic should be forwarded to the controller.
    # We'll go through the flows and change the output port of flows that we
    # know to be trap flows to the OF CONTROLLER port.
    def update_flow_table(self, flows):
        stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())
        self.log.info('pushing-olt-flow-table')

        eapol_flows = {}
        eapol_flow_without_vlan = False

        for flow in flows:
            classifier_info = self.get_classifier_info(flow)

            self.log.debug('classifier_info', classifier_info=classifier_info)

            if IP_PROTO in classifier_info:
                if classifier_info[IP_PROTO] == 17:
                    if UDP_SRC in classifier_info:
                        if classifier_info[UDP_SRC] == 68:
                            self.log.info('dhcp upstream flow add')
                        elif classifier_info[UDP_SRC] == 67:
                            self.log.info('dhcp downstream flow add')
                    self.to_controller(flow)
                elif classifier_info[IP_PROTO] == 2:
                    self.log.info('igmp flow add')
                    self.to_controller(flow)
                else:
                    self.log.warn("Invalid-Classifier-to-handle",
                                   classifier_info=classifier_info)
            elif ETH_TYPE in classifier_info:
                if classifier_info[ETH_TYPE] == EAP_ETH_TYPE:
                    self.log.info('eapol flow add')
                    self.to_controller(flow)
                    if VLAN_VID in classifier_info:
                        eapol_flows[classifier_info[VLAN_VID]] = flow
                    else:
                        eapol_flow_without_vlan = True

        # The OLT app is now adding EAPOL flows with VLAN_VID=4091 but Ponsim can't
        # properly handle this because it uses VLAN_VID to encode the UNI port ID.
        # Add an EAPOL trap flow with no VLAN_VID match if we see the 4091 match.
        if 4091 in eapol_flows and not eapol_flow_without_vlan:
            new_eapol_flow = [
                fd.mk_flow_stat(
                    priority=10000,
                    match_fields=[fd.in_port(1), fd.eth_type(EAP_ETH_TYPE)],
                    actions=[fd.output(ofp.OFPP_CONTROLLER)]
                )
            ]
            flows.extend(new_eapol_flow)
            self.log.info('add eapol flow with no VLAN_VID match')

        stub.UpdateFlowTable(FlowTable(
            port=0,
            flows=flows
        ))
        self.log.info('success')

    def remove_from_flow_table(self, flows):
        self.log.debug('remove-from-flow-table', flows=flows)
        # TODO: Update PONSIM code to accept incremental flow changes
        # Once completed, the accepts_add_remove_flow_updates for this
        # device type can be set to True

    def add_to_flow_table(self, flows):
        self.log.debug('add-to-flow-table', flows=flows)
        # TODO: Update PONSIM code to accept incremental flow changes
        # Once completed, the accepts_add_remove_flow_updates for this
        # device type can be set to True

    def update_pm_config(self, device, pm_config):
        log.info("handler-update-pm-config", device=device,
                 pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    def send_proxied_message(self, proxy_address, msg):
        self.log.debug('sending-proxied-message')
        if isinstance(msg, FlowTable):
            stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())
            self.log.info('pushing-onu-flow-table', port=msg.port)

            # Extract ctag -> uni_port mapping from ONU flows.
            # Below we assume that a downstream flow whose VLAN_VID is not
            # equal to the logcal port is stripping the ctag.
            # If we find such a flow we add the mapping to the ctag_map.
            # Note that this wouldn't be necessary if we actually knew the logical
            # port that an upstream packet arrived on.
            logical_port_id = "uni-{}".format(msg.port)
            logical_port = self.adapter_agent.get_logical_port(self.logical_device_id, logical_port_id)
            if logical_port:
                uni_port_id = logical_port.device_port_no
                ctag = None

                for flow in msg.flows:
                    classifier_info = self.get_classifier_info(flow)
                    self.log.debug('classifier_info', classifier_info=classifier_info)

                    if VLAN_VID in classifier_info and IN_PORT in classifier_info:
                        if classifier_info[IN_PORT] != uni_port_id and classifier_info[VLAN_VID] != msg.port:
                            if ctag is not None:
                                self.log.error('more than one ctag inferred', ctag1=ctag, ctag2=classifier_info[VLAN_VID])
                            ctag = classifier_info[VLAN_VID]

                self.update_ctag_map(ctag, msg.port)
            else:
                self.log.error('no logical port found', id=logical_port_id)

            res = stub.UpdateFlowTable(msg)
            self.adapter_agent.receive_proxied_message(proxy_address, res)
        elif isinstance(msg, PonSimMetricsRequest):
            stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())
            self.log.debug('proxying onu stats request', port=msg.port)
            res = stub.GetStats(msg)
            self.adapter_agent.receive_proxied_message(proxy_address, res)

    def packet_out(self, egress_port, msg):
        self.log.debug('sending-packet-out', egress_port=egress_port,
                       msg_hex=hexify(msg))
        pkt = Ether(msg)
        out_pkt = pkt
        self.log.debug("packet_out: incoming: %s" % pkt.summary())
        if egress_port != self.nni_port.port_no:
            # don't do the vlan manipulation for the NNI port, vlans are already correct
            if pkt.haslayer(Dot1Q):
                if pkt.haslayer(Dot1AD):
                    outer_shim = pkt.getlayer(Dot1AD)
                else:
                    outer_shim = pkt.getlayer(Dot1Q)
                if isinstance(outer_shim.payload, Dot1Q):
                    # If double tag, remove the outer tag
                    out_pkt = (
                            Ether(src=pkt.src, dst=pkt.dst,
                                  type=outer_shim.type) /
                            outer_shim.payload
                    )
                else:
                    out_pkt = pkt
            else:
                # Add egress port as VLAN tag
                out_pkt = (
                    Ether(src=pkt.src, dst=pkt.dst) /
                    Dot1Q(vlan=egress_port, type=pkt.type) /
                    pkt.payload
                )
        self.log.debug("packet_out: outgoing: %s" % out_pkt.summary())

        # TODO need better way of mapping logical ports to PON ports
        out_port = self.nni_port.port_no if egress_port == self.nni_port.port_no else 1

        if self.ponsim_comm == 'grpc':
            # send over grpc stream
            stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())
            frame = PonSimFrame(id=self.device_id, payload=str(out_pkt), out_port=out_port)
            stub.SendFrame(frame)
        else:
            # send over frameio
            self.io_port.send(str(out_pkt))

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

        # Update the child devices connect state to UNREACHABLE
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      connect_status=ConnectStatus.UNREACHABLE)

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

        # Update the child devices connect state to REACHABLE
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      connect_status=ConnectStatus.REACHABLE)

        self.log.info('rebooted', device_id=self.device_id)

    def self_test_device(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        log.info('self-test-device', device=device.id)
        raise NotImplementedError()

    def disable(self):
        self.log.info('disabling', device_id=self.device_id)

        self.stop_kpi_collection()

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Update the operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      admin_state=AdminState.DISABLED)

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        # Set all ports to disabled
        self.adapter_agent.disable_all_ports(self.device_id)

        self.close_channel()
        self.log.info('disabled-grpc-channel')

        if self.ponsim_comm == 'frameio':
            # close the frameio port
            registry('frameio').close_port(self.io_port)
            self.log.info('disabled-frameio-port')

        self.log.info('disabled', device_id=device.id)

    def reenable(self):
        self.log.info('re-enabling', device_id=self.device_id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Set the ofp_port_no and nni_port in case we bypassed the reconcile
        # process if the device was in DISABLED state on voltha restart
        if not self.ofp_port_no and not self.nni_port:
            stub = ponsim_pb2_grpc.PonSimStub(self.get_channel())
            info = stub.GetDeviceInfo(Empty())
            log.info('got-info', info=info)
            self.ofp_port_no = info.nni_port
            self.nni_port = self._get_nni_port()

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Set all ports to enabled
        self.adapter_agent.enable_all_ports(self.device_id)

        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        # Reenable all child devices
        self.adapter_agent.update_child_devices_state(device.id,
                                                      admin_state=AdminState.ENABLED)

        if self.ponsim_comm == 'grpc':
            # establish frame grpc-stream
            reactor.callInThread(self.rcv_grpc)
        else:
            # finally, open the frameio port to receive in-band packet_in messages
            self.io_port = registry('frameio').open_port(
                self.interface, self.rcv_io, is_inband_frame)

        self.start_kpi_collection(device.id)

        self.log.info('re-enabled', device_id=device.id)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        # Remove all child devices
        self.adapter_agent.delete_all_child_devices(self.device_id)

        self.close_channel()
        self.log.info('disabled-grpc-channel')

        if self.ponsim_comm == 'frameio':
            # close the frameio port
            registry('frameio').close_port(self.io_port)
            self.log.info('disabled-frameio-port')

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('deleted', device_id=self.device_id)

    def start_kpi_collection(self, device_id):

        def _collect(device_id, prefix):

            try:
                # Step 1: gather metrics from device
                port_metrics = \
                    self.pm_metrics.collect_port_metrics(self.get_channel())

                # Step 2: prepare the KpiEvent for submission
                # we can time-stamp them here (or could use time derived from OLT
                ts = arrow.utcnow().timestamp
                kpi_event = KpiEvent(
                    type=KpiEventType.slice,
                    ts=ts,
                    prefixes={
                        # OLT NNI port
                        prefix + '.nni': MetricValuePairs(
                            metrics=port_metrics['nni']),
                        # OLT PON port
                        prefix + '.pon': MetricValuePairs(
                            metrics=port_metrics['pon'])
                    }
                )

                # Step 3: submit
                self.adapter_agent.submit_kpis(kpi_event)

            except Exception as e:
                log.exception('failed-to-submit-kpis', e=e)

        self.pm_metrics.start_collector(_collect)

    def stop_kpi_collection(self):
        self.pm_metrics.stop_collector()

    def get_interface_config(self, data):
        interfaceConfig = InterfaceConfig()
        if isinstance(data, ChannelgroupConfig):
            interfaceConfig.channel_group_config.CopyFrom(data)
        elif isinstance(data, ChannelpartitionConfig):
            interfaceConfig.channel_partition_config.CopyFrom(data)
        elif isinstance(data, ChannelpairConfig):
            interfaceConfig.channel_pair_config.CopyFrom(data)
        elif isinstance(data, ChannelterminationConfig):
            interfaceConfig.channel_termination_config.CopyFrom(data)
        elif isinstance(data, OntaniConfig):
            interfaceConfig.ont_ani_config.CopyFrom(data)
        elif isinstance(data, VOntaniConfig):
            interfaceConfig.vont_ani_config.CopyFrom(data)
        elif isinstance(data, VEnetConfig):
            interfaceConfig.venet_config.CopyFrom(data)
        elif isinstance(data, TrafficDescriptorProfileData):
            interfaceConfig.traffic_descriptor_profile_config_data.CopyFrom(
                data)
        elif isinstance(data, TcontsConfigData):
            interfaceConfig.tconts_config_data.CopyFrom(data)
        elif isinstance(data, GemportsConfigData):
            interfaceConfig.gemports_config_data.CopyFrom(data)
        elif isinstance(data, MulticastGemportsConfigData):
            interfaceConfig.multicast_gemports_config_data.CopyFrom(data)
        elif isinstance(data, MulticastDistributionSetData):
            interfaceConfig.multicast_distribution_set_data.CopyFrom(data)
        else:
            return None
        return interfaceConfig

    def xpon_ponsim_olt_interface(self, method_name, data, data2=None):
        interfaceConfig = self.get_interface_config(data)
        if interfaceConfig is not None:
            self.log.info(
                'forwarding-{}-request-to-olt-for-interface-type'
                    .format(self.xpon_ponsim_olt_itfs[method_name]['log']),
                interface_type=type(data))
            stub = ponsim_pb2_grpc.XPonSimStub(self.get_channel())
            _method = getattr(
                stub, self.xpon_ponsim_olt_itfs[method_name]['method_name'])
            if isinstance(data, TcontsConfigData):
                tcont_config = TcontInterfaceConfig()
                tcont_config.tconts_config_data.CopyFrom(data)
                tcont_config.traffic_descriptor_profile_config_data.CopyFrom(
                    data2)
                _method(tcont_config)
            else:
                _method(interfaceConfig)
            self.log.info('success')

    def create_interface(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def update_interface(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def remove_interface(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def create_tcont(self, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, tcont_data,
                                       traffic_descriptor_data);

    def update_tcont(self, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, tcont_data,
                                       traffic_descriptor_data);

    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, tcont_data,
                                       traffic_descriptor_data);

    def create_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def update_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def remove_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def create_multicast_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def update_multicast_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def remove_multicast_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def create_multicast_distribution_set(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def update_multicast_distribution_set(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def remove_multicast_distribution_set(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_olt_interface(_method_name, data);

    def simulate_alarm(self, alarm):
        # Ponsim_olt implements its own AdapterAlarms class, rather than using the Voltha alarm extension. Until that
        # has been reconciled, temporarily instantiate the Voltha alarm extension's AdapterAlarms here, for the
        # purpose of sending simulated alarms.
        alarms = VolthaAdapterAlarms(self.adapter_agent, self.device_id, self.logical_device_id)
        simulator = AdapterAlarmSimulator(alarms)
        simulator.simulate_alarm(alarm)
