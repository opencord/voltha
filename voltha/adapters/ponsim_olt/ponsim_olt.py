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
from uuid import uuid4

import arrow
import grpc
import structlog
from scapy.layers.l2 import Ether, Dot1Q
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from zope.interface import implementer

from common.frameio.frameio import BpfProgramFilter, hexify
from common.utils.asleep import asleep
from twisted.internet.task import LoopingCall
from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos import ponsim_pb2
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Device, \
PmConfig, PmConfigs
from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs
from voltha.protos.health_pb2 import HealthStatus
from google.protobuf.empty_pb2 import Empty

from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPF_1GB_FD, \
    OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS, \
    ofp_switch_features, ofp_desc
from voltha.protos.openflow_13_pb2 import ofp_port
from voltha.protos.ponsim_pb2 import FlowTable
from voltha.registry import registry

_ = third_party
log = structlog.get_logger()


PACKET_IN_VLAN = 4000
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))

class AdapterPmMetrics:
    def __init__(self,device):
        self.pm_names = {'tx_64','tx_65_127', 'tx_128_255', 'tx_256_511',
                        'tx_512_1023', 'tx_1024_1518', 'tx_1519_9k', 'rx_64',
                        'rx_65_127', 'rx_128_255', 'rx_256_511', 'rx_512_1023',
                        'rx_1024_1518', 'rx_1519_9k'}
        self.device = device
        self.id = device.id
        self.name = 'ponsim_olt'
        #self.id = "abc"
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
            self.lc.start(interval=self.default_freq/10)
        for m in pm_config.metrics:
            self.pon_metrics_config[m.name].enabled = m.enabled
            self.nni_metrics_config[m.name].enabled = m.enabled

    def make_proto(self):
        pm_config = PmConfigs(
            id=self.id,
            default_freq=self.default_freq,
            grouped = False,
            freq_override = False)
        for m in sorted(self.pon_metrics_config):
            pm=self.pon_metrics_config[m] # Either will do they're the same
            pm_config.metrics.extend([PmConfig(name=pm.name,
                                               type=pm.type,
                                               enabled=pm.enabled)])
        return pm_config

    def collect_port_metrics(self, channel):
        rtrn_port_metrics = dict()
        stub = ponsim_pb2.PonSimStub(channel)
        stats = stub.GetStats(Empty())
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
        self.lc.start(interval=self.default_freq/10)


@implementer(IAdapterInterface)
class PonSimOltAdapter(object):

    name = 'ponsim_olt'

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
        self.logical_device_id_to_root_device_id = dict()

    def start(self):
        log.debug('starting')
        log.info('started')

    def stop(self):
        """
        This method is called when this device instance is no longer
        required,  which means there is a request to remove this device.
        :return:
        """
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

    def update_pm_config(self, device, pm_config):
        log.info("adapter-update-pm-config", device=device, pm_config=pm_config)
        handler = self.devices_handlers[device.id]
        handler.update_pm_config(device, pm_config)

    def adopt_device(self, device):
        self.devices_handlers[device.id] = PonSimOltHandler(self, device.id)
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
        log.info('reboot-device', device_id=device.id)
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
        handler = self.devices_handlers[proxy_address.device_id]
        handler.send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):

        def ldi_to_di(ldi):
            di = self.logical_device_id_to_root_device_id.get(ldi)
            if di is None:
                logical_device = self.adapter_agent.get_logical_device(ldi)
                di = logical_device.root_device_id
                self.logical_device_id_to_root_device_id[ldi] = di
            return di

        device_id = ldi_to_di(logical_device_id)
        handler = self.devices_handlers[device_id]
        handler.packet_out(egress_port_no, msg)


class PonSimOltHandler(object):

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
        self.pm_metrics = None

    def __del__(self):
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)

    def get_channel(self):
        if self.channel is None:
            device = self.adapter_agent.get_device(self.device_id)
            self.channel = grpc.insecure_channel(device.host_and_port)
        return self.channel

    def activate(self, device):
        self.log.info('activating')

        if not device.host_and_port:
            device.oper_status = OperStatus.FAILED
            device.reason = 'No host_and_port field provided'
            self.adapter_agent.update_device(device)
            return

        stub = ponsim_pb2.PonSimStub(self.get_channel())
        info = stub.GetDeviceInfo(Empty())
        log.info('got-info', info=info)

        device.root = True
        device.vendor = 'ponsim'
        device.model ='n/a'
        device.serial_number = device.host_and_port
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Now set the initial PM configuration for this device
        self.pm_metrics=AdapterPmMetrics(device)
        pm_config = self.pm_metrics.make_proto()
        log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config,init=True)

        nni_port = Port(
            port_no=2,
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
            # not setting id and datapth_id will let the adapter agent pick id
            desc=ofp_desc(
                mfr_desc='cord porject',
                hw_desc='simualted pon',
                sw_desc='simualted pon',
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
            root_device_id=device.id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.ofp_port_no = info.nni_port
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=info.nni_port,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % info.nni_port),
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

        # register ONUS per uni port
        for port_no in info.uni_ports:
            vlan_id = port_no
            self.adapter_agent.child_device_detected(
                parent_device_id=device.id,
                parent_port_no=1,
                child_device_type='ponsim_onu',
                proxy_address=Device.ProxyAddress(
                    device_id=device.id,
                    channel_id=vlan_id
                ),
                vlan=vlan_id
            )

        # finally, open the frameio port to receive in-band packet_in messages
        self.log.info('registering-frameio')
        self.io_port = registry('frameio').open_port(
            self.interface, self.rcv_io, is_inband_frame)
        self.log.info('registered-frameio')

        # Start collecting stats from the device after a brief pause
        self.start_kpi_collection(device.id)

    def rcv_io(self, port, frame):
        self.log.info('reveived', iface_name=port.iface_name,
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



    def update_flow_table(self, flows):
        stub = ponsim_pb2.PonSimStub(self.get_channel())
        self.log.info('pushing-olt-flow-table')
        stub.UpdateFlowTable(FlowTable(
            port=0,
            flows=flows
        ))
        self.log.info('success')

    def update_pm_config(self, device, pm_config):
        log.info("handler-update-pm-config", device=device, pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    def send_proxied_message(self, proxy_address, msg):
        self.log.info('sending-proxied-message')
        if isinstance(msg, FlowTable):
            stub = ponsim_pb2.PonSimStub(self.get_channel())
            self.log.info('pushing-onu-flow-table', port=msg.port)
            res = stub.UpdateFlowTable(msg)
            self.adapter_agent.receive_proxied_message(proxy_address, res)

    def packet_out(self, egress_port, msg):
        self.log.info('sending-packet-out', egress_port=egress_port,
                      msg=hexify(msg))
        pkt = Ether(msg)
        out_pkt = (
            Ether(src=pkt.src, dst=pkt.dst) /
            Dot1Q(vlan=4000) /
            Dot1Q(vlan=egress_port, type=pkt.type) /
            pkt.payload
        )
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

        # Sleep 10 secs, simulating a reboot
        #TODO: send alert and clear alert after the reboot
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

        # Update the operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the logical device
        logical_device = self.adapter_agent.get_logical_device(
                                                    self.logical_device_id)
        self.adapter_agent.delete_logical_device(logical_device)

        # Disable all child devices first
        self.adapter_agent.disable_all_child_devices(self.device_id)

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        # Set all ports to disabled
        self.adapter_agent.disable_all_ports(self.device_id)

        # close the frameio port
        registry('frameio').close_port(self.io_port)

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('disabled', device_id=device.id)


    def reenable(self):
        self.log.info('re-enabling', device_id=self.device_id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Set all ports to enabled
        self.adapter_agent.enable_all_ports(self.device_id)

        ld = LogicalDevice(
            # not setting id and datapth_id will let the adapter agent pick id
            desc=ofp_desc(
                mfr_desc='cord porject',
                hw_desc='simulated pon',
                sw_desc='simulated pon',
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
            root_device_id=device.id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=self.ofp_port_no,
                hw_addr=mac_str_to_tuple(
                    '00:00:00:00:00:%02x' % self.ofp_port_no),
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
            device_port_no=self.nni_port.port_no,
            root_port=True
        ))

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)
        self.logical_device_id = ld_initialized.id

        # Reenable all child devices
        self.adapter_agent.reenable_all_child_devices(device.id)

        # finally, open the frameio port to receive in-band packet_in messages
        self.log.info('registering-frameio')
        self.io_port = registry('frameio').open_port(
            self.interface, self.rcv_io, is_inband_frame)
        self.log.info('registered-frameio')

        self.log.info('re-enabled', device_id=device.id)


    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        # Remove all child devices
        self.adapter_agent.delete_all_child_devices(self.device_id)

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

