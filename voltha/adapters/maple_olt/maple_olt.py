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
Maple OLT/ONU adapter.
"""
from uuid import uuid4

import arrow
import structlog
from scapy.layers.l2 import Ether, Dot1Q
from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.spread import pb
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue
from zope.interface import implementer

from common.frameio.frameio import BpfProgramFilter, hexify

from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
import voltha.core.flow_decomposer as fd
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Device
from voltha.protos.health_pb2 import HealthStatus
from google.protobuf.empty_pb2 import Empty
from voltha.protos.events_pb2 import KpiEvent, MetricValuePairs
from voltha.protos.events_pb2 import KpiEventType
from voltha.protos.events_pb2 import AlarmEvent, AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory

from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, OFPP_CONTROLLER, OFPXMC_OPENFLOW_BASIC, \
    ofp_switch_features, ofp_desc, ofp_port
from voltha.registry import registry
from voltha.extensions.omci.omci import *

_ = third_party
log = structlog.get_logger()

PACKET_IN_VLAN = 4091
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))


class MapleOltRxHandler(pb.Root):
    def __init__(self, device_id, adapter):
        self.device_id = device_id
        self.adapter_agent = adapter.adapter_agent
        self.adapter_name = adapter.name
        # registry('main').get_args().external_host_address
        self.pb_server_ip = '192.168.24.20'
        self.pb_server_port = 24497
        self.pb_server_factory = pb.PBServerFactory(self)
        # start PB server
        self.listen_port = reactor.listenTCP(self.pb_server_port,
                                             self.pb_server_factory)
        self.omci_rx_queue = DeferredQueue()
        log.info('PB-server-started-on-port', port=self.pb_server_port)

    def get_ip(self):
        return self.pb_server_ip

    def get_port(self):
        return self.pb_server_port

    def get_host(self):
        return self.listen_port.getHost()

    def remote_echo(self, pkt_type, pon, onu, port, crc_ok, msg_size, msg_data):
        log.info('received-omci-msg',
                 pkt_type=pkt_type,
                 pon_id=pon,
                 onu_id=onu,
                 port_id=port,
                 crc_ok=crc_ok,
                 msg_size=msg_size,
                 msg_data=hexify(msg_data))
        self.omci_rx_queue.put((onu, msg_data))

    def receive_omci_msg(self):
        return self.omci_rx_queue.get()

    def remote_report_stats(self, object, key, stats_data):
        log.info('received-stats-msg',
                 object=object,
                 key=key,
                 stats=stats_data)

        prefix = 'voltha.{}.{}'.format(self.adapter_name, self.device_id)

        try:
            ts = arrow.utcnow().timestamp

            prefixes = {
                prefix + '.nni': MetricValuePairs(metrics=stats_data)
                }

            kpi_event = KpiEvent(
                type=KpiEventType.slice,
                ts=ts,
                prefixes=prefixes
            )

            self.adapter_agent.submit_kpis(kpi_event)

        except Exception as e:
            log.exception('failed-to-submit-kpis', e=e)

    def remote_report_event(self, object, key, event, event_data=None):
        log.info('received-event-msg',
                 object=object,
                 key=key,
                 event_str=event,
                 event_data=event_data)

    def remote_report_alarm(self, object, key, alarm, status, priority,
                            alarm_data=None):
        log.info('received-alarm-msg',
                 object=object,
                 key=key,
                 alarm=alarm,
                 status=status,
                 priority=priority,
                 alarm_data=alarm_data)

        id = 'voltha.{}.{}.{}'.format(self.adapter_name, self.device_id, object)
        description = '{} Alarm - {} - {}'.format(object.upper(), alarm.upper(),
                                                  'Raised' if status else 'Cleared')

        if priority == 'low':
            severity = AlarmEventSeverity.MINOR
        elif priority == 'medium':
            severity = AlarmEventSeverity.MAJOR
        elif priority == 'high':
            severity = AlarmEventSeverity.CRITICAL
        else:
            severity = AlarmEventSeverity.INDETERMINATE

        try:
            ts = arrow.utcnow().timestamp

            alarm_event = self.adapter_agent.create_alarm(
                id=id,
                resource_id=str(key),
                type=AlarmEventType.EQUIPMENT,
                category=AlarmEventCategory.PON,
                severity=severity,
                state=AlarmEventState.RAISED if status else \
                      AlarmEventState.CLEARED,
                description=description,
                context=alarm_data,
                raised_ts = ts)

            self.adapter_agent.submit_alarm(alarm_event)

        except Exception as e:
            log.exception('failed-to-submit-alarm', e=e)



@implementer(IAdapterInterface)
class MapleOltAdapter(object):
    name = 'maple_olt'

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
        self.devices_handlers = dict()  # device_id -> MapleOltHandler()
        self.logical_device_id_to_root_device_id = dict()

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
        self.devices_handlers[device.id] = MapleOltHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        raise NotImplementedError()

    def reenable_device(self, device):
        raise NotImplementedError()

    def reboot_device(self, device):
        raise NotImplementedError()

    def delete_device(self, device):
        raise NotImplementedError()

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0, "Cannot yet deal with groups"
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(flows.items, device)

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


class MaplePBClientFactory(pb.PBClientFactory, ReconnectingClientFactory):
    channel = None
    maxDelay = 60
    initialDelay = 15

    def clientConnectionMade(self, broker):
        log.info('pb-client-connection-made')
        pb.PBClientFactory.clientConnectionMade(self, broker)
        ReconnectingClientFactory.resetDelay(self)

    def clientConnectionLost(self, connector, reason, reconnecting=0):
        log.info('pb-client-connection-lost')
        pb.PBClientFactory.clientConnectionLost(self, connector, reason,
                                                reconnecting=1)
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)
        log.info('pb-client-connection-lost-retrying')

    def clientConnectionFailed(self, connector, reason):
        log.info('pb-client-connection-failed')
        pb.PBClientFactory.clientConnectionFailed(self, connector, reason)
        ReconnectingClientFactory.clientConnectionFailed(self, connector,
                                                         reason)
        log.info('pb-client-connection-failed-retrying')

    def disconnect(self, stopTrying=0):
        if stopTrying:
            ReconnectingClientFactory.stopTrying(self)
        pb.PBClientFactory.disconnect(self)

    def channel_disconnected(self, channel):
        log.info('pb-channel-disconnected', channel=channel)
        self.disconnect()

    @inlineCallbacks
    def getChannel(self):
        if self.channel is None:
            try:
                self.channel = yield self.getRootObject()
                self.channel.notifyOnDisconnect(self.channel_disconnected)
            except Exception as e:
                log.info('pb-client-failed-to-get-channel', exc=str(e))
                self.channel = None
        returnValue(self.channel)


class MapleOltHandler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.io_port = None
        self.logical_device_id = None
        self.interface = registry('main').get_args().interface
        self.pbc_factory = MaplePBClientFactory()
        self.pbc_port = 24498
        self.tx_id = 0
        self.rx_handler = MapleOltRxHandler(self.device_id, self.adapter)
        self.heartbeat_count = 0
        self.heartbeat_miss = 0
        self.heartbeat_interval = 1
        self.heartbeat_failed_limit = 3
        self.command_timeout = 5

    def __del__(self):
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)

    def get_channel(self):
        return self.pbc_factory.getChannel()

    def get_vlan_from_onu(self, onu):
        vlan = onu + 1024
        return vlan

    def get_onu_from_vlan(self, vlan):
        onu = vlan - 1024
        return onu

    @inlineCallbacks
    def send_set_remote(self):
        srv_ip = self.rx_handler.get_ip()
        srv_port = self.rx_handler.get_port()
        self.log.info('setting-remote-ip-port', ip=srv_ip, port=srv_port)

        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('set_remote', srv_ip, srv_port)
            self.log.info('set-remote', data=data, ip=srv_ip, port=srv_port)
        except Exception as e:
            self.log.info('set-remote-exception', exc=str(e))

    @inlineCallbacks
    def send_config_classifier(self, olt_no, etype, ip_proto=None,
                               dst_port=None):
        self.log.info('configuring-classifier',
                      olt=olt_no,
                      etype=etype,
                      ip_proto=ip_proto,
                      dst_port=dst_port)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('config_classifier',
                                           olt_no,
                                           etype,
                                           ip_proto,
                                           dst_port)
            self.log.info('configured-classifier', data=data)
        except Exception as e:
            self.log.info('config-classifier-exception', exc=str(e))

    @inlineCallbacks
    def send_config_acflow(self, olt_no, onu_no, etype, ip_proto=None,
                           dst_port=None):
        self.log.info('configuring-acflow',
                      olt=olt_no,
                      onu=onu_no,
                      etype=etype,
                      ip_proto=ip_proto,
                      dst_port=dst_port)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('config_acflow',
                                           olt_no,
                                           onu_no,
                                           etype,
                                           ip_proto,
                                           dst_port)

            self.log.info('configured-acflow', data=data)
        except Exception as e:
            self.log.info('config-acflow-exception', exc=str(e))

    @inlineCallbacks
    def send_connect_olt(self, olt_no):
        self.log.info('connecting-to-olt', olt=olt_no)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('connect_olt', olt_no)
            self.log.info('connected-to-olt', data=data)
        except Exception as e:
            self.log.info('connect-olt-exception', exc=str(e))

    @inlineCallbacks
    def send_activate_olt(self, olt_no):
        self.log.info('activating-olt', olt=olt_no)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('activate_olt', olt_no)
            self.log.info('activated-olt', data=data)
        except Exception as e:
            self.log.info('activate-olt-exception', exc=str(e))

    @inlineCallbacks
    def send_create_onu(self, olt_no, onu_no, serial_no, vendor_no):
        self.log.info('creating-onu',
                      olt=olt_no,
                      onu=onu_no,
                      serial=serial_no,
                      vendor=vendor_no)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('create_onu',
                                           olt_no,
                                           onu_no,
                                           serial_no,
                                           vendor_no)
            self.log.info('created-onu', data=data)
        except Exception as e:
            self.log.info('create-onu-exception', exc=str(e))

    @inlineCallbacks
    def send_configure_alloc_id(self, olt_no, onu_no, alloc_id):
        self.log.info('configuring-alloc-id',
                      olt=olt_no,
                      onu=onu_no,
                      alloc_id=alloc_id)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('configure_alloc_id',
                                           olt_no,
                                           onu_no,
                                           alloc_id)
            self.log.info('configured-alloc-id', data=data)
        except Exception as e:
            self.log.info('configure-alloc-id-exception', exc=str(e))

    @inlineCallbacks
    def send_configure_unicast_gem(self, olt_no, onu_no, uni_gem):
        self.log.info('configuring-unicast-gem',
                      olt=olt_no,
                      onu=onu_no,
                      unicast_gem_port=uni_gem)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('configure_unicast_gem',
                                           olt_no,
                                           onu_no,
                                           uni_gem)
            self.log.info('configured-unicast-gem', data=data)
        except Exception as e:
            self.log.info('configure-unicast-gem-exception', exc=str(e))

    @inlineCallbacks
    def send_configure_multicast_gem(self, olt_no, onu_no, multi_gem):
        self.log.info('configuring-multicast-gem',
                      olt=olt_no,
                      onu=onu_no,
                      multicast_gem_port=multi_gem)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('configure_multicast_gem',
                                           olt_no,
                                           onu_no,
                                           multi_gem)
            self.log.info('configured-multicast-gem', data=data)
        except Exception as e:
            self.log.info('configure-multicast-gem-exception', exc=str(e))

    @inlineCallbacks
    def send_configure_onu(self, olt_no, onu_no, alloc_id, uni_gem, multi_gem):
        self.log.info('configuring-onu',
                      olt=olt_no,
                      onu=onu_no,
                      alloc_id=alloc_id,
                      unicast_gem_port=uni_gem,
                      multicast_gem_port=multi_gem)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('configure_onu',
                                           olt_no,
                                           onu_no,
                                           alloc_id,
                                           uni_gem,
                                           multi_gem)
            self.log.info('configured-onu', data=data)
        except Exception as e:
            self.log.info('configure-onu-exception', exc=str(e))

    @inlineCallbacks
    def send_activate_onu(self, olt_no, onu_no):
        self.log.info('activating-onu', olt=olt_no, onu=onu_no)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('activate_onu', olt_no, onu_no)
            self.log.info('activated-onu', data=data)
        except Exception as e:
            self.log.info('activate-onu-exception', exc=str(e))


    @inlineCallbacks
    def heartbeat(self, device_id, state='run'):
        """Heartbeat OLT hardware

        Call PB remote method 'heartbeat' to verify connectivity to OLT
        hardware. If heartbeat missed self.heartbeat_failed_limit times OLT
        adapter is set FAILED/UNREACHABLE.
        No further action from VOLTHA core is expected as result of heartbeat
        failure. Heartbeat continues following failure and once connectivity is
        restored adapter state will be set to ACTIVE/REACHABLE

        Arguments:
        device_id: adapter device id
        state: desired state (stop, start, run)
        """

        self.log.debug('olt-heartbeat', device=device_id, state=state,
                       count=self.heartbeat_count)

        def add_timeout(d, duration):
            return reactor.callLater(duration, d.cancel)

        def cancel_timeout(t):
            if t.active():
                t.cancel()
                self.log.debug('olt-heartbeat-timeout-cancelled')

        def heartbeat_alarm(device_id, status, heartbeat_misses=0):
            try:
                ts = arrow.utcnow().timestamp

                alarm_data = {'heartbeats_missed':str(heartbeat_misses)}

                alarm_event = self.adapter_agent.create_alarm(
                    id='voltha.{}.{}.olt'.format(self.adapter.name, device_id),
                    resource_id='olt',
                    type=AlarmEventType.EQUIPMENT,
                    category=AlarmEventCategory.PON,
                    severity=AlarmEventSeverity.CRITICAL,
                    state=AlarmEventState.RAISED if status else
                        AlarmEventState.CLEARED,
                    description='OLT Alarm - Heartbeat - {}'.format('Raised'
                                                                    if status
                                                                    else 'Cleared'),
                    context=alarm_data,
                    raised_ts = ts)

                self.adapter_agent.submit_alarm(alarm_event)

            except Exception as e:
                log.exception('failed-to-submit-alarm', e=e)

        if state == 'stop':
            return

        if state == 'start':
            self.heartbeat_count = 0
            self.heartbeat_miss = 0

        try:
            d = self.get_channel()
            timeout = add_timeout(d, self.command_timeout)
            remote = yield d
            cancel_timeout(timeout)

            d = remote.callRemote('heartbeat', self.heartbeat_count)
            timeout = add_timeout(d, self.command_timeout)
            data = yield d
            cancel_timeout(timeout)
        except Exception as e:
            data = -1
            self.log.info('olt-heartbeat-exception', data=data,
                          count=self.heartbeat_miss, exc=str(e))

        if data != self.heartbeat_count:
            # something is not right
            self.heartbeat_miss += 1
            self.log.info('olt-heartbeat-miss', data=data,
                          count=self.heartbeat_count, miss=self.heartbeat_miss)
        else:
            if self.heartbeat_miss > 0:
                self.heartbeat_miss = 0
                _device = self.adapter_agent.get_device(device_id)
                _device.connect_status = ConnectStatus.REACHABLE
                _device.oper_status = OperStatus.ACTIVE
                _device.reason = ''
                self.adapter_agent.update_device(_device)
                heartbeat_alarm(device_id, 0)

        _device = self.adapter_agent.get_device(device_id)
        if (self.heartbeat_miss >= self.heartbeat_failed_limit) and \
           (_device.connect_status == ConnectStatus.REACHABLE):
            self.log.info('olt-heartbeat-failed', data=data,
                          count=self.heartbeat_miss)
            _device = self.adapter_agent.get_device(device_id)
            _device.connect_status = ConnectStatus.UNREACHABLE
            _device.oper_status = OperStatus.FAILED
            _device.reason = 'Lost connectivity to OLT'
            self.adapter_agent.update_device(_device)
            heartbeat_alarm(device_id, 1, self.heartbeat_miss)

        self.heartbeat_count += 1
        reactor.callLater(self.heartbeat_interval, self.heartbeat, device_id)

    @inlineCallbacks
    def activate(self, device):
        self.log.info('activating-olt', device=device)
        if self.logical_device_id is None:
            if not device.ipv4_address:
                device.oper_status = OperStatus.FAILED
                device.reason = 'No ipv4_address field provided'
                self.adapter_agent.update_device(device)
                return

            device.root = True
            device.vendor = 'Broadcom'
            device.model = 'bcm68620'
            device.serial_number = device.ipv4_address
            self.adapter_agent.update_device(device)

            nni_port = Port(
                port_no=2,
                label='NNI facing Ethernet port',
                type=Port.ETHERNET_NNI,
                admin_state=AdminState.ENABLED,
                oper_status=OperStatus.ACTIVE
            )
            self.adapter_agent.add_port(device.id, nni_port)
            self.adapter_agent.add_port(device.id, Port(
                port_no=1,
                label='PON port',
                type=Port.PON_OLT,
                admin_state=AdminState.ENABLED,
                oper_status=OperStatus.ACTIVE
            ))

            ld = LogicalDevice(
                # not setting id and datapth_id will let the adapter
                # agent pick id
                desc=ofp_desc(
                    mfr_desc='cord project',
                    hw_desc='n/a',
                    sw_desc='logical device for Maple-based PON',
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
                    port_no=0,  # is 0 OK?
                    hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
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
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.ACTIVATING
            self.adapter_agent.update_device(device)
            self.logical_device_id = ld_initialized.id

        device = self.adapter_agent.get_device(device.id)
        self.log.info('initiating-connection-to-olt',
                      device_id=device.id,
                      ipv4=device.ipv4_address,
                      port=self.pbc_port)
        try:
            reactor.connectTCP(device.ipv4_address, self.pbc_port, self.pbc_factory)
            device.connect_status = ConnectStatus.REACHABLE
            device.oper_status = OperStatus.ACTIVE
            device.reason = ''
            self.adapter_agent.update_device(device)
        except Exception as e:
            self.log.info('get-channel-exception', exc=str(e))
            device = self.adapter_agent.get_device(device.id)
            device.oper_status = OperStatus.FAILED
            device.reason = 'Failed to connect to OLT'
            self.adapter_agent.update_device(device)
            self.pbc_factory.stopTrying()
            reactor.callLater(5, self.activate, device)
            return

        device = self.adapter_agent.get_device(device.id)
        self.log.info('connected-to-olt',
                       device_id=device.id,
                       ipv4=device.ipv4_address,
                       port=self.pbc_port)

        reactor.callLater(0, self.heartbeat, device.id, state='start')

        yield self.send_set_remote()
        yield self.send_connect_olt(0)
        yield self.send_activate_olt(0)
        # register ONUS per uni port until done asynchronously
        for onu_no in [1]:
            vlan_id = self.get_vlan_from_onu(onu_no)
            yield self.send_create_onu(0, onu_no, '4252434d', '12345678')
            yield self.send_configure_alloc_id(0, onu_no, vlan_id)
            yield self.send_configure_unicast_gem(0,onu_no, vlan_id)
            yield self.send_configure_multicast_gem(0, onu_no, 4000)
            yield self.send_activate_onu(0, onu_no)

            self.adapter_agent.child_device_detected(
                parent_device_id=device.id,
                parent_port_no=1,
                child_device_type='broadcom_onu',
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
        self.log.info('olt-activated', device=device)

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

    @inlineCallbacks
    def update_flow_table(self, flows, device):
        self.log.info('bulk-flow-update', device_id=device.id, flows=flows)

        def is_downstream(port):
            return port == 2  # Need a better way

        def is_upstream(port):
            return not is_downstream(port)

        for flow in flows:
            _type = None
            _ip_proto = None
            _port = None
            _vlan_vid = None
            _udp_dst = None
            _udp_src = None
            _ipv4_dst = None
            _ipv4_src = None
            _metadata = None
            _output = None
            _push_tpid = None
            _field = None

            try:
                _in_port = fd.get_in_port(flow)
                assert _in_port is not None

                if is_downstream(_in_port):
                    self.log.info('downstream-flow')
                elif is_upstream(_in_port):
                    self.log.info('upstream-flow')
                else:
                    raise Exception('port should be 1 or 2 by our convention')

                _out_port = fd.get_out_port(flow)  # may be None
                self.log.info('out-port', out_port=_out_port)

                for field in fd.get_ofb_fields(flow):

                    if field.type == fd.ETH_TYPE:
                        _type = field.eth_type
                        self.log.info('field-type-eth-type',
                                      eth_type=_type)

                    elif field.type == fd.IP_PROTO:
                        _ip_proto = field.ip_proto
                        self.log.info('field-type-ip-proto',
                                      ip_proto=_ip_proto)

                    elif field.type == fd.IN_PORT:
                        _port = field.port
                        self.log.info('field-type-in-port',
                                      in_port=_port)

                    elif field.type == fd.VLAN_VID:
                        _vlan_vid = field.vlan_vid & 0xfff
                        self.log.info('field-type-vlan-vid',
                                      vlan=_vlan_vid)

                    elif field.type == fd.VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        self.log.info('field-type-vlan-pcp',
                                      pcp=_vlan_pcp)

                    elif field.type == fd.UDP_DST:
                        _udp_dst = field.udp_dst
                        self.log.info('field-type-udp-dst',
                                      udp_dst=_udp_dst)

                    elif field.type == fd.UDP_SRC:
                        _udp_src = field.udp_src
                        self.log.info('field-type-udp-src',
                                      udp_src=_udp_src)

                    elif field.type == fd.IPV4_DST:
                        _ipv4_dst = field.ipv4_dst
                        self.log.info('field-type-ipv4-dst',
                                      ipv4_dst=_ipv4_dst)

                    elif field.type == fd.IPV4_SRC:
                        _ipv4_src = field.ipv4_src
                        self.log.info('field-type-ipv4-src',
                                      ipv4_dst=_ipv4_src)

                    elif field.type == fd.METADATA:
                        _metadata = field.metadata
                        self.log.info('field-type-metadata',
                                      metadata=_metadata)

                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in fd.get_actions(flow):

                    if action.type == fd.OUTPUT:
                        _output = action.output.port
                        self.log.info('action-type-output',
                                      output=_output, in_port=_in_port)

                    elif action.type == fd.POP_VLAN:
                        self.log.info('action-type-pop-vlan',
                                      in_port=_in_port)

                    elif action.type == fd.PUSH_VLAN:
                        _push_tpid = action.push.ethertype
                        log.info('action-type-push-vlan',
                                 push_tpid=_push_tpid, in_port=_in_port)
                        if action.push.ethertype != 0x8100:
                            self.log.error('unhandled-tpid',
                                           ethertype=action.push.ethertype)

                    elif action.type == fd.SET_FIELD:
                        _field = action.set_field.field.ofb_field
                        assert (action.set_field.field.oxm_class ==
                                OFPXMC_OPENFLOW_BASIC)
                        self.log.info('action-type-set-field',
                                      field=_field, in_port=_in_port)
                        if _field.type == fd.VLAN_VID:
                            self.log.info('et-field-type-valn-vid',
                                          vlan_vid=_field.vlan_vid & 0xfff)
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type)
                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type, in_port=_in_port)

                if is_upstream(_in_port):
                    yield self.send_config_classifier(0, _type, _ip_proto,
                                                      _udp_dst)
                    yield self.send_config_acflow(0, _in_port, _type, _ip_proto,
                                                  _udp_dst)

            except Exception as e:
                log.exception('failed-to-install-flow', e=e, flow=flow)


    @inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        if isinstance(msg, Packet):
            msg = str(msg)

        self.log.info('send-proxied-message',
                      proxy_address=proxy_address.channel_id,
                      msg=msg)

        try:
            remote = yield self.get_channel()
            yield remote.callRemote("send_omci",
                                    0,
                                    0,
                                    self.get_onu_from_vlan(proxy_address.channel_id),
                                    msg)
            onu, rmsg = yield self.rx_handler.receive_omci_msg()
            self.adapter_agent.receive_proxied_message(proxy_address, rmsg)
        except Exception as e:
            self.log.info('send-proxied_message-exception', exc=str(e))

    def packet_out(self, egress_port, msg):
        self.log.info('sending-packet-out',
                      egress_port=egress_port,
                      msg=hexify(msg))

        pkt = Ether(msg)
        out_pkt = (
            Ether(src=pkt.src, dst=pkt.dst) /
            Dot1Q(vlan=4091) /
            Dot1Q(vlan=egress_port, type=pkt.type) /
            pkt.payload
        )
        self.io_port.send(str(out_pkt))

    @inlineCallbacks
    def send_configure_stats_collection_interval(self, olt_no, interval):
        self.log.info('configuring-stats-collect-interval', olt=olt_no,
                      interval=interval)
        try:
            remote = yield self.get_channel()
            data = yield remote.callRemote('set_stats_collection_interval',
                                           interval)
            self.log.info('configured-stats-collect-interval', data=data)
        except Exception as e:
            self.log.exception('configure-stats-collect-interval', exc=str(e))
