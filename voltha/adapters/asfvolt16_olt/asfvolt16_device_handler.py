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
Asfvolt16 OLT adapter
"""

import arrow
from twisted.internet.defer import inlineCallbacks
from voltha.protos.events_pb2 import KpiEvent, MetricValuePairs
from voltha.protos.events_pb2 import KpiEventType
from voltha.protos.device_pb2 import PmConfigs, PmConfig,PmGroupConfig
from voltha.adapters.asfvolt16_olt.protos import bal_errno_pb2, bal_pb2
from voltha.protos.events_pb2 import AlarmEvent, AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory
from scapy.layers.l2 import Ether, Dot1Q
from uuid import uuid4
from common.frameio.frameio import BpfProgramFilter
from twisted.internet import reactor
from common.frameio.frameio import hexify
from scapy.packet import Packet
import voltha.core.flow_decomposer as fd
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.protos.device_pb2 import Port
from voltha.protos.common_pb2 import AdminState
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPS_LINK_DOWN, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, ofp_switch_features, ofp_desc, ofp_port, \
    OFPXMC_OPENFLOW_BASIC
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.adapters.asfvolt16_olt.bal import Bal
from voltha.adapters.device_handler import OltDeviceHandler
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
import time
import binascii

ASFVOLT_NNI_PORT = 129
# ASFVOLT_NNI_PORT needs to be other than pon port value.
# Edgecore OLT assigns PONport between 0 to 15, hence
# having a value 129 for NNI port to avoid collision.
# TODO: VLAN ID needs to come from some sort of configuration.
ASFVOLT16_DEFAULT_VLAN = 4091
PACKET_IN_VLAN = 4091
is_inband_frame = BpfProgramFilter('(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    PACKET_IN_VLAN))

ASFVOLT_EAPOL_ID = 1
ASFVOLT_DOWNLINK_EAPOL_ID = 2

ASFVOLT_EAPOL_ID_DATA_VLAN = 3
ASFVOLT_DOWNLINK_EAPOL_ID_DATA_VLAN = 4

ASFVOLT_DHCP_TAGGED_ID = 5
ASFVOLT_DOWNLINK_DHCP_TAGGED_ID = 6

ASFVOLT_IGMP_TAGGED_ID = 7
ASFVOLT_DOWNLINK_IGMP_TAGGED_ID = 8

ASFVOLT_FIRMWARE_ID = 9
ASFVOLT_DOWNLINK_FIRMWARE_ID = 10

ASFVOLT_ARP_ID = 11
ASFVOLT_DOWNLINK_ARP_ID = 12

ASFVOLT_HSIA_ID = 13
ASFVOLT_DOWNLINK_HSIA_ID = 14

ASFVOLT_DNS_ID = 15
ASFVOLT_DOWNLINK_DNS_ID = 16


class FlowInfo(object):

    def __init__(self):
        self.classifier = dict()
        self.action = dict()
        self.traffic_class = None

class VEnetHandler(object):

    def __init__(self):
        self.v_enet = VEnetConfig()
        self.gem_ports = dict()
        self.pending_flows = []

class VOntAniHandler(object):

    def __init__(self):
        self.v_ont_ani = VOntaniConfig()
        self.tconts = dict()

class Asfvolt16OltPmMetrics:
    class Metrics:
        def __init__(self, config, value=0):
            self.config = config
            self.value = value
            # group PM config is not supported currently

    def __init__(self,device):
        self.pm_names = {
             "rx_bytes", "rx_packets", "rx_ucast_packets", "rx_mcast_packets",
             "rx_bcast_packets", "rx_error_packets", "rx_unknown_protos",
             "tx_bytes", "tx_packets", "tx_ucast_packets", "tx_mcast_packets",
             "tx_bcast_packets", "tx_error_packets", "rx_crc_errors", "bip_errors"
        }
        self.device = device
        self.id = device.id
        # To collect pm metrices for each 'pm_default_freq/10' secs
        self.pm_default_freq = 20
        self.pon_metrics = dict()
        self.nni_metrics = dict()
        for m in self.pm_names:
            self.pon_metrics[m] = \
                    self.Metrics(config = PmConfig(name=m,
                                                   type=PmConfig.COUNTER,
                                                   enabled=True), value = 0)
            self.nni_metrics[m] = \
                    self.Metrics(config = PmConfig(name=m,
                                                   type=PmConfig.COUNTER,
                                                   enabled=True), value = 0)

    def update(self, device, pm_config):
        if self.pm_default_freq != pm_config.default_freq:
            self.pm_default_freq = pm_config.default_freq

        if pm_config.grouped is True:
            log.error('pm-groups-are-not-supported')
        else:
            for m in pm_config.metrics:
                self.pon_metrics[m.name].config.enabled = m.enabled
                self.nni_metrics[m.name].config.enabled = m.enabled

    def make_proto(self):
        pm_config = PmConfigs(
            id=self.id,
            default_freq=self.pm_default_freq,
            grouped = False,
            freq_override = False)
        return pm_config

class Asfvolt16Handler(OltDeviceHandler):

    def __init__(self, adapter, device_id):
        super(Asfvolt16Handler, self).__init__(adapter, device_id)
        self.filter = is_inband_frame
        self.bal = Bal(self, self.log)
        self.host_and_port = None
        self.olt_id = 0
        self.channel_groups = dict()
        self.channel_partitions = dict()
        self.channel_pairs = dict()
        self.channel_terminations = dict()
        self.v_ont_anis = dict()
        self.ont_anis = dict()
        self.v_enets = dict()
        self.traffic_descriptors = dict()
        self.adapter_name = adapter.name
        self.uni_port_num = 20
        self.pm_metrics = None
        self.heartbeat_count = 0
        self.heartbeat_miss = 0
        # For each 'heartbeat_interval' seconds,
        # Adapter will send heartbeat request to device
        self.heartbeat_interval = 5
        self.heartbeat_failed_limit = 1
        self.is_heartbeat_started = 0

    def __del__(self):
        super(Asfvolt16Handler, self).__del__()

    def __str__(self):
        return "Asfvolt16Handler: {}".format(self.host_and_port)

    def _get_next_uni_port(self):
        self.uni_port_num += 1
        return self.uni_port_num

    def get_venet(self, **kwargs):
        name = kwargs.pop('name', None)
        gem_port_id = kwargs.pop('gem_port_id', None)
        for key, v_enet in self.v_enets.items():
            if name is not None:
                if key == name:
                    return v_enet
            if gem_port_id is not None:
                for gem_key, gem_port in v_enet.gem_ports.items():
                    if gem_port_id == gem_port.gemport_id:
                        return v_enet
        return None

    def get_v_ont_ani(self, name):
        for key, v_ont_ani in self.v_ont_anis.items():
            if key == name:
                return v_ont_ani
        return None

    def get_gem_port_info(self, v_enet, **kwargs):
        traffic_class = kwargs.pop('traffic_class', None)
        name = kwargs.pop('name', None)
        for key, gem_port in v_enet.gem_ports.items():
            if traffic_class is not None:
                if traffic_class == gem_port.traffic_class:
                    return gem_port
            if name is not None:
                if name == gem_port.name:
                    return gem_port
        return None

    def get_tcont_info(self, v_ont_ani, **kwargs):
        alloc_id = kwargs.pop('alloc_id', None)
        name = kwargs.pop('name', None)
        for key, tcont in v_ont_ani.tconts.items():
            if alloc_id is not None:
                if alloc_id == tcont.alloc_id:
                    return tcont
            if name is not None:
                if name == tcont.name:
                    return tcont
        return None

    def get_traffic_profile(self, name):
        for key, traffic_profile in self.traffic_descriptors():
            if name is not None:
                if name == traffic_profile.name:
                    return traffic_profile
        return None

    def get_flow_id(self, onu_id, intf_id, id):
        # Tp-Do Need to generate unique flow ID using
        # OnuID, IntfId, id
        # BAL accepts flow_id till 16384. So we are
        # using only onu_id and id to generate flow ID.
        return ((onu_id << 5) | id)

    def get_uni_port(self, device_id):
        ports = self.adapter_agent.get_ports(device_id, Port.ETHERNET_UNI)
        if ports:
            # For now, we use on one uni port
            return ports[0]
        return None

    def store_flows(self, uplink_classifier, uplink_action, 
                    v_enet, traffic_class):
        flow = FlowInfo()
        flow.classifier = dict(uplink_classifier)
        flow.action = dict(uplink_action)
        flow.traffic_class = traffic_class
        v_enet.pending_flows.append(flow)
        return None

    def add_pending_flows(self, v_enet, traffic_class):
        for flow in v_enet.pending_flows[:]:
            if flow.traffic_class == traffic_class:
                self.divide_and_add_flow(v_enet,
                                         flow.classifier,
                                         flow.action)
                v_enet.pending_flows.remove(flow)
        return

    def get_logical_port_using_gem_port(self, gem_port_id):
        logical_port = None
        v_enet = self.get_venet(gem_port_id=gem_port_id)
        if v_enet is None:
            self.log.error('Failed-to-get-v-enet', gem_port_id=gem_port_id)
            return

        v_ont_ani = self.get_v_ont_ani(v_enet.v_enet.data.v_ontani_ref)
        if v_ont_ani is None:
            self.log.info('Failed-to-get-v_ont_ani',
                          v_ont_ani=v_enet.v_enet.data.v_ontani_ref)
            return

        onu_device = self.adapter_agent.get_child_device(
            self.device_id, onu_id=v_ont_ani.v_ont_ani.data.onu_id)
        if onu_device is None:
            self.log.info('Failed-to-get-onu-device',
                          onu_id=v_ont_ani.v_ont_ani.data.onu_id)
            return

        uni = self.get_uni_port(onu_device.id)
        if uni is not None:
           logical_port = (onu_device.proxy_address.channel_id + uni.port_no)
        return logical_port

    def activate(self, device):

        self.log.info('activating-asfvolt16-olt', device=device)

        if not device.host_and_port:
            device.oper_status = OperStatus.FAILED
            device.reason = 'No host_and_port field provided'
            self.adapter_agent.update_device(device)
            return

        self.bal.connect_olt(device.host_and_port, self.device_id)

        if self.logical_device_id is None:

            self.host_and_port = device.host_and_port
            device.root = True
            device.vendor = 'Edgecore'
            device.model = 'ASFvOLT16'
            device.serial_number = device.host_and_port
            self.adapter_agent.update_device(device)

            self.add_port(port_no=ASFVOLT_NNI_PORT,
                          port_type=Port.ETHERNET_NNI,
                          label='NNI facing Ethernet port')
            self.logical_device_id = \
                self.add_logical_device(device_id=device.id)
            self.add_logical_port(port_no=ASFVOLT_NNI_PORT,
                                  port_type=Port.ETHERNET_NNI,
                                  device_id=device.id,
                                  logical_device_id=self.logical_device_id)

        self.bal.activate_olt()

        device = self.adapter_agent.get_device(device.id)
        device.parent_id = self.logical_device_id
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

    @inlineCallbacks
    def heartbeat(self, device, state = 'run'):
        self.log.debug('olt-heartbeat', device=device, state=state,
                       count=self.heartbeat_count)
        self.is_heartbeat_started = 1

        def heartbeat_alarm(device, status, heartbeat_misses=0):
            try:
                ts = arrow.utcnow().timestamp

                alarm_data = {'heartbeats_missed':str(heartbeat_misses)}

                alarm_event = self.adapter_agent.create_alarm(
                    id='voltha.{}.{}.olt'.format(self.adapter.name, device),
                    resource_id='olt',
                    type=AlarmEventType.EQUIPMENT,
                    category=AlarmEventCategory.OLT,
                    severity=AlarmEventSeverity.CRITICAL,
                    state=AlarmEventState.RAISED if status else
                        AlarmEventState.CLEARED,
                    description='OLT Alarm - Connection to OLT - {}'.format('Lost'
                                                                    if status
                                                                    else 'Regained'),
                    context=alarm_data,
                    raised_ts = ts)

                self.adapter_agent.submit_alarm(device, alarm_event)
                self.log.debug('olt-heartbeat alarm sent')

            except Exception as e:
                self.log.exception('failed-to-submit-alarm', e=e)

        try:
            d = yield self.bal.get_bal_heartbeat(self.device_id.__str__())
        except Exception as e:
             d = None

        _device = device

        if d == None:
            # something is not right - OLT is not Reachable
            self.heartbeat_miss += 1
            self.log.info('olt-heartbeat-miss',d=d,
                          count=self.heartbeat_count, miss=self.heartbeat_miss)
        else:
            if self.heartbeat_miss > 0:
                self.heartbeat_miss = 0
                if d.is_reboot == bal_pb2.BAL_OLT_UP_AFTER_REBOOT:
                    self.log.info('Activating OLT again after reboot')

                    # Since OLT is reachable after reboot, OLT should configurable with
                    # all the old existing flows. NNI port should be mark it as down for
                    # ONOS to push the old flows
                    self.update_logical_port(ASFVOLT_NNI_PORT, Port.ETHERNET_NNI,
                                             OFPPS_LINK_DOWN)
                    for key, v_ont_ani in self.v_ont_anis.items():
                        child_device = self.adapter_agent.get_child_device(
                           self.device_id, onu_id=v_ont_ani.v_ont_ani.data.onu_id)
                        if child_device:
                            msg = {'proxy_address': child_device.proxy_address,
                                   'event': 'deactivate-onu', 'event_data': "olt-reboot"}
                            # Send the event message to the ONU adapter
                            self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                                             msg)
                    #Activate Device
                    self.activate(device);
                else:
                    _device.connect_status = ConnectStatus.REACHABLE
                    _device.oper_status = OperStatus.ACTIVE
                    _device.reason = ''
                    self.adapter_agent.update_device(_device)
                self.log.info('Clearing the Hearbeat Alarm')
                heartbeat_alarm(_device, 0)

        if (self.heartbeat_miss >= self.heartbeat_failed_limit) and \
           (_device.connect_status == ConnectStatus.REACHABLE):
            self.log.info('olt-heartbeat-failed', count=self.heartbeat_miss)
            _device.connect_status = ConnectStatus.UNREACHABLE
            _device.oper_status = OperStatus.FAILED
            _device.reason = 'Lost connectivity to OLT'
            self.adapter_agent.update_device(_device)
            heartbeat_alarm(device, 1, self.heartbeat_miss)

        self.heartbeat_count += 1
        reactor.callLater(self.heartbeat_interval, self.heartbeat, device)

    @inlineCallbacks
    def reboot(self):
        err_status  = yield self.bal.set_bal_reboot(self.device_id.__str__())
        self.log.info('Reboot Status', err_status = err_status)

    @inlineCallbacks
    def _handle_pm_counter_req_towards_device(self, device):
        yield self._req_pm_counter_from_device_in_loop(device)

    @inlineCallbacks
    def _req_pm_counter_from_device_in_loop(self, device):
        # NNI port is hardcoded to 0
        kpi_status = -1
        if device.connect_status == ConnectStatus.UNREACHABLE:
           self.log.info('Device is not Reachable')
        else:
           try:
              pm_counters = yield self.bal.get_bal_nni_stats(0)
              kpi_status = 0
              self.log.info('pm_counters',pm_counters=pm_counters)
           except Exception as e:
              kpi_status = -1

        if kpi_status == 0 and pm_counters!=None:
           pm_data = { }
           pm_data["rx_bytes"]= pm_counters.rx_bytes
           pm_data["rx_packets"]= pm_counters.rx_packets
           pm_data["rx_ucast_packets"]= pm_counters.rx_ucast_packets
           pm_data["rx_mcast_packets"]= pm_counters.rx_mcast_packets
           pm_data["rx_bcast_packets"]= pm_counters.rx_bcast_packets
           pm_data["rx_error_packets"]= pm_counters.rx_error_packets
           pm_data["rx_unknown_protos"]= pm_counters.rx_unknown_protos
           pm_data["tx_bytes"]= pm_counters.tx_bytes
           pm_data["tx_packets"]= pm_counters.tx_packets
           pm_data["tx_ucast_packets"]= pm_counters.tx_ucast_packets
           pm_data["tx_mcast_packets"]= pm_counters.tx_mcast_packets
           pm_data["tx_bcast_packets"]= pm_counters.tx_bcast_packets
           pm_data["tx_error_packets"]= pm_counters.tx_error_packets
           pm_data["rx_crc_errors"]= pm_counters.rx_crc_errors
           pm_data["bip_errors"]= pm_counters.bip_errors

           self.log.info('KPI stats', pm_data = pm_data)
           name = 'asfvolt16_olt'
           prefix = 'voltha.{}.{}'.format(name, self.device_id)
           ts = arrow.utcnow().timestamp
           prefixes = {
                   prefix + '.nni': MetricValuePairs(metrics = pm_data)
           }

           kpi_event = KpiEvent(
                 type=KpiEventType.slice,
                 ts=ts,
                 prefixes=prefixes)
           self.adapter_agent.submit_kpis(kpi_event)
        else:
           self.log.info('Lost Connectivity to OLT')

        reactor.callLater(self.pm_metrics.pm_default_freq/10,
                          self._req_pm_counter_from_device_in_loop,
                          device)

    def update_pm_config(self, device, pm_config):
        self.log.info("update-pm-config", device=device, pm_config=pm_config)
        self.pm_metrics.update(device, pm_config)

    def handle_alarms(self, _device_id, _object, key, alarm,
                      status, priority,
                      alarm_data=None):
        self.log.info('received-alarm-msg',
                 object=_object,
                 key=key,
                 alarm=alarm,
                 status=status,
                 priority=priority,
                 alarm_data=alarm_data)

        id = 'voltha.{}.{}.{}'.format(self.adapter.name,
                                     _device_id, _object)
        description = '{} Alarm - {} - {}'.format(_object.upper(),
                                      alarm.upper(),
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
                state=AlarmEventState.RAISED if status else AlarmEventState.CLEARED,
                description=description,
                context=alarm_data,
                raised_ts=ts)

            self.adapter_agent.submit_alarm(_device_id, alarm_event)

        except Exception as e:
            self.log.exception('failed-to-submit-alarm', e=e)

        # take action based on alarm type, only pon_ni and onu objects report alarms
        if object == 'pon_ni':
            # key: {'device_id': <int>, 'pon_ni': <int>}
            # alarm: 'los'
            # status: <False|True>
            pass
        elif object == 'onu':
            # key: {'device_id': <int>, 'pon_ni': <int>, 'onu_id': <int>}
            # alarm: <'los'|'lob'|'lopc_miss'|'los_mic_err'|'dow'|'sf'|'sd'|'suf'|'df'|'tiw'|'looc'|'dg'>
            # status: <False|True>
            pass

    def BalIfaceLosAlarm(self, device_id, Iface_ID,\
                         los_status, IfaceLos_data):
        self.log.info('Interface Loss Of Signal Alarm')
        self.handle_alarms(device_id,"pon_ni",\
                           Iface_ID,\
                           "loss_of_signal",los_status,"high",\
                           IfaceLos_data)

    def BalSubsTermDgiAlarm(self, device_id, intf_id,\
                            onu_id, dgi_status, balSubTermDgi_data,\
                            ind_info):
        self.log.info('Subscriber terminal dying gasp')
        self.handle_alarms(device_id,"onu",\
                           intf_id,\
                           "dgi_indication",dgi_status,"medium",\
                           balSubTermDgi_data)
        if dgi_status == 1:
            child_device = self.adapter_agent.get_child_device(
                           device_id, onu_id=onu_id)
            if child_device is None:
               self.log.info('Onu-is-not-configured', onu_id=onu_id)
               return
            msg = {'proxy_address': child_device.proxy_address,
                   'event': 'deactivate-onu', 'event_data': ind_info}

            # Send the event message to the ONU adapter
            self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                                 msg)

    def BalSubsTermLosAlarm(self, device_id, Iface_ID,
                         los_status, SubTermAlarm_Data):
        self.log.info('ONU Alarms for Subscriber Terminal LOS')
        self.handle_alarms(device_id,"onu",\
                           Iface_ID,\
                           "ONU : Loss Of Signal",\
                           los_status, "medium",\
                           SubTermAlarm_Data)

    def BalSubsTermLobAlarm(self, device_id, Iface_ID,
                         lob_status, SubTermAlarm_Data):
        self.log.info('ONU Alarms for Subscriber Terminal LOB')
        self.handle_alarms(device_id,"onu",\
                           Iface_ID,\
                           "ONU : Loss Of Burst",\
                           lob_status, "medium",\
                           SubTermAlarm_Data)

    def BalSubsTermLopcMissAlarm(self, device_id, Iface_ID,
                         lopc_miss_status, SubTermAlarm_Data):
        self.log.info('ONU Alarms for Subscriber Terminal LOPC Miss')
        self.handle_alarms(device_id,"onu",\
                           Iface_ID,\
                           "ONU : Loss Of PLOAM miss channel",\
                           lopc_miss_status, "medium",\
                           SubTermAlarm_Data)

    def BalSubsTermLopcMicErrorAlarm(self, device_id, Iface_ID,
                         lopc_mic_error_status, SubTermAlarm_Data):
        self.log.info('ONU Alarms for Subscriber Terminal LOPC Mic Error')
        self.handle_alarms(device_id,"onu",\
                           Iface_ID,\
                           "ONU : Loss Of PLOAM MIC Error",\
                           lopc_mic_error_status, "medium",\
                           SubTermAlarm_Data)

    def add_port(self, port_no, port_type, label):
        self.log.info('adding-port', port_no=port_no, port_type=port_type)
        if port_type is Port.ETHERNET_NNI:
            oper_status = OperStatus.ACTIVE
        elif port_type is Port.PON_OLT:
            # To-Do The pon port status should be ACTIVATING.
            # For now make the status as Active.
            oper_status = OperStatus.ACTIVE
        else:
            self.log.error('invalid-port-type', port_type=port_type)
            return

        port = Port(
            port_no=port_no,
            label=label,
            type=port_type,
            admin_state=AdminState.ENABLED,
            oper_status=oper_status
        )
        self.adapter_agent.add_port(self.device_id, port)

    def add_logical_device(self, device_id):
        self.log.info('adding-logical-device', device_id=device_id)
        ld = LogicalDevice(
            # not setting id and datapth_id will let the adapter
            # agent pick id
            desc=ofp_desc(
                mfr_desc='cord project',
                hw_desc='n/a',
                sw_desc='logical device for Edgecore ASFvOLT16 OLT',
                #serial_num=uuid4().hex,
                serial_num=self.host_and_port,
                dp_desc='n/a'
            ),
            switch_features=ofp_switch_features(
                n_buffers=256,  # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    OFPC_FLOW_STATS |
                    OFPC_TABLE_STATS |
                    OFPC_PORT_STATS |
                    OFPC_GROUP_STATS
                )
            ),
            root_device_id=device_id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        return ld_initialized.id

    def add_logical_port(self, port_no, port_type,
                         device_id, logical_device_id):
        self.log.info('adding-logical-port', port_no=port_no,
                      port_type=port_type, device_id=device_id)
        if port_type is Port.ETHERNET_NNI:
            label = 'nni'
            cap = OFPPF_1GB_FD | OFPPF_FIBER
            curr_speed = OFPPF_1GB_FD
            max_speed = OFPPF_1GB_FD
        else:
            self.log.error('invalid-port-type', port_type=port_type)
            return

        ofp = ofp_port(
            port_no=port_no,  # is 0 OK?
            hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
            name=label,
            config=0,
            #state=OFPPS_LIVE,
            state=OFPPS_LINK_DOWN,
            curr=cap,
            advertised=cap,
            peer=cap,
            curr_speed=curr_speed,
            max_speed=max_speed)

        logical_port = LogicalPort(
            id=label,
            ofp_port=ofp,
            device_id=device_id,
            device_port_no=port_no,
            root_port=True
        )

        self.adapter_agent.add_logical_port(logical_device_id, logical_port)

    def update_logical_port(self, port_no, port_type, state):
        self.log.info('updating-logical-port', port_no=port_no,
                      port_type=port_type, device_id=self.device_id,
                      logical_device_id=self.logical_device_id)
        if port_type is Port.ETHERNET_NNI:
            label = 'nni'
        else:
            self.log.error('invalid-port-type', port_type=port_type)
            return
        logical_port = self.adapter_agent.get_logical_port(self.logical_device_id,
                                                           label)
        logical_port.ofp_port.state = state
        self.adapter_agent.update_logical_port(self.logical_device_id,
                                               logical_port)

    def handle_access_term_ind(self, ind_info):
        device = self.adapter_agent.get_device(self.device_id)
        if ind_info['activation_successful'] is True:
            self.log.info('successful-access-terminal-Indication',
                          olt_id=self.olt_id)
            device.connect_status = ConnectStatus.REACHABLE
            device.oper_status = OperStatus.ACTIVE
            device.reason = 'OLT activated successfully'
            self.adapter_agent.update_device(device)
            self.update_logical_port(ASFVOLT_NNI_PORT, Port.ETHERNET_NNI,
                                     OFPPS_LIVE)
            self.log.info('OLT activation complete')

            #heart beat - To health checkup of OLT
            if self.is_heartbeat_started == 0:
                self.log.info('Heart beat is not yet started..starting now')
                self.heartbeat(device)

                self.pm_metrics=Asfvolt16OltPmMetrics(device)
                pm_config = self.pm_metrics.make_proto()
                self.log.info("initial-pm-config", pm_config=pm_config)
                self.adapter_agent.update_device_pm_config(pm_config,init=True)

                # Apply the PM configuration
                self.update_pm_config(device, pm_config)

                # Request PM counters from OLT device.
                self._handle_pm_counter_req_towards_device(device)
        else:
            device.oper_status = OperStatus.FAILED
            device.reason = 'Failed to Intialize OLT'
            self.adapter_agent.update_device(device)
            reactor.callLater(15, self.activate, device)
        return

    def handle_not_started_onu(self, child_device, ind_info):
        if ind_info['_sub_group_type'] == 'onu_discovery':
            self.log.info('Onu-discovered', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)
            # To-Do: Need to handle the ONUs, where the admin state is
            # ENABLED and operation state is in Failed or Unkown
            self.log.info('Not-Yet-handled', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)
        elif ind_info['activation_successful'] is False:
            self.log.info('ONU-is in deactivated state')
            msg = {'proxy_address': child_device.proxy_address,
                   'event': 'deactivate-onu', 'event_data': ind_info}

            # Send the event message to the ONU adapter
            self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                             msg)
        elif ind_info['activation_successful'] is True:
            self.log.info('ONU-re-activated')
            msg = {'proxy_address': child_device.proxy_address,
                   'event': 'activation-completed', 'event_data': ind_info}

            # Send the event message to the ONU adapter
            self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                             msg)
        else:
            self.log.info('Invalid-ONU-event', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)

    def handle_activating_onu(self, child_device, ind_info):
        pon_id = ind_info['_pon_id']
        self.log.info('Not-handled-Yet', olt_id=self.olt_id,
                      pon_ni=pon_id, onu_data=ind_info)

    def handle_activated_onu(self, child_device, ind_info):
        if ind_info['activation_successful'] is False:
            self.log.info('ONU-is in deactivated state')
            msg = {'proxy_address': child_device.proxy_address,
                   'event': 'deactivate-onu', 'event_data': ind_info}

            # Send the event message to the ONU adapter
            self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                             msg)
        elif ind_info['activation_successful'] is True:
            self.log.info('ONU-activation-is-completed', olt_id=self.olt_id,
                        pon_ni=pon_id, onu_data=ind_info)
            msg = {'proxy_address': child_device.proxy_address,
                   'event': 'activation-completed', 'event_data': ind_info}

            # Send the event message to the ONU adapter
            self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                             msg)
        else:
            pon_id = ind_info['_pon_id']
            self.log.info('handle_activated_onu:Not-handled-Yet', olt_id=self.olt_id,
                      pon_ni=pon_id, onu_data=ind_info)

    def handle_discovered_onu(self, child_device, ind_info):
        pon_id = ind_info['_pon_id']
        if ind_info['_sub_group_type'] == 'onu_discovery':
            self.log.info('Activation-is-in-progress', olt_id=self.olt_id,
                          pon_ni=pon_id, onu_data=ind_info,
                          onu_id=child_device.proxy_address.onu_id)
            onu_info = dict()
            onu_info['pon_id'] = child_device.parent_port_no
            onu_info['onu_id'] = child_device.proxy_address.onu_id
            onu_info['vendor'] = ind_info['_vendor_id']
            onu_info['vendor_specific'] = ind_info['_vendor_specific']
            self.bal.activate_onu(onu_info)

        elif ind_info['_sub_group_type'] == 'sub_term_indication':
            if ind_info['activation_successful'] is True:
                self.log.info('ONU-activation-is-completed', olt_id=self.olt_id,
                          pon_ni=pon_id, onu_data=ind_info)

                msg = {'proxy_address': child_device.proxy_address,
                   'event': 'activation-completed', 'event_data': ind_info}

                # Send the event message to the ONU adapter
                self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                             msg)
                for key, v_ont_ani in self.v_ont_anis.items():
                    if v_ont_ani.v_ont_ani.data.onu_id == \
                            child_device.proxy_address.onu_id:
                        for tcont_key, tcont in v_ont_ani.tconts.items():
                            owner_info = dict()
                            # To-Do: Right Now use alloc_id as schduler ID. Need to
                            # find way to generate uninqe number.
                            id = tcont.alloc_id
                            owner_info['type'] = 'agg_port'
                            owner_info['intf_id'] = \
                                child_device.proxy_address.channel_id
                            owner_info['onu_id'] = \
                                child_device.proxy_address.onu_id
                            owner_info['alloc_id'] = tcont.alloc_id
                            self.bal.create_scheduler(id, 'upstream',
                                                      owner_info, 8)
            else:
                self.log.info('ONU-is in deactivated state')
                msg = {'proxy_address': child_device.proxy_address,
                   'event': 'deactivate-onu', 'event_data': ind_info}

                # Send the event message to the ONU adapter
                self.adapter_agent.publish_inter_adapter_message(child_device.id,
                                                             msg)
        else:
            self.log.info('Invalid-ONU-event', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)

    onu_handlers = {
        OperStatus.UNKNOWN: handle_not_started_onu,
        OperStatus.FAILED: handle_not_started_onu,
        OperStatus.ACTIVATING: handle_activating_onu,
        OperStatus.ACTIVE: handle_activated_onu,
        OperStatus.DISCOVERED: handle_discovered_onu,
    }

    def handle_sub_term_ind(self, ind_info):
        child_device = self.adapter_agent.get_child_device(
            self.device_id,
            serial_number=(ind_info['_vendor_id'] +
                           ind_info['_vendor_specific']))
        if child_device is None:
            self.log.info('Onu-is-not-configured', olt_id=self.olt_id,
                          pon_ni=ind_info['_pon_id'], onu_data=ind_info)
            return

        handler = self.onu_handlers.get(child_device.oper_status)
        if handler:
            handler(self, child_device, ind_info)

    def send_proxied_message(self, proxy_address, msg):
        if isinstance(msg, Packet):
            msg = str(msg)
        try:
            self.bal.send_omci_request_message(proxy_address, msg)
        except Exception as e:
            self.log.exception('', exc=str(e))
        return

    def handle_omci_ind(self, ind_info):
        child_device = self.adapter_agent.get_child_device(
            self.device_id,
            onu_id=ind_info['onu_id'])
        if child_device is None:
            self.log.info('Onu is not configured', onu_id=ind_info['onu_id'])
            return
        try:
            self.adapter_agent.receive_proxied_message(
                child_device.proxy_address,
                ind_info['packet'])
        except Exception as e:
            self.log.exception('', exc=str(e))
        return

    def handle_v_ont_ani_config(self, data):
        serial_number = data.data.expected_serial_number
        child_device = self.adapter_agent.get_child_device(
            self.device_id,
            serial_number=serial_number)
        if child_device is None:
            self.log.info('Failed-to-find-ONU-Info',
                          serial_number=serial_number)
        elif child_device.admin_state == AdminState.ENABLED:
            self.log.info('Activating ONU',
                          serial_number=serial_number,
                          onu_id=child_device.proxy_address.onu_id,
                          pon_id=child_device.parent_port_no)
        else:
            self.log.info('Invalid-ONU-state-to-activate',
                          onu_id=child_device.proxy_address.onu_id,
                          serial_number=serial_number)

    def update_onu(self, msg):
        proxy_address = msg['proxy_address']
        assert proxy_address is not None
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        child_device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if child_device:
            onu_info = dict()
            onu_info['pon_id'] = child_device.parent_port_no
            onu_info['onu_id'] = child_device.proxy_address.onu_id
            onu_info['vendor'] = child_device.vendor_id
            onu_info['vendor_specific'] = child_device.serial_number[4:]
        if msg['event'] == 'onu-deactivation':
            self.bal.deactivate_onu(onu_info)
        elif msg['event'] == 'onu-activation':
            self.bal.activate_onu(onu_info)
        else:
            self.log.info('Invalid ONU event')

    def create_interface(self, data):
        try:
            if isinstance(data, ChannelgroupConfig):
                if data.name in self.channel_groups:
                    self.log('Channel-Group-already-present',
                             channel_group=data)
                else:
                    channel_group_config = ChannelgroupConfig()
                    channel_group_config.CopyFrom(data)
                    self.channel_groups[data.name] = channel_group_config
            if isinstance(data, ChannelpartitionConfig):
                if data.name in self.channel_partitions:
                    self.log('Channel-partition-already-present',
                             channel_partition=data)
                else:
                    channel_partition_config = ChannelpartitionConfig()
                    channel_partition_config.CopyFrom(data)
                    self.channel_partitions[data.name] = \
                        channel_partition_config
            if isinstance(data, ChannelpairConfig):
                if data.name in self.channel_pairs:
                    self.log('Channel-pair-already-present',
                             channel_pair=data)
                else:
                    channel_pair_config = ChannelpairConfig()
                    channel_pair_config.CopyFrom(data)
                    self.channel_pairs[data.name] = channel_pair_config
            if isinstance(data, ChannelterminationConfig):
                self.log.info('Activating-PON-port-at-OLT',
                              pon_id=data.data.xgs_ponid)
                self.add_port(port_no=data.data.xgs_ponid,
                              port_type=Port.PON_OLT,
                              label=data.name)
                self.bal.activate_pon_port(self.olt_id, data.data.xgs_ponid)
                if data.name in self.channel_terminations:
                    self.log.info('Channel-termination-already-present',
                                  channel_termination=data)
                else:
                    channel_termination_config = ChannelterminationConfig()
                    channel_termination_config.CopyFrom(data)
                    self.channel_terminations[data.name] = \
                        channel_termination_config
            if isinstance(data, VOntaniConfig):
                self.handle_v_ont_ani_config(data)
                if data.name in self.v_ont_anis:
                    self.log.info('v_ont_ani-already-present',
                                  v_ont_ani=data)
                else:
                    v_ont_ani_config = VOntAniHandler()
                    v_ont_ani_config.v_ont_ani.CopyFrom(data)
                    self.v_ont_anis[data.name] = v_ont_ani_config
            if isinstance(data, VEnetConfig):
                if data.name in self.v_enets:
                    self.log.info('v_enet-already-present',
                                  v_enet=data)
                else:
                    v_enet_config = VEnetHandler()
                    v_enet_config.v_enet.CopyFrom(data)
                    self.log.info("creating-port-at-olt")
                    self.adapter_agent.add_port(self.device_id, Port(
                        port_no=self._get_next_uni_port(),
                        label=data.interface.name,
                        type=Port.ETHERNET_UNI,
                        admin_state=AdminState.ENABLED,
                        oper_status=OperStatus.ACTIVE
                    ))
                    self.v_enets[data.name] = v_enet_config
            if isinstance(data, OntaniConfig):
                if data.name in self.ont_anis:
                    self.log.info('ont_ani-already-present',
                                  v_enet=data)
                else:
                    ont_ani_config = OntaniConfig()
                    ont_ani_config.CopyFrom(data)
                    self.ont_anis[data.name] = ont_ani_config
        except Exception as e:
            self.log.exception('', exc=str(e))
        return

    def update_interface(self, data):
        self.log.info('Not-Implemented-yet')
        return

    def remove_interface(self, data):
        self.log.info('Not-Implemented-yet')
        return

    def create_tcont(self, tcont_data, traffic_descriptor_data):
        if traffic_descriptor_data.name in self.traffic_descriptors:
            traffic_descriptor = TrafficDescriptorProfileData()
            traffic_descriptor.CopyFrom(traffic_descriptor_data)
            self.traffic_descriptors[traffic_descriptor_data.name] = \
                traffic_descriptor
        if tcont_data.interface_reference in self.v_ont_anis:
            v_ont_ani = self.v_ont_anis[tcont_data.interface_reference]
            onu_device = self.adapter_agent.get_child_device(
                self.device_id,
                onu_id=v_ont_ani.v_ont_ani.data.onu_id)
            if (onu_device is not None and
                        onu_device.oper_status == OperStatus.ACTIVE):
                owner_info = dict()
                # To-Do: Right Now use alloc_id as schduler ID. Need to
                # find way to generate uninqe number.
                id = tcont_data.alloc_id
                owner_info['type'] = 'agg_port'
                owner_info['intf_id'] = onu_device.proxy_address.channel_id
                owner_info['onu_id'] = onu_device.proxy_address.onu_id
                owner_info['alloc_id'] = tcont_data.alloc_id
                self.bal.create_scheduler(id, 'upstream', owner_info, 8)
            else:
                self.log.info('Onu-is-not-configured', olt_id=self.olt_id,
                              intf_id=onu_device.proxy_address.channel_id,
                              onu_data=onu_device.proxy_address.onu_id)
            if tcont_data.name in v_ont_ani.tconts:
                self.log.info('tcont-info-already-present',
                              tcont_info=tcont_data)
            else:
                tcont = TcontsConfigData()
                tcont.CopyFrom(tcont_data)
                v_ont_ani.tconts[tcont_data.name] = tcont

    def update_tcont(self, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def create_gemport(self, data):
        if data.itf_ref in self.v_enets:
            v_enet = self.v_enets[data.itf_ref]
            if data.name in v_enet.gem_ports:
                self.log.info('Gem-port-info-is-already-present',
                              VEnet=v_enet, gem_info=data)
            if data.gemport_id > 9215:
                raise Exception('supported range for '
                                'gem-port is from 1024 to 9215')
            gem_port = GemportsConfigData()
            gem_port.CopyFrom(data)
            v_enet.gem_ports[data.name] = gem_port
            self.add_pending_flows(v_enet, gem_port.traffic_class)
        else:
            self.log.info('VEnet-is-not-configured-yet.',
                          gem_port_info=data)

    def update_gemport(self, data):
        raise NotImplementedError()

    def remove_gemport(self, data):
        raise NotImplementedError()

    def disable(self):
        super(Asfvolt16Handler, self).disable()

    def delete(self):
        super(Asfvolt16Handler, self).delete()

    def handle_packet_in(self, ind_info):
        self.log.info('Received Packet-In', ind_info=ind_info)
        logical_port = self.get_logical_port_using_gem_port(ind_info['svc_port'])
        pkt = Ether(ind_info['packet'])
        kw = dict(
                  logical_device_id=self.logical_device_id,
                  logical_port_no=logical_port,
                  )
        self.log.info('sending-packet-in', **kw)
        self.adapter_agent.send_packet_in(packet=str(pkt), **kw)

    def packet_out(self, egress_port, msg):
        pkt_info = dict()
        pkt = Ether(msg)
        self.log.info('received-packet-out-from-of-agent',
                      egress_port=egress_port,
                      packet=str(pkt).encode("HEX"))

        if pkt.haslayer(Dot1Q):
            outer_shim = pkt.getlayer(Dot1Q)
            if isinstance(outer_shim.payload, Dot1Q):
                inner_shim = outer_shim.payload
                payload = (
                    Ether(src=pkt.src, dst=pkt.dst, type=outer_shim.type) /
                    outer_shim.payload
                )
            else:
                payload = pkt
        else:
            payload = pkt

        self.log.info('sending-packet-to-device',
                      egress_port=egress_port,
                      packet=str(payload).encode("HEX"))
        send_pkt = binascii.unhexlify(str(payload).encode("HEX"))

        if egress_port == ASFVOLT_NNI_PORT:
            port_id = 'nni'
            pkt_info['dest_type'] = 'nni'
            pkt_info['intf_id'] = 0
        else:
            port_id = 'uni-{}'.format(egress_port)
            logical_port = None
            logical_port = \
                self.adapter_agent.get_logical_port(self.logical_device_id,
                                                    port_id)
            if logical_port is None:
                self.log.info('Unable-to-find-logical-port-info',
                              logical_port_number=egress_port)
                return
            onu_device = None
            onu_device = self.adapter_agent.get_device(logical_port.device_id)
            if onu_device is None:
                self.log.info('Unable-to-find-onu_device-info',
                              onu_device_id=logical_port.device_id)
                return
            pkt_info['intf_id'] = onu_device.proxy_address.channel_id
            pkt_info['onu_id'] = onu_device.proxy_address.onu_id

            pkt_info['dest_type'] = 'onu'
            #pkt_info['dest_type'] = 'gem_port'
            if pkt_info['dest_type'] == 'gem_port':
                pkt_info['gem_port'] = 1024
        self.bal.packet_out(send_pkt, pkt_info)

    def update_flow_table(self, flows):
        device = self.adapter_agent.get_device(self.device_id)
        self.log.info('bulk-flow-update', device_id=self.device_id)

        for flow in flows:
            self.log.info('flow-details', device_id=self.device_id, flow=flow)
            classifier_info = dict()
            action_info = dict()
            is_down_stream = None
            _in_port = None
            try:
                _in_port = fd.get_in_port(flow)
                assert _in_port is not None
                # Right now there is only one NNI port. Get the NNI PORT and compare
                # with IN_PUT port number. Need to find better way.
                ports = self.adapter_agent.get_ports(device.id, Port.ETHERNET_NNI)

                for port in ports:
                    if (port.port_no == _in_port):
                        self.log.info('downstream-flow')
                        is_down_stream = True
                        break
                if is_down_stream is None:
                    is_down_stream = False
                    self.log.info('upstream-flow')

                _out_port = fd.get_out_port(flow)  # may be None
                self.log.info('out-port', out_port=_out_port)

                for field in fd.get_ofb_fields(flow):

                    if field.type == fd.ETH_TYPE:
                        classifier_info['eth_type'] = field.eth_type
                        self.log.info('field-type-eth-type',
                                      eth_type=classifier_info['eth_type'])

                    elif field.type == fd.IP_PROTO:
                        classifier_info['ip_proto'] = field.ip_proto
                        self.log.info('field-type-ip-proto',
                                      ip_proto=classifier_info['ip_proto'])

                    elif field.type == fd.IN_PORT:
                        classifier_info['in_port'] = field.port
                        self.log.info('field-type-in-port',
                                      in_port=classifier_info['in_port'])

                    elif field.type == fd.VLAN_VID:
                        classifier_info['vlan_vid'] = field.vlan_vid & 0xfff
                        self.log.info('field-type-vlan-vid',
                                      vlan=classifier_info['vlan_vid'])

                    elif field.type == fd.VLAN_PCP:
                        classifier_info['vlan_pcp'] = field.vlan_pcp
                        self.log.info('field-type-vlan-pcp',
                                      pcp=classifier_info['vlan_pcp'])

                    elif field.type == fd.UDP_DST:
                        classifier_info['udp_dst'] = field.udp_dst
                        self.log.info('field-type-udp-dst',
                                      udp_dst=classifier_info['udp_dst'])

                    elif field.type == fd.UDP_SRC:
                        classifier_info['udp_src'] = field.udp_src
                        self.log.info('field-type-udp-src',
                                      udp_src=classifier_info['udp_src'])

                    elif field.type == fd.IPV4_DST:
                        classifier_info['ipv4_dst'] = field.ipv4_dst
                        self.log.info('field-type-ipv4-dst',
                                      ipv4_dst=classifier_info['ipv4_dst'])

                    elif field.type == fd.IPV4_SRC:
                        classifier_info['ipv4_src'] = field.ipv4_src
                        self.log.info('field-type-ipv4-src',
                                      ipv4_dst=classifier_info['ipv4_src'])

                    elif field.type == fd.METADATA:
                        classifier_info['metadata'] = field.table_metadata
                        self.log.info('field-type-metadata',
                                      metadata=classifier_info['metadata'])

                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in fd.get_actions(flow):

                    if action.type == fd.OUTPUT:
                        action_info['output'] = action.output.port
                        self.log.info('action-type-output',
                                      output=action_info['output'],
                                      in_port=classifier_info['in_port'])

                    elif action.type == fd.POP_VLAN:
                        action_info['pop_vlan'] = True
                        self.log.info('action-type-pop-vlan',
                                      in_port=_in_port)

                    elif action.type == fd.PUSH_VLAN:
                        action_info['push_vlan'] = True
                        action_info['tpid'] = action.push.ethertype
                        self.log.info('action-type-push-vlan',
                                      push_tpid=action_info['tpid'],
                                      in_port=_in_port)
                        if action.push.ethertype != 0x8100:
                            self.log.error('unhandled-tpid',
                                           ethertype=action.push.ethertype)

                    elif action.type == fd.SET_FIELD:
                        # action_info['action_type'] = 'set_field'
                        _field = action.set_field.field.ofb_field
                        assert (action.set_field.field.oxm_class ==
                                OFPXMC_OPENFLOW_BASIC)
                        self.log.info('action-type-set-field',
                                      field=_field, in_port=_in_port)
                        if _field.type == fd.VLAN_VID:
                            self.log.info('set-field-type-vlan-vid',
                                          vlan_vid=_field.vlan_vid & 0xfff)
                            action_info['vlan_vid'] = (_field.vlan_vid & 0xfff)
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type)
                    else:
                        self.log.error('unsupported-action-type',
                                       action_type=action.type, in_port=_in_port)

                if is_down_stream is False:
                    found = False
                    ports = self.adapter_agent.get_ports(self.device_id,
                                                         Port.ETHERNET_UNI)
                    for port in ports:
                        if port.port_no == classifier_info['in_port']:
                            found = True
                            break
                    if found is True:
                        v_enet = self.get_venet(name=port.label)
                    else:
                        self.log.error('Failed to get v_enet info',
                                       in_port=classifier_info['in_port'])
                        return
                    self.divide_and_add_flow(v_enet, classifier_info, action_info)
            except Exception as e:
                self.log.exception('failed-to-install-flow', e=e, flow=flow)

    # This function will divide the upstream flow into both
    # upstreand and downstream flow, as broadcom devices
    # expects down stream flows to be added to handle
    # packet_out messge from controller.
    def divide_and_add_flow(self, v_enet, classifier, action):
        if 'ip_proto' in classifier:
            if classifier['ip_proto'] == 17:
                self.log.error('Addtion of DHCP flows are defferd')
                '''
                # DHCP flow from the ONOS doesn't have Ctag and Stags
                # information. For now DHCP flow will be added as a
                # part of data flows.
                # self.add_dhcp_flow(classifier, action, v_enet,
                #                   ASFVOLT_DHCP_UNTAGGED_ID)
                '''
            elif classifier['ip_proto'] == 2:
                self.log.info('Addtion of IGMP flow are not handled yet')
                '''
                #self.add_igmp_flow(classifier, action, v_enet,
                #                   ASFVOLT_IGMP_UNTAGGED_ID)
                '''
            else:
                self.log.info("Invalid-Classifier-to-handle",
                              classifier=classifier,
                              action=action)
        elif 'eth_type' in classifier:
            if classifier['eth_type'] == 0x888e:
                # self.log.error('Addtion of EAPOL flows are defferd')
                self.add_eapol_flow(classifier, action,
                                    v_enet, ASFVOLT_EAPOL_ID,
                                    ASFVOLT_DOWNLINK_EAPOL_ID,
                                    ASFVOLT16_DEFAULT_VLAN)
        elif 'push_vlan' in action:

            self.prepare_and_add_dhcp_flow(classifier, action, v_enet,
                                           ASFVOLT_DHCP_TAGGED_ID,
                                           ASFVOLT_DOWNLINK_DHCP_TAGGED_ID)

            #self.del_flow(v_enet, ASFVOLT_EAPOL_ID, ASFVOLT_DOWNLINK_EAPOL_ID)
            self.prepare_and_add_eapol_flow(classifier, action, v_enet,
                                           ASFVOLT_EAPOL_ID_DATA_VLAN,
                                           ASFVOLT_DOWNLINK_EAPOL_ID_DATA_VLAN)
            self.add_data_flow(classifier, action, v_enet)
        else:
            self.log.info('Invalid-flow-type-to-handle',
                          classifier=classifier,
                          action=action)


    def prepare_and_add_eapol_flow(self, data_classifier, data_action,
                                  v_enet, eapol_id, downlink_eapol_id):
        eapol_classifier = dict()
        eapol_action = dict()
        eapol_classifier['eth_type'] = 0x888e
        eapol_classifier['pkt_tag_type'] = 'single_tag'
        #eapol_classifier['vlan_vid'] = data_classifier['vlan_vid']

        eapol_action['vlan_push'] = True
        eapol_action['vlan_vid'] = data_action['vlan_vid']
        self.add_eapol_flow(eapol_classifier, eapol_action, v_enet,
                           eapol_id, downlink_eapol_id, data_classifier['vlan_vid'])


    def add_eapol_flow(self, uplink_classifier, uplink_action,
                       v_enet, uplink_eapol_id, downlink_eapol_id, vlan_id):
        downlink_classifier = dict(uplink_classifier)
        downlink_action = dict(uplink_action)
        # To-Do For a time being hard code the traffic class value.
        # Need to know how to get the traffic class info from flows.
        gem_port = self.get_gem_port_info(v_enet, traffic_class=2)
        if gem_port is None:
            self.log.info('Failed-to-get-gemport',)
            # To-Do: If Gemport not found, then flow failure indication
            # should be sent to controller. For now, not sure how to
            # send that to controller. so store the flows in v_enet
            # and add it when gem port is created
            self.store_flows(uplink_classifier, uplink_action,
                             v_enet, traffic_class=2)
            return
        v_ont_ani = self.get_v_ont_ani(v_enet.v_enet.data.v_ontani_ref)
        if v_ont_ani is None:
            self.log.info('Failed-to-get-v_ont_ani',
                          v_ont_ani=v_enet.v_enet.data.v_ontani_ref)
            return
        tcont = self.get_tcont_info(v_ont_ani, name=gem_port.tcont_ref)
        if tcont is None:
            self.log.info('Failed-to-get-tcont-info',
                          tcont=gem_port.tcont_ref)
            return
        onu_device = self.adapter_agent.get_child_device(
            self.device_id, onu_id=v_ont_ani.v_ont_ani.data.onu_id)
        if onu_device is None:
            self.log.info('Failed-to-get-onu-device',
                          onu_id=v_ont_ani.v_ont_ani.data.onu_id)
            return

        flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                   onu_device.proxy_address.channel_id,
                                   uplink_eapol_id)
        # Add Upstream EAPOL Flow.
        #uplink_classifier['pkt_tag_type'] = 'untagged'
        uplink_classifier['pkt_tag_type'] = 'single_tag'
        uplink_classifier['vlan_vid'] = vlan_id
        uplink_action.clear()
        uplink_action['trap_to_host'] = True
        try:
            is_down_stream = False
            self.log.info('Adding-Upstream-EAPOL-flow',
                          classifier=uplink_classifier,
                          action=uplink_action, gem_port=gem_port,
                          flow_id=flow_id,
                          sched_info=tcont.alloc_id)
            self.bal.add_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              flow_id, gem_port.gemport_id,
                              uplink_classifier, is_down_stream,
                              action_info=uplink_action,
                              sched_id=tcont.alloc_id)
            # To-Do. While addition of one flow is in progress,
            # we cannot add an another flow. Right now use sleep
            # of 5 sec, assuming that addtion of flow is successful.
            time.sleep(0.1)
        except Exception as e:
            self.log.exception('failed-to-install-Upstream-EAPOL-flow', e=e,
                               classifier=uplink_classifier,
                               action=uplink_action,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)

        # Add Downstream EAPOL Flow.
        downlink_flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                            onu_device.proxy_address.channel_id,
                                            downlink_eapol_id)
        is_down_stream = True
        #downlink_classifier['pkt_tag_type'] = 'untagged'
        downlink_classifier['pkt_tag_type'] = 'single_tag'
        downlink_classifier['vlan_vid'] = vlan_id
        try:
            self.log.info('Adding-Downstream-EAPOL-flow',
                          classifier=downlink_classifier,
                          action=downlink_action,
                          gem_port=gem_port,
                          flow_id=downlink_flow_id,
                          sched_info=tcont.alloc_id)
            self.bal.add_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              downlink_flow_id, gem_port.gemport_id,
                              downlink_classifier, is_down_stream)
            # To-Do. While addition of one flow is in progress,
            # we cannot add an another flow. Right now use sleep
            # of 5 sec, assuming that addtion of flow is successful.
            time.sleep(0.1)
        except Exception as e:
            self.log.exception('failed-to-install-downstream-EAPOL-flow', e=e,
                               classifier=downlink_classifier,
                               action=downlink_action,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)

    def prepare_and_add_dhcp_flow(self, data_classifier, data_action,
                                  v_enet, dhcp_id, downlink_dhcp_id):
        dhcp_classifier = dict()
        dhcp_action = dict()
        dhcp_classifier['ip_proto'] = 17
        dhcp_classifier['udp_src'] = 68
        dhcp_classifier['udp_dst'] = 67
        dhcp_classifier['pkt_tag_type'] = 'single_tag'
        dhcp_classifier['vlan_vid'] = data_classifier['vlan_vid']
        dhcp_action['vlan_push'] = True
        dhcp_action['vlan_vid'] = data_action['vlan_vid']
        self.add_dhcp_flow(dhcp_classifier, dhcp_action, v_enet,
                           dhcp_id, downlink_dhcp_id)

    def add_dhcp_flow(self, uplink_classifier, uplink_action,
                      v_enet, dhcp_id, downlink_dhcp_id):
        downlink_classifier = dict(uplink_classifier)
        downlink_action = dict(uplink_action)
        # Add Upstream DHCP Flow.
        # To-Do For a time being hard code the traffic class value.
        # Need to know how to get the traffic class info from flows.
        gem_port = self.get_gem_port_info(v_enet, traffic_class=2)
        if gem_port is None:
            self.log.info('Failed-to-get-gemport')
            self.store_flows(uplink_classifier, uplink_action, 
                             v_enet, traffic_class=2)
            return
        v_ont_ani = self.get_v_ont_ani(v_enet.v_enet.data.v_ontani_ref)
        if v_ont_ani is None:
            self.log.error('Failed-to-get-v_ont_ani',
                           v_ont_ani=v_enet.v_enet.data.v_ontani_ref)
            return
        tcont = self.get_tcont_info(v_ont_ani, name=gem_port.tcont_ref)
        if tcont is None:
            self.log.error('Failed-to-get-tcont-info',
                           tcont=gem_port.tcont_ref)
            return
        onu_device = self.adapter_agent.get_child_device(
            self.device_id, onu_id=v_ont_ani.v_ont_ani.data.onu_id)
        if onu_device is None:
            self.log.error('Failed-to-get-onu-device',
                           onu_id=v_ont_ani.v_ont_ani.data.onu_id)
            return

        flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                   onu_device.proxy_address.channel_id,
                                   dhcp_id)
        uplink_action.clear()
        uplink_action['trap_to_host'] = True
        try:
            is_down_stream = False
            self.log.info('Adding-Upstream-DHCP-flow',
                          classifier=uplink_classifier,
                          action=uplink_action,
                          gem_port=gem_port,
                          flow_id=flow_id,
                          sched_info=tcont.alloc_id)
            self.bal.add_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              flow_id, gem_port.gemport_id,
                              uplink_classifier, is_down_stream,
                              action_info=uplink_action,
                              sched_id=tcont.alloc_id)
            # To-Do. While addition of one flow is in progress,
            # we cannot add an another flow. Right now use sleep
            # of 5 sec, assuming that addtion of flow is successful.
            time.sleep(0.1)

        except Exception as e:
            self.log.exception('failed-to-install-dhcp-upstream-flow', e=e,
                               classifier=uplink_classifier,
                               action=uplink_action,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)

        is_down_stream = True
        downlink_classifier['udp_src'] = 67
        downlink_classifier['udp_dst'] = 68

        if dhcp_id == ASFVOLT_DHCP_TAGGED_ID:
            downlink_classifier['pkt_tag_type'] = 'double_tag'
            # Copy O_OVID
            downlink_classifier['vlan_vid'] = downlink_action['vlan_vid']
            # Copy I_OVID
            #downlink_classifier['metadata'] = uplink_classifier['vlan_vid']
            if 'push_vlan' in downlink_classifier:
                downlink_action.pop('push_vlan')
            downlink_action['pop_vlan'] = True
        else:
            downlink_classifier['pkt_tag_type'] =  'untagged'
            downlink_classifier.pop('vlan_vid')


        downlink_flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                            onu_device.proxy_address.channel_id,
                                            downlink_dhcp_id)

        try:
            self.log.info('Adding-Downstream-DHCP-flow',
                          classifier=downlink_classifier,
                          action=downlink_action, gem_port=gem_port,
                          flow_id=downlink_flow_id,
                          sched_info=tcont.alloc_id)
            self.bal.add_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              downlink_flow_id, gem_port.gemport_id,
                              downlink_classifier, is_down_stream,
                              action_info=downlink_action)
            # To-Do. While addition of one flow is in progress,
            # we cannot add an another flow. Right now use sleep
            # of 5 sec, assuming that addtion of flow is successful.
            time.sleep(0.1)
        except Exception as e:
            self.log.exception('failed-to-install-dhcp-downstream-flow', e=e,
                               classifier=downlink_classifier,
                               action=downlink_action,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)

    def add_igmp_flow(self, classifier, action, v_enet, igmp_id):
        self.log.info('Not-Implemented-Yet')
        return

    def add_data_flow(self, uplink_classifier, uplink_action, v_enet):

        downlink_classifier = dict(uplink_classifier)
        downlink_action = dict(uplink_action)

        uplink_classifier['pkt_tag_type'] = 'single_tag'

        downlink_classifier['pkt_tag_type'] = 'double_tag'
        downlink_classifier['vlan_vid'] = uplink_action['vlan_vid']
        downlink_classifier['metadata'] = uplink_classifier['vlan_vid']
        del downlink_action['push_vlan']
        downlink_action['pop_vlan'] = True

        # To-Do right now only one GEM port is supported, so below method
        # will take care of handling all the p bits.
        # We need to revisit when mulitple gem port per bits is needed.
        self.add_hsia_flow(uplink_classifier, uplink_action,
                          downlink_classifier, downlink_action,
                          v_enet, ASFVOLT_HSIA_ID, ASFVOLT_DOWNLINK_HSIA_ID)

    def add_hsia_flow(self, uplink_classifier, uplink_action,
                     downlink_classifier, downlink_action,
                     v_enet, hsia_id, downlink_hsia_id):
        # Add Upstream Firmware Flow.
        # To-Do For a time being hard code the traffic class value.
        # Need to know how to get the traffic class info from flows.
        gem_port = self.get_gem_port_info(v_enet, traffic_class=2)
        if gem_port is None:
            self.log.info('Failed-to-get-gemport')
            self.store_flows(uplink_classifier, uplink_action, 
                             v_enet, traffic_class=2)
            return
        v_ont_ani = self.get_v_ont_ani(v_enet.v_enet.data.v_ontani_ref)
        if v_ont_ani is None:
            self.log.info('Failed-to-get-v_ont_ani',
                          v_ont_ani=v_enet.v_enet.data.v_ontani_ref)
            return
        tcont = self.get_tcont_info(v_ont_ani, name=gem_port.tcont_ref)
        if tcont is None:
            self.log.info('Failed-to-get-tcont-info',
                          tcont=gem_port.tcont_ref)
            return
        onu_device = self.adapter_agent.get_child_device(
            self.device_id, onu_id=v_ont_ani.v_ont_ani.data.onu_id)
        if onu_device is None:
            self.log.info('Failed-to-get-onu-device',
                          onu_id=v_ont_ani.v_ont_ani.data.onu_id)
            return

        flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                   onu_device.proxy_address.channel_id,
                                   hsia_id)
        try:
            is_down_stream = False
            self.log.info('Adding-ARP-upstream-flow',
                          classifier=uplink_classifier,
                          action=uplink_action,
                          gem_port=gem_port,
                          flow_id=flow_id,
                          sched_info=tcont.alloc_id)
            self.bal.add_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              flow_id, gem_port.gemport_id,
                              uplink_classifier, is_down_stream,
                              action_info=uplink_action,
                              sched_id=tcont.alloc_id)
            # To-Do. While addition of one flow is in progress,
            # we cannot add an another flow. Right now use sleep
            # of 5 sec, assuming that addtion of flow is successful.
            time.sleep(0.1)
        except Exception as e:
            self.log.exception('failed-to-install-ARP-upstream-flow', e=e,
                               classifier=uplink_classifier,
                               action=uplink_action,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)
        is_down_stream = True
        # To-Do: For Now hard code the p-bit values.
        #downlink_classifier['vlan_pcp'] = 7
        downlink_flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                            onu_device.proxy_address.channel_id,
                                            hsia_id)
                                            #downlink_hsia_id)
        try:
            self.log.info('Adding-ARP-downstream-flow',
                          classifier=downlink_classifier,
                          action=downlink_action,
                          gem_port=gem_port,
                          flow_id=downlink_flow_id)
            self.bal.add_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              downlink_flow_id, gem_port.gemport_id,
                              downlink_classifier, is_down_stream,
                              action_info=downlink_action)
            # To-Do. While addition of one flow is in progress,
            # we cannot add an another flow. Right now use sleep
            # of 5 sec, assuming that addtion of flow is successful.
            time.sleep(0.1)
        except Exception as e:
            self.log.exception('failed-to-install-ARP-downstream-flow', e=e,
                               classifier=downlink_classifier,
                               action=downlink_action,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)


    def del_flow(self, v_enet, uplink_id, downlink_id):
        # To-Do For a time being hard code the traffic class value.
        # Need to know how to get the traffic class info from flows.
        v_ont_ani = self.get_v_ont_ani(v_enet.v_enet.data.v_ontani_ref)
        if v_ont_ani is None:
            self.log.info('Failed-to-get-v_ont_ani',
                          v_ont_ani=v_enet.v_enet.data.v_ontani_ref)
            return
        onu_device = self.adapter_agent.get_child_device(
            self.device_id, onu_id=v_ont_ani.v_ont_ani.data.onu_id)
        if onu_device is None:
            self.log.info('Failed-to-get-onu-device',
                          onu_id=v_ont_ani.v_ont_ani.data.onu_id)
            return

        flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                   onu_device.proxy_address.channel_id,
                                   uplink_id)
        try:
            is_down_stream = False
            self.log.info('deleting-Upstream-EAPOL-flow',
                          flow_id=flow_id)
            self.bal.delete_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              flow_id, is_down_stream)
            # To-Do. While deletion of one flow is in progress,
            # we cannot delete an another flow. Right now use sleep
            # of 5 sec, assuming that deletion of flow is successful.
            time.sleep(0.1)
        except Exception as e:
            self.log.exception('failed-to-delete-Upstream-EAPOL-flow', e=e,
                               flow_id=flow_id,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)

        downlink_flow_id = self.get_flow_id(onu_device.proxy_address.onu_id,
                                            onu_device.proxy_address.channel_id,
                                            downlink_id)
        is_down_stream = True
        try:
            self.log.info('Deleting-Downstream-EAPOL-flow',
                          flow_id=downlink_flow_id)

            self.bal.delete_flow(onu_device.proxy_address.onu_id,
                              onu_device.proxy_address.channel_id,
                              downlink_flow_id, is_down_stream)
            # To-Do. While deletion of one flow is in progress,
            # we cannot delete an another flow. Right now use sleep
            # of 5 sec, assuming that deletion of flow is successful.
            time.sleep(0.1)
        except Exception as e:
            self.log.exception('failed-to-install-downstream-EAPOL-flow', e=e,
                               flow_id=flow_id,
                               onu_id=onu_device.proxy_address.onu_id,
                               intf_id=onu_device.proxy_address.channel_id)
