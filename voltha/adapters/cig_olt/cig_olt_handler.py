#
# Copyright 2017-present CIG, Inc.
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
import datetime
import pprint
import random
import argparse
import datetime
import shlex
import time

import arrow
import structlog
import json

from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue
from twisted.internet.task import LoopingCall

#from adapter_alarms import AdapterAlarms
from cig_olt_zmq import *
from cig_olt_device import *
from cig_olt_xpon import *
from download import *
from voltha.extensions.omci.omci import *

from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.core.flow_decomposer import *
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory
from voltha.protos.device_pb2 import Device, Image, DeviceType, DeviceTypes, Port, Device, \
    PmConfigs, PmConfig, PmGroupConfig
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalPorts, LogicalDevice
from voltha.protos.openflow_13_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_common_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_d_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_pon_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_switch_pb2 import *
from voltha.protos.olt_common_pb2 import *
from voltha.protos.olt_d_pb2 import *
from voltha.protos.olt_pon_pb2 import *
from voltha.protos.olt_switch_pb2 import *

from voltha.protos.bbf_fiber_base_pb2 import \
    ChannelgroupConfig, ChannelpartitionConfig, ChannelpairConfig, ChannelterminationConfig, \
    OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs

from voltha.registry import registry
from common.frameio.frameio import BpfProgramFilter, hexify
from common.utils.asleep import asleep
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import Raw

from google.protobuf.json_format import MessageToDict

class CigOltHandler(object):
    """
    The OLT Handler is used to wrap a single instance of a 10G OLT 1-U pizza-box
    """

    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.io_port = None
        self.logical_device_id = None
        self._logical_device = None
        #self.interface = registry('main').get_args().interface
        self.work_mode = None
        self.work_status = 0
        self.reboot_status = 0
        self.command_timeout = 5
        self.pm_metrics = None
        self.default_freq = 150
        self.lc = None
        #self.onus = {}

        self.alarms = None

        self.ip_address = None
        self.olt_mac = None
        self.startup = None
        self.zmq_client_echo = None
        self.zmq_client_sync = None
        self.zmq_client_omci = None
        self.zmq_client_of_packet = None
        self.zmq_client_async = None
        self.zmq_client_sub = None
        
        self.echo_incoming_queue = DeferredQueue()
        self.sync_incoming_queue = DeferredQueue()
        self.async_incoming_queue = DeferredQueue()
        self.omci_incoming_queue = DeferredQueue()
        self.of_pkt_incoming_queue = DeferredQueue()
        
        self.pon_port = None
        self.onu_id = None

        #self.channel = None  # Proxy messaging channel with 'send' method

        # Northbound and Southbound ports
        self.northbound_ports = {}  # port number -> Port
        self.southbound_ports = {}  # port number -> Port  (For PON, use pon-id as key)
        # self.management_ports = {}  # port number -> Port   TODO: Not currently supported

        self.num_northbound_ports = None
        self.num_southbound_ports = None
        # self.num_management_ports = None

        # Heartbeat support
        self.heartbeat_miss = 0
        self.heartbeat_interval = 2  # TODO: Decrease before release or any scale testing
        self.heartbeat_failed_limit = 3
        self.heartbrat_status = 0
        self.reboot_check_times = 0
        self.seq_no = 0
        
        self.heartbeat = None
        self.asyncmsg = None
        self.omcimsg = None
        self.packetmsg = None

        #self.io_port = None
        #self.interface = registry('main').get_args().interface      

        # Installed flows
        #self.flow_entries = {}  # Flow ID/name -> FlowEntry

        # xPON config dictionaries
        self._channel_groups = {}         # Name -> dict
        self._channel_partitions = {}     # Name -> dict
        self._channel_pairs = {}          # Name -> dict
        self._channel_terminations = {}   # Name -> dict
        self._v_ont_anis = {}             # Name -> dict
        self._ont_anis = {}               # Name -> dict
        self._v_enets = {}                # Name -> dict
        self._tconts = {}                 # Name -> dict
        self._traffic_descriptors = {}    # Name -> dict
        self._gemports = {}               # Name -> dict
        self._cached_xpon_pon_info = {}   # PON-id -> dict

        self._download_protocols = None
        self._download_deferred = None
        self._downloads = {}        # name -> Download obj
        
    def __del__(self):
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)

    @inlineCallbacks
    def activate(self, device):
        """
        Activate the OLT device

        :param device: A voltha.Device object, with possible device-type
                       specific extensions.
        :param reconciling: If True, this adapter is taking over for a previous adapter
                            for an existing OLT
        """
        log.debug('cig activate starting')
        log.info('cig activate started')
        self.log.info('CigDeviceHandler.activating', device=device)

        self.ip_address = device.ipv4_address
        self.zmq_client_sync = CigZmqClientSync(self.ip_address, self.sync_incoming_queue)

        olt_info = yield self.get_olt_info_com()
        if olt_info == None:
            self.log.info(' get olt info fail.')
            self.activate_failed(device, "ipc timeout.", reachable=False)
            return
        else:
            reactor.callLater(1, self._olt_activate, device, olt_info)

    def _olt_activate(self, device, olt_info):
        self.work_mode = olt_info.work_mode
        self.olt_mac = olt_info.mac_address
        device.root = True
        device.vendor = olt_info.vendor
        device.model = olt_info.model
        device.hardware_version = olt_info.hardware_version
        device.firmware_version = olt_info.firmware_version
        device.serial_number = olt_info.serial_number
        self.adapter_agent.update_device(device)
            
        logical_device = self.get_logical_device(device)
        self._logical_device = self.adapter_agent.create_logical_device(logical_device,dpid=self.olt_mac)

        for m in olt_info.nni_port:
            self.log.info('nni_port.port_no', m.port_no)
            self.log.info('nni_port.port_type', m.port_type)
            self.log.info('nni_port.mac_address', m.mac_address)
            if m.port_no==1:
                self.northbound_ports[m.port_no] = NniPort(m, self.device_id)
                phy_port = self.northbound_ports[m.port_no].get_port()
                self.adapter_agent.add_port(device.id, phy_port)
                logical_port = self.northbound_ports[m.port_no].get_logical_port()
                self.adapter_agent.add_logical_port(self._logical_device.id, logical_port)              

        for m in olt_info.pon_port:
            self.log.info('pon_port.port_no', m.port_no)
            self.log.info('pon_port.port_type', m.port_type)
            #if m.port_no==1  or m.port_no==2:
            #if m.port_no==1:
                #self.southbound_ports[m.port_no] = PonPort(m.port_no, self.device_id)
            self.southbound_ports[m.port_no] = PonPort(m.port_no, self)
            phy_port = self.southbound_ports[m.port_no].get_port()
            self.adapter_agent.add_port(device.id, phy_port)
                    
        self.log.info('create CigZmqClientAsync socket.')
        self.zmq_client_async = CigZmqClientAsync(self.ip_address, self.heartbeat_receive)
        self.log.info('send olt activate_msg.')
        self.olt_activate_msg_send()
        self.work_status = 1

        ############################################################################
        # Setup Alarm handler

        #self.alarms = AdapterAlarms(self.adapter, device)

        ############################################################################
        self.log.info('get_device.....')
        
        device = self.adapter_agent.get_device(device.id)
        device.parent_id = self._logical_device.id
        #device.connect_status = ConnectStatus.UNREACHABLE
        #device.oper_status = OperStatus.ACTIVATING
        #self.adapter_agent.update_device(device)
        self.logical_device_id = self._logical_device.id

        #device = self.adapter_agent.get_device(device.id)
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        device.reason = ''
        self.log.info('update_device.....')
        self.adapter_agent.update_device(device)

        self.log.info('create others zmq sockets.....')
        self.zmq_client_sub = CigZmqClientSub(self.ip_address, self.async_incoming_queue)
        self.zmq_client_omci = CigZmqClientOmci(self.ip_address, self.omci_incoming_queue)
        self.zmq_client_of_packet = CigZmqClientPacketInOut(self.ip_address, self.of_pkt_incoming_queue)
        
        # Schedule the heartbeat for the device
        self.log.debug('Starting heartbeat')
        self.start_heartbeat(delay=5)
        
        #self.start_onu_test()
        
        self.start_poll_async_msg()
        self.start_poll_omci_msg()

        #self.start_kpi_collection()
        self.start_poll_packet_in_msg()
        
        self.log.info('activate over.', device_id=self.device_id)
        

    @inlineCallbacks
    def collect_gem_metrics(self,prefix):
        try:
            # get pon port
            gem_metrics = {}
            self.log.info("collect-gem-metrics")

            for m in self.southbound_ports:
                phy_port = self.southbound_ports[m]._pon_id
                self.log.info("collect-gem-metrics", m=m, port=phy_port)

                xgem_pm_req_head = OltMsgCommonHdr(
                    type=OLT_PON_GET_XGEM_PM_REQ,
                    src_appId=OLT_APPID_VOLTHA,
                    sync=1
                )

                data = xgem_pm_req_head.SerializeToString()
                self.zmq_client_sync.sync_send(data, 1)

                xgem_pm_req_data = OltPonXGemPMReq(
                    pon_slot=0,
                    pon_port=phy_port
                )

                data = xgem_pm_req_data.SerializeToString()
                self.zmq_client_sync.sync_send(data, 0)

                #time.sleep(1)

                self.startup = self.get_sync_queue()
                results = yield self.startup

                self.log.info('get_sync_queue', results=results)
                if results == "RecvTimeoutErr.":
                    self.log.info('get OLT_PON_GET_XGEM_PM_ACK info timeout.', results=results)
                    self.zmq_client_sync.sync_reconnect()
                else:
                    gem_pm_info_rep = OltMsgCommonHdr()
                    gem_pm_info_rep.ParseFromString(results[0])
                    self.log.info('gem_pm_info_rep.type', gem_pm_info_rep.type)
                    self.log.info('gem_pm_info_rep.src_appId', gem_pm_info_rep.src_appId)
                    self.log.info('gem_pm_info_rep.sync', gem_pm_info_rep.sync)

                    if (gem_pm_info_rep.type != OLT_PON_GET_XGEM_PM_ACK) or (
                        gem_pm_info_rep.src_appId != OLT_APPID_OLTD) \
                        or (gem_pm_info_rep.sync != 1) or (len(results) < 2):
                        self.log.info('get OLT_PON_GET_XGEM_PM_ACK err.')
                    else:
                        gem_pm_info = OltPonXGemPMAck()
                        gem_pm_info.ParseFromString(results[1])
                        self.log.info('gem_pm_info.pon_port', pon_port=gem_pm_info.pon_port)
                        self.log.info('gem_pm_info.pon_slot', pon_slot=gem_pm_info.pon_slot)
                        self.log.info('gem_pm_info.tx_gem_frames', tx_gem_frames=gem_pm_info.tx_gem_frames)
                        self.log.info('gem_pm_info.rx_gem_frames', rx_gem_frames=gem_pm_info.rx_gem_frames)
                        self.log.info('gem_pm_info.tx_nolfbit_count', tx_nolfbit_count=gem_pm_info.tx_nolfbit_count)
                        self.log.info('gem_pm_info.hec_err_count', hec_err_count=gem_pm_info.hec_err_count)
                        self.log.info('gem_pm_info.frame_lost_count', frame_lost_count=gem_pm_info.frame_lost_count)
                        self.log.info('gem_pm_info.key_err_count', key_err_count=gem_pm_info.key_err_count)

                        gem_metrics['tx_gem_frames'] = gem_pm_info.tx_gem_frames
                        gem_metrics['rx_gem_frames'] = gem_pm_info.rx_gem_frames
                        gem_metrics['tx_nolfbit_count'] = gem_pm_info.tx_nolfbit_count
                        gem_metrics['hec_err_count'] = gem_pm_info.hec_err_count
                        gem_metrics['frame_lost_count'] = gem_pm_info.frame_lost_count
                        gem_metrics['key_err_count'] = gem_pm_info.key_err_count

                        # Step 2: prepare the KpiEvent for submission
                        # we can time-stamp them here (or could use time derived from OLT
                        ts = arrow.utcnow().timestamp
                        prefixstr = "%s pon_port:%d xgem" % (prefix, gem_pm_info.pon_port)
                        self.log.info('prefixstr', prefixstr=prefixstr)
                        kpi_event = KpiEvent(
                            type=KpiEventType.slice,
                            ts=ts,
                            prefixes={
                                # xgem
                                prefixstr: MetricValuePairs(
                                metrics=gem_metrics),
                            }
                        )

                        # Step 3: submit
                        self.adapter_agent.submit_kpis(kpi_event)
                        gem_metrics.clear()


        except Exception as e:
            log.exception('failed-to-submit-kpis', e=e)


    def start_kpi_collection(self):
        prefix = 'voltha.{}.{}'.format('cig-olt', self.device_id)
        self.log.info('start_kpi_collection',prefix=prefix)
        self.lc = LoopingCall(self.collect_gem_metrics,prefix)
        self.log.info('start_kpi_collection ',interval=self.default_freq / 10)
        self.lc.start(interval=self.default_freq / 10)
        #reactor.run()

    def stop_kpi_collection(self):
        self.lc.stop()

    #packet_in, strip svlan and cvlan, and send to onos   
    '''
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
            elif pkt.haslayer(Raw):
                raw_data = json.loads(pkt.getlayer(Raw).load)
                self.alarms.send_alarm(self, raw_data)
    '''

    def activate_failed(self, device, reason, reachable=True):
        """
        Activation process (adopt_device) has failed.

        :param device:  A voltha.Device object, with possible device-type
                        specific extensions. Such extensions shall be described as part of
                        the device type specification returned by device_types().
        :param reason: (string) failure reason
        :param reachable: (boolean) Flag indicating if device may be reachable
                                    via RESTConf or NETConf even after this failure.
        """
        device.oper_status = OperStatus.FAILED
        if not reachable:
            device.connect_status = ConnectStatus.UNREACHABLE

        device.reason = reason
        self.adapter_agent.update_device(device)
        raise RuntimeError('Failed to activate OLT: {}'.format(device.reason))

    #@inlineCallbacks
    def deactivate(self, device):
        # OLT Specific things here

        d, self.startup = self.startup, None
        if d is not None:
            d.cancel()

        self.pons.clear()

        # TODO: Any other? OLT specific deactivate steps

        # Call into base class and have it clean up as well
        super(AdtranOltHandler, self).deactivate(device)

    #@inlineCallbacks
    def update_flow_table(self, flows, device):
        '''
        for flow in flows:
            self.log.info('bulk-flow-update1', device_id=device.id, flow=flow)
            for field in get_ofb_fields(flow):
                if field.type == IN_PORT:
                    if field.port >= 100 and field.port < 124:
                        field.port = field.port - 100
                        flow.cookie = 1
                    elif field.port >= 0 and field.port < 6:
                        flow.cookie = 2
                    else:
                        pass
            for action in get_actions(flow):
                if action.type == OUTPUT:
                    if action.output.port >= 100 and action.output.port < 124:
                        action.output.port = action.output.port - 100
            self.log.info('bulk-flow-update2', device_id=device.id, flow=flow)
        '''
        
        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_SWITCH_UPDATE_FLOW_TABLE,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )

            data=msg_hdr.SerializeToString()
    
            self.zmq_client_async.async_send(data,1)

            flow_table = OltSwitchFlowTable(
                flows=flows
            )
            data=flow_table.SerializeToString()
    
            self.zmq_client_async.async_send(data,0)

        except Exception as e:
            self.log.exception('Exception during update flow table.', e=e)

    #@inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        if isinstance(msg, Packet):
            msg = str(msg)

        self.log.info('send-proxied-message',
                      proxy_address=proxy_address,
                      msg=msg)

        if self.zmq_client_omci is not None:
            pon_id = proxy_address.channel_id - 100
            onu_id = proxy_address.onu_id
            self.log.info('send-proxied-message pon_id:',pon_id)
            self.log.info('send-proxied-message onu_id:',onu_id)
            
        else:
            return
        

        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_PON_SEND_OMCI,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data=msg_hdr.SerializeToString()
            self.zmq_client_omci.omci_send(data,1)

            omci_msg = OltPonSendOmci(
                pon_slot=0,
                pon_port=pon_id,
                onu_id=onu_id,
                omci_content=msg
            )
            
            #self.log.info('omci_msg.pon_slot', omci_msg.pon_slot)
            #self.log.info('omci_msg.pon_port', omci_msg.pon_port)
            self.log.info('omci_msg.onu_id', omci_msg.onu_id, datetime.datetime.now())
            #self.log.info('omci_msg.omci_content', omci_msg.omci_content)
            
            data=omci_msg.SerializeToString()
            self.zmq_client_omci.omci_send(data,0)

        except Exception as e:
            self.log.info('zmq_client_omci.omci_send exception', exc=str(e))
            #raise
            
    def packet_in_msg_proc(self, message):
        try:
            self.log.info('packet_in_msg_proc: Message from oltd')
            sub_msg_header = OltMsgCommonHdr()
            sub_msg_header.ParseFromString(message[0])
            #self.log.info('got-response', sub_msg_header.type)
            #self.log.info('got-response', sub_msg_header.src_appId)
            #self.log.info('got-response', sub_msg_header.sync)

            if (sub_msg_header.src_appId != OLT_APPID_OLTD) or (sub_msg_header.sync != 0):
                self.log.exception('Get error msg.')
                return

            if sub_msg_header.type == OLT_D_PACKET_IN:
                if len(message) != 2:
                    self.log.exception('Get error packet in msg.')
                    return

                packet_msg = OltDEthPacket()
                packet_msg.ParseFromString(message[1])

                frame = packet_msg.pkt_buf
                #self.log.info('received packet_msg.pkt_len', packet_msg.pkt_len)
                #self.log.info('received packet_msg', hexify(packet_msg.pkt_buf))
                #self.log.info('received frame:', hexify(frame))
                #self.packet_out(1,frame)
                pkt = Ether(frame)
                if pkt.haslayer(Dot1Q):
                    inner_shim = pkt.getlayer(Dot1Q)
                    #if isinstance(outer_shim.payload, Dot1Q):
                        #inner_shim = outer_shim.payload
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
                        
                    #elif pkt.haslayer(Raw):
                        #raw_data = json.loads(pkt.getlayer(Raw).load)
                        #self.alarms.send_alarm(self, raw_data)
                else:
                    self.log.info('No Dot1Q tag.')
            else:
                self.log.exception('No support msg type.')
                return
        except Exception as e:
            self.log.exception('Exception during packet_in_msg_proc processing', e=e)

    def packet_out(self, egress_port, msg):
        self.log.debug('sending-packet-out', egress_port=egress_port,
                       msg_hex=hexify(msg))
        pkt = Ether(msg)
        out_pkt = (
            Ether(src=pkt.src, dst=pkt.dst) /
            Dot1Q(vlan=egress_port, type=pkt.type) /
            pkt.payload
        )
        #self.io_port.send(str(out_pkt))

        if self.zmq_client_of_packet is None:
            return            

        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_D_PACKET_OUT,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data=msg_hdr.SerializeToString()
            self.zmq_client_of_packet.packet_send(data,1)

            packet_msg = OltDEthPacket(
                pkt_len=len(str(out_pkt)),
                pkt_buf=str(out_pkt)
            )
            
            #self.log.info('packet_msg.pkt_len', packet_msg.pkt_len)
            #self.log.info('packet_msg.pkt_buf', packet_msg.pkt_buf)
            
            data=packet_msg.SerializeToString()
            self.zmq_client_of_packet.packet_send(data,0)

        except Exception as e:
            self.log.info('zmq_client_of_packet.packet_send exception', exc=str(e))

    def poll_metrics_receive(self, message):
        try:
            self.log.info('poll_metrics_receive: Message from oltd')
            self.poll_incoming_queue.put(message)

        except Exception as e:
            self.log.exception('Exception during poll_metrics_receive processing', e=e)

    def of_packet_receive(self, message):
        try:
            self.log.info('of_packet_receive: Message from oltd')
            
        except Exception as e:
            self.log.exception('Exception during of_packet_receive processing', e=e)

    def heartbeat_receive(self, message):
        if self.work_status == 0:
            return
        try:
            #self.log.info('heartbeat_receive: Message from oltd')
            sub_msg_header = OltMsgCommonHdr()
            sub_msg_header.ParseFromString(message[0])
            if sub_msg_header.type == OLT_COMMON_HEART_BEAT_ACK:

                heartbeat_ack = OltCommonHeartBeat()
                heartbeat_ack.ParseFromString(message[1])
                #self.log.info('heartbeat_ack.is_active', heartbeat_ack.is_active)
                if heartbeat_ack.seq_no != self.seq_no:
                    return 
                self.heartbeat_miss = 0
                #self.log.info("receive-heart-beat-ack heartbeat_ack.seq_no", heartbeat_ack.seq_no)
                
                if heartbeat_ack.is_active == 0:

                    if self.reboot_status == 0:
                        for port in self.southbound_ports.itervalues():
                            port.delete()
                
                    self.olt_activate_msg_send()
                    for channel_term in self._channel_terminations:
                        self.log.info('self._channel_terminations:', channel_term)
                        self._on_channel_termination_create(channel_term)
                        self.configure_pon(channel_term)
                        
                    for vont_ani in self._v_ont_anis:
                        self.log.info('self._v_ont_anis:', vont_ani)
                        self._on_vont_ani_create(vont_ani)
                        
                    for ont_ani in self._ont_anis:
                        self.log.info('self._ont_anis:', ont_ani)
                        self._on_ont_ani_create(ont_ani)

                    #self.log.info('pon and onu config recovery.', device_id=self.device_id)
                
        except Exception as e:
            self.log.exception('Exception during of_packet_receive processing', e=e)

    def omci_msg_proc(self, message):
        try:
            self.log.info('omci_msg_proc: Message from oltd')
            sub_msg_header = OltMsgCommonHdr()
            sub_msg_header.ParseFromString(message[0])
            #self.log.info('got-response', sub_msg_header.type)
            #self.log.info('got-response', sub_msg_header.src_appId)
            #self.log.info('got-response', sub_msg_header.sync)

            if (sub_msg_header.src_appId != OLT_APPID_OLTD) or (sub_msg_header.sync != 0):
                self.log.exception('Get error async msg.')
                return

            if sub_msg_header.type == OLT_PON_SEND_OMCI:
                if len(message) != 2:
                    self.log.exception('Get error omci msg.')
                    return

                omci_msg = OltPonSendOmci()
                omci_msg.ParseFromString(message[1])
                
                #self.log.info('omci_msg.pon_slot', omci_msg.pon_slot)
                #self.log.info('omci_msg.pon_port', omci_msg.pon_port)
                self.log.info('omci_msg.onu_id', omci_msg.onu_id, datetime.datetime.now())
                #self.log.info('omci_msg.omci_content', omci_msg.omci_content)

                #proxy_address=Device.ProxyAddress(
                #    device_id=self.device_id,
                #    channel_id=omci_msg.pon_port + 100,
                #    onu_id=omci_msg.onu_id,
                #)
                child_device = self.adapter_agent.get_child_device(self.device_id, onu_id=omci_msg.onu_id)
                self.adapter_agent.receive_proxied_message(child_device.proxy_address, omci_msg.omci_content)
                #self.adapter_agent.receive_proxied_message(proxy_address, omci_msg.omci_content)
            else:
                self.log.exception('No support omci msg type.')
                return
        except Exception as e:
            self.log.exception('Exception during omci_receive processing', e=e)

    def async_msg_proc(self, message):
        try:
            self.log.info('sub_receive: Message from oltd')
            sub_msg_header = OltMsgCommonHdr()
            sub_msg_header.ParseFromString(message[0])
            #self.log.info('got-response', sub_msg_header.type)
            #self.log.info('got-response', sub_msg_header.src_appId)
            #self.log.info('got-response', sub_msg_header.sync)

            if (sub_msg_header.src_appId != OLT_APPID_OLTD) or (sub_msg_header.sync != 0):
                self.log.exception('Get error async msg.')
                return

            if sub_msg_header.type == OLT_PON_ONU_RANGING_EVENT:
                if len(message) != 2:
                    self.log.exception('Get error async msg(OLT_PON_ONU_RANGING_EVENT).')
                    return

                self.log.info('sub_receive. msg_len', len(message), message[1])
                
                self.onu_detected(message[1])
            elif sub_msg_header.type == OLT_PON_ONU_ACTIVATE_COMPLETE:
                if len(message) != 2:
                    self.log.exception('Get error async msg(OLT_PON_ONU_ACTIVATE_COMPLETE).')
                    return

                self.log.info('sub_receive. msg_len', len(message), message[1])
                self.onu_activate_complete_msg_proc(message[1])
                
            else:
                self.log.exception('No support msg type.')
                #return

        except Exception as e:
            self.log.exception('Exception during sub_receive processing', e=e)


    def get_echo_queue(self):
        request = self.echo_incoming_queue.get()
        return request
        

    def get_sync_queue(self):
        request = self.sync_incoming_queue.get()
        return request

    def get_async_queue(self):
        request = self.async_incoming_queue.get()
        return request

    def get_omci_queue(self):
        request = self.omci_incoming_queue.get()
        return request

    def get_packet_in_queue(self):
        request = self.of_pkt_incoming_queue.get()
        return request

    def start_poll_async_msg(self):
        self.log.info('*** Starting polling async msg ***')
        self.asyncmsg = reactor.callLater(0, self.poll_async_msg)
        return self.asyncmsg
        
    @inlineCallbacks
    def poll_async_msg(self):
        try:
            response = yield self.get_async_queue()
            self.async_msg_proc(response)
        except Exception as e:
            self.log.info('wait-for-async-exception', exc=str(e))

        self.asyncmsg = reactor.callLater(0.07, self.poll_async_msg)

    def start_poll_omci_msg(self):
        self.log.info('*** Starting polling omci msg ***')
        self.omcimsg = reactor.callLater(0, self.poll_omci_msg)
        return self.omcimsg
        
    @inlineCallbacks
    def poll_omci_msg(self):
        try:
            response = yield self.get_omci_queue()
            self.omci_msg_proc(response)
        except Exception as e:
            self.log.info('wait-for-omci-exception', exc=str(e))

        self.omcimsg = reactor.callLater(0.1, self.poll_omci_msg)

    def start_poll_packet_in_msg(self):
        self.log.info('*** Starting polling packet in msg ***')
        self.packetmsg = reactor.callLater(0, self.poll_packet_in_msg)
        return self.packetmsg
        
    @inlineCallbacks
    def poll_packet_in_msg(self):
        try:
            response = yield self.get_packet_in_queue()
            self.packet_in_msg_proc(response)
        except Exception as e:
            self.log.info('wait-for-packet-in-exception', exc=str(e))

        self.packetmsg = reactor.callLater(0.1, self.poll_packet_in_msg)

    def start_heartbeat(self, delay=10):
        assert delay > 1
        self.log.info('*** Starting Device Heartbeat ***')
        self.heartbeat = reactor.callLater(delay, self.check_pulse)
        return self.heartbeat
        
    def check_pulse(self): 
        if self.work_status == 0:
            return
    
        self.heartbeat_check_status()
            
        try:
            echo_req = OltMsgCommonHdr(
                type=1,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
        
            data=echo_req.SerializeToString()
            self.zmq_client_async.async_send(data,1)
            
            self.seq_no += 1
            heart_beat = OltCommonHeartBeat(
                seq_no=self.seq_no,
                is_active=1
            )
            
            #self.log.info('send-heartbeat heart_beat.seq_no', heart_beat.seq_no)
            #self.log.info('send-heartbeat heart_beat.is_active', heart_beat.is_active)
            
            data=heart_beat.SerializeToString()
            self.zmq_client_async.async_send(data,0)
            
            self.heartbeat_miss += 1
            
        except Exception as e:
            self.log.exception('Exception during echo processing', e=e)

        # Reschedule next heartbeat
        #if self.logical_device_id is not None:
        #if self.startup_heartbeat
        self.heartbeat = reactor.callLater(self.heartbeat_interval, self.check_pulse)

    def heartbeat_check_status(self):
        """
        Check the number of heartbeat failures against the limit and emit an alarm if needed
        """
        device = self.adapter_agent.get_device(self.device_id)

        if self.heartbeat_miss >= self.heartbeat_failed_limit and device.connect_status == ConnectStatus.REACHABLE:
            self.log.warning('olt-heartbeat-failed', count=self.heartbeat_miss)
            self.heartbrat_status = 0
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.FAILED
            device.reason = 'heartbeat timeout'
            self.adapter_agent.update_device(device)

            self.heartbeat_alarm(True, self.heartbeat_miss)
        else:
            # Update device states
            if self.heartbeat_miss == 0 and device.connect_status != ConnectStatus.REACHABLE:
                self.heartbrat_status = 1
                self.log.info('heartbeat success')
                device.connect_status = ConnectStatus.REACHABLE
                device.oper_status = OperStatus.ACTIVE
                device.reason = ''
                self.adapter_agent.update_device(device)

                self.heartbeat_alarm(False)
            
    def heartbeat_alarm(self, status, heartbeat_misses=0):
        try:
            ts = arrow.utcnow().timestamp

            alarm_data = {'heartbeats_missed':str(heartbeat_misses)}

            alarm_event = self.adapter_agent.create_alarm(
                id='voltha.{}.{}.olt'.format(self.adapter.name, self.device_id),
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

            self.adapter_agent.submit_alarm(self.device_id, alarm_event)
            self.log.debug('olt-heartbeat alarm sent')

        except Exception as e:
            log.exception('failed-to-submit-alarm', e=e)    

    def onu_detected(self, message):

        onu_ranging_event = OltPonOnuRangingEvent()
        onu_ranging_event.ParseFromString(message)
        
        #self.log.info('onu_detected', onu_ranging_event.pon_slot)
        #self.log.info('onu_detected', onu_ranging_event.pon_port)
        self.log.info('onu_detected', onu_ranging_event.onu_id, datetime.datetime.now())
        #self.log.info('onu_detected', onu_ranging_event.sn)
        #self.log.info('onu_detected', onu_ranging_event.ranging_state)

        if onu_ranging_event.ranging_state == 1:
            if self.southbound_ports[onu_ranging_event.pon_port].onu_exist_check(onu_ranging_event.onu_id)==False:
                if self.work_mode == OLT_MODE_AUTO:
                    self.adapter_agent.child_device_detected(
                        parent_device_id=self.device_id,
                        parent_port_no=100 + onu_ranging_event.pon_port,
                        child_device_type='broadcom_onu',
                        proxy_address=Device.ProxyAddress(
                            device_id=self.device_id,
                            channel_id=onu_ranging_event.pon_port + 100,
                            onu_id=onu_ranging_event.onu_id,
                        ),
                        admin_state=AdminState.ENABLED,
                    )

                onu_info = {
                    'name': None,
                    'device-id': self.device_id,
                    'serial-number': onu_ranging_event.sn,
                    'xpon-name': None,
                    #'pon': onu_ranging_event.pon_port,
                    'pon': self.southbound_ports[onu_ranging_event.pon_port],
                    'onu-id': onu_ranging_event.onu_id,
                    'ranging-status': 1,
                    'config-status': 0,
                    'status_machine': 'init',
                    'enabled': None,
                    'channel-partition': None,
                    'expected-registration-id': None,
                    'upstream-channel-speed': None,
                    'upstream-fec': True,
                    'password': Onu.DEFAULT_PASSWORD,
                    't-conts': None,
                    'gem-ports': None,
                    'onu-vid': None,
                    'channel-id': onu_ranging_event.pon_port + 100,
                    'vont-ani': None
                }
                self.southbound_ports[onu_ranging_event.pon_port].onu_add(onu_info)

            else:
                if self.work_mode == OLT_MODE_CONFIG:
                    onu_info = {
                        'name': None,
                        'device-id': self.device_id,
                        'serial-number': onu_ranging_event.sn,
                        'xpon-name': None,
                        'pon': self.southbound_ports[onu_ranging_event.pon_port],
                        'onu-id': onu_ranging_event.onu_id,
                        'ranging-status': 1,
                        'config-status': None,
                        'status_machine': None,
                        'enabled': None,
                        'channel-partition': None,
                        'expected-registration-id': None,
                        'upstream-channel-speed': None,
                        'upstream-fec': None,
                        'password': None,
                        't-conts': None,
                        'gem-ports': None,
                        'onu-vid': None,
                        'channel-id': None,
                        'vont-ani': None
                    }
                    self.southbound_ports[onu_ranging_event.pon_port].onu_update(onu_info)
            
        else :
            if self.southbound_ports[onu_ranging_event.pon_port].onu_exist_check(onu_ranging_event.onu_id)==True:
                if self.work_mode == OLT_MODE_AUTO:
                    self.southbound_ports[onu_ranging_event.pon_port].onu_del(onu_ranging_event.onu_id)
                    child_device = self.adapter_agent.get_child_device(self.device_id, onu_id=onu_ranging_event.onu_id)
                    if child_device:
                        self.adapter_agent.delete_child_device(self.device_id, child_device.id)
                elif self.work_mode == OLT_MODE_CONFIG:
                    onu_info = {
                        'name': None,
                        'device-id': self.device_id,
                        'serial-number': onu_ranging_event.sn,
                        'xpon-name': None,
                        'pon': self.southbound_ports[onu_ranging_event.pon_port],
                        'onu-id': onu_ranging_event.onu_id,
                        'ranging-status': 0,
                        'config-status': None,
                        'status_machine': None,
                        'enabled': None,
                        'channel-partition': None,
                        'expected-registration-id': None,
                        'upstream-channel-speed': None,
                        'upstream-fec': None,
                        'password': None,
                        't-conts': None,
                        'gem-ports': None,
                        'onu-vid': None,
                        'channel-id': None,
                        'vont-ani': None
                    }
                    self.southbound_ports[onu_ranging_event.pon_port].onu_update(onu_info)

                    child_device = self.adapter_agent.get_child_device(self.device_id, onu_id=onu_ranging_event.onu_id)

                    self.log.info('onu_activate_ranging_down_msg', child_device)
                    time.sleep(1)
                        
                    if child_device is not None:
                        msg = {'proxy_address': child_device.proxy_address,'event': 'deactivation-completed'}
                        self.adapter_agent.publish_inter_adapter_message(child_device.id, msg)
                else:
                    pass


    def onu_activate_complete_msg_proc(self, message):
        onu_activate_complete_event = OltPonOnuActivateComplete()
        onu_activate_complete_event.ParseFromString(message)
        
        #self.log.info('onu_activate_complete_msg_proc', onu_activate_complete_event.pon_port)
        #self.log.info('onu_activate_complete_msg_proc', onu_activate_complete_event.onu_id)
        #self.log.info('onu_activate_complete_msg_proc', onu_activate_complete_event.result)

        child_device = self.adapter_agent.get_child_device(self.device_id, onu_id=onu_activate_complete_event.onu_id)

        self.log.info('onu_activate_complete_msg_proc', child_device)
        time.sleep(1)
            
        if child_device is not None:
            if onu_activate_complete_event.result==0:
                ind_info = {
                    'activation_successful': True
                }
                onu_status = 'activation_successful'
            else :
                ind_info = {
                    'activation_successful': False
                }
                onu_status = 'activation_fail'

            msg = {'proxy_address': child_device.proxy_address,'event': 'activation-completed', 'event_data': ind_info}
            self.adapter_agent.publish_inter_adapter_message(child_device.id, msg)
            self.log.info('onu_activate_complete_msg_proc', onu_activate_complete_event.pon_port)
            self.log.info('onu_activate_complete_msg_proc', onu_activate_complete_event.onu_id)
            self.log.info('onu_activate_complete_msg_proc', onu_activate_complete_event.result)
            
            #update onu
            onu_info = {
                'name': None,
                'device-id': self.device_id,
                'serial-number': None,
                'xpon-name': None,
                'pon': self.southbound_ports[onu_activate_complete_event.pon_port],
                'onu-id': onu_activate_complete_event.onu_id,
                'ranging-status': None,
                'config-status': None,
                'status_machine': onu_status,
                'enabled': None,
                'channel-partition': None,
                'expected-registration-id': None,
                'upstream-channel-speed': None,
                'upstream-fec': None,
                'password': None,
                't-conts': None,
                'gem-ports': None,
                'onu-vid': None,
                'channel-id':None,
                'vont-ani': None
            }
            self.southbound_ports[onu_activate_complete_event.pon_port].onu_update(onu_info)

            onu = self.southbound_ports[onu_activate_complete_event.pon_port].onu(onu_activate_complete_event.onu_id)
            if onu._status_machine == 'activation_successful':
                for tcont_id in onu._tconts:
                    self.log.info('onu_activate_complete_msg_proc tcont add', tcont_id)
                    onu.tcont_add_msg_send(self, tcont_id)
                for gemport_id in onu._gem_ports:
                    self.log.info('onu_activate_complete_msg_proc gem add', gemport_id)
                    gemport = onu._gem_ports.get(gemport_id)
                    onu.add_gemport(gemport, True)
                    
            
    def start_onu_test(self):
        self.log.info('*** Starting onu report test ***')
        self.test = reactor.callLater(0, self.onu_test, 1, 1, 1)
        return self.test

    def onu_test(self, port, onuid, state):
        onu_ranging_event = OltPonOnuRangingEvent(
            pon_slot=1,
            pon_port=port,
            onu_id=onuid,
            #sn='CIGONU' + str((port << 24) + (onuid << 8)),
            sn='BRCM00000001',
            ranging_state=state,
            eqd=1,
            distance=1
        )

        data=onu_ranging_event.SerializeToString()
        self.onu_detected(data)
        self.onu_id = onuid
        self.pon_port = port
        if self.onu_id < 1 :
            self.pon_port = port
            self.onu_id = onuid + 1
        else:
            self.pon_port = port + 1
            self.onu_id = 1

        if self.pon_port < 2:
            self.test = reactor.callLater(0.07, self.onu_test, self.pon_port, self.onu_id, state)
        #elif state == 1:
            #self.pon_port = 1
            #self.onu_id = 0
            #state = 0
            #self.test = reactor.callLater(0.07, self.onu_test, self.pon_port, self.onu_id, state)
            
    @inlineCallbacks
    def get_olt_info_com(self):

        while (True):    
            try:
                get_olt_info_req = OltMsgCommonHdr(
                    type=OLT_D_GET_OLT_INFO_REQ,
                    src_appId=OLT_APPID_VOLTHA,
                    sync=1
                )
           
                data=get_olt_info_req.SerializeToString()
                self.log.info('send get olt info msg.')
                self.zmq_client_sync.sync_send(data,0) 
                self.startup = self.get_sync_queue()
                results = yield self.startup
            
                if results == "RecvTimeoutErr.":
                    self.log.info('get olt info timeout.')
                    self.zmq_client_sync.sync_reconnect()
                    #returnValue (None)
                else:    
                    get_olt_info_rep = OltMsgCommonHdr()
                    get_olt_info_rep.ParseFromString(results[0])
                    self.log.info('get_olt_info_rep.type', get_olt_info_rep.type)
                    self.log.info('get_olt_info_rep.src_appId', get_olt_info_rep.src_appId)
                    self.log.info('get_olt_info_rep.sync', get_olt_info_rep.sync)
                    
                    if (get_olt_info_rep.type != OLT_D_GET_OLT_INFO_ACK) or (get_olt_info_rep.src_appId != OLT_APPID_OLTD) \
                        or (get_olt_info_rep.sync != 1) or (len(results) < 2):
                        self.log.info('get OltDGetOltInfoAck err.')
                        returnValue (None)
                    else:
                        olt_info = OltDGetOltInfoAck()
                        olt_info.ParseFromString(results[1])
                        self.log.info('olt_info.olt_state', olt_info.olt_state)
                        self.log.info('olt_info.vendor', olt_info.vendor)
                        self.log.info('olt_info.model', olt_info.model)
                        self.log.info('olt_info.hardware_version', olt_info.hardware_version)
                        self.log.info('olt_info.firmware_version', olt_info.firmware_version)
                        self.log.info('olt_info.software_version', olt_info.software_version)
                        self.log.info('olt_info.serial_number', olt_info.serial_number)
                        #add mac loginfo
                        self.log.info('olt_info.work_mode',olt_info.work_mode)
                        self.log.info('olt_info.mac_address',olt_info.mac_address)
                        returnValue (olt_info)
                    
            except Exception as e:
                self.log.exception('Exception during activate get olt info processing', e=e)
                returnValue (None)


    def olt_activate_msg_send(self):
        try:
            olt_activate_msg = OltMsgCommonHdr(
                type=OLT_D_ACTIVATE_OLT,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
        
            data=olt_activate_msg.SerializeToString()
        
            self.zmq_client_async.async_send(data,0)
        except Exception as e:
            self.log.exception('Exception during activate processing', e=e)

    def olt_deactivate_msg_send(self):
        try:
            msg_hdr = OltMsgCommonHdr(
                #type=OLT_D_DISABLE_OLT,
                type=OLT_D_DEACTIVATE_OLT,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data = msg_hdr.SerializeToString()
            self.zmq_client_async.async_send(data, 0)

            self.log.info("send-deactivate-olt ok")
        except Exception as e:
            self.log.exception('Exception during send deactivate olt', e=e)

    def olt_reboot_msg_send(self):
        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_D_REBOOT_OLT,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data = msg_hdr.SerializeToString()
            self.zmq_client_async.async_send(data, 0)

            self.log.info("send-reboot-olt ok")
        except Exception as e:
            self.log.exception('Exception during send deactivate olt', e=e)


    def get_logical_device(self, device):
        """
        Get the VOLTHA logical device
        :return: VOLTHA logical device or None
        """
        if self._logical_device is None:
            self._logical_device = LogicalDevice(
                # not setting id and datapth_id will let the adapter
                # agent pick id
                desc=ofp_desc(
                    mfr_desc='cord project',
                    hw_desc='n/a',
                    sw_desc='logical device for Cig-based PON',
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
        return self._logical_device
            



    def _get_xpon_collection(self, data):
        if isinstance(data, ChannelgroupConfig):
            return self._channel_groups
        elif isinstance(data, ChannelpartitionConfig):
            return self._channel_partitions
        elif isinstance(data, ChannelpairConfig):
            return self._channel_pairs
        elif isinstance(data, ChannelterminationConfig):
            return self._channel_terminations
        elif isinstance(data, OntaniConfig):
            return self._ont_anis
        elif isinstance(data, VOntaniConfig):
            return self._v_ont_anis
        elif isinstance(data, VEnetConfig):
            return self._v_enets
        return None
        
    def pon(self, pon_id):
        return self.southbound_ports.get(pon_id)

    @property
    def channel_terminations(self):
        return self._channel_terminations

    @property
    def channel_pairs(self):
        return self._channel_pairs

    @property
    def channel_partitions(self):
        return self._channel_partitions

    @property
    def ont_anis(self):
        return self._ont_anis

    @property
    def v_ont_anis(self):
        return self._v_ont_anis

    @property
    def v_enets(self):
        return self._v_enets

    @property
    def tconts(self):
        return self._tconts

    def _data_to_dict(self, data):
        name = data.name
        interface = data.interface
        inst_data = data.data

        if isinstance(data, ChannelgroupConfig):
            return 'channel-group', {
                'name': name,
                'enabled': interface.enabled,
                'system-id': inst_data.system_id,
                'polling-period': inst_data.polling_period
            }

        elif isinstance(data, ChannelpartitionConfig):
            def _auth_method_enum_to_string(value):
                from voltha.protos.bbf_fiber_types_pb2 import SERIAL_NUMBER, LOID, \
                    REGISTRATION_ID, OMCI, DOT1X
                return {
                    SERIAL_NUMBER: 'serial-number',
                    LOID: 'loid',
                    REGISTRATION_ID: 'registration-id',
                    OMCI: 'omci',
                    DOT1X: 'dot1x'
                }.get(value, 'unknown')

            return 'channel-partition', {
                'name': name,
                'enabled': interface.enabled,
                'authentication-method': _auth_method_enum_to_string(inst_data.authentication_method),
                'channel-group': inst_data.channelgroup_ref,
                'fec-downstream': inst_data.fec_downstream,
                'mcast-aes': inst_data.multicast_aes_indicator,
                'differential-fiber-distance': inst_data.differential_fiber_distance,
                'closest_ont_distance':inst_data.closest_ont_distance
            }

        elif isinstance(data, ChannelpairConfig):
            return 'channel-pair', {
                'name': name,
                'enabled': interface.enabled,
                'channel-group': inst_data.channelgroup_ref,
                'channel-partition': inst_data.channelpartition_ref,
                'line-rate': inst_data.channelpair_linerate
            }

        elif isinstance(data, ChannelterminationConfig):
            return 'channel-termination', {
                'name': name,
                'enabled': interface.enabled,
                'xgs-ponid': inst_data.xgs_ponid,
                'xgpon-ponid': inst_data.xgpon_ponid,
                'channel-pair': inst_data.channelpair_ref,
                'ber-calc-period': inst_data.ber_calc_period,
                'pon_tag':inst_data.pon_tag
            }

        elif isinstance(data, OntaniConfig):
            return 'ont-ani', {
                'name': name,
                'enabled': interface.enabled,
                'upstream-fec': inst_data.upstream_fec_indicator,
                'mgnt-gemport-aes': inst_data.mgnt_gemport_aes_indicator
            }

        elif isinstance(data, VOntaniConfig):
            return 'vOnt-ani', {
                'name': name,
                'enabled': interface.enabled,
                'onu-id': inst_data.onu_id,
                'expected-serial-number': inst_data.expected_serial_number,
                'expected-registration-id': inst_data.expected_registration_id,
                'preferred-channel-pair': inst_data.preferred_chanpair,
                'channel-partition': inst_data.parent_ref,
                'upstream-channel-speed': inst_data.upstream_channel_speed,
                'data': data
            }

        elif isinstance(data, VEnetConfig):
            return 'vEnet', {
                'name': name,
                'enabled': interface.enabled,
                'v-ont-ani': inst_data.v_ontani_ref
            }

        else:
            raise NotImplementedError('Unknown data type')

    @staticmethod
    def _dict_diff(lhs, rhs):
        """
        Compare the values of two dictionaries and return the items in 'rhs'
        that are different than 'lhs. The RHS dictionary keys can be a subset of the
        LHS dictionary, or the RHS dictionary keys can contain new values.
    
        :param lhs: (dict) Original dictionary values
        :param rhs: (dict) New dictionary values to compare to the original (lhs) dict
        :return: (dict) Dictionary with differences from the RHS dictionary
        """
        assert len(lhs.keys()) == len(set(lhs.iterkeys()) & (rhs.iterkeys())), 'Dictionary Keys do not match'
        return {k: v for k, v in rhs.items() if k not in lhs or lhs[k] != rhs[k]}

    def _valid_to_modify(self, item_type, valid, diffs):
        bad_keys = [mod_key not in valid for mod_key in diffs]
        if len(bad_keys) != 0:
            self.log.warn("{} modification of '{}' not supported").format(item_type, bad_keys[0])
            return False
        return True

    def _on_channel_group_modify(self, name, items, diffs):
        if len(diffs) == 0:
            return
    
        valid_keys = ['polling-period']     # Modify of these keys supported
    
        if self._valid_to_modify('channel-group', valid_keys, diffs.keys()):
            self.log.info('TODO: Not-Implemented-yet')
            # for k, v in diffs.items:
            #     items[name][k] = v
    
    def _on_channel_partition_modify(self, name, items, diffs):
        if len(diffs) == 0:
            return
    
        valid_keys = ['fec-downstream', 'mcast-aes', 'differential-fiber-distance']
    
        if self._valid_to_modify('channel-partition', valid_keys, diffs.keys()):
            self.log.info('TODO: Not-Implemented-yet')
            # for k, v in diffs.items:
            #     items[name][k] = v
    
    def _on_channel_pair_modify(self, name, items, diffs):
        if len(diffs) == 0:
            return
    
        valid_keys = ['line-rate']     # Modify of these keys supported
    
        if self._valid_to_modify('channel-pair', valid_keys, diffs.keys()):
            self.log.info('TODO: Not-Implemented-yet')
            # for k, v in diffs.items:
            #     items[name][k] = v



    def _on_channel_termination_create(self, name, pon_type='xgs-ponid'):
        assert name in self._channel_terminations, \
            '{} is not a channel-termination'.format(name)
        ct = self._channel_terminations[name]

        pon_id = ct[pon_type]
        # Look up the southbound PON port

        pon_port = self.southbound_ports.get(pon_id, None)
        if pon_port is None:
            raise ValueError('Unknown PON port. PON-ID: {}'.format(pon_id))

        assert ct['channel-pair'] in self._channel_pairs, \
            '{} is not a channel-pair'.format(ct['channel-pair'])
        cpair = self._channel_pairs[ct['channel-pair']]

        assert cpair['channel-group'] in self._channel_groups, \
            '{} is not a -group'.format(cpair['channel-group'])
        assert cpair['channel-partition'] in self._channel_partitions, \
            '{} is not a channel-partition'.format(cpair('channel-partition'))
        cg = self._channel_groups[cpair['channel-group']]
        cpart = self._channel_partitions[cpair['channel-partition']]

        enabled = ct['enabled']
        
        polling_period = cg['polling-period']
        authentication_method = cpart['authentication-method']
        # line_rate = cpair['line-rate']
        downstream_fec = cpart['fec-downstream']
        deployment_range = cpart['differential-fiber-distance']
        # mcast_aes = cpart['mcast-aes']

        # TODO: Support BER calculation period
        # TODO Support setting of line rate

        pon_port.xpon_name = name
        pon_port.discovery_tick = polling_period
        pon_port.authentication_method = authentication_method
        pon_port.deployment_range = deployment_range * 1000     # pon-agent uses meters
        pon_port.downstream_fec_enable = downstream_fec
        # TODO: For now, upstream FEC = downstream
        pon_port.upstream_fec_enable = downstream_fec

        # TODO: pon_port.mcast_aes = mcast_aes

        pon_port.admin_state = AdminState.ENABLED if enabled else AdminState.DISABLED

    def _on_channel_termination_modify(self, name, items, diffs):
        if len(diffs) == 0:
            return
    
        valid_keys = ['enabled']     # Modify of these keys supported
    
        if self._valid_to_modify('channel-termination', valid_keys, diffs.keys()):
            self.log.info('TODO: Not-Implemented-yet')
            # for k, v in diffs.items:
            #     items[name][k] = v

    def _on_channel_termination_delete(self, name, pon_type='xgs-ponid'):
        assert name in self._channel_terminations, \
            '{} is not a channel-termination'.format(name)
        ct = self._channel_terminations[name]
    
        # Look up the southbound PON port
        pon_id = ct[pon_type]
        pon_port = self.southbound_ports.get(pon_id, None)
        if pon_port is None:
            raise ValueError('Unknown PON port. PON-ID: {}'.format(pon_id))
    
        pon_port.admin_state = AdminState.DISABLED

    def _on_vont_ani_create(self, name):
        assert name in self._v_ont_anis, \
            '{} is not a v_ont_ani'.format(name)

        vani = self._v_ont_anis[name]

        va_cp_name = vani['preferred-channel-pair'] 
        
        if vani['preferred-channel-pair'] in self.channel_pairs:
            for ct_name in self._channel_terminations:
                #ct_name = ct['channel-pair']
                ct_cp_name = self._channel_terminations[ct_name]['channel-pair']

                if va_cp_name == ct_cp_name:
                    ct = self._channel_terminations[ct_name]
                    pon_id = ct['xgs-ponid']
            
                    # Look up the southbound PON port
                    pon_port = self.southbound_ports.get(pon_id, None)
                    if pon_port is not None:
                        sn = vani['expected-serial-number']
                        onu_id = vani['onu-id']
                        if pon_port.onu_exist_check(onu_id)==False:
                            #add onu
                            onu_info = {
                                'name': vani['name'],
                                'device-id': self.device_id,
                                'serial-number': sn,
                                'xpon-name': None,
                                'pon': pon_port,
                                'onu-id': onu_id,
                                'ranging-status': 0,
                                'config-status': 1,
                                'status_machine': 'init',
                                'enabled': vani['enabled'],
                                'channel-partition': vani['channel-partition'],
                                'expected-registration-id': vani['expected-registration-id'],
                                'upstream-channel-speed': vani['upstream-channel-speed'],
                                'upstream-fec': True,
                                'password': Onu.DEFAULT_PASSWORD,
                                't-conts': None,
                                'gem-ports': None,
                                'onu-vid': None,
                                'channel-id': pon_id + 100,
                                'vont-ani': vani
                            }
                            pon_port.onu_add(onu_info)
                        else:
                            #update onu
                            onu_info = {
                                'name': vani['name'],
                                'device-id': self.device_id,
                                'serial-number': sn,
                                'xpon-name': None,
                                'pon': pon_port,
                                'onu-id': onu_id,
                                'ranging-status': None,
                                'config-status': 1,
                                'status_machine': None,
                                'enabled': vani['enabled'],
                                'channel-partition': vani['channel-partition'],
                                'expected-registration-id': vani['expected-registration-id'],
                                'upstream-channel-speed': vani['upstream-channel-speed'],
                                'upstream-fec': None,
                                'password': None,
                                't-conts': None,
                                'gem-ports': None,
                                'onu-vid': None,
                                'channel-id':None,
                                'vont-ani': vani
                            }
                            pon_port.onu_update(onu_info)

                    else:
                        pass
                else:
                    pass
            else:
                pass
        else:
            pass            
            
        #if vani['protection-channel-pair'] in self.channel_pairs:
            #for ct in self._channel_terminations:
                #if ct['channel-pair']== vani['protection-channel-pair']:
                    #pon_id = ct['xgs-ponid']
            
                    # Look up the southbound PON port
                    #pon_port = self.southbound_ports.get(pon_id, None)
                    #if pon_port is not None:
                        #sn = vani['expected-serial-number']
                        #onu_id = vani['onu-id']
                        #if pon_port.onu_exist_check(onuid)==False:
                            #add onu
                            #onu_info = {
                                #'device-id': self.device_id,
                                #'serial-number': sn,
                                #'xpon-name': None,
                                #'pon': pon_port,
                                #'onu-id': onu_id,
                                #'enabled': enabled,
                                #'upstream-channel-speed': vani['upstream-channel-speed'],
                                #'password': Onu.DEFAULT_PASSWORD,
                                #'t-conts': None,
                                #'gem-ports': None,
                                #'onu-vid': None,
                                #'vont-ani': vani
                            #}
                            #pon_port.onu_add(onu_info)
                        #else:
                            #update onu


    def _on_vont_ani_delete(self, name):
        assert name in self._v_ont_anis, \
            '{} is not a v_ont_ani'.format(name)

        vani = self._v_ont_anis[name]

        va_cp_name = vani['preferred-channel-pair'] 
        
        if vani['preferred-channel-pair'] in self.channel_pairs:
            for ct_name in self._channel_terminations:
                ct_cp_name = self._channel_terminations[ct_name]['channel-pair']

                if va_cp_name == ct_cp_name:
                    ct = self._channel_terminations[ct_name]
                    pon_id = ct['xgs-ponid']
            
                    # Look up the southbound PON port
                    pon_port = self.southbound_ports.get(pon_id, None)
                    if pon_port is not None:
                        onu_id = vani['onu-id']
                        onu_info = {
                            'name': vani['name'],
                            'device-id': self.device_id,
                            'serial-number': None,
                            'xpon-name': None,
                            'pon': pon_port,
                            'onu-id': onu_id,
                            'ranging-status': None,
                            'config-status': 0,
                            'status_machine': None,
                            'enabled': None,
                            'channel-partition': None,
                            'expected-registration-id': None,
                            'upstream-channel-speed': None,
                            'upstream-fec': None,
                            'password': None,
                            't-conts': None,
                            'gem-ports': None,
                            'onu-vid': None,
                            'channel-id':None,
                            'vont-ani': None
                        }
                        pon_port.onu_update(onu_info)
                    else:
                        pass
                else:
                    pass
            else:
                pass
        else:
            pass            
            
        #if vani['protection-channel-pair'] in self.channel_pairs:
            #for ct in self._channel_terminations:
                #if ct['channel-pair']== vani['protection-channel-pair']:
                    #pon_id = ct['xgs-ponid']
            
                    # Look up the southbound PON port
                    #pon_port = self.southbound_ports.get(pon_id, None)
                    #if pon_port is not None:
                        #sn = vani['expected-serial-number']
                        #onu_id = vani['onu-id']
                        #if pon_port.onu_exist_check(onuid)==False:
                            #add onu
                            #onu_info = {
                                #'device-id': self.device_id,
                                #'serial-number': sn,
                                #'xpon-name': None,
                                #'pon': pon_port,
                                #'onu-id': onu_id,
                                #'enabled': enabled,
                                #'upstream-channel-speed': vani['upstream-channel-speed'],
                                #'password': Onu.DEFAULT_PASSWORD,
                                #'t-conts': None,
                                #'gem-ports': None,
                                #'onu-vid': None,
                                #'vont-ani': vani
                            #}
                            #pon_port.onu_add(onu_info)
                        #else:
                            #update onu


    def _on_ont_ani_create(self, name):
        assert name in self._ont_anis, \
            '{} is not a ont_ani'.format(name)

        ani = self._ont_anis[name]

        upstream_fec = ani['upstream-fec']

        #if upstream_fec == 1:
            #return 
            
        vani = self._v_ont_anis[name]

        if vani is None:
            return
            
        va_cp_name = vani['preferred-channel-pair'] 
        
        if va_cp_name in self.channel_pairs:
            for ct_name in self._channel_terminations:
                ct_cp_name = self._channel_terminations[ct_name]['channel-pair']

                if va_cp_name == ct_cp_name:
                    ct = self._channel_terminations[ct_name]
                    pon_id = ct['xgs-ponid']
            
                    # Look up the southbound PON port
                    pon_port = self.southbound_ports.get(pon_id, None)
                    if pon_port is not None:
                        sn = vani['expected-serial-number']
                        onu_id = vani['onu-id']
                        if pon_port.onu_exist_check(onu_id)==True:
                            #update onu
                            onu_info = {
                                'name': vani['name'],
                                'device-id': self.device_id,
                                'serial-number': sn,
                                'xpon-name': None,
                                'pon': pon_port,
                                'onu-id': onu_id,
                                'ranging-status': None,
                                'config-status': None,
                                'status_machine': None,
                                'enabled': None,
                                'channel-partition': None,
                                'expected-registration-id': None,
                                'upstream-channel-speed': None,
                                'upstream-fec': upstream_fec,
                                'password': None,
                                't-conts': None,
                                'gem-ports': None,
                                'onu-vid': None,
                                'channel-id':None,
                                'vont-ani': None
                            }
                            pon_port.onu_update(onu_info)

                    else:
                        pass
                else:
                    pass
            else:
                pass
        else:
            pass            
            
        
                    
    def create_interface(self, data):
        """
        Create XPON interfaces
        :param data: (xpon config info)
        """
        self.log.debug('create-interface', interface=data.interface, inst_data=data.data)

        name = data.name
        items = self._get_xpon_collection(data)

        if items is not None and name not in items:
            self._cached_xpon_pon_info = {}     # Clear cached data

        item_type, new_item = self._data_to_dict(data)
        #self.log.debug('new-item', item_type=item_type, item=new_item)

        if name not in items:
            self.log.debug('new-item', item_type=item_type, item=new_item)

            items[name] = new_item

            if isinstance(data, ChannelterminationConfig):
                self._on_channel_termination_create(name)
                self.configure_pon(name)
            elif isinstance(data, VOntaniConfig):
                self._on_vont_ani_create(name)
            elif isinstance(data, OntaniConfig):
                self._on_ont_ani_create(name)
            else:
                pass

    def configure_pon(self,name,pon_type='xgs-ponid'):
        self.log.debug('configure-pon', name=name)
        try:
            assert name in self._channel_terminations, \
                '{} is not a channel-termination'.format(name)
            ct = self._channel_terminations[name]

            pon_id = ct[pon_type]
            # Look up the southbound PON port
            pon_port = pon_id

            assert ct['channel-pair'] in self._channel_pairs, \
                '{} is not a channel-pair'.format(ct['channel-pair'])
            cpair = self._channel_pairs[ct['channel-pair']]

            assert cpair['channel-group'] in self._channel_groups, \
                '{} is not a -group'.format(cpair['channel-group'])
            assert cpair['channel-partition'] in self._channel_partitions, \
                '{} is not a channel-partition'.format(cpair('channel-partition'))
            cg = self._channel_groups[cpair['channel-group']]
            cpart = self._channel_partitions[cpair['channel-partition']]

            pon_tag = ct['pon_tag']
            closest_ont_distance = cpart['closest_ont_distance']
            differential_fiber_distance = cpart['differential-fiber-distance']
            fec_downstream = cpart['fec-downstream']
            aes_downstream = 1
            aes_upstream = 1
            pon_profile = 0
            bwmap_cycle = 8
            discover_period = cg['polling-period']




            msg_hdr = OltMsgCommonHdr(
                type=OLT_PON_CONFIGURE_PON,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data = msg_hdr.SerializeToString()
            self.zmq_client_async.async_send(data, 1)

            config_pon = OltPonConfigurePon(
                pon_port = pon_port,
                pon_id = pon_id,
                pon_tag = pon_tag,
                closest_ont_distance = closest_ont_distance,
                differential_fiber_distance = differential_fiber_distance,
                fec_downstream = fec_downstream,
                aes_downstream = aes_downstream,
                aes_upstream = aes_upstream,
                pon_profile = pon_profile,
                bwmap_cycle = bwmap_cycle,
                discover_period = discover_period
            )
            data = config_pon.SerializeToString()
            self.zmq_client_async.async_send(data, 0)
            self.log.debug('send configure-pon message success',config_pon=config_pon)

        except Exception as e:
            self.log.exception('Exception during configure pon', e=e)

            
    def update_interface(self, data):
        """
        Update XPON interfaces
        :param data: (xpon config info)
        """
        self.log.debug('update_interface', interface=data.interface, inst_data=data.data)
        
        name = data.name
        items = self._get_xpon_collection(data)

        if items is None:
            raise ValueError('Unknown data type: {}'.format(type(data)))

        existing_item = items.get(name)
        if existing_item is None:
            raise KeyError("'{}' not found. Type: {}".format(name, type(data)))
            
        item_type, update_item = self._data_to_dict(data)
        self.log.debug('update-item', item_type=item_type, item=update_item)
        
        # Calculate the difference
        diffs = self._dict_diff(existing_item, update_item)
        
        if len(diffs) == 0:
            self.log.debug('update-item-no-diffs')
        
        self._cached_xpon_pon_info = {}     # Clear cached data

        # Act on changed items
        if isinstance(data, ChannelgroupConfig):
            self._on_channel_group_modify(name, items, diffs)
            #raise NotImplementedError('TODO: not yet supported')
        
        elif isinstance(data, ChannelpartitionConfig):
            self._on_channel_partition_modify(name, items, diffs)
            #raise NotImplementedError('TODO: not yet supported')
        
        elif isinstance(data, ChannelpairConfig):
            self._on_channel_pair_modify(name, items, diffs)
            #raise NotImplementedError('TODO: not yet supported')
        
        elif isinstance(data, ChannelterminationConfig):
            self._on_channel_termination_modify(name, items, diffs)
            #raise NotImplementedError('TODO: not yet supported')
        
        elif isinstance(data, OntaniConfig):
            raise NotImplementedError('TODO: not yet supported')
        
        elif isinstance(data, VOntaniConfig):
            raise NotImplementedError('TODO: not yet supported')
        
        elif isinstance(data, VEnetConfig):
            raise NotImplementedError('TODO: not yet supported')
        
        else:
            raise NotImplementedError('Unknown data type')
            

    def remove_interface(self, data):
        """
        Deleete XPON interfaces
        :param data: (xpon config info)
        """
        self.log.debug('remove_interface', interface=data.interface, inst_data=data.data)
        
        name = data.name

        items = self._get_xpon_collection(data)
        item = items.get(name)
        self.log.debug('delete-interface', name=name, data=data)
        self.log.debug('remove_interface len(items)', len(items))

        if item is not None:
            self._cached_xpon_pon_info = {}     # Clear cached data
            #del items[name]

            if isinstance(data, ChannelgroupConfig):
                pass  # Rely upon xPON logic to not allow delete of a referenced group

            elif isinstance(data, ChannelpartitionConfig):
                pass  # Rely upon xPON logic to not allow delete of a referenced partition

            elif isinstance(data, ChannelpairConfig):
                pass  # Rely upon xPON logic to not allow delete of a referenced pair

            elif isinstance(data, ChannelterminationConfig):
                self._on_channel_termination_delete(name)

            elif isinstance(data, OntaniConfig):
                pass

            elif isinstance(data, VOntaniConfig):
                self._on_vont_ani_delete(name)
                #pass

            elif isinstance(data, VEnetConfig):
                pass

            else:
                raise NotImplementedError('Unknown data type')

            del items[name]
            self.log.debug('remove_interface len(items)', len(items))
            #raise NotImplementedError('TODO: not yet supported')


    def create_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Create TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        self.log.debug('create-tcont', tcont=tcont_data, td=traffic_descriptor_data)
        traffic_descriptor = TrafficDescriptor.create(traffic_descriptor_data)
        tcont = TCont.create(tcont_data, traffic_descriptor)

        if tcont.name not in self._tconts:
            self._cached_xpon_pon_info = {}     # Clear cached data
            self._tconts[tcont.name] = tcont
            
            # Update any ONUs referenced
            tcont.xpon_create(self)

            if traffic_descriptor.name not in self._traffic_descriptors:
                self._traffic_descriptors[traffic_descriptor.name] = traffic_descriptor

                # Update any ONUs referenced
                traffic_descriptor.xpon_create(self, tcont)

    def update_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Update TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        self.log.debug('update-tcont', tcont=tcont_data, td=traffic_descriptor_data)

        if tcont_data.name not in self._tconts:
            raise KeyError("TCONT '{}' does not exists".format(tcont_data.name))

        if traffic_descriptor_data.name not in self._traffic_descriptors:
            raise KeyError("Traffic Descriptor '{}' does not exists".
                           format(traffic_descriptor_data.name))

        self._cached_xpon_pon_info = {}     # Clear cached data

        traffic_descriptor = TrafficDescriptor.create(traffic_descriptor_data)
        tcont = TCont.create(tcont_data, traffic_descriptor)
        #
        # Update any ONUs referenced
        # tcont.xpon_update(self)
        # traffic_descriptor.xpon_update(self, tcont)
        pass
        raise NotImplementedError('TODO: Not yet supported')

    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Remove TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        self.log.debug('remove-tcont', tcont=tcont_data, td=traffic_descriptor_data)
        
        tcont = self._tconts.get(tcont_data.name)
        traffic_descriptor = self._traffic_descriptors.get(traffic_descriptor_data.name)

        if traffic_descriptor is not None:
            del self._traffic_descriptors[traffic_descriptor_data.name]

            self._cached_xpon_pon_info = {}     # Clear cached data
            pass         # Perform any needed operations
            #raise NotImplementedError('TODO: Not yet supported')

        if tcont is not None:
            #del self._tconts[tcont_data.name]

            self._cached_xpon_pon_info = {}     # Clear cached data

            #Update any ONUs referenced
            tcont.xpon_delete(self)
            del self._tconts[tcont_data.name]

            pass         # Perform any needed operations
            #raise NotImplementedError('TODO: Not yet supported')

    def create_gemport(self, gemport_data):
        """
        Create GEM Port
        :param data:
        """

        self.log.debug('create-gemport', gemport=gemport_data)
        gemport = Gemport.create(gemport_data)

        if gemport.name not in self._gemports:
            self._cached_xpon_pon_info = {}     # Clear cached data
            self._gemports[gemport.name] = gemport
            
            # Update any ONUs referenced
            gemport.xpon_create(self)

    def remove_gemport(self, data):
        """
        Delete GEM Port
        :param data:
        """
        self.log.debug('remove-gemport', gem_port=data.name)

        gemport = self._gemports.get(data.name)

        if gemport is not None:
            #del self._tconts[tcont_data.name]

            self._cached_xpon_pon_info = {}     # Clear cached data

            #Update any ONUs referenced
            gemport.xpon_delete(self)
            del self._gemports[data.name]

            pass         # Perform any needed operations


    def update_gemport(self, data):
        """
        Update GEM Port
        :param data:
        """
        self.log.debug('update-gemport', gem_port=data)
        pass



    def _unregister_for_inter_adapter_messages(self):
        try:
            self.adapter_agent.unregister_for_inter_adapter_messages()
        except:
            pass

    def _delete_logical_device(self):
        ldi, self.logical_device_id = self.logical_device_id, None

        if ldi is None:
            return

        self.log.debug('delete-logical-device', ldi=ldi)

        logical_device = self.adapter_agent.get_logical_device(ldi)
        self.adapter_agent.delete_logical_device(logical_device)

        device = self.adapter_agent.get_device(self.device_id)
        device.parent_id = ''

        #  Update the logical device mapping
        if ldi in self.adapter.logical_device_id_to_root_device_id:
            del self.adapter.logical_device_id_to_root_device_id[ldi]

    def _cancel_deferred(self):
        
        d1, self.heartbeat = self.heartbeat, None
        d2, self.asyncmsg = self.asyncmsg, None
        d3, self.omcimsg = self.omcimsg, None
        d4, self.packetmsg = self.packetmsg, None

        for d in [d1, d2, d3, d4]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def _zmq_shutdown(self):

        self.zmq_client_sub.sub_shutdown()
        self.zmq_client_sync.sync_shutdown()
        self.zmq_client_async.async_shutdown()
        self.zmq_client_omci.omci_shutdown()  
        self.zmq_client_of_packet.packet_shutdown()

    def _finish_reboot(self):

        if self.heartbrat_status == 1:
            self.log.info('reboot self.reboot_check_times:', self.reboot_check_times)
            self.reboot_check_times = 0

            # Reenable all child devices
            self.adapter_agent.update_child_devices_state(self.device_id,
                                                          admin_state=AdminState.ENABLED)
            #self.olt_activate_msg_send()
            #self.work_status = 1

            #for channel_term in self._channel_terminations:
                #self.log.info('self._channel_terminations:', channel_term)
                #self._on_channel_termination_create(channel_term)
                #self.configure_pon(channel_term)
                
            #for vont_ani in self._v_ont_anis:
                #self.log.info('self._v_ont_anis:', vont_ani)
                #self._on_vont_ani_create(vont_ani)

            self.reboot_status = 0
            self.log.info('rebooted', device_id=self.device_id)

        else:
            self.reboot_check_times += 1
            if self.reboot_check_times < 20:
                self.startup = reactor.callLater(10, self._finish_reboot)
            else:
                self.log.info('reboot fail. olt is unreachable.', device_id=self.device_id)

    def disable(self):
        self.log.info('disabling', device_id=self.device_id)

        #send deactivate msg
        self.olt_deactivate_msg_send()
        self.work_status = 0

        # Cancel any running enable/disable/... in progress
        d, self.startup = self.startup, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

        self._cancel_deferred()

        self._unregister_for_inter_adapter_messages()
        device = self.adapter_agent.get_device(self.device_id)

        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        #device.admin_state = AdminState.DISABLED
        self.adapter_agent.update_device(device)

        # Remove the logical device
        logical_device = self.adapter_agent.get_logical_device(
            self.logical_device_id)
        self.adapter_agent.delete_logical_device(logical_device)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      oper_status=OperStatus.UNKNOWN,
                                                      connect_status=ConnectStatus.UNREACHABLE,
                                                      admin_state=AdminState.DISABLED)
                                                      
        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        for port in self.southbound_ports.itervalues():
            port.delete()

        # Set all ports to disabled
        self.adapter_agent.disable_all_ports(self.device_id)

        #  Update the logice device mapping
        if self.logical_device_id in \
                self.adapter.logical_device_id_to_root_device_id:
            del self.adapter.logical_device_id_to_root_device_id[
                self.logical_device_id]
                
        if self.logical_device_id is not None:
            self.logical_device_id = None

        #self._delete_logical_device()
        self.log.info('disabled', device_id=device.id)

        #zmq shutdown
        #self._zmq_shutdown()
                

    def reenable(self,done_deferred=None):
        """
        This is called when a previously disabled device needs to be enabled based on a NBI call.
        :param done_deferred: (Deferred) Deferred to fire when done
        """
        self.log.info('re-enabling', device_id=self.device_id)

        # Cancel any running enable/disable/... in progress
        d, self.startup = self.startup, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass
            
        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVATING
        self.adapter_agent.update_device(device)

        # Set all ports to enabled
        self.adapter_agent.enable_all_ports(self.device_id)

        # Recreate the logical device
        logical_device = self.get_logical_device(device)
        self._logical_device = self.adapter_agent.create_logical_device(logical_device,dpid=self.olt_mac)

        # Recreate logical ports for all southbound and northbound interfaces
        for port_no in self.northbound_ports:
            logical_port = self.northbound_ports[port_no].get_logical_port()
            self.adapter_agent.add_logical_port(self._logical_device.id, logical_port)              

        # update device active status now
        device = self.adapter_agent.get_device(device.id)
        device.parent_id = self._logical_device.id
        device.oper_status = OperStatus.ACTIVE
        device.reason = ''
        self.logical_device_id = self._logical_device.id
        self.adapter_agent.update_device(device)
        

        # Reenable all child devices
        self.adapter_agent.update_child_devices_state(device.id,
                                                      oper_status=OperStatus.DISCOVERED,
                                                      connect_status=ConnectStatus.REACHABLE,
                                                      admin_state=AdminState.ENABLED)

        self.olt_activate_msg_send()
        self.work_status = 1

        for channel_term in self._channel_terminations:
            self.log.info('self._channel_terminations:', channel_term)
            self._on_channel_termination_create(channel_term)
            self.configure_pon(channel_term)
            
        for vont_ani in self._v_ont_anis:
            self.log.info('self._v_ont_anis:', vont_ani)
            self._on_vont_ani_create(vont_ani)

        for ont_ani in self._ont_anis:
            self.log.info('self._ont_anis:', ont_ani)
            self._on_ont_ani_create(ont_ani)
        
        #start heart_beat pm_collect
        self.log.debug('Starting heartbeat')
        self.start_heartbeat(delay=5)
        #self.start_onu_test()
        self.start_poll_async_msg()
        self.start_poll_omci_msg()
        #self.start_kpi_collection()
        self.start_poll_packet_in_msg()

        self.log.info('re-enabled', device_id=device.id)
        

    def reboot(self):
        self.log.info('rebooting', device_id=self.device_id)

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE
        #device = self.adapter_agent.get_device(self.device_id)
        #previous_oper_status = device.oper_status
        #previous_conn_status = device.connect_status
        #device.oper_status = OperStatus.ACTIVATING
        #device.connect_status = ConnectStatus.UNREACHABLE
        #self.adapter_agent.update_device(device)

        # Update the child devices connect state to UNREACHABLE
        #self.adapter_agent.update_child_devices_state(self.device_id,
        #                                              connect_status=ConnectStatus.UNREACHABLE)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(self.device_id,
                                                      admin_state=AdminState.DISABLED)
                                                      
        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(self.device_id)

        for port in self.southbound_ports.itervalues():
            port.delete()
                                                      
        self.olt_reboot_msg_send()

        self.reboot_status = 1
        self.heartbrat_status = 0
        self.reboot_check_times = 0
        self.startup = reactor.callLater(10, self._finish_reboot)


    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        #send deactivate msg
        #self.olt_deactivate_msg_send()

        #self._cancel_deferred()

        # Drop registration for adapter messages
        #self._unregister_for_inter_adapter_messages()

        # Cancel any outstanding tasks

        #d, self.startup = self.startup, None
        #try:
            #if d is not None and not d.called:
                #d.cancel()
        #except:
            #pass



        # clear xpon config
        self._channel_groups.clear
        self._channel_partitions.clear
        self._channel_pairs.clear
        self._channel_terminations.clear
        self._v_ont_anis.clear
        self._ont_anis.clear
        self._v_enets.clear
        self._tconts.clear
        self._traffic_descriptors.clear
        self._gemports.clear
        self._cached_xpon_pon_info.clear

        # Remove all child devices
        self.adapter_agent.delete_all_child_devices(self.device_id)
        
        self.log.info("_delete_logical_device")
        # Remove the logical device (should already be gone if disable came first)
        if self.logical_device_id is not None:
            logical_device = self.adapter_agent.get_logical_device(
                self.logical_device_id)
            self.adapter_agent.delete_logical_device(logical_device)
        
        #self.log.info("delete_all_peer_references")
        # Remove the peer references from this device
        #self.adapter_agent.delete_all_peer_references(self.device_id)

        #  Update the logice device mapping
        if self.logical_device_id in \
                self.adapter.logical_device_id_to_root_device_id:
            del self.adapter.logical_device_id_to_root_device_id[
                self.logical_device_id]

        if self.logical_device_id is not None:
            self.logical_device_id = None

        # Tell all ports to stop any background processing
        for port in self.northbound_ports.itervalues():
            port.delete()

        for port in self.southbound_ports.itervalues():
            port.delete()

        self.northbound_ports.clear()
        self.southbound_ports.clear()

        # Shutdown communications with OLT
        self._zmq_shutdown()

        self.log.info('deleted', device_id=self.device_id)

    def _update_download_status(self, request, download):
        if download is not None:
            request.state = download.download_state
            request.reason = download.failure_reason
            request.image_state = download.image_state
            request.additional_info = download.additional_info
            request.downloaded_bytes = download.downloaded_bytes
        else:
            request.state = ImageDownload.DOWNLOAD_UNKNOWN
            request.reason = ImageDownload.UNKNOWN_ERROR
            request.image_state = ImageDownload.IMAGE_UNKNOWN
            request.additional_info = "Download request '{}' not found".format(request.name)
            request.downloaded_bytes = 0

        self.adapter_agent.update_image_download(request)

    def start_download(self, device, request, done):
        """
        This is called to request downloading a specified image into
        the standby partition of a device based on a NBI call.

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done
        :return: (Deferred) Shall be fired to acknowledge the download.
        """
        log.info('image_download', request=request)

        try:
            if request.name in self._downloads:
                raise Exception("Download request with name '{}' already exists".
                                format(request.name))
            try:
                download = Download.create(self, request, self._download_protocols)

            except Exception:
                request.additional_info = 'Download request creation failed due to exception'
                raise

            try:
                self._downloads[download.name] = download
                self._update_download_status(request, download)
                done.callback('started')
                return done

            except Exception:
                request.additional_info = 'Download request startup failed due to exception'
                del self._downloads[download.name]
                download.cancel_download(request)
                raise

        except Exception as e:
            self.log.exception('create', e=e)

            request.reason = ImageDownload.UNKNOWN_ERROR
            request.state = ImageDownload.DOWNLOAD_FAILED
            if not request.additional_info:
                request.additional_info = e.message

            self.adapter_agent.update_image_download(request)

            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)
            raise




        

    def download_status(self, device, request, done):
        """
        This is called to inquire about a requested image download status based
        on a NBI call.

        The adapter is expected to update the DownloadImage DB object with the
        query result

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) Shall be fired to acknowledge
        """
        log.info('download_status', request=request)
        download = self._downloads.get(request.name)

        self._update_download_status(request, download)

        if request.state != ImageDownload.DOWNLOAD_STARTED:
            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)

        done.callback(request.state)
        return done



        

        
    def cancel_download(self, device, request, done):
        """
        This is called to cancel a requested image download based on a NBI
        call.  The admin state of the device will not change after the
        download.

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) Shall be fired to acknowledge
        """
        log.info('cancel_download', request=request)

        download = self._downloads.get(request.name)

        if download is not None:
            del self._downloads[request.name]
            result = download.cancel_download(request)
            self._update_download_status(request, download)
            done.callback(result)
        else:
            self._update_download_status(request, download)
            done.errback(KeyError('Download request not found'))

        if device.admin_state == AdminState.DOWNLOADING_IMAGE:
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)

        return done


    def activate_image(self, device, request, done):
        """
        This is called to activate a downloaded image from a standby partition
        into active partition.

        Depending on the device implementation, this call may or may not
        cause device reboot. If no reboot, then a reboot is required to make
        the activated image running on device

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) OperationResponse object.
        """
        log.info('activate_image', request=request)

        download = self._downloads.get(request.name)
        if download is not None:
            del self._downloads[request.name]
            result = download.activate_image()
            self._update_download_status(request, download)
            done.callback(result)
        else:
            self._update_download_status(request, download)
            done.errback(KeyError('Download request not found'))

        # restore admin state to enabled
        device.admin_state = AdminState.ENABLED
        self.adapter_agent.update_device(device)
        return done

    def revert_image(self, device, request, done):
        """
        This is called to deactivate the specified image at active partition,
        and revert to previous image at standby partition.

        Depending on the device implementation, this call may or may not
        cause device reboot. If no reboot, then a reboot is required to
        make the previous image running on device

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) OperationResponse object.
        """
        log.info('revert_image', request=request)
        download = self._downloads.get(request.name)
        if download is not None:
            del self._downloads[request.name]
            result = download.revert_image()
            self._update_download_status(request, download)
            done.callback(result)
        else:
            self._update_download_status(request, download)
            done.errback(KeyError('Download request not found'))

        # restore admin state to enabled
        device.admin_state = AdminState.ENABLED
        self.adapter_agent.update_device(device)
        return done



        
    
