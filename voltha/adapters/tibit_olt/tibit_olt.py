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
Tibit OLT device adapter
"""
import json
import time
from uuid import uuid4
import struct

import arrow
import structlog
from scapy.fields import StrField
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet, bind_layers
from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet.task import LoopingCall
from zope.interface import implementer

from common.frameio.frameio import BpfProgramFilter, hexify
from voltha.adapters.interface import IAdapterInterface
from voltha.extensions.eoam.EOAM import EOAMPayload, DPoEOpcode_SetRequest
from voltha.extensions.eoam.EOAM_TLV import DOLTObject, \
     NetworkToNetworkPortObject, OLTUnicastLogicalLink, \
     PortIngressRuleClauseMatchLength01, AddStaticMacAddress, \
     PortIngressRuleClauseMatchLength02, PortIngressRuleResultForward, \
     PortIngressRuleResultSet, PortIngressRuleResultInsert, \
     PortIngressRuleResultCopy, PortIngressRuleResultReplace, \
     PortIngressRuleResultDelete, PortIngressRuleResultOLTQueue, \
     PortIngressRuleResultOLTBroadcastQueue, \
     PortIngressRuleTerminator, AddPortIngressRule, CablelabsOUI, \
     ItuOUI, PonPortObject
from voltha.extensions.eoam.EOAM_TLV import PortIngressRuleHeader
from voltha.extensions.eoam.EOAM_TLV import ClauseSubtypeEnum
from voltha.extensions.eoam.EOAM_TLV import RuleOperatorEnum
from voltha.extensions.eoam.EOAM_TLV import DPoEVariableResponseCodes
from voltha.extensions.eoam.EOAM_TLV import TibitOUI
from voltha.extensions.eoam.EOAM import EOAMPayload, CablelabsOUI
from voltha.core.flow_decomposer import *
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.common_pb2 import LogLevel, ConnectStatus
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Device, Port
from voltha.protos.device_pb2 import DeviceType, DeviceTypes
from voltha.protos.events_pb2 import KpiEvent, MetricValuePairs
from voltha.protos.events_pb2 import KpiEventType
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_port, OFPPF_10GB_FD, \
     OFPPF_FIBER, OFPPS_LIVE, ofp_switch_features, OFPC_PORT_STATS, \
     OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS
from voltha.registry import registry
log = structlog.get_logger()

TIBIT_ONU_LINK_INDEX = 2

# Match on the MGMT VLAN, Priority 7
TIBIT_MGMT_VLAN = 4090
TIBIT_MGMT_PRIORITY = 7
frame_match_case1 = 'ether[14:2] = 0x{:01x}{:03x}'.format(
    TIBIT_MGMT_PRIORITY << 1, TIBIT_MGMT_VLAN)

TIBIT_PACKET_IN_VLAN = 4000
frame_match_case2 = '(ether[14:2] & 0xfff) = 0x{:03x}'.format(
    TIBIT_PACKET_IN_VLAN)

TIBIT_PACKET_OUT_VLAN = 4000

TIBIT_MSG_WAIT_TIME = 3

is_tibit_frame = BpfProgramFilter('{} or {}'.format(
    frame_match_case1, frame_match_case2))

### Received OAM Message Types
RxedOamMsgTypeEnum = {
    "Unknown": 0x00,
    # Info PDU - not currently used
    "Info": 0x01,
    # Event Notification - Tibit or DPoE Event
    "Event Notification": 0x02,
    "DPoE Get Response": 0x03,
    "DPoE Set Response": 0x04,
    # Specifically - a File Transfer ACK
    "DPoE File Transfer": 0x05,
    # Contains an embedded OMCI message
    "OMCI Message": 0x06,
    }

# TODO: This information should be conveyed to the adapter
# from a higher level.
MULTICAST_VLAN = 140


# Extract OLT MAC address: This is a good
# example of getting the OLT mac address

#for mac, device in self.device_ids.iteritems():
#    if device == dev_id:
#        olt_mac_address = mac
#        log.info('packet-out', olt_mac_address=olt_mac_address)

# To be removed in favor of OAM
class TBJSON(Packet):
    """ TBJSON 'packet' layer. """
    name = "TBJSON"
    fields_desc = [StrField("data", default="")]

bind_layers(Ether, TBJSON, type=0xA8C8)

TIBIT_COMMUNICATIONS_OUI=u'000CE2'
SUMITOMO_ELECTRIC_INDUSTRIES_OUI=u'0025DC'

ADTRAN_SHORTENED_VSSN=u'4144'                 # 'AD'
TIBIT_SHORTENED_VSSN=u'5442'                 # 'TB'

@implementer(IAdapterInterface)
class TibitOltAdapter(object):

    name = 'tibit_olt'

    supported_device_types = [
        DeviceType(
            id='tibit_olt',
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Tibit Communications Inc.',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.interface = registry('main').get_args().interface
        self.io_port = None
        self.incoming_queues = {}  # OLT mac_address -> DeferredQueue()
        self.device_ids = {}  # OLT mac_address -> device_id
        self.vlan_to_device_ids = {}  # c-vid -> (device_id, logical_device_id, mac_address)

    def start(self):
        log.debug('starting', interface=self.interface)
        log.info('started', interface=self.interface)

    def stop(self):
        log.debug('stopping')
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)
        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        log.info('adopt-device', device=device)
        self._activate_io_port()
        reactor.callLater(0, self._launch_device_activation, device)

    def _activate_io_port(self):
        if self.io_port is None:
            self.io_port = registry('frameio').open_port(
                self.interface, self._rcv_io, is_tibit_frame)

    @inlineCallbacks
    def _launch_device_activation(self, device):
        try:
            log.debug('launch_dev_activation')
            # prepare receive queue
            self.incoming_queues[device.mac_address] = DeferredQueue(size=100)

            # add mac_address to device_ids table
            olt_mac = device.mac_address
            self.device_ids[olt_mac] = device.id

            # send out ping to OLT device
            ping_frame = self._make_ping_frame(mac_address=olt_mac)
            self.io_port.send(ping_frame)

            # wait till we receive a response
            ## TODO add timeout mechanism so we can signal if we cannot reach
            ##device
            while True:
                response = yield self.incoming_queues[olt_mac].get()
                # verify response and if not the expected response
                if 1: # TODO check if it is really what we expect, and wait if not
                    break

        except Exception as e:
            log.exception('launch device failed', e=e)

        # if we got response, we can fill out the device info, mark the device
        # reachable
        jdev = json.loads(response.payload.payload.body.load)
        device.root = True
        device.vendor = 'Tibit Communications, Inc.'
        device.model = jdev.get('results', {}).get('device', 'DEVICE_UNKNOWN')
        device.hardware_version = jdev['results']['datecode']
        device.firmware_version = jdev['results']['firmware']
        device.software_version = jdev['results']['modelversion']
        device.serial_number = jdev['results']['manufacturer']

        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # then shortly after we create some ports for the device
        log.info('create-port')
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

        log.info('create-logical-device')
        # then shortly after we create the logical device with one port
        # that will correspond to the NNI port
        ld = LogicalDevice(
            desc=ofp_desc(
                mfr_desc=device.vendor,
                hw_desc=jdev['results']['device'],
                sw_desc=jdev['results']['firmware'],
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
        cap = OFPPF_10GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=0,
                hw_addr=mac_str_to_tuple(device.mac_address),
                name='nni',
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_10GB_FD,
                max_speed=OFPPF_10GB_FD
            ),
            device_id=device.id,
            device_port_no=nni_port.port_no,
            root_port=True
        ))

        # and finally update to active
        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        # Just transitioned to ACTIVE, wait a tenth of second
        # before checking for ONUs
        reactor.callLater(0.1, self._detect_onus, device)

    @inlineCallbacks
    def _detect_onus(self, device):
        # send out get 'links' to the OLT device
        olt_mac = device.mac_address
        links_frame = self._make_links_frame(mac_address=olt_mac)
        self.io_port.send(links_frame)
        while True:
            response = yield self.incoming_queues[olt_mac].get()
            # verify response and if not the expected response
            if 1: # TODO check if it is really what we expect, and wait if not
                break

        jdev = json.loads(response.payload.payload.body.load)
        onu_mac = ''
        child_device_name = ''
        for macid in jdev['results']:
            if macid['macid'] is None:
                log.info('MAC ID is NONE %s' % str(macid['macid']))
            elif macid['macid'][:6].upper() == SUMITOMO_ELECTRIC_INDUSTRIES_OUI:
                onu_mac_string = macid['macid']
                log.info('SUMITOMO mac address %s' % str(macid['macid']))
                child_device_name = 'dpoe_onu'

            elif macid['macid'][:4].upper() == ADTRAN_SHORTENED_VSSN:
                onu_mac_string = macid['macid']
                log.info('ADTRAN mac address %s' % str(macid['macid']))
                child_device_name = 'adtran_onu'

            else:
                onu_mac_string = '000c' + macid.get('macid', 'e2000000')[4:]
                log.info('TIBIT mac address %s' % onu_mac)
                child_device_name = 'tibit_onu'

            # Convert from string to colon separated form
            onu_mac = ':'.join(s.encode('hex') for s in onu_mac_string.decode('hex'))
            log.info('activate-olt-for-onu-%s' % onu_mac)
            mac_octet_4 = int(macid['macid'][-4:-2], 16)
            vlan_id = self._olt_side_onu_activation(mac_octet_4)
            self.adapter_agent.child_device_detected(
                parent_device_id=device.id,
                parent_port_no=1,
                child_device_type=child_device_name,
                mac_address = onu_mac,
                proxy_address=Device.ProxyAddress(
                    device_id=device.id,
                    channel_id=vlan_id
                    ),
                    vlan=vlan_id
                )

            ## Automatically setup default downstream control frames flow (in this case VLAN 4000)
            ## on the OLT for the new ONU/ONT device
            Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
            Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}
            packet_out_rule = (
                Ether(dst=device.mac_address) /
                Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
                EOAMPayload(
                    body=TibitOUI() / DPoEOpcode_SetRequest() /
                    NetworkToNetworkPortObject()/
                    PortIngressRuleHeader(precedence=13)/
                    PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                       operator=Operator['=='],
                                                       match=TIBIT_PACKET_OUT_VLAN)/
                    PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                       operator=Operator['=='], match=vlan_id)/
                    PortIngressRuleResultOLTQueue(unicastvssn="TBIT", unicastlink=int(onu_mac_string[4:], 16))/
                    PortIngressRuleResultForward()/
                    PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                    PortIngressRuleTerminator()/
                    AddPortIngressRule()))

            self.io_port.send(str(packet_out_rule))
            
            # Get and process the Set Response
            ack = False
            start_time = time.time()

            # Loop until we have a set response or timeout
            while not ack:
                frame = yield self.incoming_queues[olt_mac].get()
                #TODO - Need to add propoer timeout functionality
                #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                #    break  # don't wait forever

                respType = self._voltha_get_oam_msg_type(frame)
                log.info('Received OAM Message 0x %s' % str(respType))

                #Check that the message received is a Set Response
                if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                    ack = True
                else:
                    # Handle unexpected events/OMCI messages
                    self._voltha_check_resp(frame)

            # Verify Set Response
            if ack:
                (rc,branch,leaf,status) = self._voltha_check_set_resp(frame)
                if (rc == True):
                    log.info('Set Response had no errors')
                else:
                    raise Exception('Set Respose had errors')
                    log.info('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[status]))

            # also record the vlan_id -> (device_id, logical_device_id, linkid) for
            # later use.  The linkid is the macid returned.
            self.vlan_to_device_ids[vlan_id] = (device.id, device.parent_id, macid.get('macid', 0))

        ### KPI Metrics - Work in progress feature - Disabling for now
        ### Give the ONUs a chance to arrive before starting metric collection
        ###    reactor.callLater(5.0, self.start_kpi_collection, device.id)

    def _olt_side_onu_activation(self, serial):
        """
        This is where if this was a real OLT, the OLT-side activation for
        the new ONU should be performed. By the time we return, the OLT shall
        be able to provide tunneled (proxy) communication to the given ONU,
        using the returned information.
        """
        vlan_id = serial + 200
        return vlan_id

    def _rcv_io(self, port, frame):

        log.info('frame-received', frame=hexify(frame))

        # make into frame to extract source mac
        response = Ether(frame)

        if response.haslayer(Dot1Q):

            # All OAM responses from the OLT should have a TIBIT_MGMT_VLAN.
            # Responses from the ONUs should have a TIBIT_MGMT_VLAN followed by a ONU CTAG
            # All packet-in frames will have the TIBIT_PACKET_IN_VLAN.
            if response.getlayer(Dot1Q).type == 0x8100:

                if response.getlayer(Dot1Q).vlan == TIBIT_PACKET_IN_VLAN:

                    inner_tag_and_rest = response.payload.payload

                    if isinstance(inner_tag_and_rest, Dot1Q):

                        cvid = inner_tag_and_rest.vlan

                        frame = Ether(src=response.src,
                                      dst=response.dst,
                                      type=inner_tag_and_rest.type) /\
                                      inner_tag_and_rest.payload

                        _, logical_device_id, _ = self.vlan_to_device_ids.get(cvid)
                        if logical_device_id is None:
                            log.error('invalid-cvid', cvid=cvid)
                        else:
                            self.adapter_agent.send_packet_in(
                                logical_device_id=logical_device_id,
                                logical_port_no=cvid,  # C-VID encodes port no
                                packet=str(frame))

                    else:
                        log.error('packet-in-single-tagged',
                                  frame=hexify(response))

                else:
                    ## Mgmt responses received from the ONU
                    ## Since the type of the first layer is 0x8100,
                    ## then the frame must have an inner tag layer
                    olt_mac = response.src
                    device_id = self.device_ids[olt_mac]
                    channel_id = response[Dot1Q:2].vlan
                    log.info('received_channel_id', channel_id=channel_id,
                             device_id=device_id)

                    proxy_address=Device.ProxyAddress(
                        device_id=device_id,
                        channel_id=channel_id
                        )
                    # pop dot1q header(s)
                    msg = response.payload.payload
                    self.adapter_agent.receive_proxied_message(proxy_address, msg)

            else:
                ## Mgmt responses received from the OLT
                ## enqueue incoming parsed frame to right device
                log.info('received-dot1q-not-8100')
                self.incoming_queues[response.src].put(response)

    def _make_ping_frame(self, mac_address):
        # Create a json packet
        json_operation_str = '{\"operation\":\"version\"}'
        frame = Ether(dst=mac_address)/Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY)/TBJSON(data='json %s' % json_operation_str)
        return str(frame)

    def _make_links_frame(self, mac_address):
        # Create a json packet
        json_operation_str = '{\"operation\":\"links\"}'
        frame = Ether(dst=mac_address)/Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY)/TBJSON(data='json %s' % json_operation_str)
        return str(frame)

    def _make_stats_frame(self, mac_address, itype, link):
        # Create a json packet
        json_operation_str = ('{\"operation\":\"stats\",\"parameters\":{\"itype\":\"%s\",\"iinst\",\"0\",\"macid\":\"%s\"}}' % (itype, link))
        frame = Ether(dst=mac_address)/Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY)/TBJSON(data='json %s' % json_operation_str)
        return str(frame)

    def abandon_device(self, device):
        raise NotImplementedError(0
                                  )
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

    @inlineCallbacks
    def update_flows_bulk(self, device, flows, groups):
        log.info('########################################')
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0, "Cannot yet deal with groups"

        # extract ONU VID
        # vid_from_device_id = {v[0]: k for k,v in self.vlan_to_device_ids.iteritems()}
        # ONU_VID = vid_from_device_id[device.id]
        _inner_vid = None
        olt_mac = device.mac_address

        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

        for flow in flows.items:

            try:
                in_port = get_in_port(flow)
                assert in_port is not None

                precedence = 255 - min(flow.priority / 256, 255)

                if in_port == 2:
                    log.info('#### Downstream Rule ####')
                    dn_req = NetworkToNetworkPortObject()
                    dn_req /= PortIngressRuleHeader(precedence=precedence)

                    for field in get_ofb_fields(flow):

                        if field.type == ETH_TYPE:
                            _type = field.eth_type
                            log.info('#### field.type == ETH_TYPE ####')
                            dn_req /= PortIngressRuleClauseMatchLength02(
                                fieldcode=Clause['L2 Type/Len'],
                                operator=Operator['=='],
                                match=_type)

                        elif field.type == IP_PROTO:
                            _proto = field.ip_proto
                            log.info('#### field.type == IP_PROTO ####')

                        elif field.type == IN_PORT:
                            _port = field.port
                            log.info('#### field.type == IN_PORT ####', port=_port)

                        elif field.type == VLAN_VID:
                            _vlan_vid = field.vlan_vid & 0xfff
                            log.info('#### field.type == VLAN_VID ####', vlan=_vlan_vid)
                            _outer_vid = _vlan_vid

                        elif field.type == VLAN_PCP:
                            _vlan_pcp = field.vlan_pcp
                            log.info('#### field.type == VLAN_PCP ####', pcp=_vlan_pcp)

                        elif field.type == UDP_DST:
                            _udp_dst = field.udp_dst
                            log.info('#### field.type == UDP_DST ####', udp_dst=_udp_dst)

                        elif field.type == UDP_SRC:
                            _udp_src = field.udp_src
                            log.info('#### field.type == UDP_SRC ####', udp_src=_udp_src)

                        elif field.type == IPV4_DST:
                            _ipv4_dst = field.ipv4_dst
                            log.info('#### field.type == IPV4_DST ####', ipv4_dst=_ipv4_dst)

                        elif field.type == METADATA:
                            _metadata = field.table_metadata
                            log.info('#### field.type == METADATA ####', metadata=_metadata)
                            _inner_vid = _metadata

                        else:
                            raise NotImplementedError('field.type={}'.format(
                                field.type))

                    for action in get_actions(flow):

                        if action.type == OUTPUT:
                            log.info('#### action.type == OUTPUT ####')
                            dn_req /= PortIngressRuleResultForward()
                            if _outer_vid == MULTICAST_VLAN:
                                dn_req /= PortIngressRuleResultOLTBroadcastQueue()
                            elif _inner_vid is not None:
                                serial = _inner_vid - 200
                                link = (0xe222 << 16) | (serial << 8)
                                dn_req /= PortIngressRuleResultOLTQueue(unicastvssn="TBIT",
                                                                        unicastlink=link)
                            elif _inner_vid is None:
                                log.info('#### action.type == OUTPUT INNER VID is NONE ####')

                        elif action.type == POP_VLAN:
                            log.info('#### action.type == POP_VLAN ####')
                            if _outer_vid == MULTICAST_VLAN:
                                dn_req /= PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                                             operator=Operator['=='], match=_outer_vid)
                            else:
                                dn_req /= PortIngressRuleResultDelete(fieldcode=Clause['S-VLAN Tag'])
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                                             operator=Operator['=='], match=_outer_vid)
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                                             operator=Operator['=='], match=_inner_vid)

                        elif action.type == PUSH_VLAN:
                            log.info('#### action.type == PUSH_VLAN ####')
                            if action.push.ethertype != 0x8100:
                                log.error('unhandled-tpid',
                                          ethertype=action.push.ethertype)
                                dn_req /= PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'])

                        elif action.type == SET_FIELD:
                            log.info('#### action.type == SET_FIELD ####')
                            assert (action.set_field.field.oxm_class ==
                                    ofp.OFPXMC_OPENFLOW_BASIC)
                            field = action.set_field.field.ofb_field
                            if field.type == VLAN_VID:
                                dn_req /= PortIngressRuleResultSet(
                                    fieldcode=Clause['C-VLAN Tag'], value=field.vlan_vid & 0xfff)
                            else:
                                log.error('unsupported-action-set-field-type',
                                          field_type=field.type)
                        else:
                            log.error('UNSUPPORTED-ACTION-TYPE',
                                      action_type=action.type)

                    dn_req /= PortIngressRuleTerminator()
                    dn_req /= AddPortIngressRule()

                    msg = (
                        Ether(dst=device.mac_address) /
                        Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
                        EOAMPayload(
                            body=TibitOUI() / DPoEOpcode_SetRequest() / dn_req)
                    )

                    self.io_port.send(str(msg))

                    # Get and process the Set Response
                    ack = False
                    start_time = time.time()

                    # Loop until we have a set response or timeout
                    while not ack:
                        frame = yield self.incoming_queues[olt_mac].get()
                        #TODO - Need to add propoer timeout functionality
                        #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                        #    break  # don't wait forever

                        respType = self._voltha_get_oam_msg_type(frame)
                        log.info('Received OAM Message 0x %s' % str(respType))

                        #Check that the message received is a Set Response
                        if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                            ack = True
                        else:
                            # Handle unexpected events/OMCI messages
                            self._voltha_check_resp(frame)

                    # Verify Set Response
                    if ack:
                        (rc,branch,leaf,status) = self._voltha_check_set_resp(frame)
                        if (rc == True):
                            log.info('Set Response had no errors')
                        else:
                            raise Exception('Set Respose had errors')
                            log.info('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[status]))

                elif in_port == 1:
                    # Upstream rule
                    log.info('#### Upstream Rule ####')

                    field_match_vlan_upstream_with_link = False
                    up_req_link = PortIngressRuleHeader(precedence=precedence)

                    up_req_pon = PonPortObject()
                    up_req_pon /= PortIngressRuleHeader(precedence=precedence)

                    for field in get_ofb_fields(flow):

                        if field.type == ETH_TYPE:
                            _type = field.eth_type
                            log.info('#### field.type == ETH_TYPE ####', in_port=in_port,
                                     match=_type)
                            up_req_pon /= PortIngressRuleClauseMatchLength02(
                                fieldcode=Clause['L2 Type/Len'],
                                operator=Operator['=='],
                                match=_type)

                            up_req_link /= PortIngressRuleClauseMatchLength02(
                                fieldcode=Clause['L2 Type/Len'],
                                operator=Operator['=='],
                                match=_type)

                        elif field.type == IP_PROTO:
                            _proto = field.ip_proto
                            log.info('#### field.type == IP_PROTO ####', in_port=in_port,
                                     ip_proto=_proto)

                            up_req_pon /= PortIngressRuleClauseMatchLength01(
                                fieldcode=Clause['IPv4/IPv6 Protocol Type'],
                                operator=Operator['=='], match=_proto)

                            up_req_link /= PortIngressRuleClauseMatchLength01(
                                fieldcode=Clause['IPv4/IPv6 Protocol Type'],
                                operator=Operator['=='], match=_proto)

                        elif field.type == IN_PORT:
                            _port = field.port
                            log.info('#### field.type == IN_PORT ####')

                        elif field.type == VLAN_VID:
                            _vlan_vid = field.vlan_vid & 0xfff
                            log.info('#### field.type == VLAN_VID ####')
                            up_req_pon /= PortIngressRuleClauseMatchLength02(
                                fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                operator=Operator['=='], match=_vlan_vid)

                            serial = _vlan_vid - 200
                            link = (0xe222 << 16) | (serial << 8)
                            up_req_link /= OLTUnicastLogicalLink(unicastvssn='TBIT', unicastlink=link)

                            up_req_link /= PortIngressRuleClauseMatchLength02(
                                fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                operator=Operator['=='], match=_vlan_vid)
                            field_match_vlan_upstream_with_link = True


                        elif field.type == VLAN_PCP:
                            _vlan_pcp = field.vlan_pcp
                            log.info('#### field.type == VLAN_PCP ####')

                        elif field.type == UDP_DST:
                            _udp_dst = field.udp_dst
                            log.info('#### field.type == UDP_DST ####')
                            up_req_pon /= (PortIngressRuleClauseMatchLength02(fieldcode=Clause['TCP/UDP source port'],
                                                                              operator=Operator['=='], match=0x0044)/
                                           PortIngressRuleClauseMatchLength02(fieldcode=Clause['TCP/UDP destination port'],
                                                                              operator=Operator['=='], match=0x0043))

                        elif field.type == UDP_SRC:
                            _udp_src = field.udp_src
                            log.info('#### field.type == UDP_SRC ####')

                        else:
                            raise NotImplementedError('field.type={}'.format(
                                field.type))

                    for action in get_actions(flow):

                        if action.type == OUTPUT:
                            log.info('#### action.type == OUTPUT ####')
                            up_req_pon /= PortIngressRuleResultForward()
                            up_req_link /= PortIngressRuleResultForward()

                        elif action.type == POP_VLAN:
                            log.info('#### action.type == POP_VLAN ####')

                        elif action.type == PUSH_VLAN:
                            log.info('#### action.type == PUSH_VLAN ####')
                            if action.push.ethertype != 0x8100:
                                log.error('unhandled-ether-type',
                                          ethertype=action.push.ethertype)
                            if field_match_vlan_upstream_with_link == True:
                                up_req_link /= PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'],
                                                                      fieldinstance=1)
                            else:
                                up_req_pon /= PortIngressRuleResultInsert(fieldcode=Clause['C-VLAN Tag'],
                                                                      fieldinstance=0)

                        elif action.type == SET_FIELD:
                            log.info('#### action.type == SET_FIELD ####')
                            assert (action.set_field.field.oxm_class ==
                                    ofp.OFPXMC_OPENFLOW_BASIC)
                            field = action.set_field.field.ofb_field
                            if field.type == VLAN_VID:
                                if field_match_vlan_upstream_with_link == True:
                                    up_req_link /=(PortIngressRuleResultCopy(fieldcode=Clause['C-VLAN Tag'])/
                                                   PortIngressRuleResultReplace(fieldcode=Clause['C-VLAN Tag']))

                                up_req_pon /= PortIngressRuleResultSet(
                                    fieldcode=Clause['C-VLAN Tag'], value=field.vlan_vid & 0xfff)
                                up_req_link /= PortIngressRuleResultSet(
                                    fieldcode=Clause['C-VLAN Tag'], value=field.vlan_vid & 0xfff)
                            else:
                                log.error('unsupported-action-set-field-type',
                                          field_type=field.type)

                        else:
                            log.error('UNSUPPORTED-ACTION-TYPE',
                                      action_type=action.type)

                    if (field_match_vlan_upstream_with_link == True):
                        up_req = up_req_link
                    else:
                        up_req = up_req_pon

                    up_req /= PortIngressRuleTerminator()
                    up_req /= AddPortIngressRule()

                    msg = (
                        Ether(dst=device.mac_address) /
                        Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
                        EOAMPayload(
                            body=TibitOUI() / DPoEOpcode_SetRequest() / up_req)
                    )

                    self.io_port.send(str(msg))

                    # Get and process the Set Response
                    ack = False
                    start_time = time.time()

                    # Loop until we have a set response or timeout
                    while not ack:
                        frame = yield self.incoming_queues[olt_mac].get()
                        #TODO - Need to add propoer timeout functionality
                        #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                        #    break  # don't wait forever

                        respType = self._voltha_get_oam_msg_type(frame)
                        log.info('Received OAM Message 0x %s' % str(respType))

                        #Check that the message received is a Set Response
                        if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                            ack = True
                        else:
                            # Handle unexpected events/OMCI messages
                            self._voltha_check_resp(frame)

                    # Verify Set Response
                    if ack:
                        (rc,branch,leaf,status) = self._voltha_check_set_resp(frame)
                        if (rc == True):
                            log.info('Set Response had no errors')
                        else:
                            raise Exception('Set Respose had errors')
                            log.info('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[status]))

                else:
                    raise Exception('Port should be 1 or 2 by our convention')

            except Exception, e:
                log.exception('failed-to-install-flow', e=e, flow=flow)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address)
        device = self.adapter_agent.get_device(proxy_address.device_id)

        mac_address = self.vlan_to_device_ids[proxy_address.channel_id][2].upper()

        if mac_address.startswith(TIBIT_SHORTENED_VSSN):
            # Send straight OAM
            frame = Ether(dst=device.mac_address) / \
              Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) / \
              Dot1Q(vlan=proxy_address.channel_id, prio=TIBIT_MGMT_PRIORITY) / \
              msg
        else:
            # Use the standard to send OMCI over OAM
            encapsulated_omci = EOAMPayload(body=ItuOUI()/msg)

            frame = Ether(dst=device.mac_address) / \
              Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) / \
              Dot1Q(vlan=proxy_address.channel_id, prio=TIBIT_MGMT_PRIORITY) / \
              encapsulated_omci

        self.io_port.send(str(frame))

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

        _, logical_dev_id, _ = self.vlan_to_device_ids[egress_port_no]
        if logical_dev_id != logical_device_id:
            raise Exception('Internal table mismatch')

        tmp = Ether(msg)

        frame = Ether(dst=tmp.dst, src=tmp.src) / \
                Dot1Q(vlan=TIBIT_PACKET_OUT_VLAN) / \
                Dot1Q(vlan=egress_port_no) / \
                tmp.payload

        self.io_port.send(str(frame))

    def start_kpi_collection(self, device_id):
        """ Periodic KPI metric collection from the device """
        import random

        # This is setup (for now) to be called from the adapter.  Push
        # architectures should be explored in the near future.
        @inlineCallbacks
        def _collect(device_id, prefix):

            pon_port_metrics = {}
            links = []
            olt_mac = next((mac for mac, device in self.device_ids.iteritems() if device == device_id), None)
            links   = [v[TIBIT_ONU_LINK_INDEX] for _,v,_ in self.vlan_to_device_ids.iteritems()]

            try:
                # Step 1: gather metrics from device
                log.info('link stats frame', links=links)
                for link in links:
                    stats_frame = self._make_stats_frame(mac_address=olt_mac, itype='olt', link=link)
                    self.io_port.send(stats_frame)

                    ## Add timeout mechanism so we can signal if we cannot reach
                    ## device
                    while True:
                        response = yield self.incoming_queues[olt_mac].get()
                        jdict = json.loads(response.payload.payload.body.load)
                        pon_port_metrics[link] = {k: int(v,16) for k,v in jdict['results'].iteritems()}
                        # verify response and if not the expected response
                        if 1: # TODO check if it is really what we expect, and wait if not
                            break

                log.info('nni stats frame')
                olt_nni_link = ''.join(l for l in olt_mac.split(':'))
                stats_frame = self._make_stats_frame(mac_address=olt_mac, itype='eth', link=olt_nni_link)
                self.io_port.send(stats_frame)

                ## Add timeout mechanism so we can signal if we cannot reach
                ## device
                while True:
                    response = yield self.incoming_queues[olt_mac].get()
                    jdict = json.loads(response.payload.payload.body.load)
                    nni_port_metrics = {k: int(v,16) for k,v in jdict['results'].iteritems()}
                    # verify response and if not the expected response
                    if 1: # TODO check if it is really what we expect, and wait if not
                        break

                olt_metrics = dict(
                    cpu_util=20 + 5 * random.random(),
                    buffer_util=10 + 10 * random.random()
                )

                # Step 2: prepare the KpiEvent for submission
                # we can time-stamp them here (or could use time derived from OLT
                ts = arrow.utcnow().timestamp
                prefixes = {
                    # CPU Metrics (example)
                    prefix: MetricValuePairs(metrics=olt_metrics),
                    # OLT NNI port
                    prefix + '.nni': MetricValuePairs(metrics=nni_port_metrics)
                    }

                for link in links:
                    # PON link ports
                    prefixes[prefix + '.pon.{}'.format(link)] = MetricValuePairs(metrics=pon_port_metrics[link])

                kpi_event = KpiEvent(
                    type=KpiEventType.slice,
                    ts=ts,
                    prefixes=prefixes
                )

                # Step 3: submit
                self.adapter_agent.submit_kpis(kpi_event)

            except Exception as e:
                log.exception('failed-to-submit-kpis', e=e)

        prefix = 'voltha.{}.{}'.format(self.name, device_id)
        lc = LoopingCall(_collect, device_id, prefix)
        lc.start(interval=15)  # TODO make this configurable

    def _voltha_get_oam_msg_type(self, frame):
        respType = RxedOamMsgTypeEnum["Unknown"]
        recv_frame = frame
        payload = recv_frame.payload
        if hasattr(payload, 'body'):
            loadstr       = payload.body.load
            bytesRead = 0;
            if (payload.opcode == 0xFE):

                # Extract the OUI
                (oui_hi, oui_lo) = struct.unpack_from('>BH', loadstr, bytesRead)
                oui = (oui_hi << 16) | oui_lo
                log.debug('oui: 0x %06x' % oui)
                bytesRead += 3

                # If this is the ITU OUI, then there is an embedded OMCI message
                if (oui == 0x0019A7):
                    respType = RxedOamMsgTypeEnum["OMCI Message"]

                # Treat Cablelabs OUI and Tibit OUI as the same
                elif ((oui == 0x001000) or (oui == 0x2AEA15)):

                    (dpoeOpcode) = struct.unpack_from('>B', loadstr, bytesRead)[0]
#                    log.info('DPoE Opcode:    {} ({:0>2X})'.format(DPoEOpcodeEnum[dpoeOpcode], dpoeOpcode))
                    bytesRead += 1

                    # Get Response
                    if (dpoeOpcode == 0x02):
                        respType = RxedOamMsgTypeEnum["DPoE Get Response"]

                    # Set Response
                    elif (dpoeOpcode == 0x04):
                        respType = RxedOamMsgTypeEnum["DPoE Set Response"]

                    # File Transfer ACK
                    elif (dpoeOpcode == 0x09):
                        respType = RxedOamMsgTypeEnum["DPoE File Transfer"]

                else:
                    log.info('Unsupported OAM OUI 0x{:0>6X}'.format(oui))

            # Handle OAM Event Notification
            elif (payload.opcode == 0x01):
                respType = RxedOamMsgTypeEnum["Event Notification"]
            else:
                log.info('Unsupported OAM Opcode {}'.format(payload.opcode))
        else:
            log.debug('received frame has no payload')

        return respType


    def _voltha_check_set_resp(self, frame):
        rc = False
        branch = 0
        leaf = 0
        status = 0

        recv_frame = frame
        payload = recv_frame.payload
        if hasattr(payload, 'body'):
            loadstr   = payload.body.load
            bytesRead = 0;
            #if self.report_obj is not None:
            #    self.report_obj.log_result(data="OAM Opcode", actual=hex(payload.opcode), expected=hex(0xFE), criteria="==")
            if (payload.opcode == 0xFE):

                # Extract the OUI
                (oui_hi, oui_lo) = struct.unpack_from('>BH', loadstr, bytesRead)
                oui = (oui_hi << 16) | oui_lo
                log.info('oui: 0x %06x' % oui)
                bytesRead += 3

                # Treat Cablelabs OUI and Tibit OUI as the same
                if ((oui == 0x001000) or (oui == 0x2AEA15)):
                    (dpoeOpcode) = struct.unpack_from('>B', loadstr, bytesRead)[0]
                    bytesRead += 1

                    startOfTlvs = bytesRead
                    # Set Response
                    if (dpoeOpcode == 0x04):
                        test =1
                        (rc,branch,leaf,status) = self._voltha_check_set_resp_attrs(loadstr, startOfTlvs)
                        if (rc == True):
                            log.info('Set Response had no errors')
                        else:
                            log.debug('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[status]))
                    else:
                        log.info('Unsupported DPoE Opcode: {} ({:0>2X})'.format(DPoEOpcodeEnum[dpoeOpcode], dpoeOpcode))
                else:
                    log.info('Unsupported OAM OUI 0x{:0>6X}'. format(oui))
            else:
                log.info('Unsupported OAM Opcode {}'.format(payload.opcode))
        else:
            log.debug('received frame has no payload')

        return rc,branch,leaf,status
    

    def _voltha_check_resp(self, frame):
        recv_frame = frame
        payload = recv_frame.payload
        if hasattr(payload, 'body'):
            loadstr   = payload.body.load
            bytesRead = 0;
            if (payload.opcode == 0xFE):
                
                # Extract the OUI
                (oui_hi, oui_lo) = struct.unpack_from('>BH', loadstr, bytesRead)
                oui = (oui_hi << 16) | oui_lo
                log.info('oui: 0x %06x' % oui)
                bytesRead += 3

                # If this is the ITU OUI, then there is an embedded OMCI message
                if (oui == 0x0019A7):
                    self._voltha_handle_omci(loadstr,bytesRead)

                # Treat Cablelabs OUI and Tibit OUI as the same
                elif ((oui == 0x001000) or (oui == 0x2AEA15)):
                    log.debug('Recieved Response OUI 0x{:0>6X}'. format(oui))
                else:
                    log.info('Unsupported OAM OUI 0x{:0>6X}'. format(oui))

            # Handle OAM Event Notification
            elif (payload.opcode == 0x01):
                self._voltha_handle_oam_event(loadstr, bytesRead)
            else:
                log.info('Unsupported OAM Opcode {}'.format(payload.opcode))

        else:
            log.debug('received frame has no payload')


    def _voltha_handle_oam_event(self, loadstr, startOfEvent):
        bytesRead = startOfEvent
        (seq_num, tlv_type, ev_len, oui_hi, oui_lo) = struct.unpack_from('>HBBBH', loadstr, bytesRead)
        oui = (oui_hi << 16) | oui_lo

        log.info('seq_num:        0x%04x' % seq_num)
        log.info('tlv_type:       0x%' % tlv_type)
        log.info('ev_len:         0x%x' % ev_len)
        log.info('oui:            0x%06x"'% oui)

        if (tlv_type != 0xFE):
            log.debug('unexpected tlv_type 0x%x (expected 0xFE)' % tlv_type)
        elif (oui == 0x001000):
            log.debug('DPoE Event')
            ## TODO - Handle DPoE Event/Alarm
        elif (oui == 0x2AEA15):
            log.debug('Tibit-specific Event')

            # TODO - Handle addition/removal of links

            bytesRead = 7

            # TODO - Check OUI and parse Source and Reference Object Contexts
    

    def _voltha_handle_omci(self, loadstr, startOfEvent):
        bytesRead = startOfEvent
#        (seq_num, tlv_type, ev_len, oui_hi, oui_lo) = struct.unpack_from('>BBBBBH', loadstr, bytesRead)

        log.debug('OMCI Message')

        # TODO - Handle OMCI message



    def _voltha_handle_get_value(self, loadstr, startOfTlvs, queryBranch, queryLeaf):
        retVal = False;
        value = 0
        branch = 0
        leaf = 0
        bytesRead = startOfTlvs
        loadstrlen    = len(loadstr)

        while (bytesRead <= loadstrlen):
            (branch, leaf) = struct.unpack_from('>BH', loadstr, bytesRead)
#            log.info('Branch/Leaf        0x{:0>2X}/0x{:0>4X}'.format(branch, leaf))

            if (branch != 0):
                bytesRead += 3
                length = struct.unpack_from('>B', loadstr, bytesRead)[0]
#                log.info('Length:            0x{:0>2X} ({})'.format(length,length))
                bytesRead += 1

                if (length == 1):
                    value = struct.unpack_from(">B", loadstr, bytesRead)[0]
                elif (length == 2):
                    value = struct.unpack_from(">H", loadstr, bytesRead)[0]
                elif (length == 4):
                    value = struct.unpack_from(">I", loadstr, bytesRead)[0]
                elif (length == 8):
                    value = struct.unpack_from(">Q", loadstr, bytesRead)[0]
                else:
                    if (length >= 0x80):
                        log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[length]))
                        # Set length to zero so bytesRead doesn't get mistakenly incremented below
                        length = 0
                    else:
                        # Attributes with a length of zero are actually 128 bytes long
                        if (length == 0):
                            length = 128;
                        valStr = ">{}s".format(length)
                        value = struct.unpack_from(valStr, loadstr, bytesRead)[0]

#                log.info('Value:             {}'.format(value))

                if (length > 0):
                    bytesRead += length

                if (branch != 0xD6):
                    if ( ((queryBranch == 0) and (queryLeaf == 0)) or
                         ((queryBranch == branch) and (queryLeaf == leaf)) ):
                        # Prevent zero-lengthed values from returning success
                        if (length > 0):
                            retVal = True;
                        break
            else:
                break

        if (retVal == False):
            value = 0

        return retVal,bytesRead,value,branch,leaf

    def _voltha_check_set_resp_attrs(self, loadstr, startOfTlvs):
        retVal = True;
        branch = 0
        leaf = 0
        length = 0
        bytesRead = startOfTlvs
        loadstrlen    = len(loadstr)

        while (bytesRead <= loadstrlen):
            (branch, leaf) = struct.unpack_from('>BH', loadstr, bytesRead)
#            log.info('Branch/Leaf        0x{:0>2X}/0x{:0>4X}'.format(branch, leaf))

            if (branch != 0):
                bytesRead += 3
                length = struct.unpack_from('>B', loadstr, bytesRead)[0]
#                log.info('Length:            0x{:0>2X} ({})'.format(length,length))
                bytesRead += 1

                if (length >= 0x80):
                    log.debug('Branch 0x{:0>2X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[length]))
                    if (length > 0x80):
                        retVal = False;
                        break;
                else:
                    bytesRead += length

            else:
                break

        return retVal,branch,leaf,length



    def _voltha_handle_fx_ack(self, loadstr, startOfXfer, block_number):
        retVal = False
        (fx_opcode, acked_block, response_code) = struct.unpack_from('>BHB', loadstr, startOfXfer)

        log.debug('fx_opcode:      0x%x' % fx_opcode)
        log.debug('acked_block:    0x%x' % acked_block)
        log.debug('response_code:  0x%x' % response_code)



        if (fx_opcode != 0x03):
            log.debug('unexpected fx_opcode 0x%x (expected 0x03)' % fx_opcode)
        elif (acked_block != block_number):
            log.debug('unexpected acked_block 0x%x (expected 0x%x)' % (acked_block, block_number))
        elif (response_code != 0):
            log.debug('unexpected response_code 0x%x (expected 0x00)' % response_code)
        else:
            retVal = True;

