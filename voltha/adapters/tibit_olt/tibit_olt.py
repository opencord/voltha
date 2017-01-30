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
from uuid import uuid4

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
     PortIngressRuleTerminator, AddPortIngressRule, CablelabsOUI, PonPortObject
from voltha.extensions.eoam.EOAM_TLV import PortIngressRuleHeader
from voltha.extensions.eoam.EOAM_TLV import ClauseSubtypeEnum
from voltha.extensions.eoam.EOAM_TLV import RuleOperatorEnum
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

is_tibit_frame = BpfProgramFilter('{} or {}'.format(
    frame_match_case1, frame_match_case2))

#is_tibit_frame = lambda x: True

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

bind_layers(Ether, TBJSON, type=0x9001)

SUMITOMO_ELECTRIC_INDUSTRIES_OUI=u"0025DC"

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
        self.vlan_to_device_ids = {}  # c-vid -> (device_id, logical_device_id)

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
        for macid in jdev['results']:
            if macid['macid'] is None:
                log.info('MAC ID is NONE %s' % str(macid['macid']))
            elif macid['macid'][:6].upper() == SUMITOMO_ELECTRIC_INDUSTRIES_OUI:
                onu_mac = macid['macid']
                log.info('SUMITOMO mac address %s' % str(macid['macid']))
                log.info('activate-olt-for-onu-%s' % onu_mac)
                # Convert from string to colon separated form
                onu_mac = ':'.join(s.encode('hex') for s in onu_mac.decode('hex'))
                vlan_id = self._olt_side_onu_activation(int(macid['macid'][-4:-2], 16))
                self.adapter_agent.child_device_detected(
                    parent_device_id=device.id,
                    parent_port_no=1,
                    child_device_type='dpoe_onu',
                    mac_address = onu_mac,
                    proxy_address=Device.ProxyAddress(
                        device_id=device.id,
                        channel_id=vlan_id
                        ),
                        vlan=vlan_id
                    )

            else:
                onu_mac = '000c' + macid.get('macid', 'e2000000')[4:]
                log.info('activate-olt-for-onu-%s' % onu_mac)
                # Convert from string to colon separated form
                onu_mac = ':'.join(s.encode('hex') for s in onu_mac.decode('hex'))
                vlan_id = self._olt_side_onu_activation(int(macid['macid'][-4:-2], 16))
                self.adapter_agent.child_device_detected(
                    parent_device_id=device.id,
                    parent_port_no=1,
                    child_device_type='tibit_onu',
                    mac_address = onu_mac,
                    proxy_address=Device.ProxyAddress(
                        device_id=device.id,
                        channel_id=vlan_id
                        ),
                        vlan=vlan_id
                    )

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

                        _, logical_device_id = self.vlan_to_device_ids.get(cvid)
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
    def deactivate_device(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('########################################')
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0, "Cannot yet deal with groups"

        # extract ONU VID
        vid_from_device_id = {v[0]: k for k,v in self.vlan_to_device_ids.iteritems()}
        ONU_VID = vid_from_device_id[device.id]

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
                            dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                                         operator=Operator['=='], match=_vlan_vid)
                            if (_vlan_vid != 140):
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                                             operator=Operator['=='], match=ONU_VID)

                        elif field.type == VLAN_PCP:
                            _vlan_pcp = field.vlan_pcp
                            log.info('#### field.type == VLAN_PCP ####', pcp=_vlan_pcp)

                        elif field.type == UDP_DST:
                            _udp_dst = field.udp_dst
                            log.info('#### field.type == UDP_DST ####')

                        elif field.type == UDP_SRC:
                            _udp_src = field.udp_src
                            log.info('#### field.type == UDP_SRC ####')

                        elif field.type == IPV4_DST:
                            _ipv4_dst = field.ipv4_dst
                            log.info('#### field.type == IPV4_DST ####')

                        elif field.type == METADATA:
                            log.info('#### field.type == METADATA ####')
                            pass

                        else:
                            raise NotImplementedError('field.type={}'.format(
                                field.type))

                    for action in get_actions(flow):

                        if action.type == OUTPUT:
                            log.info('#### action.type == OUTPUT ####')
                            dn_req /= PortIngressRuleResultForward()
                            serial = ONU_VID - 200
                            link = (0xe222 << 16) | (serial << 8)
                            dn_req /= PortIngressRuleResultOLTQueue(unicastvssn="TBIT",
                                                                    unicastlink=link)

                        elif action.type == POP_VLAN:
                            log.info('#### action.type == POP_VLAN ####')
                            dn_req /= PortIngressRuleResultDelete(fieldcode=Clause['S-VLAN Tag'])

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
                            body=CablelabsOUI() / DPoEOpcode_SetRequest() / dn_req)
                    )

                    self.io_port.send(str(msg))

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
                            body=CablelabsOUI() / DPoEOpcode_SetRequest() / up_req)
                    )

                    self.io_port.send(str(msg))

                else:
                    raise Exception('Port should be 1 or 2 by our convention')

            except Exception, e:
                log.exception('failed-to-install-flow', e=e, flow=flow)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address)
        device = self.adapter_agent.get_device(proxy_address.device_id)
        frame = Ether(dst=device.mac_address) / \
                Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) / \
                Dot1Q(vlan=proxy_address.channel_id, prio=TIBIT_MGMT_PRIORITY) / \
                msg

        self.io_port.send(str(frame))

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

        dev_id, logical_dev_id = self.vlan_to_device_ids[egress_port_no]
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
            links   = [v[TIBIT_ONU_LINK_INDEX] for _,v in self.vlan_to_device_ids.iteritems()]

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

