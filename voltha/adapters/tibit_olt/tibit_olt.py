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
import re

import arrow
import structlog
from scapy.fields import StrField, PacketField, X3BytesField
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet, bind_layers

from scapy.fields import ByteEnumField, XShortField, XByteField, MACField, \
    ByteField, BitEnumField, BitField, ShortField
from scapy.fields import XLongField, StrFixedLenField, XIntField, \
    FieldLenField, StrLenField, IntField



from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet.task import LoopingCall
from zope.interface import implementer

from common.frameio.frameio import BpfProgramFilter, hexify
from voltha.adapters.interface import IAdapterInterface
from voltha.extensions.eoam.EOAM import EOAMPayload, EOAMEvent, EOAM_VendSpecificMsg
from voltha.extensions.eoam.EOAM import EOAM_OmciMsg, EOAM_TibitMsg, EOAM_DpoeMsg
from voltha.extensions.eoam.EOAM import OAM_ETHERTYPE
from voltha.extensions.eoam.EOAM import CableLabs_OUI, Tibit_OUI, IEEE_OUI

from voltha.extensions.eoam.EOAM_TLV import DOLTObject, \
     NetworkToNetworkPortObject, OLTUnicastLogicalLink, \
     PortIngressRuleClauseMatchLength01, AddStaticMacAddress, \
     PortIngressRuleClauseMatchLength02, PortIngressRuleResultForward, \
     PortIngressRuleResultSet, PortIngressRuleResultInsert, \
     PortIngressRuleResultCopy, PortIngressRuleResultReplace, \
     PortIngressRuleResultDelete, PortIngressRuleResultOLTQueue, \
     PortIngressRuleResultOLTBroadcastQueue, PortIngressRuleResultOLTEPONQueue, \
     PortIngressRuleTerminator, AddPortIngressRule, \
     ItuOUI, PonPortObject
from voltha.extensions.eoam.EOAM_TLV import PortIngressRuleHeader
from voltha.extensions.eoam.EOAM_TLV import ClauseSubtypeEnum
from voltha.extensions.eoam.EOAM_TLV import RuleOperatorEnum
from voltha.extensions.eoam.EOAM_TLV import DPoEVariableResponseCodes, DPoEOpcodeEnum
from voltha.extensions.eoam.EOAM_TLV import VendorName, OltMode, HardwareVersion, ManufacturerInfo
from voltha.extensions.eoam.EOAM_TLV import TibitLinkMacTable
from voltha.extensions.eoam.EOAM_TLV import SlowProtocolsSubtypeEnum
from voltha.extensions.eoam.EOAM_TLV import EndOfPDU

from voltha.extensions.eoam.EOAM_TLV import RxFramesGreen, \
    TxFramesGreen, RxFrame_64, RxFrame_65_127, \
    RxFrame_128_255, RxFrame_256_511, RxFrame_512_1023, \
    RxFrame_1024_1518, RxFrame_1519Plus, TxFrame_64, \
    TxFrame_65_127, TxFrame_128_255, TxFrame_256_511, \
    TxFrame_512_1023, TxFrame_1024_1518, TxFrame_1519Plus

from voltha.extensions.eoam.EOAM_TLV import RxFramesGreen, TxFramesGreen, \
    RxFrame_64, RxFrame_65_127, RxFrame_128_255, RxFrame_256_511, \
    RxFrame_512_1023,RxFrame_1024_1518, RxFrame_1519Plus, \
    TxFrame_64, TxFrame_65_127, TxFrame_128_255, \
    TxFrame_256_511, TxFrame_512_1023, TxFrame_1024_1518, \
    TxFrame_1519Plus



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
        self.mode = "GPON"

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

            # Loop until we have a Get Response or timeout
            ack = False
            start_time = time.time()
            while not ack:
                frame = yield self.incoming_queues[olt_mac].get()
                #TODO - Need to add proper timeout functionality
                #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                #    break  # don't wait forever

                respType = self._get_oam_msg_type(frame)
             
                if (respType == RxedOamMsgTypeEnum["DPoE Get Response"]):
                    ack = True
                else:
                    # Handle unexpected events/OMCI messages
                    self._check_resp(frame)

        except Exception as e:
            log.exception('launch device failed', e=e)

        if ack:
            # Process the Get Request message
            self._process_ping_frame_response(device, frame)

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
                    hw_desc=device.hardware_version,
                    sw_desc=device.software_version,
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

        # END if ack

    @inlineCallbacks
    def _detect_onus(self, device):
        # send out get 'links' to the OLT device
        olt_mac = device.mac_address
        links_frame = self._make_links_frame(mac_address=olt_mac)
        self.io_port.send(links_frame)


        # Loop until we have a Get Response or timeout
        ack = False
        start_time = time.time()
        while not ack:

            frame = yield self.incoming_queues[olt_mac].get()

            #TODO - Need to add proper timeout functionality
            #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
            #    break  # don't wait forever

            respType = self._get_oam_msg_type(frame)
 
            if (respType == RxedOamMsgTypeEnum["DPoE Get Response"]):
                ack = True
            else:
                # Handle unexpected events/OMCI messages
                self._check_resp(frame)

        if ack:
            #Process the Get Response
            mac_table = [0xB7, 0x0103]
            links = []
            branch_leaf_pairs = [mac_table]

            for pair in branch_leaf_pairs:
                temp_pair = pair
                (rc, value) = (self._get_value_from_msg(frame, pair[0], pair[1]))
                temp_pair.append(rc)
                temp_pair.append(value)
                if rc:
                    overall_rc = True
                else: 
                    log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(temp_pair[0], temp_pair[1]))
                    ack = True

            if mac_table[rc]:
                value = mac_table.pop()
                macLen = 0
                while (macLen < len(value)):
                    macAddr = struct.unpack_from(">6B", value, macLen)
                    linkAddr = "".join([hex(i).lstrip("0x").zfill(2) for i in macAddr])

                    if linkAddr is None:
                        log.info('MAC Addr is NONE')
                    elif linkAddr[:6].upper() == SUMITOMO_ELECTRIC_INDUSTRIES_OUI:
                        onu_mac_string = linkAddr 
                        log.info('SUMITOMO mac address %s' % str(linkAddr))
                        child_device_name = 'dpoe_onu'
                    elif linkAddr[:4].upper() == ADTRAN_SHORTENED_VSSN:
                        onu_mac_string = linkAddr 
                        log.info('ADTRAN mac address %s' % str(linkAddr))
                        child_device_name = 'adtran_onu'
                    else:
                        onu_mac_string = '000c' + linkAddr[4:]
                        log.info('TIBIT mac address %s' % onu_mac_string)
                        child_device_name = 'tibit_onu'

                    if linkAddr is not None:
                        # Convert from string to colon separated form
                        onu_mac = ':'.join(s.encode('hex') for s in onu_mac_string.decode('hex'))
                        log.info('activate-olt-for-onu-%s' % onu_mac)
                        mac_octet_4 = int(linkAddr[-4:-2], 16)
                        vlan_id = self._olt_side_onu_activation(mac_octet_4)

                        macLen += 6
                
                        ## Automatically setup default downstream control frames flow (in this case VLAN 4000)
                        ## on the OLT for the new ONU/ONT device
                        Clause = {v: k for k, v in ClauseSubtypeEnum.iteritems()}
                        Operator = {v: k for k, v in RuleOperatorEnum.iteritems()}

                        if self.mode.upper()[0] == "G":  # GPON
                            vssn = "TBIT"
                            link = int(onu_mac_string[4:12], 16)
                            resultOltQueue = "PortIngressRuleResultOLTQueue(unicastvssn=vssn, unicastlink=link)"
                        else:                       # EPON
                            vssn = int(onu_mac_string[0:8].rjust(8,"0"), 16)
                            link = int((onu_mac_string[8:10]+"02").ljust(8,"0"), 16)
                            resultOltQueue = "PortIngressRuleResultOLTEPONQueue(unicastvssn=vssn, unicastlink=link)"

                        packet_out_rule = (
                            Ether(dst=device.mac_address) /
                            Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
                            EOAMPayload() / EOAM_VendSpecificMsg(oui=Tibit_OUI) /
                            EOAM_TibitMsg(dpoe_opcode=0x03,
                                body=NetworkToNetworkPortObject()/
                                PortIngressRuleHeader(precedence=13)/
                                PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                                   operator=Operator['=='],
                                                                   match=TIBIT_PACKET_OUT_VLAN)/
                                PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=1,
                                                                   operator=Operator['=='], match=vlan_id)/
                                eval(resultOltQueue)/
                                PortIngressRuleResultForward()/
                                PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])/
                                PortIngressRuleTerminator()/
                                AddPortIngressRule())/
                            EndOfPDU()
                            )

                        self.io_port.send(str(packet_out_rule))

                        # Get and process the Set Response
                        ack = False
                        start_time = time.time()

                        # Loop until we have a set response or timeout
                        while not ack:

                            frame = yield self.incoming_queues[olt_mac].get()
                            #TODO - Need to add proper timeout functionality
                            #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                            #    break  # don't wait forever

                            respType = self._get_oam_msg_type(frame)

                            #Check that the message received is a Set Response
                            if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                                ack = True
                            else:
                                # Handle unexpected events/OMCI messages
                                self._check_resp(frame)

                        # Verify Set Response
                        if ack:
                            (rc,branch,leaf,status) = self._check_set_resp(frame)
                            if (rc == True):
                                log.info('Set Response had no errors')

                                # also record the vlan_id -> (device_id, logical_device_id, linkid) for
                                # later use.  The linkid is the macid returned.

                                self.vlan_to_device_ids[vlan_id] = (device.id, device.parent_id, linkAddr)


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

                            else:
                                log.info('Set Response had errors')
                                log.info('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[status]))

                    # END linkAddr is not none
            else:
                log.info('No links were found in the MAC Table')
            # END if mac_table[rc]
        #END if ack

        ### KPI Metrics - Work in progress feature - Disabling for now
        ### Give the ONUs a chance to arrive before starting metric collection

        # TODO - Disable Stats Reporting for the moment
        # reactor.callLater(5.0, self.start_kpi_collection, device.id)


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
        frame = (
            Ether(dst=mac_address) /
            Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
            EOAMPayload() / EOAM_VendSpecificMsg(oui=Tibit_OUI) /
            EOAM_TibitMsg(dpoe_opcode=0x01,body=VendorName() /
                                                OltMode() /
                                                HardwareVersion() /
                                                ManufacturerInfo()
                                                ) /
            EndOfPDU()
            )

        return str(frame)

    def _process_ping_frame_response(self, device, frame):

        vendor = [0xD7, 0x0011]
        oltMode = [0xB7, 0x0101]
        hw_version = [0xD7, 0x0013]
        manufacturer =  [0xD7, 0x0006]
        branch_leaf_pairs = [vendor, oltMode, hw_version, manufacturer]
                    
        for pair in branch_leaf_pairs:
            temp_pair = pair
            (rc, value) = (self._get_value_from_msg(frame, pair[0], pair[1]))
            temp_pair.append(rc)
            temp_pair.append(value)
            if rc:
                overall_rc = True
            else: 
                log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(temp_pair[0], temp_pair[1]))
                ack = True

        if vendor[rc]:
            device.vendor = vendor.pop()
        else:
            device.vendor = "UNKNOWN"
            
        # mode: 3 = EPON OLT, 7 = GPON OLT
        # mode: 2 = EPON ONU, 6 = GPON ONU    
        if oltMode[rc]:
            value = oltMode.pop()
            mode = "UNKNOWN"
            self.mode = "UNKNOWN"

            if value == 7:
                mode = "10G GPON OLT"
                self.mode = "GPON"
            if value == 3:
                mode = "10G EPON OLT"
                self.mode = "EPON"
            if value == 1:
                mode = "10G Point to Point"
                self.mode = "Unsupported"

            device.model = mode

        else:
            device.model = "UNKNOWN"
            self.mode = "UNKNOWN"

        log.info("OLT Mode is {}".format(self.mode))
                
        if hw_version[rc]:
            device.hardware_version = hw_version.pop()
        else:
            device.hardware_version = "UNKNOWN"

        if manufacturer[rc]:
            manu_value = manufacturer.pop()
            device.firmware_version = re.search('\Firmware: (.+?) ', manu_value).group(1)
            device.software_version = re.search('\Build: (.+?) ', manu_value).group(1)
            device.serial_number = re.search('\Serial #: (.+?) ', manu_value).group(1)
        else:
            device.firmware_version = "UNKNOWN"
            device.software_version = "UNKNOWN"
            device.serial_number = "UNKNOWN"
        device.root = True
        device.connect_status = ConnectStatus.REACHABLE

    def _make_links_frame(self, mac_address):
        frame = (
            Ether(dst=mac_address) /
            Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
            EOAMPayload() / EOAM_VendSpecificMsg(oui=Tibit_OUI) /
            EOAM_TibitMsg(dpoe_opcode=0x01,body=TibitLinkMacTable()
                            )/
            EndOfPDU()
            )
        return str(frame)

    def _make_link_stats_frame(self, olt_mac_address, onu_mac_address):

        if self.mode.upper()[0] == "G":  # GPON
            vssn = "TBIT"
            link = int(onu_mac_address[4:12], 16)
        else:                       # EPON
            vssn = int(onu_mac_address[0:8].rjust(8,"0"), 16)
            link = int((onu_mac_address[8:10]+"02").ljust(8,"0"), 16)
        frame = (
            Ether(dst=olt_mac_address) /
            Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
            EOAMPayload() / EOAM_VendSpecificMsg(oui=Tibit_OUI) /
            EOAM_TibitMsg(dpoe_opcode=0x01,
                          body=OLTUnicastLogicalLink(unicastvssn=vssn, unicastlink=link)/
                                #RxFramesGreen()/
                                #TxFramesGreen()/
                                RxFrame_64()/
                                RxFrame_65_127()/
                                RxFrame_128_255()/
                                RxFrame_256_511()/
                                RxFrame_512_1023()/
                                RxFrame_1024_1518()/
                                RxFrame_1519Plus()/
                                TxFrame_64()/
                                TxFrame_65_127()/
                                TxFrame_128_255()/
                                TxFrame_256_511()/
                                TxFrame_512_1023()/
                                TxFrame_1024_1518()/
                                TxFrame_1519Plus()
                            )/
            EndOfPDU()
            )

        return str(frame)

    def _make_nni_stats_frame(self, mac_address):
        frame = (
            Ether(dst=mac_address) /
            Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
            EOAMPayload() / EOAM_VendSpecificMsg(oui=Tibit_OUI) /
            EOAM_TibitMsg(dpoe_opcode=0x01, body=NetworkToNetworkPortObject()/
                                #RxFramesGreen()/
                                #TxFramesGreen()/
                                RxFrame_64()/
                                RxFrame_65_127()/
                                RxFrame_128_255()/
                                RxFrame_256_511()/
                                RxFrame_512_1023()/
                                RxFrame_1024_1518()/
                                RxFrame_1519Plus()/
                                TxFrame_64()/
                                TxFrame_65_127()/
                                TxFrame_128_255()/
                                TxFrame_256_511()/
                                TxFrame_512_1023()/
                                TxFrame_1024_1518()/
                                TxFrame_1519Plus()
                            )/
            EndOfPDU()
            )
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
                                mac_address = self.vlan_to_device_ids[_inner_vid][2].upper()

                                if self.mode.upper()[0] == "G":  # GPON
                                    vssn = "TBIT"
                                    link = int(mac_address[4:12], 16)
                                    resultOltQueue = "PortIngressRuleResultOLTQueue(unicastvssn=vssn, unicastlink=link)"
                                else:                       # EPON
                                    vssn = int(mac_address[0:8].rjust(8,"0"), 16)
                                    link = int((mac_address[8:10]+"02").ljust(8,"0"), 16)
                                    resultOltQueue = "PortIngressRuleResultOLTEPONQueue(unicastvssn=vssn, unicastlink=link)"

                                dn_req /= eval(resultOltQueue)

                            elif _inner_vid is None:
                                log.info('#### action.type == OUTPUT INNER VID is NONE ####')

                        elif action.type == POP_VLAN:
                            log.info('#### action.type == POP_VLAN ####')
                            if _outer_vid == MULTICAST_VLAN:
                                dn_req /= PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=Clause['C-VLAN Tag'], fieldinstance=0,
                                                                             operator=Operator['=='], match=_outer_vid)
                            else:
                                dn_req /= PortIngressRuleResultDelete(fieldcode=Clause['C-VLAN Tag'])
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
                        EOAMPayload() / EOAM_VendSpecificMsg(oui=Tibit_OUI) /
                        EOAM_TibitMsg(dpoe_opcode = 0x03, body=dn_req)/
                        EndOfPDU()
                    )

                    self.io_port.send(str(msg))

                    # Get and process the Set Response
                    ack = False
                    start_time = time.time()

                    # Loop until we have a set response or timeout
                    while not ack:
                        frame = yield self.incoming_queues[olt_mac].get()
                        #TODO - Need to add proper timeout functionality
                        #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                        #    break  # don't wait forever

                        respType = self._get_oam_msg_type(frame)

                        #Check that the message received is a Set Response
                        if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                            ack = True
                        else:
                            # Handle unexpected events/OMCI messages
                            self._check_resp(frame)

                    # Verify Set Response
                    if ack:
                        (rc,branch,leaf,status) = self._check_set_resp(frame)
                        if (rc == True):
                            log.info('Set Response had no errors')
                        else:
                            log.info('Set Response had errors')
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
                            mac_address = self.vlan_to_device_ids[_vlan_vid][2].upper()

                            if self.mode.upper()[0] == "G":  # GPON
                                vssn = "TBIT"
                                link = int(mac_address[4:12], 16)
                                logical_link = "OLTUnicastLogicalLink(unicastvssn=vssn, unicastlink=link)"
                            else:                       # EPON
                                vssn = int(mac_address[0:8].rjust(8,"0"), 16)
                                link = int((mac_address[8:10]+"02").ljust(8,"0"), 16)
                                logical_link = "OLTEPONUnicastLogicalLink(unicastvssn=vssn, unicastlink=link)"

                            up_req_link /= eval(logical_link)
                            
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
                        EOAMPayload() / EOAM_VendSpecificMsg(oui=Tibit_OUI) /
                        EOAM_TibitMsg(dpoe_opcode = 0x03, body=up_req)/
                        EndOfPDU()
                    )

                    self.io_port.send(str(msg))

                    # Get and process the Set Response
                    ack = False
                    start_time = time.time()

                    # Loop until we have a set response or timeout
                    while not ack:
                        frame = yield self.incoming_queues[olt_mac].get()
                        #TODO - Need to add proper timeout functionality
                        #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                        #    break  # don't wait forever

                        respType = self._get_oam_msg_type(frame)

                        #Check that the message received is a Set Response
                        if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                            ack = True
                        else:
                            # Handle unexpected events/OMCI messages
                            self._check_resp(frame)

                    # Verify Set Response
                    if ack:
                        (rc,branch,leaf,status) = self._check_set_resp(frame)
                        if (rc == True):
                            log.info('Set Response had no errors')
                        else:
                            log.info('Set Respose had errors')
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

        if mac_address.startswith(TIBIT_SHORTENED_VSSN) or self.mode.upper()[0] == "E":
            # Send straight OAM
            frame = Ether(dst=device.mac_address) / \
              Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) / \
              Dot1Q(vlan=proxy_address.channel_id, prio=TIBIT_MGMT_PRIORITY) / \
              msg
        else:
            # Use the standard to send OMCI over OAM
            encapsulated_omci = EOAM_OmciMsg(body=msg)

            frame = Ether(dst=device.mac_address) / \
              Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) / \
              Dot1Q(vlan=proxy_address.channel_id, prio=TIBIT_MGMT_PRIORITY) / \
              EOAMPayload() / EOAM_VendSpecificMsg(oui=IEEE_OUI) / \
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

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()    

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

    def start_kpi_collection(self, device_id):
        """ Periodic KPI metric collection from the device """
        import random

        # This is setup (for now) to be called from the adapter.  Push
        # architectures should be explored in the near future.
        @inlineCallbacks
        def _collect(device_id, prefix):

            pon_port_metrics = []
            pon_metrics_list = {}
            nni_metrics = []

            branch_leaf_pairs = [
                            #[0xD7, 0x0201,], [0xD7, 0x0202], 
                            [0xD7, 0x0204, "rx_64"], [0xD7, 0x0205, "rx_65_127"], 
                            [0xD7, 0x0206, "rx_128_255"], [0xD7, 0x0207, "rx_256_511"],
                            [0xD7, 0x0208, "rx_512_1023"], [0xD7, 0x0209, "rx_1024_1518"],
                            [0xD7, 0x020A, "rx_1519_9k"], [0xD7, 0x020B, "tx_64"],
                            [0xD7, 0x020C, "tx_65_127"], [0xD7, 0x020D, "tx_128_255"],
                            [0xD7, 0x020E, "tx_256_511"], [0xD7, 0x020F, "tx_512_1023"],
                            [0xD7, 0x0210, "tx_1024_1518"], [0xD7, 0x0211, "tx_1519_9k"]]

            olt_mac = next((mac for mac, device in self.device_ids.iteritems() if device == device_id), None)

            try:
                # Step 1: gather metrics from device

                #for each link on this OLT
                for vlan_id in self.vlan_to_device_ids:

                    log.info('link stats frame', links=self.vlan_to_device_ids[vlan_id])

                    # send out link_stats_frame
                    mac_address = self.vlan_to_device_ids[vlan_id][2].upper()

                    link_stats_frame = self._make_link_stats_frame(olt_mac_address=olt_mac, onu_mac_address=mac_address)
        
                    self.io_port.send(link_stats_frame)

                    # Loop until we have a Get Response or timeout
                    ack = False
                    start_time = time.time()
                    while not ack:
                        frame = yield self.incoming_queues[olt_mac].get()
                        #TODO - Need to add proper timeout functionality
                        #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                        #    break  # don't wait forever

                        respType = self._get_oam_msg_type(frame)
                 
                        if (respType == RxedOamMsgTypeEnum["DPoE Get Response"]):
                            ack = True
                        else:
                            # Handle unexpected events/OMCI messages
                            self._check_resp(frame)

                    if ack:
                        # Process the Get Request message
                        log.info('Received Link Stats Get Response Frame')

                        for pair in branch_leaf_pairs:
                            (rc, value) = (self._get_value_from_msg(frame, pair[0], pair[1]))

                            if rc:
                                log.info('Response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(pair[0], pair[1]))
                                pon_port_metrics.append((pair[2],value))
                            else:
                                log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(pair[0], pair[1]))

                        pon_metrics_list[vlan_id] = pon_port_metrics

                #end looping on each vlan_id

                log.info('nni stats frame')

                link_stats_frame = self._make_nni_stats_frame(mac_address=olt_mac)
                self.io_port.send(link_stats_frame)

                # Loop until we have a Get Response or timeout
                ack = False
                start_time = time.time()
                while not ack:
                    frame = yield self.incoming_queues[olt_mac].get()
                    #TODO - Need to add proper timeout functionality
                    #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
                    #    break  # don't wait forever

                    respType = self._get_oam_msg_type(frame)
             
                    if (respType == RxedOamMsgTypeEnum["DPoE Get Response"]):
                        ack = True
                    else:
                        # Handle unexpected events/OMCI messages
                        self._check_resp(frame)

                if ack:
                    # Process the Get Response message
                    log.info('Recieved NNI Stats Get Response Frame')
                                
                    for pair in branch_leaf_pairs:
                        (rc, value) = (self._get_value_from_msg(frame, pair[0], pair[1]))
                        if rc:
                            log.info('Response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(pair[0], pair[1]))
                            nni_metrics.append((pair[2],value))
                        else:
                            log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(temp_pair[0], temp_pair[1]))

                #Need to replace with actual data
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
                    prefix + '.nni': MetricValuePairs(metrics=nni_metrics)
                    }

                for link in pon_metrics_list:
                    # PON link ports
                    prefixes[prefix + '.pon.{}'.format(link)] = MetricValuePairs(metrics=pon_metrics_list[link])

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


    # Methods for Get / Set  Response Processing from eoam_messages


    def _get_oam_msg_type(self, frame):

        respType = RxedOamMsgTypeEnum["Unknown"]
        recv_frame = frame

        if recv_frame.haslayer(EOAMPayload):
            if recv_frame.haslayer(EOAMEvent):
                recv_frame = RxedOamMsgTypeEnum["Event Notification"]
            elif recv_frame.haslayer(EOAM_OmciMsg):
                respType = RxedOamMsgTypeEnum["OMCI Message"]
            else:
                dpoeOpcode = 0x00
                if recv_frame.haslayer(EOAM_TibitMsg):
                    dpoeOpcode = recv_frame.getlayer(EOAM_TibitMsg).dpoe_opcode;
                elif recv_frame.haslayer(EOAM_DpoeMsg):
                    dpoeOpcode = recv_frame.getlayer(EOAM_DpoeMsg).dpoe_opcode;

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
                    log.info('Unsupported DPoE Opcode {:0>2X}'.format(dpoeOpcode))
        else:
            log.info('Invalid OAM Header')

        log.info('Received OAM Message 0x %s' % str(respType))

        return respType


    def _get_value_from_msg(self, frame, branch, leaf):
        retVal = False
        value = 0
        recv_frame = frame

        if recv_frame.haslayer(EOAMPayload):
            payload = recv_frame.payload
            if hasattr(payload, 'body'):
                loadstr = payload.body.load
                # Get a specific TLV value
                (retVal,bytesRead,value,retbranch,retleaf) = self._handle_get_value(loadstr, 0, branch, leaf)
            else:
                log.info('received frame has no payload')
        else:
            log.info('Invalid OAM Header')
        return retVal,value,


    def _handle_get_value(self, loadstr, startOfTlvs, queryBranch, queryLeaf):
        retVal = False;
        value = 0
        branch = 0
        leaf = 0
        bytesRead = startOfTlvs
        loadstrlen    = len(loadstr)

        while (bytesRead <= loadstrlen):
            (branch, leaf) = struct.unpack_from('>BH', loadstr, bytesRead)

            if (branch != 0):
                bytesRead += 3
                length = struct.unpack_from('>B', loadstr, bytesRead)[0]
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


    def _check_set_resp(self, frame):
        rc = False
        branch = 0
        leaf = 0
        status = 0
        recv_frame = frame
        if recv_frame.haslayer(EOAMPayload):
            payload = recv_frame.payload
            if hasattr(payload, 'body'):
                loadstr = payload.body.load
                # Get a specific TLV value
                (rc,branch,leaf,status) = self._check_set_resp_attrs(loadstr, 0)
            else:
                log.info('received frame has no payload')
        else:
            log.info('Invalid OAM Header')
        return rc,branch,leaf,status



    def _check_resp(self, frame):
        respType = RxedOamMsgTypeEnum["Unknown"]
        recv_frame = frame
        if recv_frame.haslayer(EOAMPayload):

            if recv_frame.haslayer(EOAMEvent):
                self.handle_oam_event(recv_frame)
            elif recv_frame.haslayer(EOAM_OmciMsg):
                 self.handle_omci(recv_frame)
            else:
                dpoeOpcode = 0x00
                if recv_frame.haslayer(EOAM_TibitMsg):
                    dpoeOpcode = recv_frame.getlayer(EOAM_TibitMsg).dpoe_opcode;
                elif recv_frame.haslayer(EOAM_DpoeMsg):
                    dpoeOpcode = recv_frame.getlayer(EOAM_DpoeMsg).dpoe_opcode;

                if hasattr(recv_frame, 'body'):
                    payload = recv_frame.payload
                    loadstr = payload.body.load

                # Get Response
                if (dpoeOpcode == 0x02):
                    # Get a specific TLV value
                    branch = 0xD7
                    leaf = 0x0006
                    (rc,bytesRead,value,retbranch,retleaf) = self._handle_get_value(loadstr, startOfTlvs, branch, leaf)
                    if (rc == True):
                        log.info('Branch 0x{:X} Leaf 0x{:0>4X}  value = {}'.format(branch, leaf, value))
                    else:
                        log.info('Branch 0x{:X} Leaf 0x{:0>4X}  no value'.format(branch, leaf))

                    # Walk through all TLV values
                    bytesRead = 0
                    rc = True
                    while(rc == True):
                        branch = 0
                        leaf = 0
                        (rc,bytesRead,value,branch,leaf) = self._handle_get_value(loadstr, bytesRead, branch, leaf)
                        if (rc == True):
                            log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X}  value = {}'.format(branch, leaf, value))
                        elif (branch != 0):
                            log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X}  no value'.format(branch, leaf))

                # Set Response
                elif (dpoeOpcode == 0x04):
                    (rc,branch,leaf,status) = self._check_set_resp_attrs(loadstr, 0)
                    if (rc == True):
                        log.info('Set Response had no errors')
                    else:
                        log.info('Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[status]))

                # File Transfer ACK
                elif (dpoeOpcode == 0x09):
                    rc = self._handle_fx_ack(loadstr, bytesRead, block_number)
                else:
                    log.info('Unsupported DPoE Opcode {:0>2X}'.format(dpoeOpcode))
        else:
            log.info('Invalid OAM Header')

        return respType    

    def _check_set_resp_attrs(self, loadstr, startOfTlvs):
        retVal = True;
        branch = 0
        leaf = 0
        length = 0
        bytesRead = startOfTlvs
        loadstrlen    = len(loadstr)

        while (bytesRead <= loadstrlen):
            (branch, leaf) = struct.unpack_from('>BH', loadstr, bytesRead)
#            print "Branch/Leaf        0x{:0>2X}/0x{:0>4X}".format(branch, leaf)

            if (branch != 0):
                bytesRead += 3
                length = struct.unpack_from('>B', loadstr, bytesRead)[0]
#                print "Length:            0x{:0>2X} ({})".format(length,length)
                bytesRead += 1

                if (length >= 0x80):
                    log.info('Branch 0x{:0>2X} Leaf 0x{:0>4X} {}'.format(branch, leaf, DPoEVariableResponseCodes[length]))
                    if (length > 0x80):
                        retVal = False;
                        break;
                else:
                    bytesRead += length

            else:
                break

        return retVal,branch,leaf,length

        
    def _handle_fx_ack(self, loadstr, startOfXfer, block_number):
        retVal = False
        (fx_opcode, acked_block, response_code) = struct.unpack_from('>BHB', loadstr, startOfXfer)

        #print "fx_opcode:      0x%x" % fx_opcode
        #print "acked_block:    0x%x" % acked_block
        #print "response_code:  0x%x" % response_code


        if (fx_opcode != 0x03):
            log.info('unexpected fx_opcode 0x%x (expected 0x03)' % fx_opcode)
        elif (acked_block != block_number):
            log.info('unexpected acked_block 0x%x (expected 0x%x)' % (acked_block, block_number))
        elif (response_code != 0):
            log.info('unexpected response_code 0x%x (expected 0x00)' % response_code)
        else:
            retVal = True;    