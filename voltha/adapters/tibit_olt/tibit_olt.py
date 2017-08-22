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

from voltha.extensions.eoam.EOAM_Layers import EOAMPayload, EOAM_EventMsg, EOAM_VendSpecificMsg
from voltha.extensions.eoam.EOAM_Layers import EOAM_OmciMsg, EOAM_TibitMsg
from voltha.extensions.eoam.EOAM_Layers import OAM_ETHERTYPE
from voltha.extensions.eoam.EOAM_Layers import CABLELABS_OUI, TIBIT_OUI, ITU_OUI
from voltha.extensions.eoam.EOAM_Layers import RxedOamMsgTypeEnum, RxedOamMsgTypes
from voltha.extensions.eoam.EOAM import get_oam_msg_type, get_value_from_msg, check_set_resp, check_resp
from voltha.extensions.eoam.EOAM import get_unicast_logical_link, get_olt_queue
from voltha.extensions.eoam.EOAM import ADTRAN_SHORTENED_VSSN, TIBIT_SHORTENED_VSSN

from voltha.extensions.eoam.EOAM_TLV import DOLTObject, \
     NetworkToNetworkPortObject, OLTUnicastLogicalLink, OLTEPONUnicastLogicalLink, \
     PortIngressRuleClauseMatchLength01, AddStaticMacAddress, \
     PortIngressRuleClauseMatchLength02, PortIngressRuleResultForward, \
     PortIngressRuleResultSet, PortIngressRuleResultInsert, \
     PortIngressRuleResultCopy, PortIngressRuleResultReplace, \
     PortIngressRuleResultDelete, PortIngressRuleResultOLTQueue, \
     PortIngressRuleResultOLTBroadcastQueue, PortIngressRuleResultOLTEPONQueue, \
     PortIngressRuleTerminator, AddPortIngressRule, \
     ItuOUI, PonPortObject, DPoEOpcodes
from voltha.extensions.eoam.EOAM_TLV import PortIngressRuleHeader
from voltha.extensions.eoam.EOAM_TLV import ClauseSubtypeEnum, RuleClauses
from voltha.extensions.eoam.EOAM_TLV import RuleOperatorEnum, RuleOperators
from voltha.extensions.eoam.EOAM_TLV import DPoEVariableResponseEnum, DPoEOpcodeEnum
from voltha.extensions.eoam.EOAM_TLV import VendorName, OltMode, HardwareVersion, ManufacturerInfo
from voltha.extensions.eoam.EOAM_TLV import TibitLinkMacTable, OltPonAdminStateSet, TibitDeviceReset
from voltha.extensions.eoam.EOAM_TLV import SlowProtocolsSubtypeEnum
from voltha.extensions.eoam.EOAM_TLV import EndOfPDU

from voltha.extensions.eoam.EOAM_TLV import RxFramesGreen, \
    TxFramesGreen, RxFrame_64, RxFrame_65_127, \
    RxFrame_128_255, RxFrame_256_511, RxFrame_512_1023, \
    RxFrame_1024_1518, RxFrame_1519Plus, TxFrame_64, \
    TxFrame_65_127, TxFrame_128_255, TxFrame_256_511, \
    TxFrame_512_1023, TxFrame_1024_1518, TxFrame_1519Plus


from voltha.core.flow_decomposer import *
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.common_pb2 import LogLevel, ConnectStatus
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Device, Port, Image
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


# Match on the MGMT VLAN, Priority 7
TIBIT_MGMT_VLAN       = 4090
TIBIT_MGMT_PRIORITY   = 7
frame_match_case1     = 'ether[14:2] = 0x{:01x}{:03x}'.format(TIBIT_MGMT_PRIORITY << 1, TIBIT_MGMT_VLAN)

TIBIT_PACKET_IN_VLAN  = 4000
frame_match_case2     = '(ether[14:2] & 0xfff) = 0x{:03x}'.format(TIBIT_PACKET_IN_VLAN)

TIBIT_PACKET_OUT_VLAN = 4000

TIBIT_MSG_WAIT_TIME = 3

is_tibit_frame = BpfProgramFilter('{} or {}'.format(frame_match_case1, frame_match_case2))


# TODO: This information should be conveyed to the adapter
# from a higher level.
MULTICAST_VLAN = 140

TIBIT_COMMUNICATIONS_OUI         = u'000CE2'
SUMITOMO_ELECTRIC_INDUSTRIES_OUI = u'0025DC'


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

    def reconcile_device(self, device):
        raise NotImplementedError()

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
            self.device_ids[device.mac_address] = device.id

            # send out ping to OLT device
            resp = []
            action = "Get Device Info"
            body = VendorName()/OltMode()/HardwareVersion()/ManufacturerInfo()
            yield self._get_req_rsp(device, action, body, resp)
            if resp is not []: frame = resp[0]

        except Exception as e:
            log.exception('launch device failed', e=e)

        if frame:
            # Process the Get Response message
            self._process_ping_frame_response(device, frame)

            yield self.change_device_state(device, 1)

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

            # There could be multiple software version on the device,
            # active, standby etc. Choose the active or running software
            # below. See simulated_olt for example implementation
            version = device.images.image[0].version

            ld = LogicalDevice(
                desc=ofp_desc(
                    mfr_desc=device.vendor,
                    hw_desc=device.hardware_version,
                    sw_desc=version,
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

        # END if frame


    @inlineCallbacks
    def _detect_onus(self, device):
        # send out get 'links' to the OLT device
        resp = []
        action = "Get Registered Links"
        body = TibitLinkMacTable()
        yield self._get_req_rsp(device, action, body, resp)
        if resp is not []: frame = resp[0]

        if frame:
            #Process the Get Response
            mac_table = [0xB7, 0x0103]
            links = []
            branch_leaf_pairs = [mac_table]
            overall_rc = False

            for pair in branch_leaf_pairs:
                temp_pair = pair
                (rc, value) = (get_value_from_msg(log, frame, pair[0], pair[1]))
                temp_pair.append(rc)
                temp_pair.append(value)
                if rc:
                    overall_rc = True
                else:
                    log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(temp_pair[0], temp_pair[1]))

            if overall_rc and mac_table[rc]:
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

                        resultOltQueue = get_olt_queue(onu_mac_string, self.mode)
                        action = "Set DS Rule for ONU to strip C Tag"

                        body=NetworkToNetworkPortObject()
                        body/=PortIngressRuleHeader(precedence=13)
                        body/=PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=0,
                                                           operator=RuleOperators['=='],
                                                           match=TIBIT_PACKET_OUT_VLAN)
                        body/=PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=1,
                                                           operator=RuleOperators['=='], match=vlan_id)
                        body/=eval(resultOltQueue)
                        body/=PortIngressRuleResultForward()
                        body/=PortIngressRuleResultDelete(fieldcode=RuleClauses['C-VLAN Tag'])
                        body/=PortIngressRuleTerminator()
                        body/=AddPortIngressRule()

                        # Get and process the Set Response
                        rc = []
                        yield self._set_req_rsp(device, action, body, rc)

                        if rc[0] is True:
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
                                    admin_state=AdminState.ENABLED,
                                    vlan=vlan_id
                            )


                    # END linkAddr is not none
            else:
                log.info('No links were found in the MAC Table')
		        # Poll to get more ONUs
                reactor.callLater(3, self._detect_onus, device)

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


    def _process_ping_frame_response(self, device, frame):

        vendor       = [VendorName().branch, VendorName().leaf]
        oltMode      = [OltMode().branch, OltMode().leaf]
        hw_version   = [HardwareVersion().branch, HardwareVersion().leaf]
        manufacturer = [ManufacturerInfo().branch, ManufacturerInfo().leaf]
        branch_leaf_pairs = [vendor, oltMode, hw_version, manufacturer]

        for pair in branch_leaf_pairs:
            temp_pair = pair
            (rc, value) = (get_value_from_msg(log, frame, pair[0], pair[1]))
            temp_pair.append(rc)
            temp_pair.append(value)
            if rc:
                overall_rc = True
            else:
                log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(temp_pair[0], temp_pair[1]))
                ack = True

        if vendor[rc]:
            device.vendor = vendor.pop()
            if device.vendor.endswith(''):
                device.vendor = device.vendor[:-1]
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
            device.hardware_version = device.hardware_version.replace("FA","")
            if device.hardware_version.endswith(''):
                device.hardware_version = device.hardware_version[:-1]
        else:
            device.hardware_version = "UNKNOWN"

        if manufacturer[rc]:
            manu_value = manufacturer.pop()
            device.firmware_version = re.search('\Firmware: (.+?) ', manu_value).group(1)
            # There could be multiple software versions on the device (one active, other
            # standby etc.). Look for simulated_olt for example implementation.
            image_1 = Image(version = \
                                  re.search('\Build: (.+?) ', manu_value).group(1))
            device.images.image.extend([ image_1 ])
            device.serial_number = re.search('\Serial #: (.+?) ', manu_value).group(1)
        else:
            device.firmware_version = "UNKNOWN"
            image_1 = Image(version="UNKNOWN")
            device.images.image.extend([ image_1 ])
            device.serial_number = "UNKNOWN"
        device.root = True
        device.connect_status = ConnectStatus.REACHABLE


    def abandon_device(self, device):
        raise NotImplementedError(0)

    @inlineCallbacks
    def disable_device(self, device):

        # Update the operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the logical device
        logical_device = self.adapter_agent.get_logical_device(
                        device.parent_id)
        self.adapter_agent.delete_logical_device(logical_device)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(device.id,
                                                      admin_state=AdminState.DISABLED)

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(device.id)

        # Set all ports to disabled
        self.adapter_agent.disable_all_ports(device.id)
        log.info('disabled', device_id=device.id)

        # Update the device last
        log.info('Disabling OLT: {}'.format(device.mac_address))
        yield self.change_device_state(device, 0)


    @inlineCallbacks
    def reenable_device(self, device):
        log.info('Re-enabling OLT: {}'.format(device.mac_address))
        yield self.change_device_state(device, 1)

        log.info('re-enabling', device_id=device.id)

        # Get the latest device reference
        device = self.adapter_agent.get_device(device.id)

        # Update the connect status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Set all ports to enabled
        self.adapter_agent.enable_all_ports(device.id)

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
            device_port_no=2,
            root_port=True
        ))

        # and finally update to active
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        # Reenable all child devices
        self.adapter_agent.update_child_devices_state(device.id,
                                                      admin_state=AdminState.ENABLED)

        log.info('re-enabled', device_id=device.id)


    @inlineCallbacks
    def reboot_device(self, device):
        log.info('Rebooting OLT: {}'.format(device.mac_address))

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE
        previous_oper_status = device.oper_status
        previous_conn_status = device.connect_status
        device.oper_status = OperStatus.ACTIVATING
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Update the child devices connect state to UNREACHABLE
        self.adapter_agent.update_child_devices_state(device.id,
                                                      connect_status=ConnectStatus.UNREACHABLE)

        # Send the Device Reset
        action = "Device Reset"
        rc = []
        tlvs = TibitDeviceReset()
        yield self._set_req_rsp(device, action, tlvs, rc)

        # Change the operational status back to its previous state.
        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        self.adapter_agent.update_device(device)

        # Update the child devices connect state to REACHABLE
        self.adapter_agent.update_child_devices_state(device.id,
                                                      connect_status=ConnectStatus.REACHABLE)
        log.info('OLT Rebooted: {}'.format(device.mac_address))

    def download_image(self, device, request):
        raise NotImplementedError()

    def get_image_download_status(self, device, request):
        raise NotImplementedError()

    def cancel_image_download(self, device, request):
        raise NotImplementedError()

    def activate_image_update(self, device, request):
        raise NotImplementedError()

    def revert_image_update(self, device, request):
        raise NotImplementedError()

    def self_test_device(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        log.info('self-test-device', device=device.id)
        raise NotImplementedError()

    def delete_device(self, device):
        log.info('deleting', device_id=device.id)

        # Remove all child devices
        # TODO
        # 1) Remove all flows from the device
        # 2) Remove the device from the adapter
        self.adapter_agent.delete_all_child_devices(device.id)
        log.info('deleted', device_id=device.id)

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
                                fieldcode=RuleClauses['L2 Type/Len'],
                                operator=RuleOperators['=='],
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

                    ruleInnerVidNotSet = False;

                    for action in get_actions(flow):

                        if action.type == OUTPUT:
                            log.info('#### action.type == OUTPUT ####')
                            dn_req /= PortIngressRuleResultForward()
                            if _outer_vid == MULTICAST_VLAN:
                                dn_req /= PortIngressRuleResultOLTBroadcastQueue()
                            elif _inner_vid is not None:
                                serial = _inner_vid - 200
                                mac_address = self.vlan_to_device_ids[_inner_vid][2].upper()

                                resultOltQueue = get_olt_queue(mac_address, self.mode)
                                dn_req /= eval(resultOltQueue)

                            elif _inner_vid is None:
                                ruleInnerVidNotSet = True
                                log.info('#### action.type == OUTPUT INNER VID is NONE ####')

                        elif action.type == POP_VLAN:
                            log.info('#### action.type == POP_VLAN ####')
                            if _outer_vid == MULTICAST_VLAN:
                                dn_req /= PortIngressRuleResultDelete(fieldcode=RuleClauses['C-VLAN Tag'])
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=0,
                                                                             operator=RuleOperators['=='], match=_outer_vid)
                            else:
                                dn_req /= PortIngressRuleResultDelete(fieldcode=RukeClauses['C-VLAN Tag'])
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=0,
                                                                             operator=RuleOperators['=='], match=_outer_vid)
                                dn_req /= PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=1,
                                                                             operator=RuleOperators['=='], match=_inner_vid)

                        elif action.type == PUSH_VLAN:
                            log.info('#### action.type == PUSH_VLAN ####')
                            if action.push.ethertype != 0x8100:
                                log.error('unhandled-tpid',
                                          ethertype=action.push.ethertype)
                                dn_req /= PortIngressRuleResultInsert(fieldcode=RuleClauses['C-VLAN Tag'])

                        elif action.type == SET_FIELD:
                            log.info('#### action.type == SET_FIELD ####')
                            assert (action.set_field.field.oxm_class ==
                                    ofp.OFPXMC_OPENFLOW_BASIC)
                            field = action.set_field.field.ofb_field
                            if field.type == VLAN_VID:
                                # need to convert value in Set to a variable length value
                                ctagStr = struct.pack('>H', (field.vlan_vid & 0xfff))

                                dn_req /= PortIngressRuleResultSet(
                                    fieldcode=RuleClauses['C-VLAN Tag'], value=ctagStr)
                            else:
                                log.error('unsupported-action-set-field-type',
                                          field_type=field.type)
                        else:
                            log.error('UNSUPPORTED-ACTION-TYPE',
                                      action_type=action.type)

                    # Don't send the rule if a Queue was not set in the Port Ingress Rule
                    if ruleInnerVidNotSet == True:
                        continue

                    dn_req /= PortIngressRuleTerminator()
                    dn_req /= AddPortIngressRule()

                    # Get and process the Set Response
                    action = "Set DS Rule"
                    rc = []
                    yield self._set_req_rsp(device, action, dn_req, rc)


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
                                fieldcode=RuleClauses['L2 Type/Len'],
                                operator=RuleOperators['=='],
                                match=_type)

                            up_req_link /= PortIngressRuleClauseMatchLength02(
                                fieldcode=RuleClauses['L2 Type/Len'],
                                operator=RuleOperators['=='],
                                match=_type)

                        elif field.type == IP_PROTO:
                            _proto = field.ip_proto
                            log.info('#### field.type == IP_PROTO ####', in_port=in_port,
                                     ip_proto=_proto)

                            up_req_pon /= PortIngressRuleClauseMatchLength01(
                                fieldcode=RuleClauses['IPv4/IPv6 Protocol Type'],
                                operator=RuleOperators['=='], match=_proto)

                            up_req_link /= PortIngressRuleClauseMatchLength01(
                                fieldcode=RuleClauses['IPv4/IPv6 Protocol Type'],
                                operator=RuleOperators['=='], match=_proto)

                        elif field.type == IN_PORT:
                            _port = field.port
                            log.info('#### field.type == IN_PORT ####')

                        elif field.type == VLAN_VID:
                            _vlan_vid = field.vlan_vid & 0xfff
                            log.info('#### field.type == VLAN_VID ####')
                            up_req_pon /= PortIngressRuleClauseMatchLength02(
                                fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=0,
                                operator=RuleOperators['=='], match=_vlan_vid)

                            serial = _vlan_vid - 200
                            mac_address = self.vlan_to_device_ids[_vlan_vid][2].upper()

                            logical_link = get_unicast_logical_link(mac_address, self.mode)
                            up_req_link /= eval(logical_link)

                            up_req_link /= PortIngressRuleClauseMatchLength02(
                                fieldcode=RuleClauses['C-VLAN Tag'], fieldinstance=0,
                                operator=RuleOperators['=='], match=_vlan_vid)
                            field_match_vlan_upstream_with_link = True


                        elif field.type == VLAN_PCP:
                            _vlan_pcp = field.vlan_pcp
                            log.info('#### field.type == VLAN_PCP ####')

                        elif field.type == UDP_DST:
                            _udp_dst = field.udp_dst
                            log.info('#### field.type == UDP_DST ####')
                            up_req_pon /= (PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['TCP/UDP source port'],
                                                                              operator=RuleOperators['=='], match=0x0044)/
                                           PortIngressRuleClauseMatchLength02(fieldcode=RuleClauses['TCP/UDP destination port'],
                                                                              operator=RuleOperators['=='], match=0x0043))

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
                                up_req_link /= PortIngressRuleResultInsert(fieldcode=RuleClauses['C-VLAN Tag'],
                                                                      fieldinstance=1)
                            else:
                                up_req_pon /= PortIngressRuleResultInsert(fieldcode=RuleClauses['C-VLAN Tag'],
                                                                      fieldinstance=0)

                        elif action.type == SET_FIELD:
                            log.info('#### action.type == SET_FIELD ####')
                            assert (action.set_field.field.oxm_class ==
                                    ofp.OFPXMC_OPENFLOW_BASIC)
                            field = action.set_field.field.ofb_field
                            if field.type == VLAN_VID:
                                if field_match_vlan_upstream_with_link == True:
                                    up_req_link /=(PortIngressRuleResultCopy(fieldcode=RuleClauses['C-VLAN Tag'])/
                                                   PortIngressRuleResultReplace(fieldcode=RuleClauses['C-VLAN Tag']))

                                # need to convert value in Set to a variable length value
                                ctagStr = struct.pack('>H', (field.vlan_vid & 0xfff))

                                up_req_pon /= PortIngressRuleResultSet(
                                    fieldcode=RuleClauses['C-VLAN Tag'], value=ctagStr)
                                up_req_link /= PortIngressRuleResultSet(
                                    fieldcode=RuleClauses['C-VLAN Tag'], value=ctagStr)
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

                    # Get and process the Set Response
                    action = "Set US Rule"
                    rc = []
                    yield self._set_req_rsp(device, action, up_req, rc)

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

            # Can receive OMCI frames encoded as strings or as byte-arrays
            try:
                msgBytes = bytearray.fromhex(msg)
                encapsulated_omci = EOAM_OmciMsg(body=msgBytes)
            except ValueError:
                encapsulated_omci = EOAM_OmciMsg(body=msg)

            frame = Ether(dst=device.mac_address) / \
              Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) / \
              Dot1Q(vlan=proxy_address.channel_id, prio=TIBIT_MGMT_PRIORITY) / \
              EOAMPayload() / EOAM_VendSpecificMsg(oui=ITU_OUI) / \
              encapsulated_omci /\
              EndOfPDU()

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
                            [RxFrame_64().branch,        RxFrame_64().leaf,        "rx_64"],
                            [RxFrame_65_127().branch,    RxFrame_65_127().leaf,    "rx_65_127"],
                            [RxFrame_128_255().branch,   RxFrame_128_255().leaf,   "rx_128_255"],
                            [RxFrame_256_511().branch,   RxFrame_256_511().leaf,   "rx_256_511"],
                            [RxFrame_512_1023().branch,  RxFrame_512_1023().leaf,  "rx_512_1023"],
                            [RxFrame_1024_1518().branch, RxFrame_1024_1518().leaf, "rx_1024_1518"],
                            [RxFrame_1519Plus().branch,  RxFrame_1519Plus().leaf,  "rx_1519_9k"],

                            [TxFrame_64().branch,        TxFrame_64().leaf,        "tx_64"],
                            [TxFrame_65_127().branch,    TxFrame_65_127().leaf,    "tx_65_127"],
                            [TxFrame_128_255().branch,   TxFrame_128_255().leaf,   "tx_128_255"],
                            [TxFrame_256_511().branch,   TxFrame_256_511().leaf,   "tx_256_511"],
                            [TxFrame_512_1023().branch,  TxFrame_512_1023().leaf,  "tx_512_1023"],
                            [TxFrame_1024_1518().branch, TxFrame_1024_1518().leaf, "tx_1024_1518"],
                            [TxFrame_1519Plus().branch,  TxFrame_1519Plus().leaf,  "tx_1519_9k"]
                            ]

            stats_tlvs =  RxFrame_64()/RxFrame_65_127()/RxFrame_128_255()/RxFrame_256_511()/RxFrame_512_1023()/RxFrame_1024_1518()/RxFrame_1519Plus()
            stats_tlvs /= TxFrame_64()/TxFrame_65_127()/TxFrame_128_255()/TxFrame_256_511()/TxFrame_512_1023()/TxFrame_1024_1518()/TxFrame_1519Plus()

            # Get the latest device reference
            device = self.adapter_agent.get_device(device_id)

            try:
                # Step 1: gather metrics from device

                #for each link on this OLT
                for vlan_id in self.vlan_to_device_ids:

                    log.info('link stats frame', links=self.vlan_to_device_ids[vlan_id])

                    # send out link_stats_frame
                    onu_mac_address = self.vlan_to_device_ids[vlan_id][2].upper()

                    logical_link = get_unicast_logical_link(onu_mac_address, self.mode)

                    resp = []
                    action = "Get Link Stats"
                    tlvs = eval(logical_link)/stats_tlvs
                    yield self._get_req_rsp(device, action, tlvs, resp)
                    if resp is not []: frame = resp[0]

                    if frame:
                        # Process the Get Request message
                        log.info('Received Link Stats Get Response Frame')

                        for pair in branch_leaf_pairs:
                            (rc, value) = (get_value_from_msg(log, frame, pair[0], pair[1]))

                            if rc:
                                log.info('Response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(pair[0], pair[1]))
                                pon_port_metrics.append((pair[2],value))
                            else:
                                log.info('Failed to get valid response for Branch 0x{:X} Leaf 0x{:0>4X} '.format(pair[0], pair[1]))

                        pon_metrics_list[vlan_id] = pon_port_metrics

                #end looping on each vlan_id

                log.info('nni stats frame')

                resp = []
                action = "Get NNI Stats"
                tlvs=NetworkToNetworkPortObject()/stats_tlvs
                yield self._get_req_rsp(device, action, tlvs, resp)
                if resp is not []: frame = resp[0]

                if frame:
                    # Process the Get Response message
                    log.info('Recieved NNI Stats Get Response Frame')

                    for pair in branch_leaf_pairs:
                        (rc, value) = (get_value_from_msg(log, frame, pair[0], pair[1]))
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


    @inlineCallbacks
    def change_device_state(self, device, state=0):
        if state is 0:
            stateStr = "disabled"
        else:
            stateStr = "enabled"
        action = "Set PON Admin State to " + stateStr

        # Get and process the Set Response
        rc = []
        tlvs = PonPortObject()/OltPonAdminStateSet(value=state)
        yield self._set_req_rsp(device, action, tlvs, rc)


    # Generic Request handlers

    def _build_tibit_oam_msg(self, mac_addr, opcode, body):
        msg = (
            Ether(dst=mac_addr) /
            Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) /
            EOAMPayload() / EOAM_VendSpecificMsg(oui=TIBIT_OUI) /
            EOAM_TibitMsg(dpoe_opcode = opcode, body=body)/
            EndOfPDU()
            )
        return msg


    @inlineCallbacks
    def _get_req_rsp(self, device, action, body, resp):
        msg = self._build_tibit_oam_msg(device.mac_address, DPoEOpcodes["Get Request"], body)
        log.info('Send to {} for {}: {}'.format(action, device.model, device.mac_address))

        self.io_port.send(str(msg))

        # Loop until we have a Get Response or timeout
        ack = False
        start_time = time.time()
        while not ack:
            frame = yield self.incoming_queues[device.mac_address].get()
            #TODO - Need to add proper timeout functionality
            #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
            #    break  # don't wait forever

            respType = get_oam_msg_type(log, frame)

            if (respType == RxedOamMsgTypeEnum["DPoE Get Response"]):
                ack = True
                resp.append(frame)
            else:
                # Handle unexpected events/OMCI messages
                check_resp(log, frame)


    @inlineCallbacks
    def _handle_set_resp(self, device, action, retcode):
        # Get and process the Set Response
        ack = False
        #start_time = time.time()

        # Loop until we have a set response or timeout
        while not ack:
            frame = yield self.incoming_queues[device.mac_address].get()
            #TODO - Need to add proper timeout functionality
            #if (time.time() - start_time) > TIBIT_MSG_WAIT_TIME or (frame is None):
            #    break  # don't wait forever

            respType = get_oam_msg_type(log, frame)

            #Check that the message received is a Set Response
            if (respType == RxedOamMsgTypeEnum["DPoE Set Response"]):
                ack = True
            else:
                log.info('Received Unexpected OAM Message 0x{:X} while waiting for Set Resp for {}'.format(respType,action))
                # Handle unexpected events/OMCI messages
                check_resp(log, frame)

        # Verify Set Response
        rc = False
        if ack:
            (rc,branch,leaf,status) = check_set_resp(log, frame)
            if (rc is False):
                log.info('Set Response for {} for {}: {} had errors - Branch 0x{:X} Leaf 0x{:0>4X} {}'.format(action, device.model, device.mac_address,branch, leaf, DPoEVariableResponseEnum[status]))
            else:
                log.info('Set Response received for {} for {}: {} had no errors'.format(action, device.model, device.mac_address))
        else:
            log.info('No Set Response received for {} for {}: {}'.format(action, device.model, device.mac_address))

        retcode.append(rc)


    @inlineCallbacks
    def _set_req_rsp(self, device, action, body, rc):
        msg = self._build_tibit_oam_msg(device.mac_address, DPoEOpcodes["Set Request"], body)
        log.info('Send to {} for {}: {}'.format(action, device.model, device.mac_address))
        self.io_port.send(str(msg))

        # Get and process the Set Response
        yield self._handle_set_resp(device, action, rc)

    def create_interface(self, device, data):
        raise NotImplementedError()

    def update_interface(self, device, data):
        raise NotImplementedError()

    def remove_interface(self, device, data):
        raise NotImplementedError()

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def create_gemport(self, device, data):
        raise NotImplementedError()

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def update_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def remove_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def update_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def remove_multicast_distribution_set(self, device, data):
        raise NotImplementedError()
