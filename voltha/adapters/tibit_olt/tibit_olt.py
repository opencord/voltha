#
# Copyright 2016 the original author or authors.
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
import scapy
import structlog
import json

from uuid import uuid4

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether, Dot1Q
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet import reactor

from zope.interface import implementer

from common.utils.asleep import asleep

from common.frameio.frameio import BpfProgramFilter
from voltha.registry import registry
from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.device_pb2 import Device, Port
from voltha.protos.device_pb2 import DeviceType, DeviceTypes
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.common_pb2 import LogLevel, ConnectStatus
from voltha.protos.common_pb2 import OperStatus, AdminState

from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_port, OFPPF_10GB_FD, \
    OFPPF_FIBER, OFPPS_LIVE, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS

from scapy.packet import Packet, bind_layers
from scapy.fields import StrField

log = structlog.get_logger()

# Match on the MGMT VLAN, Priority 7
TIBIT_MGMT_VLAN=4090
TIBIT_MGMT_PRIORITY=7
frame_match = 'ether[14:2] = 0x{:01x}{:03x}'.format(TIBIT_MGMT_PRIORITY << 1, TIBIT_MGMT_VLAN)
is_tibit_frame = BpfProgramFilter(frame_match)
#is_tibit_frame = lambda x: True

# To be removed in favor of OAM
class TBJSON(Packet):
    """ TBJSON 'packet' layer. """
    name = "TBJSON"
    fields_desc = [StrField("data", default="")]

bind_layers(Ether, TBJSON, type=0x9001)

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

    def start(self):
        log.debug('starting', interface=self.interface)
        log.info('started', interface=self.interface)

    def stop(self):
        log.debug('stopping')
        if self.io_port is not None:
            registry('frameio').del_interface(self.interface)
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
            self.io_port = registry('frameio').add_interface(
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

        except Exception, e:
            log.exception('launch device failed', e=e)

        # if we got response, we can fill out the device info, mark the device
        # reachable
        jdev = json.loads(response.data[5:])
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
        logical_device_id = uuid4().hex[:12]
        ld = LogicalDevice(
            id=logical_device_id,
            datapath_id=int('0x' + logical_device_id[:8], 16), # from id
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
        self.adapter_agent.create_logical_device(ld)
        cap = OFPPF_10GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(ld.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=129,
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
        device.parent_id = ld.id
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

        jdev = json.loads(response.data[5:])
        tibit_mac = ''
        for macid in jdev['results']:
            if macid['macid'] is None:
                log.info('MAC ID is NONE %s' % str(macid['macid']))
            else:
                tibit_mac = '000c' + macid.get('macid', 'e2000000')[4:]
                log.info('activate-olt-for-onu-%s' % tibit_mac)

            # Convert from string to colon separated form
            tibit_mac = ':'.join(s.encode('hex') for s in tibit_mac.decode('hex'))

            gemport, vlan_id = self._olt_side_onu_activation(int(macid['macid'][-4:-2], 16))
            self.adapter_agent.child_device_detected(
                parent_device_id=device.id,
                parent_port_no=1,
                child_device_type='tibit_onu',
                mac_address = tibit_mac,
                proxy_address=Device.ProxyAddress(
                    device_id=device.id,
                    channel_id=vlan_id
                    ),
                vlan=vlan_id
                )

    def _olt_side_onu_activation(self, serial):
        """
        This is where if this was a real OLT, the OLT-side activation for
        the new ONU should be performed. By the time we return, the OLT shall
        be able to provide tunneled (proxy) communication to the given ONU,
        using the returned information.
        """
        gemport = serial
        vlan_id = serial + 200
        return gemport, vlan_id

    def _rcv_io(self, port, frame):

        log.info('frame-received')

        # make into frame to extract source mac
        response = Ether(frame)

        if response.haslayer(Dot1Q):
            # All responses from the OLT should have a TIBIT_MGMT_VLAN.
            # Responses from the ONUs should have a TIBIT_MGMT_VLAN followed by a ONU CTAG
            if response.getlayer(Dot1Q).type == 0x8100:
                ## Responses from the ONU
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
                ## Respones from the OLT
                ## enqueue incoming parsed frame to right device
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

    def abandon_device(self, device):
        raise NotImplementedError(0
                                  )
    def deactivate_device(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.debug('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address)
        # TODO build device_id -> mac_address cache
        device = self.adapter_agent.get_device(proxy_address.device_id)
        frame = Ether(dst='00:0c:e2:22:29:00') / \
                Dot1Q(vlan=TIBIT_MGMT_VLAN, prio=TIBIT_MGMT_PRIORITY) / \
                Dot1Q(vlan=proxy_address.channel_id, prio=TIBIT_MGMT_PRIORITY) / \
                msg

        self.io_port.send(str(frame))

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()
