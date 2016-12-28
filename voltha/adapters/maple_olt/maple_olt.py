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

import sys
from uuid import uuid4

import structlog
from twisted.spread import pb
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from zope.interface import implementer

from common.utils.asleep import asleep
from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Device, Port
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_port, OFPPF_1GB_FD, \
    OFPPF_FIBER, OFPPS_LIVE, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS

log = structlog.get_logger()


class AsyncRx(pb.Root):
    def remote_echo(self, pkt_type, pon, onu, port, crc_ok, msg_size, msg_data):
        log.info('packet-type', pkt_type=pkt_type)
        log.info('pon-id', pon_id=pon)
        log.info('onu-id', onu_id=onu)
        log.info('port', port_id=port)
        log.info('crc-ok', crc_ok=crc_ok)
        log.info('msg-size', msg_size=msg_size)
        log.info('msg-data', msg_data="".join("{:02x}".format(ord(c)) for c in msg_data))
        return 0

@implementer(IAdapterInterface)
class MapleOltAdapter(object):

    name = 'maple_olt'

    supported_device_types = [
        DeviceType(
            id='maple_olt',
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
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.PBServerPort = 24497
        #start PB server
        reactor.listenTCP(self.PBServerPort, pb.PBServerFactory(AsyncRx()))
        log.info('PB-server-started on port', port=self.PBServerPort)

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

    def adopt_device(self, device):
        log.info('adopt-device', device=device)
        # We kick of a simulated activation scenario
        reactor.callLater(0.2, self._activate_device, device)
        return device

    def abandon_device(self, device):
        raise NotImplementedError(0
                                  )
    def deactivate_device(self, device):
        raise NotImplementedError()

    @inlineCallbacks
    def _activate_device(self, device):

        # launch connecion
        log.info('initiating-connection-to-olt', device_id=device.id, ipv4=device.ipv4_address)
        self.pbc_factory = pb.PBClientFactory()
        reactor.connectTCP(device.ipv4_address, 24498, self.pbc_factory)
        self.remote = yield self.pbc_factory.getRootObject()
        log.info('connected-to-olt', device_id=device.id, ipv4=device.ipv4_address)

        data = yield self.remote.callRemote('connect_olt', 0)
        #TODO: add error handling
        log.info('connect-data', data=data)

        data = yield self.remote.callRemote('activate_olt', 0)
        #TODO: add error handling
        log.info('activate-data', data=data)

        # first we pretend that we were able to contact the device and obtain
        # additional information about it
        device.root = True
        device.vendor = 'Broadcom'
        device.model = 'Maple XYZ'
        device.hardware_version = 'Fill this'
        device.firmware_version = 'Fill this'
        device.software_version = 'Fill this'
        device.serial_number = 'Fill this'
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # register ports
        nni_port = Port(
            port_no=0,
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

        # register logical device (as we are a root device)
        logical_device_id = uuid4().hex[:12]
        ld = LogicalDevice(
            id=logical_device_id,
            datapath_id=int('0x' + logical_device_id[:8], 16), # from id
            desc=ofp_desc(
                mfr_desc='cord porject',
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
        self.adapter_agent.create_logical_device(ld)
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(ld.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=0,
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

        # and finally update to active
        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        reactor.callLater(0.1, self._simulate_detection_of_onus, device)

    def _simulate_detection_of_onus(self, device):
        for i in xrange(1, 2):
            log.info('activate-olt-for-onu-{}'.format(i))
            vlan_id = self._olt_side_onu_activation(i)
            self.adapter_agent.child_device_detected(
                parent_device_id=device.id,
                parent_port_no=1,
                child_device_type='broadcom_onu',
                proxy_address=Device.ProxyAddress(
                    device_id=device.id,
                    channel_id=i
                ),
                vlan=i+1024
            )

    @inlineCallbacks
    def _olt_side_onu_activation(self, seq):
        """
        This is where if this was a real OLT, the OLT-side activation for
        the new ONU should be performed. By the time we return, the OLT shall
        be able to provide tunneled (proxy) communication to the given ONU,
        using the returned information.
        """
        data = yield self.remote.callRemote('create_onu', 0, seq, '4252434d', '12345678')
        log.info('create-onu-data', data=data)

        vlan_id = seq + 1024

        data = yield self.remote.callRemote('configure_onu', 0, seq, alloc_id=vlan_id, unicast_gem=vlan_id, multicast_gem=4095)
        log.info('configure-onu-data', data=data)

        data = yield self.remote.callRemote('activate_onu', 0, seq)
        log.info('activate-onu-data', data=data)

        log.info('ready-to-send-omci')
        omci_msg = "00014F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"
        log.info('sending-omci-msg', msg=omci_msg)
        try:
            res = yield self.remote.callRemote(
                             'send_omci',
                             0,
                             0,
                             1,
                             omci_msg
                        )
            log.info('omci-send-result', result=res)
        except Exception, e:
            log.info('omci-send-exception', exc=str(e))

        #reactor.callLater(5.0, self._send_omci_test_msg)

        returnValue(vlan_id)

    @inlineCallbacks
    def _send_omci_test_msg(self):
        omci_msg = "00014F0A00020000000000000000000000000000000000000000000000000000000000000000000000000028"
        log.info('sending-omci-msg', msg=omci_msg)
        try:
            res = yield self.remote.callRemote(
                             'send_omci',
                             0,
                             0,
                             1,
                             omci_msg
                        )
            log.info('omci-send-result', result=res)
        except Exception, e:
            log.info('omci-send-exception', exc=str(e))

    def update_flows_bulk(self, device, flows, groups):
        log.debug('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)
        # we mimic a response by sending the same message back in a short time
        reactor.callLater(
            0.2,
            self.adapter_agent.receive_proxied_message,
            proxy_address,
            msg
        )

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))
