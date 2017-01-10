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
Mock device adapter for testing.
"""
from uuid import uuid4

import structlog
from klein import Klein
from scapy.layers.l2 import Ether, EAPOL, Padding
from twisted.internet import endpoints
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.web.server import Site
from zope.interface import implementer

from common.utils.asleep import asleep
from voltha.adapters.interface import IAdapterInterface
from voltha.core.flow_decomposer import *
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


@implementer(IAdapterInterface)
class SimulatedOltAdapter(object):

    name = 'simulated_olt'

    supported_device_types = [
        DeviceType(
            id='simulated_olt',
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    app = Klein()

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Voltha project',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.control_endpoint = None

    def start(self):
        log.debug('starting')

        # setup a basic web server for test control
        self.control_endpoint = endpoints.TCP4ServerEndpoint(reactor, 18880)
        self.control_endpoint.listen(self.get_test_control_site())

        # TODO tmp: populate some devices and logical devices
        # reactor.callLater(0, self._tmp_populate_stuff)
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
        # We kick of a simulated activation scenario
        reactor.callLater(0.2, self._simulate_device_activation, device)
        return device

    def abandon_device(self, device):
        raise NotImplementedError()

    def deactivate_device(self, device):
        raise NotImplementedError()

    def _tmp_populate_stuff(self):
        """
        pretend that we discovered some devices and create:
        - devices
        - device ports for each
        - logical device
        - logical device ports
        """

        olt = Device(
            id='simulated_olt_1',
            type='simulated_olt',
            root=True,
            vendor='simulated',
            model='n/a',
            hardware_version='n/a',
            firmware_version='n/a',
            software_version='1.0',
            serial_number=uuid4().hex,
            adapter=self.name,
            oper_status=OperStatus.DISCOVERED
        )
        self.adapter_agent.add_device(olt)
        self.adapter_agent.add_port(
            olt.id, Port(port_no=1, label='pon', type=Port.PON_OLT))
        self.adapter_agent.add_port(
            olt.id, Port(port_no=2, label='eth', type=Port.ETHERNET_NNI))

        onu1 = Device(
            id='simulated_onu_1',
            type='simulated_onu',
            root=False,
            parent_id=olt.id,
            parent_port_no=1,
            vendor='simulated',
            model='n/a',
            hardware_version='n/a',
            firmware_version='n/a',
            software_version='1.0',
            serial_number=uuid4().hex,
            adapter='simulated_onu',
            oper_status=OperStatus.DISCOVERED,
            vlan=101
        )
        self.adapter_agent.add_device(onu1)
        self.adapter_agent.add_port(onu1.id, Port(
            port_no=2, label='eth', type=Port.ETHERNET_UNI))
        self.adapter_agent.add_port(onu1.id, Port(
            port_no=1,
            label='pon',
            type=Port.PON_ONU,
            peers=[Port.PeerPort(device_id=olt.id, port_no=1)]))

        onu2 = Device(
            id='simulated_onu_2',
            type='simulated_onu',
            root=False,
            parent_id=olt.id,
            parent_port_no=1,
            vendor='simulated',
            model='n/a',
            hardware_version='n/a',
            firmware_version='n/a',
            software_version='1.0',
            serial_number=uuid4().hex,
            adapter='simulated_onu',
            oper_status=OperStatus.DISCOVERED,
            vlan=102
        )
        self.adapter_agent.add_device(onu2)
        self.adapter_agent.add_port(onu2.id, Port(
            port_no=2, label='eth', type=Port.ETHERNET_UNI))
        self.adapter_agent.add_port(onu2.id, Port(
            port_no=1,
            label='pon',
            type=Port.PON_ONU,
            peers=[Port.PeerPort(device_id=olt.id, port_no=1)]))

        ld = LogicalDevice(
            id='simulated1',
            datapath_id=1,
            desc=ofp_desc(
                mfr_desc='cord project',
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
            root_device_id=olt.id
        )
        self.adapter_agent.create_logical_device(ld)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        for port_no, name, device_id, device_port_no, root_port in [
            (1, 'onu1', onu1.id, 2, False),
            (2, 'onu2', onu2.id, 2, False),
            (129, 'olt1', olt.id, 2, True)]:
            port = LogicalPort(
                id=name,
                ofp_port=ofp_port(
                    port_no=port_no,
                    hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                    name=name,
                    config=0,
                    state=OFPPS_LIVE,
                    curr=cap,
                    advertised=cap,
                    peer=cap,
                    curr_speed=OFPPF_1GB_FD,
                    max_speed=OFPPF_1GB_FD
                ),
                device_id=device_id,
                device_port_no=device_port_no,
                root_port=root_port
            )
            self.adapter_agent.add_logical_port(ld.id, port)

        olt.parent_id = ld.id
        self.adapter_agent.update_device(olt)

    @inlineCallbacks
    def _simulate_device_activation(self, device):

        # first we pretend that we were able to contact the device and obtain
        # additional information about it
        device.root = True
        device.vendor = 'simulated'
        device.model = 'n/a'
        device.hardware_version = 'n/a'
        device.firmware_version = 'n/a'
        device.software_version = '1.0'
        device.serial_number = uuid4().hex
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # then shortly after we create some ports for the device
        yield asleep(0.05)
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

        # then shortly after we create the logical device with one port
        # that will correspond to the NNI port
        yield asleep(0.05)
        logical_device_id = uuid4().hex[:12]
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
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=129,
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
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        # reactor.callLater(0.1, self._simulate_detection_of_onus, device.id)

    @inlineCallbacks
    def _simulate_detection_of_onus(self, device_id):
        for i in xrange(1, 5):
            log.info('activate-olt-for-onu-{}'.format(i))
            vlan_id = self._olt_side_onu_activation(i)
            yield asleep(0.05)
            self.adapter_agent.child_device_detected(
                parent_device_id=device_id,
                parent_port_no=1,
                child_device_type='simulated_onu',
                proxy_address=Device.ProxyAddress(
                    device_id=device_id,
                    channel_id=vlan_id
                ),
                vlan=vlan_id
            )

    def _olt_side_onu_activation(self, seq):
        """
        This is where if this was a real OLT, the OLT-side activation for
        the new ONU should be performed. By the time we return, the OLT shall
        be able to provide tunneled (proxy) communication to the given ONU,
        using the returned information.
        """
        vlan_id = seq + 100
        return vlan_id

    def update_flows_bulk(self, device, flows, groups):
        log.debug('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

        # sample code that analyzes the incoming flow table
        assert len(groups.items) == 0, "Cannot yet deal with groups"

        for flow in flows.items:
            in_port = get_in_port(flow)
            assert in_port is not None

            if in_port == 2:

                # Downstream rule

                for field in get_ofb_fields(flow):
                    if field.type == ETH_TYPE:
                        _type = field.eth_type
                        pass  # construct ether type based condition here

                    elif field.type == IP_PROTO:
                        _proto = field.ip_proto
                        pass  # construct ip_proto based condition here

                    elif field.type == IN_PORT:
                        _port = field.port
                        pass  # construct in_port based condition here

                    elif field.type == VLAN_VID:
                        _vlan_vid = field.vlan_vid
                        pass  # construct VLAN ID based filter condition here

                    elif field.type == VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        pass  # construct VLAN PCP based filter condition here

                    elif field.type == METADATA:
                        pass  # safe to ignore

                    # TODO
                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in get_actions(flow):

                    if action.type == OUTPUT:
                        pass  # construct packet emit rule here

                    elif action.type == PUSH_VLAN:
                        if action.push.ethertype != 0x8100:
                            log.error('unhandled-ether-type',
                                      ethertype=action.push.ethertype)
                        pass  # construct vlan push command here

                    elif action.type == POP_VLAN:
                        pass  # construct vlan pop command here

                    elif action.type == SET_FIELD:
                        assert (action.set_field.field.oxm_class ==
                                ofp.OFPXMC_OPENFLOW_BASIC)
                        field = action.set_field.field.ofb_field
                        if field.type == VLAN_VID:
                            pass  # construct vlan_id set command here
                        else:
                            log.error('unsupported-action-set-field-type',
                                      field_type=field.type)

                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type)

                # final assembly of low level device flow rule and pushing it
                # down to device
                pass

            elif in_port == 1:

                # Upstream rule

                for field in get_ofb_fields(flow):

                    if field.type == ETH_TYPE:
                        _type = field.eth_type
                        pass  # construct ether type based condition here

                    elif field.type == IP_PROTO:
                        _proto = field.ip_proto
                        pass  # construct ip_proto based condition here

                    elif field.type == IN_PORT:
                        _port = field.port
                        pass  # construct in_port based condition here

                    elif field.type == VLAN_VID:
                        _vlan_vid = field.vlan_vid
                        pass  # construct VLAN ID based filter condition here

                    elif field.type == VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        pass  # construct VLAN PCP based filter condition here

                    elif field.type == UDP_DST:
                        _udp_dst = field.udp_dst
                        pass  # construct UDP SDT based filter here

                    # TODO
                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in get_actions(flow):

                    if action.type == OUTPUT:
                        pass  # construct packet emit rule here

                    elif action.type == PUSH_VLAN:
                        if action.push.ethertype != 0x8100:
                            log.error('unhandled-ether-type',
                                      ethertype=action.push.ethertype)
                        pass  # construct vlan push command here

                    elif action.type == SET_FIELD:
                        assert (action.set_field.field.oxm_class ==
                                ofp.OFPXMC_OPENFLOW_BASIC)
                        field = action.set_field.field.ofb_field
                        if field.type == VLAN_VID:
                            pass  # construct vlan_id set command here
                        else:
                            log.error('unsupported-action-set-field-type',
                                      field_type=field.type)

                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type)

                # final assembly of low level device flow rule and pushing it
                # down to device
                pass

            else:
                raise Exception('Port should be 1 or 2 by our convention')


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

    # ~~~~~~~~~~~~~~~~~~~~ Embedded test Klein rest server ~~~~~~~~~~~~~~~~~~~~

    def get_test_control_site(self):
        return Site(self.app.resource())

    @app.route('/devices/<string:device_id>/detect_onus')
    def detect_onus(self, request, device_id):
        log.info('detect-onus', request=request, device_id=device_id)
        self._simulate_detection_of_onus(device_id)
        return '{"status": "OK"}'

    @app.route('/devices/<string:device_id>/test_eapol_in')
    def test_eapol_in(self, request, device_id):
        """Simulate a packet in message posted upstream"""
        log.info('test_eapol_in', request=request, device_id=device_id)
        eapol_start = str(
            Ether(src='00:11:22:33:44:55') /
            EAPOL(type=1, len=0) /
            Padding(load=42*'\x00')
        )
        device = self.adapter_agent.get_device(device_id)
        self.adapter_agent.send_packet_in(logical_device_id=device.parent_id,
                                          logical_port_no=1,
                                          packet=eapol_start)
        return '{"status": "sent"}'
