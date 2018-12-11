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
Broadcom OLT/ONU adapter.
"""

from uuid import uuid4
import structlog
from twisted.internet import reactor, task
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue
from zope.interface import implementer

from common.utils.asleep import asleep
from voltha.adapters.interface import IAdapterInterface
from voltha.core.logical_device_agent import mac_str_to_tuple
import voltha.core.flow_decomposer as fd
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Image
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPF_1GB_FD, OFPPS_LINK_DOWN
from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, ofp_port, \
    ofp_port_stats
from voltha.protos.bbf_fiber_base_pb2 import VEnetConfig, VOntaniConfig
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData

from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *

from voltha.registry import registry

_ = third_party
log = structlog.get_logger()


MANAGEMENT_VLAN = 4090
BRDCM_DEFAULT_VLAN = 4091
ADMIN_STATE_LOCK = 1
ADMIN_STATE_UNLOCK = 0
RESERVED_VLAN_ID = 4095
FLOW_TYPE_EAPOL = 34958

@implementer(IAdapterInterface)
class BroadcomOnuAdapter(object):

    name = 'broadcom_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            vendor_ids=['NONE'],
            adapter=name,
            accepts_bulk_flow_update=True,
            accepts_add_remove_flow_updates=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Voltha project',
            version='0.46',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.devices_handlers = dict()  # device_id -> BroadcomOnuHandler()

        # register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

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
        log.info('adopt_device', device_id=device.id)
        self.devices_handlers[device.id] = BroadcomOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device

    def reconcile_device(self, device):
        log.info('reconcile-device', device_id=device.id)
        self.devices_handlers[device.id] = BroadcomOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].reconcile, device)

    def abandon_device(self, device):
        log.info('abadon-device - Not implemented')
        raise NotImplementedError()

    def disable_device(self, device):
        log.info('disable-onu-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.disable(device)

    def reenable_device(self, device):
        log.info('reenable-onu-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.reenable(device)

    def reboot_device(self, device):
        log.info('reboot-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.reboot()

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
        log.info('self-test-device - Not implemented', device=device.id)
        raise NotImplementedError()

    def delete_device(self, device):
        log.info('delete-device', device_id=device.id, device_handlers=self.devices_handlers)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                log.debug('calling-handler-delete', handler=handler)
                handler.delete(device)
            del self.devices_handlers[device.id]
        return

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        '''
        log.info('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)
        '''
        assert len(groups.items) == 0
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(device, flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        log.info('incremental-flow-update', device_id=device.id,
                 flows=flow_changes, groups=group_changes)
        # For now, there is no support for group changes
        assert len(group_changes.to_add.items) == 0
        assert len(group_changes.to_remove.items) == 0

        handler = self.devices_handlers[device.id]
        # Remove flows
        if len(flow_changes.to_remove.items) != 0:
            handler.remove_from_flow_table(flow_changes.to_remove.items)

        # Add flows
        if len(flow_changes.to_add.items) != 0:
            handler.add_to_flow_table(flow_changes.to_add.items)

    def send_proxied_message(self, proxy_address, msg):
        log.debug('send-proxied-message', proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.debug('receive-proxied-message', proxy_address=proxy_address,
                 device_id=proxy_address.device_id, msg=hexify(msg))
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.receive_message(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        log.debug('receive_inter_adapter_message', msg=msg)
        proxy_address = msg['proxy_address']
        assert proxy_address is not None
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.event_messages.put(msg)
        else:
            log.error("device-not-found")

    def create_interface(self, device, data):
        log.debug('create-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_interface(data)

    def update_interface(self, device, data):
        log.debug('update-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_interface(data)

    def remove_interface(self, device, data):
        log.debug('remove-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_interface(data)

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.debug('create-tcont', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_tcont(tcont_data, traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('update_tcont not implemented in onu')

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.debug('remove-tcont', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_tcont(tcont_data, traffic_descriptor_data)

    def create_gemport(self, device, data):
        log.debug('create-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_gemport(data)

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        log.debug('remove-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_gemport(data)

    def create_multicast_gemport(self, device, data):
        log.debug('create-multicast-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_multicast_gemport(data)

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

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()


class BroadcomOnuHandler(object):

    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue()
        self.event_messages = DeferredQueue()
        self.proxy_address = None
        self.tx_id = 0
        self.flow_map = dict()

        # Need to query ONU for number of supported uni ports
        # For now, temporarily set number of ports to 1 - port #2
        self.uni_ports = (1, 2, 3, 4, 5)
        self.flow_config_in_progress = False

        # Handle received ONU event messages
        reactor.callLater(0, self.handle_onu_events)

    def receive_message(self, msg):
        self.incoming_messages.put(msg)

    @inlineCallbacks
    def handle_onu_events(self):
        event_msg = yield self.event_messages.get()

        if event_msg['event'] == 'activation-completed':

            if event_msg['event_data']['activation_successful'] == True:

                yield self.message_exchange()

                device = self.adapter_agent.get_device(self.device_id)
                device.connect_status = ConnectStatus.REACHABLE
                device.oper_status = OperStatus.ACTIVE
                self.adapter_agent.update_device(device)

            else:
                device = self.adapter_agent.get_device(self.device_id)
                self.disable_ports(device)
                device.connect_status = ConnectStatus.UNREACHABLE
                device.oper_status = OperStatus.FAILED
                self.adapter_agent.update_device(device)
                self.flow_map.clear()

        elif event_msg['event'] == 'deactivation-completed':
            device = self.adapter_agent.get_device(self.device_id)
            device.oper_status = OperStatus.DISCOVERED
            self.adapter_agent.update_device(device)

        elif event_msg['event'] == 'deactivate-onu':
            device = self.adapter_agent.get_device(self.device_id)
            self.disable_ports(device)
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.DISCOVERED
            self.adapter_agent.update_device(device)
            self.flow_map.clear()

        elif (event_msg['event'] == 'olt-reboot'):
            device = self.adapter_agent.get_device(self.device_id)
            device.connect_status = ConnectStatus.UNREACHABLE
            self.adapter_agent.update_device(device)
            self.flow_map.clear()

        elif event_msg['event'] == 'ranging-completed':

            if event_msg['event_data']['ranging_successful'] == True:
                device = self.adapter_agent.get_device(self.device_id)
                device.oper_status = OperStatus.ACTIVATING
                self.adapter_agent.update_device(device)

            else:
                device = self.adapter_agent.get_device(self.device_id)
                device.oper_status = OperStatus.FAILED
                self.adapter_agent.update_device(device)

        elif event_msg['event'] == 'olt-disabled':
            self.adapter_agent.disable_all_ports(self.device_id)
            device = self.adapter_agent.get_device(self.device_id)
            device.connect_status = ConnectStatus.UNREACHABLE
            self.adapter_agent.update_device(device)
            self.flow_map.clear()

        elif event_msg['event'] == 'olt-enabled':
            self.adapter_agent.enable_all_ports(self.device_id)
            device = self.adapter_agent.get_device(self.device_id)
            device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(device)

        elif event_msg['event'] == 'create-tcont':
            tcont = TcontsConfigData()
            tcont.alloc_id = event_msg['event_data']['alloc_id']
            self.create_tcont(tcont, traffic_descriptor_data=None)

        elif event_msg['event'] == 'create-venet':
            venet = VEnetConfig(name=event_msg['event_data']['uni_name'])
            venet.interface.name = event_msg['event_data']['interface_name']
            self.create_interface(venet)

        elif event_msg['event'] == 'create-gemport':
            gem_port = GemportsConfigData()
            gem_port.gemport_id = event_msg['event_data']['gemport_id']
            self.create_gemport(gem_port)

        # Handle next event
        reactor.callLater(0, self.handle_onu_events)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        #assert device.proxy_address.channel_id      # c-vid

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)


        # populate device info
        device.root = True
        device.vendor = 'Broadcom'
        device.model = 'n/a'
        device.hardware_version = 'to be filled'
        device.firmware_version = 'to be filled'
        device.images.image.extend([
                                        Image(version="to be filled")
                                       ])
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        self.adapter_agent.add_port(device.id, Port(
            port_no=100,
            label='PON port',
            type=Port.PON_ONU,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE,
            peers=[
                Port.PeerPort(
                    device_id=device.parent_id,
                    port_no=device.parent_port_no
                )
            ]
        ))

        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.DISCOVERED
        self.adapter_agent.update_device(device)
        self.log.info('activated')


    def reconcile(self, device):

        self.log.debug('reconciling-broadcom-onu-device-starts')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # TODO: Query ONU current status after reconcile and update.
        #       To be addressed in future commits.

        self.log.info('reconciling-broadcom-onu-device-ends')

    def update_logical_port(self, logical_device_id, port_id, state):
        try:
            self.log.debug('updating-logical-port', logical_port_id=port_id,
                          logical_device_id=logical_device_id, state=state)
            logical_port = self.adapter_agent.get_logical_port(logical_device_id,
                                                               port_id)
            logical_port.ofp_port.state = state
            self.adapter_agent.update_logical_port(logical_device_id,
                                                   logical_port)
        except Exception as e:
            self.log.exception("exception-updating-port",e=e)

    def delete(self, device):
        self.log.info('delete-onu', device=device)

        parent_device = self.adapter_agent.get_device(device.parent_id)
        if parent_device.type == 'openolt':
            parent_adapter = registry('adapter_loader').get_agent(parent_device.adapter).adapter
            self.log.debug('parent-adapter-delete-onu', onu_device=device,
                          parent_device=parent_device,
                          parent_adapter=parent_adapter)
            try:
                parent_adapter.delete_child_device(parent_device.id, device)
            except AttributeError:
                self.log.debug('parent-device-delete-child-not-implemented')

    @inlineCallbacks
    def update_flow_table(self, device, flows):

        # Twisted code is not inherently thread safe. This API could
        # be invoked again by reactor while previous one is in progress.
        # Since we maintain some stateful information here, we better
        # synchronize parallel invocations on this API.
        yield self._wait_for_previous_update_flow_to_finish()
        self.flow_config_in_progress = True

        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        try:
            # Calculates flows_to_adds and flows_to_delete using
            # incoming_flows and current_flows.
            current_flows = set(self.flow_map.keys())

            # Only adding those flows to incoming_flows which are having cookie.
            incoming_flows = set(flow.cookie for flow in flows if flow.cookie)
            flows_to_add = incoming_flows.difference(current_flows)
            flows_to_delete = current_flows.difference(incoming_flows)

            # Sends request to delete flows for ONU flows in flows_to_delete list.
            for cookie in flows_to_delete:
                if cookie in self.flow_map:
                    c_tag = self.flow_map[cookie]["vlan_id"]
                    self.log.debug("flow-to-delete-cookie",
                                   cookie=cookie, c_tag=c_tag)

                    # Deleting flow from ONU.
                    yield self._delete_onu_flow(self.flow_map[cookie])

                    # Removing flow_map entry for deleted flow.
                    del self.flow_map[cookie]
                else:
                    self.log.info('ignoring-cookie_received', cookie=cookie)

            # If flow is not in flow_to_add, no need to add flow to ONU.
            for flow in flows:
                if flow.cookie not in flows_to_add:
                    self.log.debug("flow-not-to-be-added", cookie=flow.cookie)
                    continue

                # Adding flow to ONU.
                yield self._add_onu_flow(flow)

        except Exception as e:
            self.log.exception('failed-to-update-flow-table', e=e)

        self.flow_config_in_progress = False

    @inlineCallbacks
    def add_to_flow_table(self, flows):
        """
        This function is called for update_flows_incrementally to add
        only delta flows to ONU.
        :param flows: flows to add to ONU.
        """
        yield self._wait_for_previous_update_flow_to_finish()
        self.flow_config_in_progress = True
        self.log.debug('add-to-flow-table', flows=flows)
        try:
            for flow in flows:
                # if incoming flow contains cookie, then add to ONU
                if flow.cookie:
                    # Adds flow to ONU.
                    yield self._add_onu_flow(flow)
        except Exception as e:
            self.log.exception('failed-to-add-to-flow-table', e=e)

        self.flow_config_in_progress = False

    @inlineCallbacks
    def remove_from_flow_table(self, flows):
        """
        This function is called for update_flow_incrementally to delete
        only delta flows from ONU.
        :param flows: flows to delete from ONU
        """
        yield self._wait_for_previous_update_flow_to_finish()
        self.flow_config_in_progress = True
        self.log.debug('remove-from-flow-table', flows=flows)
        try:
            cookies = [flow.cookie for flow in flows]
            for cookie in cookies:
                if cookie in self.flow_map:
                    c_tag = self.flow_map[cookie]["vlan_id"]
                    self.log.debug("remove-from-flow-table",
                                   cookie=cookie, c_tag=c_tag)
                    # Deleting flow from ONU.
                    yield self._delete_onu_flow(self.flow_map[cookie])
                    # Removing flow_map entry for deleted flow.
                    del self.flow_map[cookie]
                else:
                    self.log.error('ignoring-cookie_received', cookie=cookie)
        except Exception as e:
            self.log.exception('failed-to-remove-from-flow-table', e=e)
        self.flow_config_in_progress = False

    def get_tx_id(self):
        self.tx_id += 1
        return self.tx_id

    def send_omci_message(self, frame):
        _frame = hexify(str(frame))
        self.log.debug('send-omci-message-%s' % _frame)
        device = self.adapter_agent.get_device(self.device_id)
        try:
            self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        except Exception as e:
            self.log.warn('send-omci-message-exception', exc=str(e))

    def send_get_circuit_pack(self, entity_id=0):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=CircuitPack.class_id,
                entity_id=entity_id,
                attributes_mask=CircuitPack.mask_for('vendor_id')
            )
        )
        self.send_omci_message(frame)

    def send_mib_reset(self, entity_id=0):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=OntData.class_id,
                entity_id=entity_id
            )
        )
        self.send_omci_message(frame)

    def send_create_gal_ethernet_profile(self,
                                         entity_id,
                                         max_gem_payload_size):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GalEthernetProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    max_gem_payload_size=max_gem_payload_size
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_admin_state(self,
                       entity_id,
                       admin_state):
        data = dict(
            administrative_state=admin_state
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=OntG.class_id,
                entity_id=entity_id,
                attributes_mask=OntG.mask_for(*data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_tcont(self,
                       entity_id,
                       alloc_id):
        data = dict(
            alloc_id=alloc_id
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Tcont.class_id,
                entity_id=entity_id,
                attributes_mask=Tcont.mask_for(*data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_8021p_mapper_service_profile(self,
                                                 entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    tp_pointer=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_0=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_1=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_2=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_3=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_4=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_5=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_6=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_7=OmciNullPointer
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_mac_bridge_service_profile(self,
                                               entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgeServiceProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    spanning_tree_ind=False,
                    learning_ind=True,
                    priority=0x8000,
                    max_age=20 * 256,
                    hello_time=2 * 256,
                    forward_delay=15 * 256,
                    unknown_mac_address_discard=True
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_gem_port_network_ctp(self,
                                         entity_id,
                                         port_id,
                                         tcont_id,
                                         direction,
                                         tm):
        _directions = {"upstream": 1, "downstream": 2, "bi-directional": 3}
        if _directions.has_key(direction):
            _direction = _directions[direction]
        else:
            self.log.error('invalid-gem-port-direction', direction=direction)
            raise ValueError('Invalid GEM port direction: {_dir}'.format(_dir=direction))

        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemPortNetworkCtp.class_id,
                entity_id=entity_id,
                data=dict(
                    port_id=port_id,
                    tcont_pointer=tcont_id,
                    direction=_direction,
                    traffic_management_pointer_upstream=tm
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_multicast_gem_interworking_tp(self,
                                                  entity_id,
                                                  gem_port_net_ctp_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MulticastGemInterworkingTp.class_id,
                entity_id=entity_id,
                data=dict(
                    gem_port_network_ctp_pointer=gem_port_net_ctp_id,
                    interworking_option=0,
                    service_profile_pointer=0x1
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_gem_inteworking_tp(self,
                                       entity_id,
                                       gem_port_net_ctp_id,
                                       service_profile_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemInterworkingTp.class_id,
                entity_id=entity_id,
                data=dict(
                    gem_port_network_ctp_pointer=gem_port_net_ctp_id,
                    interworking_option=5,
                    service_profile_pointer=service_profile_id,
                    interworking_tp_pointer=0x0,
                    gal_profile_pointer=0x1
                )
            )
        )
        self.send_omci_message(frame)

    def send_delete_omci_mesage(self,
                                class_id,
                                entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciDelete.message_id,
            omci_message=OmciDelete(
                entity_class=class_id,
                entity_id=entity_id
            )
        )
        self.send_omci_message(frame)

    def send_set_8021p_mapper_service_profile(self,
                                              entity_id,
                                              interwork_tp_id_0_6=None,
                                              interwork_tp_id_7=None):
        data = dict()
        if interwork_tp_id_0_6 is not None:
            data['interwork_tp_pointer_for_p_bit_priority_0']=interwork_tp_id_0_6
            data['interwork_tp_pointer_for_p_bit_priority_1']=interwork_tp_id_0_6
            data['interwork_tp_pointer_for_p_bit_priority_2']=interwork_tp_id_0_6
            data['interwork_tp_pointer_for_p_bit_priority_3']=interwork_tp_id_0_6
            data['interwork_tp_pointer_for_p_bit_priority_4']=interwork_tp_id_0_6
            data['interwork_tp_pointer_for_p_bit_priority_5']=interwork_tp_id_0_6
            data['interwork_tp_pointer_for_p_bit_priority_6']=interwork_tp_id_0_6
        if interwork_tp_id_7 is not None:
            data['interwork_tp_pointer_for_p_bit_priority_0']=interwork_tp_id_7
            data['interwork_tp_pointer_for_p_bit_priority_1']=interwork_tp_id_7
            data['interwork_tp_pointer_for_p_bit_priority_2']=interwork_tp_id_7
            data['interwork_tp_pointer_for_p_bit_priority_3']=interwork_tp_id_7
            data['interwork_tp_pointer_for_p_bit_priority_4']=interwork_tp_id_7
            data['interwork_tp_pointer_for_p_bit_priority_5']=interwork_tp_id_7
            data['interwork_tp_pointer_for_p_bit_priority_6']=interwork_tp_id_7
            data['interwork_tp_pointer_for_p_bit_priority_7']=interwork_tp_id_7

        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=entity_id,
                attributes_mask=Ieee8021pMapperServiceProfile.mask_for(
                    *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_mac_bridge_port_configuration_data(self,
                                                       entity_id,
                                                       bridge_id,
                                                       port_id,
                                                       tp_type,
                                                       tp_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgePortConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    bridge_id_pointer=bridge_id,
                    port_num=port_id,
                    tp_type=tp_type,
                    tp_pointer=tp_id
                )
            )
        )
        self.send_omci_message(frame)

    def send_create_vlan_tagging_filter_data(self,
                                             entity_id,
                                             vlan_id,
                                             fwd_operation):
        vlan_filter_list = [0] * 12
        vlan_filter_list[0] = vlan_id
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=entity_id,
                data=dict(
                    vlan_filter_list=vlan_filter_list,
                    forward_operation=fwd_operation,
                    number_of_entries=1
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_vlan_tagging_filter_data(self,
                                          entity_id,
                                          vlan_id):
        vlan_filter_list = [0] * 12
        vlan_filter_list[0] = vlan_id
        data = dict(
            vlan_filter_list=vlan_filter_list,
            forward_operation=0x10,
            number_of_entries=1
        )

        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=entity_id,
                attributes_mask=VlanTaggingFilterData.mask_for(
                    *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_delete_vlan_tagging_filter_data(self,
                                          entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciDelete.message_id,
            omci_message=OmciDelete(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=entity_id
            )
        )
        self.send_omci_message(frame)

    def send_create_extended_vlan_tagging_operation_configuration_data(self,
                                                                       entity_id,
                                                                       assoc_type,
                                                                       assoc_me):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    association_type=assoc_type,
                    associated_me_pointer=assoc_me
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_tpid_configuration_data(self,
                                                                         entity_id,
                                                                         input_tpid,
                                                                         output_tpid):
        data = dict(
            input_tpid=input_tpid,
            output_tpid=output_tpid,
            downstream_mode=0,  # inverse of upstream
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(self,
                                                                                  entity_id,
                                                                                  filter_inner_vid,
                                                                                  treatment_inner_vid):
        data = dict(
            received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,
                    filter_outer_vid=4096,
                    filter_outer_tpid_de=0,

                    filter_inner_priority=15,
                    filter_inner_vid=filter_inner_vid,
                    filter_inner_tpid_de=0,
                    filter_ether_type=0,

                    treatment_tags_to_remove=0,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,
                    treatment_outer_tpid_de=0,

                    treatment_inner_priority=0,
                    treatment_inner_vid=treatment_inner_vid,
                    treatment_inner_tpid_de=4
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_delete_extended_vlan_tagging_operation_vlan_configuration_data_untagged(self,
                                                                                     entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciDelete.message_id,
            omci_message=OmciDelete(
                entity_class=ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(self,
                                                                                    entity_id,
                                                                                    filter_inner_priority,
                                                                                    filter_inner_vid,
                                                                                    filter_inner_tpid_de,
                                                                                    treatment_tags_to_remove,
                                                                                    treatment_inner_priority,
                                                                                    treatment_inner_vid):
        data = dict(
            received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,
                    filter_outer_vid=4096,
                    filter_outer_tpid_de=0,

                    filter_inner_priority=filter_inner_priority,
                    filter_inner_vid=filter_inner_vid,
                    filter_inner_tpid_de=filter_inner_tpid_de,
                    filter_ether_type=0,

                    treatment_tags_to_remove=treatment_tags_to_remove,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,
                    treatment_outer_tpid_de=0,

                    treatment_inner_priority=treatment_inner_priority,
                    treatment_inner_vid=treatment_inner_vid,
                    treatment_inner_tpid_de=4
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data_double_tag(self,
                                                                                    entity_id,
                                                                                    filter_outer_vid,
                                                                                    filter_inner_vid,
                                                                                    treatment_tags_to_remove
                                                                                    ):
        # Note: The default values below are meaningful if transparent handling is
        # needed for double vlan tagged packets with matching inner and outer vlans.
        # If any other handling is needed for double vlan tagged packets, the default
        # values may not work and the function needs to be adapted accordingly.
        data = dict(
            received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=14,
                    filter_outer_vid=filter_outer_vid,
                    filter_outer_tpid_de=0,
                    filter_inner_priority=14,
                    filter_inner_vid=filter_inner_vid,
                    filter_inner_tpid_de=0,
                    filter_ether_type=0,
                    treatment_tags_to_remove=treatment_tags_to_remove,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,  # N/A
                    treatment_outer_tpid_de=0,  # N/A
                    treatment_inner_priority=15,
                    treatment_inner_vid=0,  # N/A
                    treatment_inner_tpid_de=0  # N/A
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_delete_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(self,
                                                                                       entity_id):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciDelete.message_id,
            omci_message=OmciDelete(
                entity_class=ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id
            )
        )
        self.send_omci_message(frame)

    def send_create_multicast_operations_profile(self,
                                                 entity_id,
                                                 igmp_ver):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                    MulticastOperationsProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    igmp_version=igmp_ver,
                    igmp_function=0,
                    immediate_leave=0
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_operations_profile_acl_row0(self,
                                                       entity_id,
                                                       acl_table,
                                                       row_key,
                                                       gem_port,
                                                       vlan,
                                                       src_ip,
                                                       dst_ip_start,
                                                       dst_ip_end):
        row0 = AccessControlRow0(
                    set_ctrl=1,
                    row_part_id=0,
                    test=0,
                    row_key=row_key,
                    gem_port_id=gem_port,
                    vlan_id=vlan,
                    src_ip=src_ip,
                    dst_ip_start=dst_ip_start,
                    dst_ip_end=dst_ip_end,
                    ipm_group_bw=0
                )

        if acl_table == 'dynamic':
            data = dict(
                dynamic_access_control_list_table=row0
            )
        else:
            data = dict(
                static_access_control_list_table=row0
            )

        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastOperationsProfile.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastOperationsProfile.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_operations_profile_ds_igmp_mcast_tci(self,
                                                                entity_id,
                                                                ctrl_type,
                                                                tci):
        data = dict(
            ds_igmp_mcast_tci=
                DownstreamIgmpMulticastTci(
                    ctrl_type=ctrl_type,
                    tci=tci
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastOperationsProfile.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastOperationsProfile.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_create_multicast_subscriber_config_info(self,
                                                     entity_id,
                                                     me_type,
                                                     mcast_oper_profile):
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                data=dict(
                    me_type=me_type,
                    mcast_operations_profile_pointer=mcast_oper_profile
                )
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_subscriber_config_info(self,
                                                  entity_id,
                                                  max_groups=0,
                                                  max_mcast_bw=0,
                                                  bw_enforcement=0):
        data = dict(
            max_simultaneous_groups=max_groups,
            max_multicast_bandwidth=max_mcast_bw,
            bandwidth_enforcement=bw_enforcement
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_service_package(self,
                                           entity_id,
                                           row_key,
                                           vid_uni,
                                           max_groups,
                                           max_mcast_bw,
                                           mcast_oper_profile):
        data = dict(
            multicast_service_package_table=
                MulticastServicePackage(
                    set_ctrl=1,
                    row_key=row_key,

                    vid_uni=vid_uni,
                    max_simultaneous_groups=max_groups,
                    max_multicast_bw=max_mcast_bw,
                    mcast_operations_profile_pointer=mcast_oper_profile
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_allowed_preview_groups_row0(self,
                                                       entity_id,
                                                       row_key,
                                                       src_ip,
                                                       vlan_id_ani,
                                                       vlan_id_uni):
        data = dict(
            allowed_preview_groups_table=
                AllowedPreviewGroupsRow0(
                    set_ctrl=1,
                    row_part_id=0,
                    row_key=row_key,

                    src_ip=src_ip,
                    vlan_id_ani=vlan_id_ani,
                    vlan_id_uni=vlan_id_uni
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_set_multicast_allowed_preview_groups_row1(self,
                                                       entity_id,
                                                       row_key,
                                                       dst_ip,
                                                       duration,
                                                       time_left):
        data = dict(
            allowed_preview_groups_table=
                AllowedPreviewGroupsRow1(
                    set_ctrl=1,
                    row_part_id=1,
                    row_key=row_key,

                    dst_ip=dst_ip,
                    duration=duration,
                    time_left=time_left
                )
        )
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=MulticastSubscriberConfigInfo.class_id,
                entity_id=entity_id,
                attributes_mask=MulticastSubscriberConfigInfo.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.send_omci_message(frame)

    def send_reboot(self):
        self.log.info('send omci reboot message')
        frame = OmciFrame(
            transaction_id=self.get_tx_id(),
            message_type=OmciReboot.message_id,
            omci_message=OmciReboot(
                entity_class=OntG.class_id,
                entity_id=0
            )
        )
        self.send_omci_message(frame)

    @inlineCallbacks
    def wait_for_response(self):
        self.log.debug('wait-for-response')
        try:
            response = yield self.incoming_messages.get()
            self.log.debug('got-response')
            resp = OmciFrame(response)
            resp.show()
            returnValue(resp)
        except Exception as e:
            returnValue(None)
            self.log.info('wait-for-response-exception', exc=str(e))

    @inlineCallbacks
    def message_exchange(self):
        # reset incoming message queue
        while self.incoming_messages.pending:
            _ = yield self.incoming_messages.get()

        mcvid = MANAGEMENT_VLAN
        cvid = BRDCM_DEFAULT_VLAN

        # construct message
        # MIB Reset - OntData - 0
        self.send_mib_reset()
        yield self.wait_for_response()

        # Create AR - GalEthernetProfile - 1
        self.send_create_gal_ethernet_profile(1, 48)
        yield self.wait_for_response()

        # MAC Bridge Service config
        # Create AR - MacBridgeServiceProfile - 513
        self.send_create_mac_bridge_service_profile(0x201)
        yield self.wait_for_response()

        # Mapper Service config
        # Create AR - 802.1pMapperServiceProfile - 32769
        self.send_create_8021p_mapper_service_profile(0x8001)
        yield self.wait_for_response()

        # MAC Bridge Port config
        # Create AR - MacBridgePortConfigData - 8450 - 513 - 3 - 3 - 32769
        self.send_create_mac_bridge_port_configuration_data(0x2102, 0x201, 3, 3, 0x8001)
        yield self.wait_for_response()

        # VLAN Tagging Filter config
        # Create AR - VlanTaggingFilterData - 8450 - c-vid
        # As per G.988 - Table 9.3.11-1 - Forward operation attribute values
        self.send_create_vlan_tagging_filter_data(0x2102, cvid, 0x10)
        yield self.wait_for_response()


        for port_id in self.uni_ports:
            # Extended VLAN Tagging Operation config
            # Create AR - ExtendedVlanTaggingOperationConfigData - 514 - 2 - 0x102(Uni-Port-Num)
            self.send_create_extended_vlan_tagging_operation_configuration_data(0x200 + port_id, 2, 0x100 + port_id)
            yield self.wait_for_response()

            # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - 8100 - 8100
            self.send_set_extended_vlan_tagging_operation_tpid_configuration_data(0x200 + port_id, 0x8100, 0x8100)
            yield self.wait_for_response()



            # Create AR - MacBridgePortConfigData - Entity_id -
            #                                       bridge ID -
            #                                       port num -
            #                                       tp_type -
            #                                       IEEE MApper poniter
            self.send_create_mac_bridge_port_configuration_data(0x200 + port_id, 0x201, port_id, 1, 0x100 + port_id)
            yield self.wait_for_response()

            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
            # To be removed once DPU supports sending vlan4090p3 instead of vlan4090p0
            self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x200 + port_id, 0, mcvid, 0, 1, 7, mcvid)
            yield self.wait_for_response()


            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
            self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x200 + port_id, 3, mcvid, 0, 1, 7, mcvid)
            yield self.wait_for_response()

            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to untagged pkts - c-vid
            self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(0x200 + port_id, 0x1000, cvid)
            yield self.wait_for_response()

        # Multicast related MEs
        # Set AR - MulticastOperationsProfile - Dynamic Access Control List table
        # Create AR - MacBridgePortConfigData - 9000 - 513 - 6 - 6 - 6
        self.send_create_mac_bridge_port_configuration_data(0x2328, 0x201, 6, 6, 6)
        yield self.wait_for_response()

        # Multicast Operation Profile config
        # Create AR - MulticastOperationsProfile
        self.send_create_multicast_operations_profile(0x201, 3)
        yield self.wait_for_response()

        # Multicast Subscriber config
        # Create AR - MulticastSubscriberConfigInfo
        self.send_create_multicast_subscriber_config_info(0x201, 0, 0x201)
        yield self.wait_for_response()

        # Create AR - GemPortNetworkCtp - 260 - 4000 - 0 Multicast
        self.send_create_gem_port_network_ctp(0x104, 0x0FA0, 0, "downstream", 0)
        yield self.wait_for_response()

        # Multicast GEM Interworking config Multicast
        # Create AR - MulticastGemInterworkingTp - 6 - 260
        self.send_create_multicast_gem_interworking_tp(0x6, 0x104)
        yield self.wait_for_response()

        self.send_set_multicast_operations_profile_acl_row0(0x201,
                                                            'dynamic',
                                                            0,
                                                            0x0fa0,
                                                            0x0fa0,
                                                            '0.0.0.0',
                                                            '224.0.0.0',
                                                            '239.255.255.255')
        yield self.wait_for_response()

        # Multicast Operation Profile config
        # Set AR - MulticastOperationsProfile - Downstream IGMP Multicast TCI
        self.send_set_multicast_operations_profile_ds_igmp_mcast_tci(0x201, 4, cvid)
        yield self.wait_for_response()

    def add_uni_port(self, device, parent_logical_device_id,
                     name, parent_port_num=None):
        self.log.info('adding-logical-port', device_id=device.id,
                      logical_device_id=parent_logical_device_id,
                      name=name)
        if parent_port_num is not None:
            uni = parent_port_num
            port_no = parent_port_num
        else:
            uni = self.uni_ports[0]
            port_no = device.proxy_address.channel_id + uni
            # register physical ports
        uni_port = Port(
            port_no=uni,
            label='uni-'+str(uni),
            type=Port.ETHERNET_UNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.adapter_agent.add_port(device.id, uni_port)
        # add uni port to logical device
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(parent_logical_device_id,
            LogicalPort(
                id='uni-{}'.format(port_no),
                ofp_port=ofp_port(
                    port_no=port_no,
                    hw_addr=mac_str_to_tuple('00:00:00:%02x:%02x:%02x' %
                                             (device.proxy_address.onu_id & 0xff,
                                              (port_no >> 8) & 0xff,
                                              port_no & 0xff)),
                    #name='uni-{}'.format(port_no),
                    name=name,
                    config=0,
                    state=OFPPS_LIVE,
                    curr=cap,
                    advertised=cap,
                    peer=cap,
                    curr_speed=OFPPF_1GB_FD,
                    max_speed=OFPPF_1GB_FD
                ),
                device_id=device.id,
                device_port_no=uni_port.port_no
            ))

    def del_uni_port(self, device, parent_logical_device_id,
                     name, parent_port_num=None):
        self.log.debug('del-uni-port', device_id=device.id,
                      logical_device_id=parent_logical_device_id,
                      name=name)
        if parent_port_num is not None:
            uni = parent_port_num
            port_no = parent_port_num
        else:
            uni = self.uni_ports[0]
            port_no = device.proxy_address.channel_id + uni
            # register physical ports
        ports = self.adapter_agent.get_ports(self.device_id, Port.ETHERNET_UNI)
        for port in ports:
            if port.label == 'uni-'+str(uni):
                break
        self.adapter_agent.delete_port(self.device_id, port)
        self.adapter_agent.delete_logical_port_by_id(parent_logical_device_id,
                                                     'uni-{}'.format(port_no))

    def delete_v_ont_ani(self, data):
        self.log.info('deleting-v_ont_ani')

        device = self.adapter_agent.get_device(self.device_id)
        self.proxy_address = device.proxy_address
        self.adapter_agent.unregister_for_proxied_messages(device.proxy_address)

        ports = self.adapter_agent.get_ports(self.device_id, Port.PON_ONU)
        if ports is not None:
            for port in ports:
                if port.label == 'PON port':
                    self.adapter_agent.delete_port(self.device_id, port)
                    break

        # construct message
        # MIB Reset - OntData - 0
        if device.connect_status != ConnectStatus.REACHABLE:
            self.log.error('device-unreachable')
            return

        self.send_mib_reset()

        # It is observed that the device is already deleted before the response
        # is received. So, there is no point waiting for response.
        # Also, currently there is no response validation or timeout.
        # Until we move to the OpenOMCI framework, it is ok to ignore this
        # response for now.

        # yield self.wait_for_response()

    def create_interface(self, data):
        if isinstance(data, VEnetConfig):
            parent_port_num = None
            onu_device = self.adapter_agent.get_device(self.device_id)
            ports = self.adapter_agent.get_ports(onu_device.parent_id, Port.ETHERNET_UNI)
            parent_port_num = None
            for port in ports:
                if port.label == data.interface.name:
                    parent_port_num = port.port_no
                    break

            parent_device = self.adapter_agent.get_device(onu_device.parent_id)
            logical_device_id = parent_device.parent_id
            assert logical_device_id
            self.add_uni_port(onu_device, logical_device_id,
                              data.name, parent_port_num)

            if parent_port_num is None:
                self.log.error("matching-parent-uni-port-num-not-found")
                return

            onu_ports = self.adapter_agent.get_ports(self.device_id, Port.PON_ONU)
            if onu_ports:
                # To-Do :
                # Assumed only one PON port and UNI port per ONU.
                pon_port = onu_ports[0]
            else:
                self.log.error("No-Pon-port-configured-yet")
                return

            self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                                 pon_port)

            pon_port.peers[0].device_id = onu_device.parent_id
            pon_port.peers[0].port_no = parent_port_num
            pon_port.admin_state = AdminState.ENABLED
            pon_port.oper_status = OperStatus.ACTIVE
            self.adapter_agent.add_port_reference_to_parent(self.device_id,
                                                            pon_port)
        else:
            self.log.info('Not-handled-Yet')
        return

    def update_interface(self, data):
        self.log.info('Not-Implemented-yet')
        return

    def remove_interface(self, data):
        if isinstance(data, VEnetConfig):
            parent_port_num = None
            onu_device = self.adapter_agent.get_device(self.device_id)
            ports = self.adapter_agent.get_ports(onu_device.parent_id, Port.ETHERNET_UNI)
            parent_port_num = None
            for port in ports:
                if port.label == data.interface.name:
                    parent_port_num = port.port_no
                    break

            parent_device = self.adapter_agent.get_device(onu_device.parent_id)
            logical_device_id = parent_device.parent_id
            assert logical_device_id
            self.del_uni_port(onu_device, logical_device_id,
                              data.name, parent_port_num)
        if isinstance(data, VOntaniConfig):
            self.delete_v_ont_ani(data)
        else:
            self.log.info('not-handled-yet')
        return

    @inlineCallbacks
    def create_gemport(self, data):
        self.log.debug('create-gemport')
        gem_port = GemportsConfigData()
        gem_port.CopyFrom(data)
        if gem_port.tcont_ref is None:
            self.log.error('recevied-null-gem-port-data')
        else:
            #To-Do Need to see how the valuse 0x8001 is derived
            self.send_create_gem_port_network_ctp(gem_port.gemport_id,
                                                  gem_port.gemport_id, 0x8001,
                                                  "bi-directional", 0x100)
            yield self.wait_for_response()

            # GEM Interworking config
            # Create AR - GemInterworkingTp - Gem_port,TP_pointer -
            #                                 Gem port CTP pointer -
            #                                 Mapper service profile id
            self.send_create_gem_inteworking_tp(gem_port.gemport_id,
                                                gem_port.gemport_id, 0x8001)
            yield self.wait_for_response()

            # Mapper Service Profile config
            # Set AR - 802.1pMapperServiceProfile - Mapper_ profile_id -
            #                                       gem_port_tp pointer

            if gem_port.traffic_class == 2:
                self.send_set_8021p_mapper_service_profile(0x8001,
                                                           interwork_tp_id_7=gem_port.gemport_id)
            else:
                self.send_set_8021p_mapper_service_profile(0x8001,
                                                           interwork_tp_id_0_6=gem_port.gemport_id)
               
            yield self.wait_for_response()


    @inlineCallbacks
    def remove_gemport(self, data):
        self.log.debug('remove-gemport')
        gem_port = GemportsConfigData()
        gem_port.CopyFrom(data)
        device = self.adapter_agent.get_device(self.device_id)
        if device.connect_status != ConnectStatus.REACHABLE:
            self.log.error('device-unreachable')
            return

        self.send_set_8021p_mapper_service_profile(0x8001,
                                                   interwork_tp_id_0_6=0xFFFF,
                                                   interwork_tp_id_7=0xFFFF)
        yield self.wait_for_response()

        self.send_delete_omci_mesage(GemInterworkingTp.class_id,
                                    gem_port.gemport_id)
        yield self.wait_for_response()

        #To-Do Need to see how the valuse 0x8001 is derived
        self.send_delete_omci_mesage(GemPortNetworkCtp.class_id,
                                gem_port.gemport_id)
        yield self.wait_for_response()

    @inlineCallbacks
    def create_tcont(self, tcont_data, traffic_descriptor_data):
        self.log.debug('create-tcont')
        tcont = TcontsConfigData()
        tcont.CopyFrom(tcont_data)
        if tcont.interface_reference is not None:
            self.log.debug('tcont', tcont=tcont.alloc_id)
            self.send_set_tcont(0x8001, tcont.alloc_id)
            yield self.wait_for_response()
        else:
            self.log.info('recevied-null-tcont-data', tcont=tcont.alloc_id)

    @inlineCallbacks
    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        self.log.debug('remove-tcont')
        device = self.adapter_agent.get_device(self.device_id)
        if device.connect_status != ConnectStatus.REACHABLE:
            self.log.error('device-unreachable')
            return

        self.send_set_tcont(0x8001, 0xFFFF)
        yield self.wait_for_response()

    def create_multicast_gemport(self, data):
        self.log.info('Send relevant OMCI message - Not implemented yet')

    @inlineCallbacks
    def disable(self, device):
        try:
            self.log.info('sending-admin-state-lock-towards-device', device=device)
            self.send_set_admin_state(0x0000, ADMIN_STATE_LOCK)
            yield self.wait_for_response()
            # Disable all ports on that device
            self.disable_ports(device)
            device.oper_status = OperStatus.UNKNOWN
            device.connect_status = ConnectStatus.UNREACHABLE
            self.adapter_agent.update_device(device)
        except Exception as e:
            log.exception('exception-in-onu-disable', exception=e)

    @inlineCallbacks
    def reenable(self, device):
        try:
            self.log.info('sending-admin-state-unlock-towards-device', device=device)
            self.send_set_admin_state(0x0000, ADMIN_STATE_UNLOCK)
            yield self.wait_for_response()
            self.enable_ports(device)
            device.oper_status = OperStatus.ACTIVE
            device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(device)
        except Exception as e:
            log.exception('exception-in-onu-reenable', exception=e)

    @inlineCallbacks
    def reboot(self):
        self.log.info('reboot-device')
        device = self.adapter_agent.get_device(self.device_id)
        if device.connect_status != ConnectStatus.REACHABLE:
            self.log.error("device-unreacable")
            return

        try:
            self.send_reboot()
            response = yield self.wait_for_response()
            if response is not None:
                omci_response = response.getfieldval("omci_message")
                success_code = omci_response.getfieldval("success_code")
                if success_code == 0:
                    self.log.debug("reboot-command-processed-successfully")
                    # Update the device connection and operation status
                    device = self.adapter_agent.get_device(self.device_id)
                    device.connect_status = ConnectStatus.UNREACHABLE
                    device.oper_status = OperStatus.DISCOVERED
                    self.adapter_agent.update_device(device)
                    self.disable_ports(device)
                    self.flow_map.clear()
                else:
                    self.log.error("reboot-failed", success_code=success_code)
            else:
                self.log.error("error-in-processing-reboot-response")
        except Exception as e:
            self.log.error('wait-for-response-exception', exc=str(e))

    def disable_ports(self, device):
        self.log.info('disable-ports', device_id=self.device_id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        parent_device = self.adapter_agent.get_device(device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        ports = self.adapter_agent.get_ports(device.id, Port.ETHERNET_UNI)
        for port in ports:
            port_id = 'uni-{}'.format(port.port_no)
            try:
                lgcl_port = self.adapter_agent.get_logical_port(logical_device_id, port_id)
                lgcl_port.ofp_port.state = OFPPS_LINK_DOWN
                self.adapter_agent.update_logical_port(logical_device_id, lgcl_port)
            except KeyError:
                self.log.info('logical-port-not-found', device_id=self.device_id,
                              portid=port_id)

    def enable_ports(self, device):
        self.log.info('enable-ports', device_id=self.device_id)

        # Enable all ports on that device
        self.adapter_agent.enable_all_ports(self.device_id)

        parent_device = self.adapter_agent.get_device(device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        ports = self.adapter_agent.get_ports(device.id, Port.ETHERNET_UNI)
        for port in ports:
            port_id = 'uni-{}'.format(port.port_no)
            try:
                lgcl_port = self.adapter_agent.get_logical_port(logical_device_id, port_id)
                lgcl_port.ofp_port.state = OFPPS_LIVE
                self.adapter_agent.update_logical_port(logical_device_id, lgcl_port)
            except KeyError:
                self.log.info('logical-port-not-found', device_id=self.device_id,
                              portid=port_id)

    @inlineCallbacks
    def _add_onu_flow(self, flow):
        _type = None
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
        _set_vlan_vid = None
        self.log.info('add-flow', flow=flow)

        def is_downstream(port):
            return port == 100  # Need a better way

        def is_upstream(port):
            return not is_downstream(port)

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
                    _proto = field.ip_proto
                    self.log.info('field-type-ip-proto',
                                  ip_proto=_proto)

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
                    _metadata = field.table_metadata
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
                    self.log.info('action-type-push-vlan',
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
                        _set_vlan_vid = _field.vlan_vid & 0xfff
                        self.log.info('set-field-type-vlan-vid',vlan=_set_vlan_vid)
                    else:
                        self.log.error('unsupported-action-set-field-type',
                                       field_type=_field.type)
                else:
                    self.log.error('unsupported-action-type',
                                   action_type=action.type, in_port=_in_port)

            #
            # All flows created from ONU adapter should be OMCI based
            #
            if _vlan_vid == 0 and _set_vlan_vid != None and _set_vlan_vid != 0:
                # allow priority tagged packets
                # Set AR - ExtendedVlanTaggingOperationConfigData
                #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid


                if _set_vlan_vid != RESERVED_VLAN_ID:
                    # As per G.988 - Table 9.3.11-1 - Forward operation attribute values
                    # Forward action of 0x10 allows VID Investigation
                    if _type != FLOW_TYPE_EAPOL:
                        self.log.info("Triggering-extended-vlan-configurations",vlan=_set_vlan_vid,eth_type=_type)
                        self.send_set_vlan_tagging_filter_data(0x2102, _set_vlan_vid)
                        #self.send_create_vlan_tagging_filter_data(0x2102, _set_vlan_vid, 0x10)
                        yield self.wait_for_response()

                        for port_id in self.uni_ports:

                            self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(0x200 + port_id, 0x1000, _set_vlan_vid)
                            yield self.wait_for_response()

                            self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x200 + port_id, 8, 0, 0, 1, 8, _set_vlan_vid)
                            yield self.wait_for_response()
                    else:
                        self.log.info("Use-vlan-4091-for-eapol",eth_type=_type)

                else:
                    # As per G.988 - Table 9.3.11-1 - Forward operation attribute values
                    # Forward action of 0x00 does not perform VID Investigation for transparent vlan case
                    self.send_delete_vlan_tagging_filter_data(0x2102)
                    yield self.wait_for_response()

                    self.send_create_vlan_tagging_filter_data(0x2102, _set_vlan_vid, 0x00)
                    yield self.wait_for_response()

                    for port_id in self.uni_ports:
                        self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x200 + port_id, 14, 4096, 0, 0, 15, 0)
                        yield self.wait_for_response()
                        #self.send_set_extended_vlan_tagging_operation_vlan_configuration_data_double_tag( \
                        #    0x200 + port_id, 4096, 4096, 0)
                        #yield self.wait_for_response()

                # Create the entry in the internal flow table
                self.flow_map[flow.cookie] = {"vlan_id": _set_vlan_vid,
                                              "eth_type":_type,
                                              "vlan_tagging_filter_data_entity_id": 0x2102,
                                              "extended_vlan_tagging_filter_data": [0x200 + port_id for port_id in self.uni_ports]}
        except Exception as e:
            self.log.exception('failed-to-install-flow', e=e, flow=flow)

    @inlineCallbacks
    def _delete_onu_flow(self, flow_map_value):
        # Deletes ONU flows.
        try:
            if flow_map_value["vlan_id"] != RESERVED_VLAN_ID:
                for extended_vlan_tagging_filter_data in flow_map_value["extended_vlan_tagging_filter_data"]:
                    if flow_map_value["eth_type"] != FLOW_TYPE_EAPOL:
                        self.send_delete_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(
                            extended_vlan_tagging_filter_data)
                        yield self.wait_for_response()

                        self.send_delete_extended_vlan_tagging_operation_vlan_configuration_data_untagged(
                            extended_vlan_tagging_filter_data)
                        yield self.wait_for_response()

            else:
                for extended_vlan_tagging_filter_data in flow_map_value["extended_vlan_tagging_filter_data"]:
                    self.send_delete_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(
                        extended_vlan_tagging_filter_data)
                    yield self.wait_for_response()

            for port_id in self.uni_ports:
                # Extended VLAN Tagging Operation config
                # Create AR - ExtendedVlanTaggingOperationConfigData - 514 - 2 - 0x102(Uni-Port-Num)
                self.send_create_extended_vlan_tagging_operation_configuration_data(0x200 + port_id, 2, 0x100 + port_id)
                yield self.wait_for_response()

                # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - 8100 - 8100
                self.send_set_extended_vlan_tagging_operation_tpid_configuration_data(0x200 + port_id, 0x8100, 0x8100)
                yield self.wait_for_response()

        except Exception as e:
            self.log.exception('failed-to-delete-flow', e=e, flow_map_value=flow_map_value)

    @inlineCallbacks
    def _wait_for_previous_update_flow_to_finish(self):
        while self.flow_config_in_progress:
            # non-blocking wait for 200ms
            yield asleep(0.2)
        return
