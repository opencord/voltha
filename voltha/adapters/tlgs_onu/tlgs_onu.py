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
PMC Sierra ONU adapter
"""

import structlog
from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue
from zope.interface import implementer
import voltha.core.flow_decomposer as fd

from voltha.adapters.interface import IAdapterInterface

from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_entities import Ieee8021pMapperServiceProfile

from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel, ConnectStatus, AdminState, OperStatus
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_10GB_FD, OFPPF_FIBER, ofp_port, OFPPS_LIVE, OFPXMC_OPENFLOW_BASIC

from voltha.extensions.omci.omci_messages import OmciGet, OmciGetResponse, OmciCreate, OmciMibResetResponse, OmciSet, \
    OmciSetResponse, OmciCreateResponse, OmciMibReset, OmciDelete, OmciDeleteResponse

from voltha.adapters.microsemi_olt.PAS5211_comm import PAS5211Communication
from voltha.registry import registry
from voltha.extensions.omci.omci_entities import VlanTaggingOperation
from voltha.protos.openflow_13_pb2 import Flows, FlowGroups

from common.frameio.frameio import hexify

from tlgs_constants import OMCI_GEM_IWTP_IW_OPT_8021P_MAPPER, PON_FALSE, \
    GEM_DIR_BIDIRECT, OMCI_MAC_BRIDGE_PCD_LANFCS_FORWARDED, \
    OMCI_MAC_BRIDGE_PCD_ENCAP_METHOD_LLC, OMCI_8021P_MSP_UNMARKED_FRAME_TAG_FRAME, OMCI_8021P_MSP_TP_TYPE_NULL, \
    OMCI_EX_VLAN_TAG_OCD_ASSOCIATION_TYPE_PPTP_ETH_UNI, OMCI_EX_VLAN_TAG_OCD_DS_MODE_US_INVERSE, PMC_UPSTREAM_PORT, \
    SLA_gr_bw_gros, SLA_be_bw_gros, SLA_gr_bw_fine, SLA_be_bw_fine, PORT_NUMBER

import Queue
from struct import pack, unpack

_ = third_party
log = structlog.get_logger()

OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_NO_TAG = 15
OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE = 4096
OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE = 0
OMCI_EX_VLAN_TAG_OCD_FILTER_ETYPE_NONE = 0
OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_DEFAULT = 14
OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_8100 = 4
OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE = 15
OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_OUTER = 1
OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_COPY_FROM_INNER = 4096
OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_INNER = 0
OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_EQ_8100 = 4

def sequence_generator(init):
    num = init
    while True:
        yield num
        num += 1


@implementer(IAdapterInterface)
class TlgsOnuAdapter(object):

    name = 'tlgs_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]


    def __init__(self, adapter_agent, config):
        self.omci_proxy = None
        self.api_proxy = None
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='TLGS',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )

        # self.incoming_messages = DeferredQueue()
        #self.trangen = sequence_generator(1)

        # As of broadcom_onu.py
        # [channel_id] and [onu_id] -> BrcmOnuHandler()
        self.device_handlers = dict()
        # register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

        self.interface = registry('main').get_args().interface

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

    def adopt_device(self, device):
        log.debug('adopt-device', device=device)
        # reactor.callLater(0.1, self._onu_device_activation, device)
        # return device
        # two level array channel

        if device.proxy_address.channel_id not in self.device_handlers:
            self.device_handlers[device.proxy_address.channel_id] = dict()

        self.device_handlers[device.proxy_address.channel_id] = TlgsOnuHandler(self, device.id)

        reactor.callLater(1, self.device_handlers[device.proxy_address.channel_id].activate, device)

        return device

    def reconcile_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        log.debug('disable-device', device=device.id)
        reactor.callLater(0, self.device_handlers[device.proxy_address.channel_id].deactivate, device)

    def reenable_device(self, device):
        raise NotImplementedError()

    def reboot_device(self, device):
        raise NotImplementedError()

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
        log.debug('self-test-device', device=device.id)
        raise NotImplementedError()

    def delete_device(self, device):
        log.debug('delete-device', device_id=device.id)
        raise NotImplementedError()

    def get_device_details(self, device):
        raise NotImplementedError()

    def deactivate(self, device):
        try:
            handler = self.device_handlers[
                device.proxy_address.channel_id]
            return handler.deactivate(device)
        except Exception as e:
            log.exception('failed-to-deactivate-onu', e=e)
            raise e

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.debug('onu-bulk-flow-update', device_id=device.id,
            flows=flows, groups=groups)
        log.debug(str(self.device_handlers.keys))
        try:
            assert len(groups.items) == 0
            handler = self.device_handlers[
                device.proxy_address.channel_id]
            handler.update_flow_table(device, flows.items)
        except Exception as e:
            log.exception('failed-to-update-flow-table', e=e)
            raise e

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.debug("send-proxied-message in TLGS ONU")

    def receive_proxied_message(self, proxy_address, msg):
        log.debug('receive-proxied-message', msg=hexify(msg))

        handler = self.device_handlers[
            proxy_address.channel_id]

        omci = OmciFrame(msg)
        if omci is not None:
            if omci.message_type in (16, 17):
                return

        handler.receive_message(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.debug('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def create_interface(self, device, data):
        raise NotImplementedError()

    def update_interface(self, device, data):
        raise NotImplementedError()

    def remove_interface(self, device, data):
        raise NotImplementedError()

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

    # Not used, delegated to handler
    def update_flow_table(self, device, flows):
        log.debug('update-flow-table', device_id=device.id, flows=flows)

class TlgsOnuHandler(object):

    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue()
        self.event_messages = Queue.Queue()
        self.proxy_address = None
        self.tx_id = 0
        self.trangen = sequence_generator(1)
        self.port_id = None
        self.alloc_id = None
        self.cvlan_id = None
        self.subsvlan_id = 0
        self.bandwidth = None
        self.flows_lock = 0
        self.flows = None
        self.policy_id = None
        self.flow_queue = DeferredQueue()

    def receive_message(self, msg):
        log.debug("receive-message")
        self.incoming_messages.put(msg)

    @inlineCallbacks
    def activate(self, device):
        log.debug('activate-onu-handler', device=device)
        try:
            # register for proxied messages right away
            self.proxy_address = device.proxy_address
            self.adapter_agent.register_for_proxied_messages(device.proxy_address)

            response = yield self.create_common_omci_config(device)

            if response:
                # First we verify that we got parent reference and proxy info
                assert device.parent_id
                assert device.proxy_address.device_id
                # == 0 # We want to activate multiple ONT's
                assert device.proxy_address.channel_id is not None
                # to get onu_id = device.proxy_address.onu_id

                # From PMC code:
                self.port_id = 1000 + 16 * device.proxy_address.onu_id
                self.alloc_id = self.port_id

                device.model = 'GPON ONU'
                device.hardware_version = 'tbd'
                device.firmware_version = 'tbd'

                device.connect_status = ConnectStatus.REACHABLE

                uni_port = Port(port_no=1,
                                label="{} ONU".format('TLGS'),
                                type=Port.ETHERNET_UNI,
                                admin_state=AdminState.ENABLED,
                                oper_status=OperStatus.ACTIVE
                                )

                self.adapter_agent.add_port(device.id, uni_port)

                log.debug('add-onu-port')

                pon_port = Port(
                                port_no=2,
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
                            )

                self.adapter_agent.add_port(device.id, pon_port)

                log.debug('add-onu-port')

                # obtain logical device id
                parent_device = self.adapter_agent.get_device(device.parent_id)
                logical_device_id = parent_device.parent_id
                assert logical_device_id
                port_no = device.proxy_address.channel_id
                cap = OFPPF_10GB_FD | OFPPF_FIBER

                self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
                    id=str(port_no),
                    ofp_port=ofp_port(
                        port_no=port_no,
                        hw_addr=mac_str_to_tuple(device.mac_address),
                        name='uni-{}'.format(port_no),
                        config=0,
                        state=OFPPS_LIVE,
                        curr=cap,
                        advertised=cap,
                        peer=cap,
                        curr_speed=OFPPF_10GB_FD,
                        max_speed=OFPPF_10GB_FD
                    ),
                    device_id=device.id,
                    device_port_no=uni_port.port_no
                ))

                log.debug('add-onu-logical-port')

                # Input logical port from ONT
                self.port_no = port_no

                # Finally update to "ACTIVE"
                device = self.adapter_agent.get_device(device.id)
                # In broadcom_onu.py this state is DISCOVERED
                device.oper_status = OperStatus.ACTIVE
                self.adapter_agent.update_device(device)

                log.info('Device activated', device=device)

                reactor.callLater(0, self.wait_for_flow_events, device)

            else:
                raise Exception('Exception during onu activation')

        except Exception as e:
            log.exception('activate-failed', e=e)
            raise Exception('Exception during onu activation')

    @inlineCallbacks
    def wait_for_flow_events(self, device):

        log.debug('wait-for-flow-events')
        event = yield self.flow_queue.get()
        log.debug("unqueued-flow-event")

        try:
            if event['action'] == 'install':
                response = yield self.install_flows_sequence(device, event['cvlan'], event['subsvlan'])
            elif event['action'] == 'reinstall':
                response = yield self.reinstall_flows_sequence(device, event['cvlan'], event['subsvlan'])
            elif event['action'] == 'remove':
                response = yield self.uninstall_flows_sequence(device)

            if response:
                log.debug("Event handled flow successfully")
            else:
                log.debug("Error handling flow event")

        except Exception as e:
            log.exception('wait-for-flow-events-exception', e=e)

        reactor.callLater(0, self.wait_for_flow_events, device)

    def deactivate(self, device):
        log.debug('deactivate', device=device)
        # Check parent reference and proxy info exists
        assert device.parent_id
        assert device.proxy_address.device_id

        # unregister from proxy messages
        self.adapter_agent.unregister_for_proxied_messages(device.proxy_address)
        self.proxy_address = None

        # Delete references to ports
        onu_port = self.adapter_agent.get_ports(device.id, Port.ETHERNET_UNI)[0]
        self.adapter_agent.delete_port_reference_from_parent(device.id, onu_port)

        pon_port = self.adapter_agent.get_ports(device.id, Port.PON_ONU)[0]
        self.adapter_agent.delete_port_reference_from_parent(device.id, pon_port)

        # Delete device and logical ports
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        # logical_device = self.adapter_agent.get_logical_device(logical_device_id)
        # self.adapter_agent.delete_logical_device(logical_device)

        logical_port = self.adapter_agent.get_logical_port(logical_device_id, self.port_no)
        self.adapter_agent.delete_logical_port(logical_device_id, logical_port)

        device = self.adapter_agent.get_device(device.id)
        self.adapter_agent.update_child_device_state(device, connect_status=ConnectStatus.UNREACHABLE)

        device = self.adapter_agent.get_device(device.id)
        self.adapter_agent.update_child_device_state(device, oper_status=OperStatus.FAILED)
        # device.connect_status = ConnectStatus.UNREACHABLE
        # self.adapter_agent.update_device(device)

        # Finally delete device
        self.adapter_agent.delete_child_device(
            parent_device_id=device.proxy_address.device_id,
            child_device_id=device.id)

        log.debug('deactivate ended')

    # @inlineCallbacks
    def update_flow_table(self, device, flows):
        cvlan_found = None
        subsvlan_found = 0

        log.debug('onu-update-flow-table', device_id=device.id, flows=flows)
        port_no = device.proxy_address.channel_id
        log.debug('Checking {} flows for port:{}'.format(len(flows), port_no))

        try:

            for flow in flows:
                # Look for inner VLAN:
                for field in fd.get_ofb_fields(flow):

                    if field.type == fd.IN_PORT and field.port == 1:
                        if flow.table_id == 0:
                            if flow.priority == 1000:
                                for action in fd.get_actions(flow):
                                    if action.type == fd.SET_FIELD:
                                        cvlan_found = action.set_field.field.ofb_field.vlan_vid & 0xfff
                                        log.debug('CVLAN found:{}'.format(cvlan_found))


            if cvlan_found:
                if cvlan_found != self.cvlan_id:
                    if self.cvlan_id:

                        log.debug('Reinstall flow triggered')
                        flow_event = {'action': 'reinstall', 'cvlan': cvlan_found,
                                'subsvlan': subsvlan_found}
                        self.flow_queue.put(flow_event)
                    else:
                        log.debug('Flows installation triggered')
                        flow_event = {'action': 'install', 'cvlan': cvlan_found,
                                'subsvlan': subsvlan_found}
                        self.flow_queue.put(flow_event)
                else:
                    log.debug('Flows already installed')
            else:
                if self.cvlan_id:
                    log.debug('Flows deinstallation triggered')
                    flow_event = {'action': 'remove', 'cvlan': self.cvlan_id,
                                'subsvlan': self.subsvlan_id}
                    self.flow_queue.put(flow_event)
                else:
                    log.debug('Incomplete flow')

            self.cvlan_id = cvlan_found
            self.subsvlan_id = subsvlan_found

        except Exception as e:
            log.exception('failed-to-launch-install-flow', e=e, flow=flows)

    @inlineCallbacks
    def uninstall_flows_sequence(self, device):
        log.debug('init-flow-deinstallaton')
        try:
            response = yield self.delete_data_flow_omci_config(device)
            returnValue(response)
        except Exception as e:
            log.exception('failed-to-launch-uninstall-flow', e=e)

    @inlineCallbacks
    def reinstall_flows_sequence(self, device, cvlan_id, subsvlan_id):
        log.debug('init-flow-reinstallaton')
        try:
            response = yield self.uninstall_flows_sequence(device)
            if response:
                response = yield self.install_flows_sequence(device, cvlan_id, subsvlan_id)
                returnValue(response)
            returnValue(False)

        except Exception as e:
            log.exception('failed-to-launch-reinstall-flow', e=e)

    @inlineCallbacks
    def install_flows_sequence(self, device, cvlan_id, subsvlan_id):
        log.debug('init-flow-installaton')
        try:
            log.debug("ONT flow OMCI config", device=device)
            response = yield self.create_data_flow_omci_config(device, cvlan_id, subsvlan_id)
            returnValue(response)
        except Exception as e:
            log.exception('failed-to-launch-install-flow', e=e)

    @inlineCallbacks
    def wait_for_omci_response(self):
        log.debug('wait-for-response')
        response = yield self.incoming_messages.get()
        log.debug("unqueued-message", msg=hexify(response))
        returnValue(OmciFrame(response))

    @inlineCallbacks
    def create_common_omci_config(self, device):
        log.debug('create-common-omci-config')

        alloc_id = 0x408 + device.proxy_address.onu_id

        self.OMCI_ont_data_mib_reset(device)
        response = yield self.wait_for_omci_response()

        if OmciMibResetResponse not in response:
            log.error("Failed to perform a MIB reset for {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_ont_data_mib_reset")

        self.OMCI_tcont_set(device, alloc_id)
        response = yield self.wait_for_omci_response()
        if OmciSetResponse not in response:
            log.error("Failed to set alloc id for {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_tcont_set")

        self.pmc_omci_mac_bridge_sp_me_create(device)
        response = yield self.wait_for_omci_response()
        if OmciCreateResponse not in response:
            log.error("Failed to set parameter on {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_mac_bridge_sp_me_create")

        self.pmc_omci_mac_bridge_pcd_me_create(device)
        response = yield self.wait_for_omci_response()
        if OmciCreateResponse not in response:
            log.error("Failed to set info for {}".format(device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_mac_bridge_pcd_me_create")

        for port in range(1, PORT_NUMBER+1):
            self.pmc_omci_mac_bridge_pcd_me_allocate(device, port)
            response = yield self.wait_for_omci_response()
            if OmciCreateResponse not in response:
                log.error("Failed to create mac bridge pcd on {}".format(
                    device.proxy_address))
                returnValue(False)
            log.debug("[RESPONSE] OMCI_mac_bridge_pcd_me_allocate")

        returnValue(True)

    @inlineCallbacks
    def create_data_flow_omci_config(self, device, cvlan_id, subsvlan_id):

        self.pmc_omci_8021p_msp_me_allocate(device)
        response = yield self.wait_for_omci_response()
        if OmciCreateResponse not in response:
            log.error("Failed to create 8021p msp on {}".format(
                device.proxy_address))
            if response is not None:
                log.error("Response received: {}".format(response.summary())) 
            returnValue(False)
        log.debug("[RESPONSE] OMCI_8021p_msp_me_allocate")

        self.send_create_vlan_tagging_filter_data(device, cvlan_id)
        response = yield self.wait_for_omci_response()
        if OmciCreateResponse not in response:
            log.error("Failed to set vlan tagging filter in {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_send_create_vlan_tagging_filter_data")

        for port in range(1, PORT_NUMBER+1):
            self.pmc_omci_evto_create(device, port)
            response = yield self.wait_for_omci_response()
            if OmciCreateResponse not in response:
                log.error("Failed to set association info for {}".format(
                    device.proxy_address))
                returnValue(False)
            log.debug("[RESPONSE] OMCI_evto_create")

            self.pmc_omci_evto_set(device, port)
            response = yield self.wait_for_omci_response()
            if OmciSetResponse not in response:
                log.error("Failed to set association tpid info for {}".format(
                    device.proxy_address))
                returnValue(False)
            log.debug("[RESPONSE] OMCI_evto_set")

            response = yield self.send_set_extended_vlan_tagging_operation_vlan_configuration_data(
            device, cvlan_id, subsvlan_id, port)

            if not response:
                returnValue(False)
            log.debug("[RESPONSE] OMCI_send_set_extended_vlan_tagging")

        self.pmc_omci_gem_nctp_me_allocate(device)
        response = yield self.wait_for_omci_response()
        if OmciCreateResponse not in response:
            log.error("Failed to Create gem nctp on {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_gem_nctp_me_allocate")

        self.pmc_omci_gem_iwtp_me_allocate(device)
        response = yield self.wait_for_omci_response()
        if OmciCreateResponse not in response:
            log.error("Failed to Create gem iwtp on {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_gem_iwtp_me_allocate")

        self.pmc_omci_8021p_msp_me_assign(device)
        response = yield self.wait_for_omci_response()
        if OmciSetResponse not in response:
            log.error("Failed to assign sp {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] OMCI_8021p_msp_me_assign")

        returnValue(True)

    @inlineCallbacks
    def delete_data_flow_omci_config(self, device):
        for port in range(1, PORT_NUMBER+1):
            self.pmc_omci_evto_deallocate(device, port)
            response = yield self.wait_for_omci_response()
            if OmciDeleteResponse not in response:
                log.error(
                    "Failed to deallocate evt for {}".format(device.proxy_address))
                if response is not None:
                    log.error("Response received: {}".format(response.summary()))
                returnValue(False)
            log.debug("[RESPONSE] pmc_omci_evto_deallocate", device=device)

        self.pmc_omci_gem_iwtp_me_deallocate(device)
        response = yield self.wait_for_omci_response()
        if OmciDeleteResponse not in response:
            log.error(
                "Failed to deallocate iwtp for {}".format(device.proxy_address))
            if response is not None:
                log.error("Response received: {}".format(response.summary())) 
            returnValue(False)
        log.debug("[RESPONSE] pmc_omci_gem_iwtp_me_deallocate", device=device)

        self.pmc_omci_gem_nctp_me_deallocate(device)
        response = yield self.wait_for_omci_response()
        if OmciDeleteResponse not in response:
            log.error(
                "Failed to deallocate nctp for {}".format(device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] pmc_omci_gem_nctp_me_deallocate", device=device)

        self.pmc_omci_vlan_tagging_filter_me_deallocate(device)
        response = yield self.wait_for_omci_response()
        if OmciDeleteResponse not in response:
            log.error(
                "Failed to deallocate vlan tagging for {}".format(device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] pmc_omci_vlan_tagging_filter_me_deallocate", device=device)

        self.pmc_omci_8021p_msp_me_deallocate(device)
        response = yield self.wait_for_omci_response()
        if OmciDeleteResponse not in response:
            log.error(
                "Failed to deallocate msp for {}".format(device.proxy_address))
            returnValue(False)
        log.debug("[RESPONSE] pmc_omci_8021p_msp_me_deallocate", device=device)

        returnValue(True)

    """ -   -   -   -   -   -   -   create_common_omci_config   -   -   -   -   -   -   - """

    def OMCI_ont_data_mib_reset(self, device):
        # DO things to the ONU
        # |###[ OmciFrame ]###
        #     |  transaction_id= 1
        #     |  message_type= 79
        #     |  omci      = 10
        #     |  \omci_message\
        #     |   |###[ OmciMibReset ]###
        #     |   |  entity_class= 2
        #     |   |  entity_id = 0
        #     |  omci_trailer= 40

        # OmciMibReset

        msg = OmciMibReset(entity_class=2, entity_id=0)
        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciMibReset.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] OMCI_ont_data_mib_reset")

    def OMCI_tcont_set(self, device, alloc_id):
        # | ###[ OmciFrame ]###
        # | transaction_id = 2
        # | message_type = 72
        # | omci = 10
        # |   \omci_message \
        #      | |  ###[ OmciSet ]###
        # | | entity_class = 262
        # | | entity_id = 32769
        # | | attributes_mask = 32768
        # | | data = {'alloc_id': 1000}
        # | omci_trailer = 40

        # tcont_id = 1; //one tcont for one ONU.
        # slot_id = 128; /* represent the ONT as a whole entinty */
        # entity_instance = ((slot_id<<8) | tcont_id); /* Compose entity
        # instance by the slot-id and t-cont id*/

        # OmciSet
        # TODO: maskdata
        msg = OmciSet(entity_class=262, entity_id=32769, attributes_mask=32768,
                      data=dict(
                          alloc_id=alloc_id
                      ))
        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciSet.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] OMCI_tcont_set")

    def pmc_omci_mac_bridge_sp_me_create(self, device):
        # length = 44
        # port_type = 0
        # port_id = 0
        # management_frame = 1
        # \frame \
        #  |  ###[ OmciFrame ]###
        # | transaction_id = 3
        # | message_type = 68
        # | omci = 10
        # |   \omci_message \
        #      | |  ###[ OmciCreate ]###
        # | | entity_class = 45
        # | | entity_id = 1
        # | | data = {'max_age': 5120, 'hello_time': 512, 'priority': 32768, 'port_bridging_ind': 0,
        #             'spanning_tree_ind': 0, 'unknown_mac_address_discard': 0, 'mac_learning_depth': 128,
        #             'learning_ind': 0, 'forward_delay': 3840}
        # | |  ###[ Raw ]###
        # | | load = '\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        # | omci_trailer = 40

        # Found in method: pmc_omci_mac_bridge_sp_me_create from: PMC_OFAL.c
        # Params
        #   - priority: The bridge priority set on the LAN card
        #   - max_age: The maximum age for an entry in the spanning tree listing
        #   - hello_time: The time interval between hello packets
        #   - forward_delay: The time that the bridge on the Ethernet card in the ONT retains a packet before forwarding it
        #   - unknown_mac_address_discard: frames with unknown destination addresses will be forwarded to all allowed ports

        msg = OmciCreate(entity_class=45, entity_id=1,
                         data=dict(
                             max_age=5120,
                             hello_time=512,
                             priority=32768,
                             port_bridging_ind=PON_FALSE,
                             spanning_tree_ind=PON_FALSE,
                             unknown_mac_address_discard=0,
                             mac_learning_depth=128,
                             learning_ind=PON_FALSE,
                             forward_delay=3840
                         ))
        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciCreate.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_mac_bridge_sp_me_create")

    def pmc_omci_mac_bridge_pcd_me_create(self, device):

        # |###[ OmciFrame ]###
        #     |  transaction_id= 4
        #     |  message_type= 68
        #     |  omci      = 10
        #     |  \omci_message\
        #     |   |###[ OmciCreate ]###
        #     |   |  entity_class= 47
        #     |   |  entity_id = 0
        #     |   |  data      = {'tp_pointer': 257, 'encapsulation_methods': 1, 'port_num': 0, 'port_priority': 10, 'tp_type': 1, 'port_path_cost': 100, 'port_spanning_tree_in': 0, 'lan_fcs_ind': 0, 'bridge_id_pointer': 1}
        #     |  omci_trailer= 40

        # Found in method: pmc_omci_mac_bridge_pcd_me_create from: PMC_OFAL.c
        # Params
        #   - port_path_cost: The cost contribution of the port to the path cost towards the spanning tree root bridge
        #   - bridge_id_pointer: MAC bridge controlling the port

        msg = OmciCreate(entity_class=47, entity_id=0,
                         data=dict(
                             tp_pointer=1,
                             encapsulation_methods=OMCI_MAC_BRIDGE_PCD_ENCAP_METHOD_LLC,
                             port_num=0,
                             port_priority=10,
                             tp_type=3,
                             port_path_cost=100,
                             port_spanning_tree_in=PON_FALSE,
                             lan_fcs_ind=OMCI_MAC_BRIDGE_PCD_LANFCS_FORWARDED,
                             bridge_id_pointer=1
                         ))

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciCreate.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_mac_bridge_pcd_me_create")

    def pmc_omci_evto_create(self, device, port):
        # |###[ OmciFrame ]###
        # |  transaction_id= 5
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]###
        # |   |  entity_class= 171
        # |   |  entity_id = 0
        # |   |  data      = {'association_type': 2, 'associated_me_pointer': 257}
        # |  omci_trailer= 40

        # Found in method: pmc_omci_evto_create from: PMC_OFAL.c
        msg = OmciCreate(entity_class=171, entity_id=port,
                         data=dict(
                             association_type=OMCI_EX_VLAN_TAG_OCD_ASSOCIATION_TYPE_PPTP_ETH_UNI,
                             associated_me_pointer=0x100+port
                         ))

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciCreate.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_evto_create")

    def pmc_omci_evto_set(self, device, port):
        # |###[ OmciFrame ]###
        # |  transaction_id= 6
        # |  message_type= 72
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciSet ]###
        # |   |  entity_class= 171
        # |   |  entity_id = 0
        # |   |  attributes_mask= 47616
        # |   |  data      = {'association_type': 2, 'input_tpid': 33024, 'associated_me_pointer': 257, 'downstream_mode': 0, 'output_tpid': 33024}
        # |  omci_trailer= 40

        # Found in method: pmc_omci_evto_set from: PMC_OFAL.c
        msg = OmciSet(entity_class=171, entity_id=port, attributes_mask=47616,
                      data=dict(
                          association_type=OMCI_EX_VLAN_TAG_OCD_ASSOCIATION_TYPE_PPTP_ETH_UNI,
                          input_tpid=0x8100,
                          associated_me_pointer=0x100+port,
                          downstream_mode=OMCI_EX_VLAN_TAG_OCD_DS_MODE_US_INVERSE,
                          output_tpid=0x8100
                      ))

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciSet.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_evto_set")

    """ -   -   -   -   -   -   -     END create_common_omci_config     -   -   -   -   -   -   - """

    """ -   -   -   -   -   -   create_default_data_flow_omci_config    -   -   -   -   -   -   - """

    def pmc_omci_8021p_msp_me_allocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 7
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]###
        # |   |  entity_class= 130
        # |   |  entity_id = 1
        # |   |  data      = {'tp_pointer': 65535, 'unmarked_frame_option': 1, 'interwork_tp_pointer_for_p_bit_priority_6': 65535,
        #          'interwork_tp_pointer_for_p_bit_priority_7': 65535, 'interwork_tp_pointer_for_p_bit_priority_4': 65535,
        #           'interwork_tp_pointer_for_p_bit_priority_5': 65535, 'interwork_tp_pointer_for_p_bit_priority_2': 65535,
        #           'interwork_tp_pointer_for_p_bit_priority_3': 65535, 'interwork_tp_pointer_for_p_bit_priority_0': 65535,
        #           'interwork_tp_pointer_for_p_bit_priority_1': 65535, 'tp_type': 0, 'default_p_bit_marking': 0}
        # |  omci_trailer= 40

        # Found in method: pmc_omci_8021p_msp_me_create from: PMC_OFAL.c
        msg = OmciCreate(entity_class=130, entity_id=1,
                         data=dict(
                             tp_pointer=65535,
                             unmarked_frame_option=OMCI_8021P_MSP_UNMARKED_FRAME_TAG_FRAME,
                             interwork_tp_pointer_for_p_bit_priority_6=65535,
                             interwork_tp_pointer_for_p_bit_priority_7=65535,
                             interwork_tp_pointer_for_p_bit_priority_4=65535,
                             interwork_tp_pointer_for_p_bit_priority_5=65535,
                             interwork_tp_pointer_for_p_bit_priority_2=65535,
                             interwork_tp_pointer_for_p_bit_priority_3=65535,
                             interwork_tp_pointer_for_p_bit_priority_0=65535,
                             interwork_tp_pointer_for_p_bit_priority_1=65535,
                             tp_type=OMCI_8021P_MSP_TP_TYPE_NULL,
                             default_p_bit_marking=0
                         ))

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciCreate.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_8021p_msp_me_allocate")

    def pmc_omci_mac_bridge_pcd_me_allocate(self, device, port):
        # |###[ OmciFrame ]###
        # |  transaction_id= 8
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]###
        # |   |  entity_class= 130
        # |   |  entity_id = 1
        # |   |  data      = {'tp_pointer': 1, 'encapsulation_methods': 1, 'port_num': 1, 'port_priority': 3, 'tp_type': 5, 'port_path_cost': 32, 'port_spanning_tree_in': 1, 'lan_fcs_ind': 0, 'bridge_id_pointer': 1}
        # |  omci_trailer= 40

        # Found in method: pmc_omci_mac_bridge_pcd_me_create from: PMC_OFAL.c
        # Params
        #   - port_path_cost: The cost contribution of the port to the path cost towards the spanning tree root bridge
        #   - bridge_id_pointer: MAC bridge controlling the port
        msg = OmciCreate(entity_class=47, entity_id=port,
                         data=dict(
                             tp_pointer=0x100 + port,
                             encapsulation_methods=OMCI_MAC_BRIDGE_PCD_ENCAP_METHOD_LLC,
                             port_num=port,
                             port_priority=10,
                             tp_type=1,
                             port_path_cost=100,
                             port_spanning_tree_in=PON_FALSE,
                             lan_fcs_ind=OMCI_MAC_BRIDGE_PCD_LANFCS_FORWARDED,
                             bridge_id_pointer=1
                         ))

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciCreate.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_mac_bridge_pcd_me_allocate")

    def pmc_omci_gem_nctp_me_allocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 9
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]###
        # |   |  entity_class= 268
        # |   |  entity_id = 1
        # |   |  data      = {'priority_queue_pointer_downstream': 0, 'direction': 3, 'tcont_pointer': 32769, 'traffic_descriptor_profile_pointer': 0, 'traffic_management_pointer_upstream': 4, 'port_id': 1000}
        # |  omci_trailer= 40

        # Found in method: pmc_omci_gem_nctp_create from: PMC_OFAL.c
        msg = OmciCreate(entity_class=268, entity_id=1,
                         data=dict(
                             priority_queue_pointer_downstream=0,   # 0 for default
                             direction=GEM_DIR_BIDIRECT,
                             tcont_pointer=32769,
                             traffic_descriptor_profile_pointer=0,
                             traffic_management_pointer_upstream=4,  # 4 for default
                             # Same as GEM port
                             # port_id=(1000 + device.proxy_address.onu_id)
                             port_id = self.port_id
                         ))

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciCreate.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_gem_nctp_me_allocate")

    def pmc_omci_gem_iwtp_me_allocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 10
        # |  message_type= 68
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciCreate ]###
        # |   |  entity_class= 266
        # |   |  entity_id = 1
        # |   |  data      = {'gem_port_network_ctp_pointer': 1, 'gal_profile_pointer': 0, 'service_profile_pointer': 1, 'interworking_option': 5, 'interworking_tp_pointer': 0}
        # |  omci_trailer= 40

        # Found in method: pmc_omci_gem_iwtp_me_create from: PMC_OFAL.c
        # Params
        #   - gem_port_network_ctp_pointer: An instance identifier of the GEM Port Network CTP that is associated with this GEM Interworking Termination Point
        #   - service_profile_pointer: The service profile type and a pointer to the instance of a service profile
        #   - interworking_tp_pointer: Used for in the case of Circuit Emulation Services and 802.1p mapper service
        #   - gal_profile_pointer: A pointer to an instance of the GAL Profile

        msg = OmciCreate(entity_class=266, entity_id=1,
                         data=dict(
                             gem_port_network_ctp_pointer=1,
                             gal_profile_pointer=0,
                             service_profile_pointer=1,
                             interworking_option=OMCI_GEM_IWTP_IW_OPT_8021P_MAPPER,
                             interworking_tp_pointer=0
                         ))

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciCreate.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_gem_iwtp_me_allocate")

    """ -   -   -   -   -   -    END create_default_data_flow_omci_config   -   -   -   -   -   - """

    """ -   -   -   -   -   -   -     create_data_flow_omci_config      -   -   -   -   -   -   - """

    @inlineCallbacks
    def send_set_extended_vlan_tagging_operation_vlan_configuration_data(self, device, cvlan_id, subs_vlan, port):
        # ###[ PAS5211MsgSendFrame ]###
        #            length    = 44
        #            port_type = 0
        #            port_id   = 0
        #            management_frame= 1
        #            \frame     \
        #             |###[ OmciFrame ]###
        #             |  transaction_id= 14
        #             |  message_type= 72
        #             |  omci      = 10
        #             |  \omci_message\
        #             |   |###[ OmciSet ]###
        #             |   |  entity_class= 171
        #             |   |  entity_id = 0
        #             |   |  attributes_mask= 1024
        #             |   |  data      = {'received_frame_vlan_tagging_operation_table': '\xf8\x00\x00\x00\x00\x00@\x00@\x0f\x00\x04\x00\x00\x00\x0c'}
        #             |  omci_trailer= 40

        self.send_vlan_tagging_operation_msg(device,
            VlanTaggingOperation(
                filter_outer_priority=OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_NO_TAG,
                filter_outer_vid=OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE,
                filter_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE,

                filter_inner_priority=0,
                filter_inner_vid=subs_vlan,
                filter_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_8100,
                filter_ether_type=OMCI_EX_VLAN_TAG_OCD_FILTER_ETYPE_NONE,

                treatment_tags_to_remove=1,
                treatment_outer_priority=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE,
                treatment_outer_vid=0,
                treatment_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_EQ_8100,

                treatment_inner_priority=0,
                treatment_inner_vid=cvlan_id,
                treatment_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_EQ_8100
            ), port)
        response = yield self.wait_for_omci_response()

        log.debug(
            "[SENT] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        if OmciSetResponse not in response:
            log.error("Failed to set vlan extended table entry {}".format(
                device.proxy_address))
            returnValue(False)

        log.debug(
            "[RESPONSE] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        self.send_vlan_tagging_operation_msg(device,
            VlanTaggingOperation(
                filter_outer_priority=OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_NO_TAG,
                filter_outer_vid=OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE,
                filter_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE,

                filter_inner_priority=OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_NO_TAG,
                filter_inner_vid=OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE,
                filter_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE,
                filter_ether_type=OMCI_EX_VLAN_TAG_OCD_FILTER_ETYPE_NONE,

                treatment_tags_to_remove=3,
                treatment_outer_priority=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE,
                treatment_outer_vid=0,
                treatment_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_OUTER,

                treatment_inner_priority=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE,
                treatment_inner_vid=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_COPY_FROM_INNER,
                treatment_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_INNER
            ), port)

        log.debug(
            "[SENT] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        response = yield self.wait_for_omci_response()
        if OmciSetResponse not in response:
            log.error("Failed to set vlan extended table entry {}".format(
                device.proxy_address))
            returnValue(False)

        log.debug(
            "[RESPONSE] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        self.send_vlan_tagging_operation_msg(device,
            VlanTaggingOperation(
                filter_outer_priority=OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_NO_TAG,
                filter_outer_vid=OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE,
                filter_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE,

                filter_inner_priority=OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_DEFAULT,
                filter_inner_vid=OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE,
                filter_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE,
                filter_ether_type=OMCI_EX_VLAN_TAG_OCD_FILTER_ETYPE_NONE,

                treatment_tags_to_remove=3,
                treatment_outer_priority=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE,
                treatment_outer_vid=0,
                treatment_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_OUTER,

                treatment_inner_priority=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE,
                treatment_inner_vid=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_COPY_FROM_INNER,
                treatment_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_INNER
            ), port)

        log.debug(
            "[SENT] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        response = yield self.wait_for_omci_response()
        if OmciSetResponse not in response:
            log.error("Failed to set vlan extended table entry {}".format(
                device.proxy_address))
            returnValue(False)

        log.debug(
            "[RESPONSE] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        self.send_vlan_tagging_operation_msg(device,
            VlanTaggingOperation(
                filter_outer_priority=OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_DEFAULT,
                filter_outer_vid=OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE,
                filter_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE,

                filter_inner_priority=OMCI_EX_VLAN_TAG_OCD_FILTER_PRIO_DEFAULT,
                filter_inner_vid=OMCI_EX_VLAN_TAG_OCD_FILTER_VID_NONE,
                filter_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_FILTER_TPID_DE_NONE,
                filter_ether_type=OMCI_EX_VLAN_TAG_OCD_FILTER_ETYPE_NONE,

                treatment_tags_to_remove=3,
                treatment_outer_priority=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE,
                treatment_outer_vid=0,
                treatment_outer_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_OUTER,

                treatment_inner_priority=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_NONE,
                treatment_inner_vid=OMCI_EX_VLAN_TAG_OCD_TREAT_PRIO_COPY_FROM_INNER,
                treatment_inner_tpid_de=OMCI_EX_VLAN_TAG_OCD_TREAT_TPID_DE_COPY_FROM_INNER
            ), port)

        log.debug(
            "[SENT] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        response = yield self.wait_for_omci_response()
        if OmciSetResponse not in response:
            log.error("Failed to set vlan extended table entry {}".format(
                device.proxy_address))
            returnValue(False)
        log.debug(
            "[RESPONSE] send_set_extended_vlan_tagging_operation_vlan_configuration_data")

        returnValue(True)

    def send_vlan_tagging_operation_msg(self, device, vlan_tagging_operation_table, port):

        data = dict(
            received_frame_vlan_tagging_operation_table=vlan_tagging_operation_table
        )

        msg = OmciSet(
            entity_class=171,
            entity_id=port,
            attributes_mask=1024,
            data=data
        )

        frame = OmciFrame(
            transaction_id=self.trangen.next(),
            message_type=OmciSet.message_id,
            omci_message=msg
        )
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] create_vlan_tagging_filter_data")

    def send_create_vlan_tagging_filter_data(self, device, cvlan_id):
        # ###[ PAS5211MsgSendFrame ]###
        #    length    = 44
        #    port_type = 0
        #    port_id   = 0
        #    management_frame= 1
        #    \frame     \
        #     |###[ OmciFrame ]###
        #     |  transaction_id= 18
        #     |  message_type= 68
        #     |  omci      = 10
        #     |  \omci_message\
        #     |   |###[ OmciCreate ]###
        #     |   |  entity_class= 84
        #     |   |  entity_id = 2
        #     |   |  data      = {'vlan_filter_0': 1, 'vlan_filter_1': 0, 'vlan_filter_2': 0, 'vlan_filter_3': 0, 'vlan_filter_4': 0, 'vlan_filter_5': 0, 'vlan_filter_6': 0, 'vlan_filter_7': 0, 'vlan_filter_8': 0, 'vlan_filter_9': 0, 'number_of_entries': 1, 'forward_operation': 16, 'vlan_filter_10': 0, 'vlan_filter_11': 0}
        #     |  omci_trailer= 40

        data = dict(
            vlan_filter_0=cvlan_id,
            forward_operation=16,
            number_of_entries=1
        )

        msg = OmciCreate(
            entity_class=84,
            entity_id=1,
            data=data
        )

        frame = OmciFrame(
            transaction_id=self.trangen.next(),
            message_type=OmciCreate.message_id,
            omci_message=msg
        )
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] create_vlan_tagging_filter_data")

    @inlineCallbacks
    def pmc_omci_vlan_tagging_filter_me_allocate(self, device):  # TODO

        self.OMCI_vlan_tagging_filter_get(device)
        response = yield self.incoming_messages.get()
        if OmciGetResponse not in response:
            log.error("Failed to Get vlan tagging filter {}".format(
                device.proxy_address))
            return

        # if: # OMCI Get is sucessfull
        #     # OMCI_vlan_tagging_filter_create
        # else:
        #     # OMCI_vlan_tagging_filter_set
        log.debug("[SENT] pmc_omci_vlan_tagging_filter_me_allocate")
        pass

    def pmc_omci_8021p_msp_me_assign(self, device):

        # ###[ PAS5211MsgSendFrame ]###
        #    length    = 44
        #    port_type = 0
        #    port_id   = 0
        #    management_frame= 1
        #    \frame     \
        #     |###[ OmciFrame ]###
        #     |  transaction_id= 21
        #     |  message_type= 72
        #     |  omci      = 10
        #     |  \omci_message\
        #     |   |###[ OmciSet ]###
        #     |   |  entity_class= 130
        #     |   |  entity_id = 2
        #     |   |  attributes_mask= 16472
        #     |   |  data      = {'tp_type': 0, 'unmarked_frame_option': 1, 'interwork_tp_pointer_for_p_bit_priority_0': 2, 'default_p_bit_marking': 0}
        #     |  omci_trailer= 40

        data = dict(tp_type=0,
                    output_tpid=33024,
                    unmarked_frame_option=1,
                    interwork_tp_pointer_for_p_bit_priority_0=1,
                    default_p_bit_marking=0
                    )

        msg = OmciSet(entity_class=130,
                      entity_id=1,
                      attributes_mask=16472,
                      data=data
                      )

        frame = OmciFrame(
            transaction_id=self.trangen.next(),
            message_type=OmciSet.message_id,
            omci_message=msg
        )
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)

        log.debug("[SENT] pmc_omci_8021p_msp_me_assign")

    def pmc_ofal_recover_default_onu_flow_omci(self, device):
        log.debug("[SENT] pmc_ofal_recover_default_onu_flow_omci")
        pass

    def OMCI_vlan_tagging_filter_get(self, device):
        # entity_class: OMCI_ENT_VLAN_TAGGING_FILT_DATA
        # entity_instance: mac_bridge_pcd
        # attr_mask = 0
        # attr_mask | OMCI_ATTR_BIT(OMCI_VLAN_TAG_FILTER_ATTR_FILTER_TABLE);
        # attr_mask | OMCI_ATTR_BIT(OMCI_VLAN_TAG_FILTER_ATTR_FWD_OP);
        # attr_mask | OMCI_ATTR_BIT(OMCI_VLAN_TAG_FILTER_ATTR_NOF_ENTRIES);
        log.debug("[SENT] OMCI_vlan_tagging_filter_get")
        pass

    def OMCI_vlan_tagging_filter_create(self, device):  # TODO
        log.debug("[SENT] OMCI_vlan_tagging_filter_create")
        pass

    def OMCI_vlan_tagging_filter_set(self, device):  # TODO
        log.debug("[SENT] OMCI_vlan_tagging_filter_set")
        pass

    """ -   -   -   -   -   -   -    END create_data_flow_omci_config      -   -   -   -   -   -   - """

    """ -   -   -   -   -   -   -   delete_data_flow_omci_config   -   -   -   -   -   -   - """

    def pmc_omci_gem_iwtp_me_deallocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 34
        # |  message_type= 70
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciDelete ]###
        # |   |  entity_class= 266
        # |   |  entity_id = 2
        # |  omci_trailer= 40
        msg = OmciDelete(entity_class=266, entity_id=1)

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciDelete.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_gem_iwtp_me_deallocate")

    def pmc_omci_gem_nctp_me_deallocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 35
        # |  message_type= 70
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciDelete ]###
        # |   |  entity_class= 268
        # |   |  entity_id = 2
        # |  omci_trailer= 40
        msg = OmciDelete(entity_class=268, entity_id=1)

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciDelete.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_gem_nctp_me_allocate")

    def pmc_omci_vlan_tagging_filter_me_deallocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 36
        # |  message_type= 70
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciDelete ]###
        # |   |  entity_class= 84
        # |   |  entity_id = 2
        # |  omci_trailer= 40
        msg = OmciDelete(entity_class=84, entity_id=1)

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciDelete.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_vlan_tagging_filter_me_deallocate")


    def pmc_omci_mac_bridge_pcd_me_deallocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 37
        # |  message_type= 70
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciDelete ]###
        # |   |  entity_class= 47
        # |   |  entity_id = 2
        # |  omci_trailer= 40
        msg = OmciDelete(entity_class=47, entity_id=1)

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciDelete.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_mac_bridge_pcd_me_deallocate")



    def pmc_omci_8021p_msp_me_deallocate(self, device):
        # |###[ OmciFrame ]###
        # |  transaction_id= 38
        # |  message_type= 70
        # |  omci      = 10
        # |  \omci_message\
        # |   |###[ OmciDelete ]###
        # |   |  entity_class= 130
        # |   |  entity_id = 2
        # |  omci_trailer= 40
        msg = OmciDelete(entity_class=130, entity_id=1)

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciDelete.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_8021p_msp_me_deallocate")

    def pmc_omci_evto_deallocate(self, device, port):

        msg = OmciDelete(entity_class=171, entity_id=port)

        frame = OmciFrame(transaction_id=self.trangen.next(),
                          message_type=OmciDelete.message_id,
                          omci_message=msg)
        _frame = hexify(str(frame))
        self.adapter_agent.send_proxied_message(device.proxy_address, _frame)
        log.debug("[SENT] pmc_omci_evto_deallocate")


    """ -   -   -   -   -   -   -   END delete_data_flow_omci_config   -   -   -   -   -   -   - """

def mac_str_to_tuple(mac):
    return tuple(int(d, 16) for d in mac.split(':'))
