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
Microsemi/Celestica Ruby vOLTHA adapter.
"""
import structlog
from twisted.internet import reactor

from voltha.adapters.interface import IAdapterInterface
from voltha.adapters.microsemi_olt.APIProxy import APIProxy
from voltha.adapters.microsemi_olt.ActivationWatcher import ActivationWatcher
from voltha.adapters.microsemi_olt.DeviceManager import DeviceManager
from voltha.adapters.microsemi_olt.OMCIProxy import OMCIProxy
from voltha.adapters.microsemi_olt.OltStateMachine import OltStateMachine
from voltha.adapters.microsemi_olt.OltInstallFlowStateMachine import OltInstallFlowStateMachine
from voltha.adapters.microsemi_olt.OltRemoveFlowStateMachine import OltRemoveFlowStateMachine
from voltha.adapters.microsemi_olt.OltReinstallFlowStateMachine import OltReinstallFlowStateMachine
from voltha.adapters.microsemi_olt.PAS5211_comm import PAS5211Communication
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciMessage
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.common_pb2 import LogLevel
from voltha.protos.device_pb2 import DeviceTypes, DeviceType
from voltha.protos.health_pb2 import HealthStatus
from voltha.registry import registry
from zope.interface import implementer

import voltha.core.flow_decomposer as fd

from voltha.protos.openflow_13_pb2 import OFPPF_1GB_FD, OFPPF_FIBER, ofp_port, OFPPS_LIVE, OFPXMC_OPENFLOW_BASIC

from voltha.protos.openflow_13_pb2 import Flows, FlowGroups

from voltha.adapters.microsemi_olt.PAS5211 import PAS5211GetOnuAllocs, PAS5211GetOnuAllocsResponse, PAS5211GetSnInfo, \
    PAS5211GetSnInfoResponse, PAS5211GetOnusRange, PAS5211GetOnusRangeResponse, PAS5211MsgSetOnuOmciPortId, \
    PAS5211MsgSetOnuOmciPortIdResponse, PAS5211MsgSetOnuAllocId, PAS5211MsgSetOnuAllocIdResponse, \
    PAS5211SetSVlanAtConfig, PAS5211SetSVlanAtConfigResponse, PAS5211SetVlanDownConfig, \
    PAS5211SetVlanDownConfigResponse, PAS5211SetDownVlanHandl, PAS5211SetDownVlanHandlResponse, \
    PAS5211SetUplinkVlanHandl, PAS5211SetDownstreamPolicingConfigResponse, PAS5211SetDownstreamPolicingConfig, \
    PAS5211SetPortIdPolicingConfig, PAS5211UnsetPortIdPolicingConfig, \
    PAS5211MsgSendDbaAlgorithmMsg, PAS5211MsgSendDbaAlgorithmMsgResponse, \
    PAS5211SetUpstreamPolicingConfigResponse, PAS5211SetUpstreamPolicingConfig, \
    PAS5211MsgSetPortIdConfig, PAS5211MsgSetPortIdConfigResponse, \
    PAS5211MsgGetOnuIdByPortId, PAS5211MsgGetOnuIdByPortIdResponse, \
    PAS5211SetVlanUplinkConfiguration, PAS5211SetVlanUplinkConfigurationResponse, PAS5211SetUplinkVlanHandlResponse, PAS5211SetVlanGenConfig, PAS5211SetVlanGenConfigResponse, \
    PAS5211GetPortIdDownstreamPolicingConfig, PAS5211GetPortIdDownstreamPolicingConfigResponse, PAS5211RemoveDownstreamPolicingConfig, \
    PAS5211MsgHeader, PAS5211UnsetPortIdPolicingConfigResponse, PAS5211RemoveDownstreamPolicingConfigResponse, \
    PAS5211SetPortIdPolicingConfigResponse
from voltha.adapters.microsemi_olt.PAS5211_constants import OMCI_GEM_IWTP_IW_OPT_8021P_MAPPER, PON_FALSE, \
    PON_1_TO_1_VLAN_MODE, PON_TRUE, PON_VLAN_UNUSED_TAG, PON_VLAN_UNUSED_PRIORITY, PON_VLAN_REPLACE_PRIORITY, \
    PON_OUTPUT_VLAN_PRIO_HANDLE_INCOMING_VLAN, PON_VLAN_UNCHANGED_PRIORITY, PON_OUTPUT_VLAN_PRIO_HANDLE_DONT_CHANGE, \
    PON_OUTPUT_VLAN_PRIO_HANDLE_DL_VLAN_TABLE, PON_DL_VLAN_SVLAN_REMOVE, PON_DL_VLAN_CVLAN_NO_CHANGE, \
    PON_VLAN_DEST_DATAPATH, GEM_DIR_BIDIRECT, OMCI_MAC_BRIDGE_PCD_LANFCS_FORWARDED, \
    OMCI_MAC_BRIDGE_PCD_ENCAP_METHOD_LLC, OMCI_8021P_MSP_UNMARKED_FRAME_TAG_FRAME, OMCI_8021P_MSP_TP_TYPE_NULL, \
    OMCI_EX_VLAN_TAG_OCD_ASSOCIATION_TYPE_PPTP_ETH_UNI, OMCI_EX_VLAN_TAG_OCD_DS_MODE_US_INVERSE, PMC_UPSTREAM_PORT, \
    PON_DISABLE, PON_VLAN_CHANGE_TAG, PON_VLAN_DONT_CHANGE_TAG, PON_PORT_TYPE_GEM, PON_PORT_DESTINATION_CNI0, PON_ENABLE, SLA_gr_bw_gros, PYTHAGORAS_UPDATE_AID_SLA, \
    SLA_gr_bw_gros, SLA_be_bw_gros, SLA_gr_bw_fine, SLA_be_bw_fine, PYTHAGORAS_DBA_DATA_COS, PYTHAGORAS_DBA_STATUS_REPORT_NSR, \
    PMC_OFAL_NO_POLICY, UPSTREAM, DOWNSTREAM

from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue
from voltha.protos.common_pb2 import OperStatus, AdminState, ConnectStatus


log = structlog.get_logger()
_ = third_party


@implementer(IAdapterInterface)
class RubyAdapter(object):

    name = "microsemi_olt"

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adaptor_agent, config):
        self.adaptor_agent = adaptor_agent
        self.config = config
        self.device_handlers = dict()
        self.descriptor = Adapter(
            id=self.name,
            vendor='Microsemi / Celestica',
            version='0.2',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )

    def start(self):
        log.debug('starting')
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        for handler in self.device_handlers:
            handler.stop()
        log.info('stopped')
        return self

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        log.debug('adopt-device', device=device)
        self.device_handlers[device.id] = RubyAdapterHandler(self.adaptor_agent, self.config, self.descriptor)
        reactor.callLater(0, self.device_handlers[device.id].activate, device)

    def reconcile_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        self.stop()

    def disable_device(self, device):
        raise NotImplementedError()

    def reenable_device(self, device):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def reboot_device(self, device):
        log.debug('reboot-device', device=device)
        device_handler = self.device_handlers[device.id]
        reactor.callLater(0, device_handler.reboot_device, device)

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
        raise NotImplementedError()

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        try:
            log.debug('olt-bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

            handler = self.device_handlers[device.id]
            if handler:
                handler.update_flow_table(device, flows)
            else:
                log.debug("No handler found for device {}".format(device.id))

        except Exception as e:
            log.exception('failed-olt-bulk-flow-update', e=e)


    def create_interface(self, device, data):
        raise NotImplementedError()

    def update_interface(self, device, data):
        raise NotImplementedError()

    def remove_interface(self, device, data):
        raise NotImplementedError()

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.debug("send-proxied-message-olt", proxy_address=proxy_address)
        device = self.adaptor_agent.get_device(proxy_address.device_id)
        self.device_handlers[device.id].send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.debug("receive-proxied-message-olt-handler", proxy_address=proxy_address)
        raise NotImplementedError()

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.debug('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

class RubyAdapterHandler(object):

    name = "microsemi_olt"

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adaptor_agent, config, descriptor):
        self.adaptor_agent = adaptor_agent
        self.config = config
        self.descriptor = descriptor
        self.device = None
        self.device_manager = None
        self.comm = None
        self.activation = None
        self.olt = None
        self.ports = dict()
        self.last_iteration_ports = []
        self.interface = registry('main').get_args().interface
        self.flow_queue = DeferredQueue()

    def stop(self):
        log.debug('stopping')
        self._abandon(self.target)
        log.info('stopped')
        return self

    def activate(self, device):
        log.debug('activate-device', device=device)
        self.last_iteration_ports = []
        self.device = device
        self.device_manager = DeviceManager(device, self.adaptor_agent)
        self.target = device.mac_address
        self.comm = PAS5211Communication(dst_mac=self.target, iface=self.interface)

        self.olt = OltStateMachine(iface=self.interface, comm=self.comm,
                              target=self.target, device=self.device_manager)
        self.activation = ActivationWatcher(iface=self.interface, comm=self.comm,
                                target=self.target, device=self.device_manager, olt_adapter=self)

        reactor.callLater(0, self.wait_for_flow_events, device)

        self.olt.runbg()
        self.activation.runbg()

    def reboot_device(self, device):
        try:
            log.debug('reboot-device', device=device)
            # Stop ONUS ...
            self.device_manager.update_child_devices_state(admin_state=AdminState.DISABLED)
            # ... and then delete them!
            self.device_manager.delete_all_child_devices
            # Wait 10s to reboot OLT
            reactor.callLater(10, self.reboot_olt, device)
        except Exception as e:
            log.exception('reboot-olt-exception', e=e)

    def reboot_olt(self, device):
        try:
            # Stop OLT...
            self.device_manager.delete_logical_device()
            self.olt.stop()
            self.activation.stop()
            # ... and start again! ONUS will activate from events got from OLT
            self.last_iteration_ports = []
            self.ports.clear()
            self.activate(device)
        except Exception as e:
            log.exception('reboot-olt-exception', e=e)

    def abandon_device(self, device):
        self._abandon(self.target)

    def get_port_list(self, flows):
        port_list = []
        for flow in flows:
            _in_port = fd.get_in_port(flow)
            if _in_port not in (0, PMC_UPSTREAM_PORT):
                if _in_port not in port_list:
                    port_list.append(_in_port)
                    log.debug('field-type-in-port', in_port=_in_port, port_list=port_list)
        return port_list

    def get_svlan(self, port, flows):
        svlan_id = None
        for flow in flows:
            _in_port = fd.get_in_port(flow)
            if _in_port == PMC_UPSTREAM_PORT:
                log.debug('svlan-port-match')
                metadata = fd.get_metadata(flow)
                if metadata:
                    if metadata == port:
                        svlan_id = self.get_vlan(flow) & 0xfff
                        log.debug('SVLAN found:{}'.format(svlan_id))

        return svlan_id

    def get_cvlan(self, svlan_id, port, flows):
        cvlan_id = None
        # Look for cvlan ...
        for flow in flows:
            _in_port = fd.get_in_port(flow)
            if _in_port == port:
                log.debug('cvlan-port-match')
                for action in fd.get_actions(flow):
                    if action.type == fd.SET_FIELD:
                        vlan = action.set_field.field.ofb_field.vlan_vid & 0xfff
                        if vlan == svlan_id:
                            cvlan_id = self.get_vlan(flow) & 0xfff
                            log.debug('CVLAN found:{}'.format(cvlan_id))
        return cvlan_id

    def get_uplink_bandwidth(self, cvlan_id, svlan_id, port, flows):
        bandwidth = None
        # Look for cvlan ...
        for flow in flows:
            _in_port = fd.get_in_port(flow)
            if _in_port == port:
                log.debug('uplink-bandwidth-port-match')
                for action in fd.get_actions(flow):
                    if action.type == fd.SET_FIELD:
                        vlan = action.set_field.field.ofb_field.vlan_vid & 0xfff
                        if vlan == svlan_id:
                            bandwidth = fd.get_metadata(flow)
                            if bandwidth:
                                log.debug('Bandwidth found:{}'.format(bandwidth))
        return bandwidth

    def get_downlink_bandwidth(self, cvlan_id, svlan_id, port, flows):
        return None

    def update_flow_table(self, device, flows):
        try:
            self.flow_queue.put({'flows':flows})
        except Exception as e:
            log.debug('flow-enqueue-exception', e=e)

    @inlineCallbacks
    def wait_for_flow_events(self, device):
        log.debug('wait-for-flow-events', device=device)

        event = yield self.flow_queue.get()
        flows = event.get('flows')

        try:
            cvlan_id = None
            svlan_id = None

            log.debug('wait-for-flow-events-flow', device=device)

            # Look for ports mentioned in flows received ...
            port_list = self.get_port_list(flows.items)

            log.debug("list-ports", port_list=port_list)

            new_ports = set(port_list)-set(self.last_iteration_ports)
            log.debug("new-ports", new_ports=new_ports)

            disconnected_ports = set(self.last_iteration_ports)-set(port_list)
            log.debug("disconnected-ports", disconnected_ports=disconnected_ports)

            # For those new ports, check if we can proceed with flow installation...
            for port in new_ports:
                # Got svlan for that port ...
                svlan_id = self.get_svlan(port, flows.items)

                # ... look for the corresponding cvlan...
                if svlan_id:
                    cvlan_id = self.get_cvlan(svlan_id, port, flows.items)

                # Both vlan found!
                if svlan_id and cvlan_id:

                    # Get bandwidths from flow info...
                    uplink_bandwidth = self.get_uplink_bandwidth(cvlan_id, svlan_id, port, flows.items)
                    if uplink_bandwidth == None:
                        uplink_bandwidth = SLA_be_bw_gros

                    downlink_bandwidth = self.get_downlink_bandwidth(cvlan_id, svlan_id, port, flows.items)
                    if downlink_bandwidth == None:
                        if uplink_bandwidth == None:
                            downlink_bandwidth = SLA_be_bw_gros
                        else:
                            downlink_bandwidth = uplink_bandwidth

                    onu_id = self.ports[port]['onu_id']
                    onu_session_id = self.ports[port]['onu_session_id']
                    port_id = 1000 + 16 * onu_id
                    alloc_id = port_id
                    channel_id= port / 32

                    # Check if flow is already installed, if so, continue with next port
                    if self.ports[port].get('cvlan') and self.ports[port].get('svlan'):
                        if self.ports[port].get('svlan') == svlan_id:
                            # Flow already installed
                            if self.ports[port].get('cvlan') == cvlan_id:
                                continue
                            # We have new VLANs so we reinstall!
                            else:
                                self.reinstall_flows_sequence(device, onu_id, svlan_id, cvlan_id, port_id,
                                    alloc_id, onu_session_id, channel_id, uplink_bandwidth, downlink_bandwidth)
                        else:
                            # New installation...
                            self.install_flows_sequence(device, onu_id, svlan_id, cvlan_id, port_id,
                                alloc_id, onu_session_id, channel_id, uplink_bandwidth, downlink_bandwidth)
                    else:
                        # New installation...
                        self.install_flows_sequence(device, onu_id, svlan_id, cvlan_id, port_id,
                            alloc_id, onu_session_id, channel_id, uplink_bandwidth, downlink_bandwidth)

                    self.ports[port]['svlan'] = svlan_id
                    self.ports[port]['cvlan'] = cvlan_id

                else:
                    # Finally, it is an incomplete port, so we remove from port list
                    try:
                        port_list.remove(port)
                    except Exception as e:
                        log.debug('remove-non-existing-port', e=e)

            # For those ports without flows, uninstall them
            for port in disconnected_ports:

                onu_id = self.ports[port]['onu_id']
                onu_session_id = self.ports[port]['onu_session_id']
                port_id = 1000 + 16 * onu_id
                alloc_id = port_id
                channel_id= port / 32

                if self.ports[port].get('cvlan') and self.ports[port].get('svlan'):
                    self.uninstall_flows_sequence(device, onu_id, port_id, alloc_id, onu_session_id,
                        channel_id)
                    self.ports[port]['svlan'] = None
                    self.ports[port]['cvlan'] = None

            self.last_iteration_ports = port_list
            log.debug('last-iteration-ports', ports=self.last_iteration_ports)

        except Exception as e:
            log.exception('failed-to-olt-update-flow-table', e=e)

        reactor.callLater(0, self.wait_for_flow_events, device)

    def get_vlan(self, flow):
        for field in fd.get_ofb_fields(flow):
            if field.type == fd.VLAN_VID:
                return field.vlan_vid
        return None

    def reinstall_flows_sequence(self, device, onu_id, svlan, cvlan, port_id,
            alloc_id, onu_session_id, channel_id, uplink_bandwidth, downlink_bandwidth):
        log.debug('init-flow-reinstallaton')
        try:
            olt = OltReinstallFlowStateMachine(iface=self.interface, comm=self.comm,
                    target=self.target, device=self.device_manager, onu_id=onu_id,
                    channel_id=channel_id, port_id=port_id, onu_session_id=onu_session_id,
                    alloc_id=alloc_id, svlan_id=svlan, cvlan_id=cvlan,
                    uplink_bandwidth=uplink_bandwidth, downlink_bandwidth=downlink_bandwidth)
            olt.runbg()
        except Exception as e:
            log.exception('failed-to-launch-reinstall-flow', e=e)

    def install_flows_sequence(self, device, onu_id, svlan, cvlan, port_id,
            alloc_id, onu_session_id, channel_id, uplink_bandwidth, downlink_bandwidth):
        log.debug('init-flow-installaton')
        try:
            olt = OltInstallFlowStateMachine(iface=self.interface, comm=self.comm,
                    target=self.target, device=self.device_manager, onu_id=onu_id,
                    channel_id=channel_id, port_id=port_id, onu_session_id=onu_session_id,
                    alloc_id=alloc_id, svlan_id=svlan, cvlan_id=cvlan,
                    uplink_bandwidth=uplink_bandwidth, downlink_bandwidth=downlink_bandwidth)
            olt.runbg()
        except Exception as e:
            log.exception('failed-to-launch-install-flow', e=e)

    def uninstall_flows_sequence(self, device, onu_id, port_id, alloc_id, onu_session_id,
            channel_id):
        log.debug('init-flow-deinstallaton')
        try:
            olt = OltRemoveFlowStateMachine(iface=self.interface, comm=self.comm,
                    target=self.target, device=self.device_manager, onu_id=onu_id,
                    channel_id=channel_id, port_id=port_id, onu_session_id=onu_session_id,
                    alloc_id=alloc_id)
            olt.runbg()
        except Exception as e:
            log.exception('failed-to-launch-deinstallaton-flow', e=e)

    def _abandon(self, target):
        self.olt.stop()
        self.activation.stop()

    # Method exposed to Activation Watcher to get onu info from Activation
    def add_onu_info(self, port, onu_id, onu_session_id):
        existing_port = self.ports.get(port)
        if existing_port:
            existing_port['onu_id'] = onu_id
            existing_port['onu_session_id'] = onu_session_id
        else:
            self.ports[port] = {'onu_id': onu_id, 'onu_session_id': onu_session_id}

    def send_proxied_message(self, proxy_address, msg):
        log.debug("send-proxied-message-olt-handler", proxy_address=proxy_address)

        if isinstance(msg, OmciFrame):
            omci_proxy = OMCIProxy(proxy_address=proxy_address,
                                   msg=msg,
                                   adapter_agent=self.adaptor_agent,
                                   target=self.device.mac_address,
                                   comm=self.comm,
                                   iface=self.interface)
            omci_proxy.runbg()

        else:
            api_proxy = APIProxy(proxy_address=proxy_address,
                                 msg=msg,
                                 adapter_agent=self.adaptor_agent,
                                 target=self.device.mac_address,
                                 comm=self.comm,
                                 iface=self.interface)
            api_proxy.runbg()