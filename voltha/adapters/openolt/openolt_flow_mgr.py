#
# Copyright 2018 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import copy
from twisted.internet import reactor
import grpc
from google.protobuf.json_format import MessageToDict
import hashlib
from simplejson import dumps

from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, \
    ofp_flow_stats, OFPMT_OXM, Flows, FlowGroups, OFPXMT_OFB_IN_PORT, \
    OFPXMT_OFB_VLAN_VID
from voltha.protos.device_pb2 import Port
import voltha.core.flow_decomposer as fd
from voltha.adapters.openolt.protos import openolt_pb2
from voltha.registry import registry

from common.tech_profile.tech_profile import DEFAULT_TECH_PROFILE_TABLE_ID

# Flow categories
HSIA_FLOW = "HSIA_FLOW"

EAP_ETH_TYPE = 0x888e
LLDP_ETH_TYPE = 0x88cc

IGMP_PROTO = 2

# FIXME - see also BRDCM_DEFAULT_VLAN in broadcom_onu.py
DEFAULT_MGMT_VLAN = 4091

# Openolt Flow
UPSTREAM = "upstream"
DOWNSTREAM = "downstream"
PACKET_TAG_TYPE = "pkt_tag_type"
UNTAGGED = "untagged"
SINGLE_TAG = "single_tag"
DOUBLE_TAG = "double_tag"

# Classifier
ETH_TYPE = 'eth_type'
TPID = 'tpid'
IP_PROTO = 'ip_proto'
IN_PORT = 'in_port'
VLAN_VID = 'vlan_vid'
VLAN_PCP = 'vlan_pcp'
UDP_DST = 'udp_dst'
UDP_SRC = 'udp_src'
IPV4_DST = 'ipv4_dst'
IPV4_SRC = 'ipv4_src'
METADATA = 'metadata'
OUTPUT = 'output'
# Action
POP_VLAN = 'pop_vlan'
PUSH_VLAN = 'push_vlan'
TRAP_TO_HOST = 'trap_to_host'


class OpenOltFlowMgr(object):

    def __init__(self, adapter_agent, log, stub, device_id, logical_device_id,
                 platform, resource_mgr):
        self.adapter_agent = adapter_agent
        self.log = log
        self.stub = stub
        self.device_id = device_id
        self.logical_device_id = logical_device_id
        self.nni_intf_id = None
        self.platform = platform
        self.logical_flows_proxy = registry('core').get_proxy(
            '/logical_devices/{}/flows'.format(self.logical_device_id))
        self.flows_proxy = registry('core').get_proxy(
            '/devices/{}/flows'.format(self.device_id))
        self.root_proxy = registry('core').get_proxy('/')
        self.resource_mgr = resource_mgr
        self.tech_profile = dict()
        self._populate_tech_profile_per_pon_port()
        self.retry_add_flow_list = []

    def add_flow(self, flow):
        self.log.debug('add flow', flow=flow)
        classifier_info = dict()
        action_info = dict()

        for field in fd.get_ofb_fields(flow):
            if field.type == fd.ETH_TYPE:
                classifier_info[ETH_TYPE] = field.eth_type
                self.log.debug('field-type-eth-type',
                               eth_type=classifier_info[ETH_TYPE])
            elif field.type == fd.IP_PROTO:
                classifier_info[IP_PROTO] = field.ip_proto
                self.log.debug('field-type-ip-proto',
                               ip_proto=classifier_info[IP_PROTO])
            elif field.type == fd.IN_PORT:
                classifier_info[IN_PORT] = field.port
                self.log.debug('field-type-in-port',
                               in_port=classifier_info[IN_PORT])
            elif field.type == fd.VLAN_VID:
                classifier_info[VLAN_VID] = field.vlan_vid & 0xfff
                self.log.debug('field-type-vlan-vid',
                               vlan=classifier_info[VLAN_VID])
            elif field.type == fd.VLAN_PCP:
                classifier_info[VLAN_PCP] = field.vlan_pcp
                self.log.debug('field-type-vlan-pcp',
                               pcp=classifier_info[VLAN_PCP])
            elif field.type == fd.UDP_DST:
                classifier_info[UDP_DST] = field.udp_dst
                self.log.debug('field-type-udp-dst',
                               udp_dst=classifier_info[UDP_DST])
            elif field.type == fd.UDP_SRC:
                classifier_info[UDP_SRC] = field.udp_src
                self.log.debug('field-type-udp-src',
                               udp_src=classifier_info[UDP_SRC])
            elif field.type == fd.IPV4_DST:
                classifier_info[IPV4_DST] = field.ipv4_dst
                self.log.debug('field-type-ipv4-dst',
                               ipv4_dst=classifier_info[IPV4_DST])
            elif field.type == fd.IPV4_SRC:
                classifier_info[IPV4_SRC] = field.ipv4_src
                self.log.debug('field-type-ipv4-src',
                               ipv4_dst=classifier_info[IPV4_SRC])
            elif field.type == fd.METADATA:
                classifier_info[METADATA] = field.table_metadata
                self.log.debug('field-type-metadata',
                               metadata=classifier_info[METADATA])
            else:
                raise NotImplementedError('field.type={}'.format(
                    field.type))

        for action in fd.get_actions(flow):
            if action.type == fd.OUTPUT:
                action_info[OUTPUT] = action.output.port
                self.log.debug('action-type-output',
                               output=action_info[OUTPUT],
                               in_port=classifier_info[IN_PORT])
            elif action.type == fd.POP_VLAN:
                if fd.get_goto_table_id(flow) is None:
                    self.log.debug('being taken care of by ONU', flow=flow)
                    return
                action_info[POP_VLAN] = True
                self.log.debug('action-type-pop-vlan',
                               in_port=classifier_info[IN_PORT])
            elif action.type == fd.PUSH_VLAN:
                action_info[PUSH_VLAN] = True
                action_info[TPID] = action.push.ethertype
                self.log.debug('action-type-push-vlan',
                               push_tpid=action_info[TPID], in_port=classifier_info[IN_PORT])
                if action.push.ethertype != 0x8100:
                    self.log.error('unhandled-tpid',
                                   ethertype=action.push.ethertype)
            elif action.type == fd.SET_FIELD:
                # action_info['action_type'] = 'set_field'
                _field = action.set_field.field.ofb_field
                assert (action.set_field.field.oxm_class ==
                        OFPXMC_OPENFLOW_BASIC)
                self.log.debug('action-type-set-field',
                               field=_field, in_port=classifier_info[IN_PORT])
                if _field.type == fd.VLAN_VID:
                    self.log.debug('set-field-type-vlan-vid',
                                   vlan_vid=_field.vlan_vid & 0xfff)
                    action_info[VLAN_VID] = (_field.vlan_vid & 0xfff)
                else:
                    self.log.error('unsupported-action-set-field-type',
                                   field_type=_field.type)
            else:
                self.log.error('unsupported-action-type',
                               action_type=action.type, in_port=classifier_info[IN_PORT])

        if fd.get_goto_table_id(flow) is not None and POP_VLAN not in action_info:
            self.log.debug('being taken care of by ONU', flow=flow)
            return

        if OUTPUT not in action_info and METADATA in classifier_info:
            # find flow in the next table
            next_flow = self.find_next_flow(flow)
            if next_flow is None:
                return
            action_info[OUTPUT] = fd.get_out_port(next_flow)
            for field in fd.get_ofb_fields(next_flow):
                if field.type == fd.VLAN_VID:
                    classifier_info[METADATA] = field.vlan_vid & 0xfff

        self.log.debug('flow-ports', classifier_inport=classifier_info[IN_PORT], action_output=action_info[OUTPUT])
        (port_no, intf_id, onu_id, uni_id) = self.platform.extract_access_from_flow(
            classifier_info[IN_PORT], action_info[OUTPUT])

        self.divide_and_add_flow(intf_id, onu_id, uni_id, port_no, classifier_info,
                                 action_info, flow)

    def _is_uni_port(self, port_no):
        try:
            port = self.adapter_agent.get_logical_port(self.logical_device_id,
                                                       'uni-{}'.format(port_no))
            if port is not None:
                return (not port.root_port), port.device_id
            else:
                return False, None
        except Exception as e:
            self.log.error("error-retrieving-port", e=e)
            return False, None

    def _clear_flow_id_from_rm(self, flow, flow_id, flow_direction):
        uni_port_no = None
        child_device_id = None
        if flow_direction == UPSTREAM:
            for field in fd.get_ofb_fields(flow):
                if field.type == fd.IN_PORT:
                    is_uni, child_device_id = self._is_uni_port(field.port)
                    if is_uni:
                        uni_port_no = field.port
        elif flow_direction == DOWNSTREAM:
            for field in fd.get_ofb_fields(flow):
                if field.type == fd.METADATA:
                    uni_port = field.table_metadata & 0xFFFFFFFF
                    is_uni, child_device_id = self._is_uni_port(uni_port)
                    if is_uni:
                        uni_port_no = field.port

            if uni_port_no is None:
                for action in fd.get_actions(flow):
                    if action.type == fd.OUTPUT:
                        is_uni, child_device_id = \
                            self._is_uni_port(action.output.port)
                        if is_uni:
                            uni_port_no = action.output.port

        if child_device_id:
            child_device = self.adapter_agent.get_device(child_device_id)
            pon_intf = child_device.proxy_address.channel_id
            onu_id = child_device.proxy_address.onu_id
            uni_id = self.platform.uni_id_from_port_num(uni_port_no) if uni_port_no is not None else None
            flows = self.resource_mgr.get_flow_id_info(pon_intf, onu_id, uni_id, flow_id)
            assert (isinstance(flows, list))
            self.log.debug("retrieved-flows", flows=flows)
            for idx in range(len(flows)):
                if flow_direction == flows[idx]['flow_type']:
                    flows.pop(idx)
                    self.update_flow_info_to_kv_store(pon_intf, onu_id, uni_id, flow_id, flows)
                    if len(flows) > 0:
                        # There are still flows referencing the same flow_id.
                        # So the flow should not be freed yet.
                        # For ex: Case of HSIA where same flow is shared
                        # between DS and US.
                        return

            self.resource_mgr.free_flow_id_for_uni(pon_intf, onu_id, uni_id, flow_id)
        else:
            self.log.error("invalid-info", uni_port_no=uni_port_no,
                           child_device_id=child_device_id)

    def retry_add_flow(self, flow):
        self.log.debug("retry-add-flow")
        if flow.id in self.retry_add_flow_list:
            self.retry_add_flow_list.remove(flow.id)
        self.add_flow(flow)

    def remove_flow(self, flow):
        self.log.debug('trying to remove flows from logical flow :',
                       logical_flow=flow)
        device_flows_to_remove = []
        device_flows = self.flows_proxy.get('/').items
        for f in device_flows:
            if f.cookie == flow.id:
                device_flows_to_remove.append(f)

        for f in device_flows_to_remove:
            (id, direction) = self.decode_stored_id(f.id)
            flow_to_remove = openolt_pb2.Flow(flow_id=id, flow_type=direction)
            try:
                self.stub.FlowRemove(flow_to_remove)
            except grpc.RpcError as grpc_e:
                if grpc_e.code() == grpc.StatusCode.NOT_FOUND:
                    self.log.debug('This flow does not exist on the switch, '
                                   'normal after an OLT reboot',
                                   flow=flow_to_remove)
                else:
                    raise grpc_e

            # once we have successfully deleted the flow on the device
            # release the flow_id on resource pool and also clear any
            # data associated with the flow_id on KV store.
            self._clear_flow_id_from_rm(f, id, direction)
            self.log.debug('flow removed from device', flow=f,
                           flow_key=flow_to_remove)

        if len(device_flows_to_remove) > 0:
            new_flows = []
            flows_ids_to_remove = [f.id for f in device_flows_to_remove]
            for f in device_flows:
                if f.id not in flows_ids_to_remove:
                    new_flows.append(f)

            self.flows_proxy.update('/', Flows(items=new_flows))
            self.log.debug('flows removed from the data store',
                           flow_ids_removed=flows_ids_to_remove,
                           number_of_flows_removed=(len(device_flows) - len(
                               new_flows)), expected_flows_removed=len(
                    device_flows_to_remove))
        else:
            self.log.debug('no device flow to remove for this flow (normal '
                           'for multi table flows)', flow=flow)

    def _get_ofp_port_name(self, intf_id, onu_id, uni_id):
        parent_port_no = self.platform.intf_id_to_port_no(intf_id, Port.PON_OLT)
        child_device = self.adapter_agent.get_child_device(self.device_id,
                                                           parent_port_no=parent_port_no, onu_id=onu_id)
        if child_device is None:
            self.log.error("could-not-find-child-device",
                           parent_port_no=intf_id, onu_id=onu_id)
            return (None, None)
        ports = self.adapter_agent.get_ports(child_device.id, Port.ETHERNET_UNI)
        logical_port = self.adapter_agent.get_logical_port(
            self.logical_device_id, ports[uni_id].label)
        ofp_port_name = (logical_port.ofp_port.name, logical_port.ofp_port.port_no)
        return ofp_port_name

    def get_tp_path(self, intf_id, ofp_port_name):
        # FIXME Should get Table id form the flow, as of now hardcoded to
        # DEFAULT_TECH_PROFILE_TABLE_ID (64)
        # 'tp_path' contains the suffix part of the tech_profile_instance path.
        # The prefix to the 'tp_path' should be set to \
        # TechProfile.KV_STORE_TECH_PROFILE_PATH_PREFIX by the ONU adapter.
        return self.tech_profile[intf_id]. \
            get_tp_path(DEFAULT_TECH_PROFILE_TABLE_ID,
                        ofp_port_name)

    def delete_tech_profile_instance(self, intf_id, onu_id, uni_id):
        # Remove the TP instance associated with the ONU
        ofp_port_name = self._get_ofp_port_name(intf_id, onu_id, uni_id)
        tp_path = self.get_tp_path(intf_id, ofp_port_name)
        return self.tech_profile[intf_id].delete_tech_profile_instance(tp_path)

    def divide_and_add_flow(self, intf_id, onu_id, uni_id, port_no, classifier,
                            action, flow):

        self.log.debug('sorting flow', intf_id=intf_id, onu_id=onu_id, uni_id=uni_id, port_no=port_no,
                       classifier=classifier, action=action)

        alloc_id, gem_ports = self.create_tcont_gemport(intf_id, onu_id, uni_id,
                                                        flow.table_id)
        if alloc_id is None or gem_ports is None:
            self.log.error("alloc-id-gem-ports-unavailable", alloc_id=alloc_id,
                           gem_ports=gem_ports)
            return

        self.log.debug('Generated required alloc and gemport ids',
                       alloc_id=alloc_id, gemports=gem_ports)

        # Flows can't be added specific to gemport unless p-bits are received.
        # Hence adding flows for all gemports
        for gemport_id in gem_ports:
            if IP_PROTO in classifier:
                if classifier[IP_PROTO] == 17:
                    self.log.debug('dhcp flow add')
                    self.add_dhcp_trap(intf_id, onu_id, uni_id, port_no, classifier,
                                       action, flow, alloc_id, gemport_id)
                elif classifier[IP_PROTO] == 2:
                    self.log.warn('igmp flow add ignored, not implemented yet')
                else:
                    self.log.warn("Invalid-Classifier-to-handle",
                                  classifier=classifier,
                                  action=action)
            elif ETH_TYPE in classifier:
                if classifier[ETH_TYPE] == EAP_ETH_TYPE:
                    self.log.debug('eapol flow add')
                    self.add_eapol_flow(intf_id, onu_id, uni_id, port_no, flow, alloc_id,
                                        gemport_id)
                    vlan_id = self.get_subscriber_vlan(fd.get_in_port(flow))
                    if vlan_id is not None:
                        self.add_eapol_flow(
                            intf_id, onu_id, uni_id, port_no, flow, alloc_id, gemport_id,
                            vlan_id=vlan_id)
                    parent_port_no = self.platform.intf_id_to_port_no(intf_id, Port.PON_OLT)
                    onu_device = self.adapter_agent.get_child_device(self.device_id,
                                                                     onu_id=onu_id,
                                                                     parent_port_no=parent_port_no)
                    (ofp_port_name, ofp_port_no) = self._get_ofp_port_name(intf_id, onu_id, uni_id)
                    if ofp_port_name is None:
                        self.log.error("port-name-not-found")
                        return

                    tp_path = self.get_tp_path(intf_id, ofp_port_name)

                    self.log.debug('Load-tech-profile-request-to-brcm-handler',
                                   tp_path=tp_path)
                    msg = {'proxy_address': onu_device.proxy_address, 'uni_id': uni_id,
                           'event': 'download_tech_profile', 'event_data': tp_path}

                    # Send the event message to the ONU adapter
                    self.adapter_agent.publish_inter_adapter_message(onu_device.id,
                                                                     msg)

                if classifier[ETH_TYPE] == LLDP_ETH_TYPE:
                    self.log.debug('lldp flow add')
                    nni_intf_id = self.get_nni_intf_id()
                    self.add_lldp_flow(flow, port_no, nni_intf_id)

            elif PUSH_VLAN in action:
                self.add_upstream_data_flow(intf_id, onu_id, uni_id, port_no, classifier,
                                            action, flow, alloc_id, gemport_id)
            elif POP_VLAN in action:
                self.add_downstream_data_flow(intf_id, onu_id, uni_id, port_no, classifier,
                                              action, flow, alloc_id, gemport_id)
            else:
                self.log.debug('Invalid-flow-type-to-handle',
                               classifier=classifier,
                               action=action, flow=flow)

    def create_tcont_gemport(self, intf_id, onu_id, uni_id, table_id):
        alloc_id, gem_port_ids = None, None
        pon_intf_onu_id = (intf_id, onu_id)

        # If we already have allocated alloc_id and gem_ports earlier, render them
        alloc_id = \
            self.resource_mgr.get_current_alloc_ids_for_onu(pon_intf_onu_id)
        gem_port_ids = \
            self.resource_mgr.get_current_gemport_ids_for_onu(pon_intf_onu_id)
        if alloc_id is not None and gem_port_ids is not None:
            return alloc_id, gem_port_ids

        try:
            (ofp_port_name, ofp_port_no) = self._get_ofp_port_name(intf_id, onu_id, uni_id)
            if ofp_port_name is None:
                self.log.error("port-name-not-found")
                return alloc_id, gem_port_ids
            # FIXME: If table id is <= 63 using 64 as table id
            if table_id < DEFAULT_TECH_PROFILE_TABLE_ID:
                table_id = DEFAULT_TECH_PROFILE_TABLE_ID

            # Check tech profile instance already exists for derived port name
            tech_profile_instance = self.tech_profile[intf_id]. \
                get_tech_profile_instance(table_id, ofp_port_name)
            self.log.debug('Get-tech-profile-instance-status', tech_profile_instance=tech_profile_instance)

            if tech_profile_instance is None:
                # create tech profile instance
                tech_profile_instance = self.tech_profile[intf_id]. \
                    create_tech_profile_instance(table_id, ofp_port_name,
                                                 intf_id)
                if tech_profile_instance is None:
                    raise Exception('Tech-profile-instance-creation-failed')
            else:
                self.log.debug(
                    'Tech-profile-instance-already-exist-for-given port-name',
                    ofp_port_name=ofp_port_name)

            # upstream scheduler
            us_scheduler = self.tech_profile[intf_id].get_us_scheduler(
                tech_profile_instance)
            # downstream scheduler
            ds_scheduler = self.tech_profile[intf_id].get_ds_scheduler(
                tech_profile_instance)
            # create Tcont
            tconts = self.tech_profile[intf_id].get_tconts(tech_profile_instance,
                                                           us_scheduler,
                                                           ds_scheduler)

            self.stub.CreateTconts(openolt_pb2.Tconts(intf_id=intf_id,
                                                      onu_id=onu_id,
                                                      uni_id=uni_id,
                                                      port_no=ofp_port_no,
                                                      tconts=tconts))

            # Fetch alloc id and gemports from tech profile instance
            alloc_id = tech_profile_instance.us_scheduler.alloc_id
            gem_port_ids = []
            for i in range(len(
                    tech_profile_instance.upstream_gem_port_attribute_list)):
                gem_port_ids.append(
                    tech_profile_instance.upstream_gem_port_attribute_list[i].
                    gemport_id)
        except BaseException as e:
            self.log.exception(exception=e)

        # Update the allocated alloc_id and gem_port_id for the ONU/UNI to KV store
        pon_intf_onu_id = (intf_id, onu_id, uni_id)
        self.resource_mgr.resource_mgrs[intf_id].update_alloc_ids_for_onu(
            pon_intf_onu_id,
            list([alloc_id])
        )
        self.resource_mgr.resource_mgrs[intf_id].update_gemport_ids_for_onu(
            pon_intf_onu_id,
            gem_port_ids
        )

        self.resource_mgr.update_gemports_ponport_to_onu_map_on_kv_store(
            gem_port_ids, intf_id, onu_id, uni_id
        )

        return alloc_id, gem_port_ids

    def add_upstream_data_flow(self, intf_id, onu_id, uni_id, port_no, uplink_classifier,
                               uplink_action, logical_flow, alloc_id,
                               gemport_id):

        uplink_classifier[PACKET_TAG_TYPE] = SINGLE_TAG

        self.add_hsia_flow(intf_id, onu_id, uni_id, port_no, uplink_classifier,
                           uplink_action, UPSTREAM,
                           logical_flow, alloc_id, gemport_id)

        # Secondary EAP on the subscriber vlan
        (eap_active, eap_logical_flow) = self.is_eap_enabled(intf_id, onu_id, uni_id)
        if eap_active:
            self.add_eapol_flow(intf_id, onu_id, uni_id, port_no, eap_logical_flow, alloc_id,
                                gemport_id, vlan_id=uplink_classifier[VLAN_VID])

    def add_downstream_data_flow(self, intf_id, onu_id, uni_id, port_no, downlink_classifier,
                                 downlink_action, flow, alloc_id, gemport_id):
        downlink_classifier[PACKET_TAG_TYPE] = DOUBLE_TAG
        # Needed ???? It should be already there
        downlink_action[POP_VLAN] = True
        downlink_action[VLAN_VID] = downlink_classifier[VLAN_VID]

        self.add_hsia_flow(intf_id, onu_id, uni_id, port_no, downlink_classifier,
                           downlink_action, DOWNSTREAM,
                           flow, alloc_id, gemport_id)

    def add_hsia_flow(self, intf_id, onu_id, uni_id, port_no, classifier, action,
                      direction, logical_flow, alloc_id, gemport_id):

        flow_store_cookie = self._get_flow_store_cookie(classifier,
                                                        gemport_id)

        # One of the OLT platform (Broadcom BAL) requires that symmetric
        # flows require the same flow_id to be used across UL and DL.
        # Since HSIA flow is the only symmetric flow currently, we need to
        # re-use the flow_id across both direction. The 'flow_category'
        # takes priority over flow_cookie to find any available HSIA_FLOW
        # id for the ONU.
        flow_id = self.resource_mgr.get_flow_id(intf_id, onu_id, uni_id,
                                                flow_store_cookie,
                                                HSIA_FLOW)
        if flow_id is None:
            self.log.error("hsia-flow-unavailable")
            return
        flow = openolt_pb2.Flow(
            access_intf_id=intf_id, onu_id=onu_id, uni_id=uni_id, flow_id=flow_id,
            flow_type=direction, alloc_id=alloc_id, network_intf_id=self.get_nni_intf_id(),
            gemport_id=gemport_id,
            classifier=self.mk_classifier(classifier),
            action=self.mk_action(action),
            priority=logical_flow.priority,
            port_no=port_no,
            cookie=logical_flow.cookie)

        if self.add_flow_to_device(flow, logical_flow):
            flow_info = self._get_flow_info_as_json_blob(flow,
                                                         flow_store_cookie,
                                                         HSIA_FLOW)
            self.update_flow_info_to_kv_store(flow.access_intf_id,
                                              flow.onu_id, flow.uni_id,
                                              flow.flow_id, flow_info)

    def add_dhcp_trap(self, intf_id, onu_id, uni_id, port_no, classifier, action, logical_flow,
                      alloc_id, gemport_id):

        self.log.debug('add dhcp upstream trap', classifier=classifier,
                       intf_id=intf_id, onu_id=onu_id, uni_id=uni_id, action=action)

        action.clear()
        action[TRAP_TO_HOST] = True
        classifier[UDP_SRC] = 68
        classifier[UDP_DST] = 67
        classifier[PACKET_TAG_TYPE] = SINGLE_TAG
        classifier.pop(VLAN_VID, None)

        flow_store_cookie = self._get_flow_store_cookie(classifier,
                                                        gemport_id)

        flow_id = self.resource_mgr.get_flow_id(
            intf_id, onu_id, uni_id, flow_store_cookie
        )
        dhcp_flow = openolt_pb2.Flow(
            onu_id=onu_id, uni_id=uni_id, flow_id=flow_id, flow_type=UPSTREAM,
            access_intf_id=intf_id, gemport_id=gemport_id,
            alloc_id=alloc_id, network_intf_id=self.get_nni_intf_id(),
            priority=logical_flow.priority,
            classifier=self.mk_classifier(classifier),
            action=self.mk_action(action),
            port_no=port_no,
            cookie=logical_flow.cookie)

        if self.add_flow_to_device(dhcp_flow, logical_flow):
            flow_info = self._get_flow_info_as_json_blob(dhcp_flow, flow_store_cookie)
            self.update_flow_info_to_kv_store(dhcp_flow.access_intf_id,
                                              dhcp_flow.onu_id,
                                              dhcp_flow.uni_id,
                                              dhcp_flow.flow_id,
                                              flow_info)

    def add_eapol_flow(self, intf_id, onu_id, uni_id, port_no, logical_flow, alloc_id,
                       gemport_id, vlan_id=DEFAULT_MGMT_VLAN):

        uplink_classifier = dict()
        uplink_classifier[ETH_TYPE] = EAP_ETH_TYPE
        uplink_classifier[PACKET_TAG_TYPE] = SINGLE_TAG
        uplink_classifier[VLAN_VID] = vlan_id

        uplink_action = dict()
        uplink_action[TRAP_TO_HOST] = True

        flow_store_cookie = self._get_flow_store_cookie(uplink_classifier,
                                                        gemport_id)
        # Add Upstream EAPOL Flow.
        uplink_flow_id = self.resource_mgr.get_flow_id(
            intf_id, onu_id, uni_id, flow_store_cookie
        )

        upstream_flow = openolt_pb2.Flow(
            access_intf_id=intf_id, onu_id=onu_id, uni_id=uni_id, flow_id=uplink_flow_id,
            flow_type=UPSTREAM, alloc_id=alloc_id, network_intf_id=self.get_nni_intf_id(),
            gemport_id=gemport_id,
            classifier=self.mk_classifier(uplink_classifier),
            action=self.mk_action(uplink_action),
            priority=logical_flow.priority,
            port_no=port_no,
            cookie=logical_flow.cookie)

        logical_flow = copy.deepcopy(logical_flow)
        logical_flow.match.oxm_fields.extend(fd.mk_oxm_fields([fd.vlan_vid(
            vlan_id | 0x1000)]))
        logical_flow.match.type = OFPMT_OXM

        if self.add_flow_to_device(upstream_flow, logical_flow):
            flow_info = self._get_flow_info_as_json_blob(upstream_flow,
                                                         flow_store_cookie)
            self.update_flow_info_to_kv_store(upstream_flow.access_intf_id,
                                              upstream_flow.onu_id,
                                              upstream_flow.uni_id,
                                              upstream_flow.flow_id,
                                              flow_info)

        if vlan_id == DEFAULT_MGMT_VLAN:
            # Add Downstream EAPOL Flow, Only for first EAP flow (BAL
            # requirement)
            # On one of the platforms (Broadcom BAL), when same DL classifier
            # vlan was used across multiple ONUs, eapol flow re-adds after
            # flow delete (cases of onu reboot/disable) fails.
            # In order to generate unique vlan, a combination of intf_id
            # onu_id and uni_id is used.
            # uni_id defaults to 0, so add 1 to it.
            special_vlan_downstream_flow = 4090 - intf_id * onu_id * (uni_id+1)
            # Assert that we do not generate invalid vlans under no condition
            assert (special_vlan_downstream_flow >= 2, 'invalid-vlan-generated')

            downlink_classifier = dict()
            downlink_classifier[PACKET_TAG_TYPE] = SINGLE_TAG
            downlink_classifier[VLAN_VID] = special_vlan_downstream_flow

            downlink_action = dict()
            downlink_action[PUSH_VLAN] = True
            downlink_action[VLAN_VID] = vlan_id


            flow_store_cookie = self._get_flow_store_cookie(downlink_classifier,
                                                            gemport_id)

            downlink_flow_id = self.resource_mgr.get_flow_id(
                intf_id, onu_id, uni_id, flow_store_cookie
            )

            downstream_flow = openolt_pb2.Flow(
                access_intf_id=intf_id, onu_id=onu_id, uni_id=uni_id, flow_id=downlink_flow_id,
                flow_type=DOWNSTREAM, alloc_id=alloc_id, network_intf_id=self.get_nni_intf_id(),
                gemport_id=gemport_id,
                classifier=self.mk_classifier(downlink_classifier),
                action=self.mk_action(downlink_action),
                priority=logical_flow.priority,
                port_no=port_no,
                cookie=logical_flow.cookie)

            downstream_logical_flow = ofp_flow_stats(
                id=logical_flow.id, cookie=logical_flow.cookie,
                table_id=logical_flow.table_id, priority=logical_flow.priority,
                flags=logical_flow.flags)

            downstream_logical_flow.match.oxm_fields.extend(fd.mk_oxm_fields([
                fd.in_port(fd.get_out_port(logical_flow)),
                fd.vlan_vid(special_vlan_downstream_flow | 0x1000)]))
            downstream_logical_flow.match.type = OFPMT_OXM

            downstream_logical_flow.instructions.extend(
                fd.mk_instructions_from_actions([fd.output(
                    self.platform.mk_uni_port_num(intf_id, onu_id, uni_id))]))

            if self.add_flow_to_device(downstream_flow, downstream_logical_flow):
                flow_info = self._get_flow_info_as_json_blob(downstream_flow,
                                                             flow_store_cookie)
                self.update_flow_info_to_kv_store(downstream_flow.access_intf_id,
                                                  downstream_flow.onu_id,
                                                  downstream_flow.uni_id,
                                                  downstream_flow.flow_id,
                                                  flow_info)

    def repush_all_different_flows(self):
        # Check if the device is supposed to have flows, if so add them
        # Recover static flows after a reboot
        logical_flows = self.logical_flows_proxy.get('/').items
        devices_flows = self.flows_proxy.get('/').items
        logical_flows_ids_provisioned = [f.cookie for f in devices_flows]
        for logical_flow in logical_flows:
            try:
                if logical_flow.id not in logical_flows_ids_provisioned:
                    self.add_flow(logical_flow)
            except Exception as e:
                self.log.exception('Problem reading this flow', e=e)

    def reset_flows(self):
        self.flows_proxy.update('/', Flows())

    """ Add a downstream LLDP trap flow on the NNI interface
    """

    def add_lldp_flow(self, logical_flow, port_no, network_intf_id=0):

        classifier = dict()
        classifier[ETH_TYPE] = LLDP_ETH_TYPE
        classifier[PACKET_TAG_TYPE] = UNTAGGED
        action = dict()
        action[TRAP_TO_HOST] = True

        # LLDP flow is installed to trap LLDP packets on the NNI port.
        # We manage flow_id resource pool on per PON port basis.
        # Since this situation is tricky, as a hack, we pass the NNI port
        # index (network_intf_id) as PON port Index for the flow_id resource
        # pool. Also, there is no ONU Id available for trapping LLDP packets
        # on NNI port, use onu_id as -1 (invalid)
        # ****************** CAVEAT *******************
        # This logic works if the NNI Port Id falls within the same valid
        # range of PON Port Ids. If this doesn't work for some OLT Vendor
        # we need to have a re-look at this.
        # *********************************************
        onu_id = -1
        uni_id = -1
        flow_store_cookie = self._get_flow_store_cookie(classifier)
        flow_id = self.resource_mgr.get_flow_id(network_intf_id, onu_id, uni_id,
                                                flow_store_cookie)

        downstream_flow = openolt_pb2.Flow(
            access_intf_id=-1,  # access_intf_id not required
            onu_id=onu_id, # onu_id not required
            uni_id=uni_id, # uni_id not used
            flow_id=flow_id,
            flow_type=DOWNSTREAM,
            network_intf_id=network_intf_id,
            gemport_id=-1,  # gemport_id not required
            classifier=self.mk_classifier(classifier),
            action=self.mk_action(action),
            priority=logical_flow.priority,
            port_no=port_no,
            cookie=logical_flow.cookie)

        self.log.debug('add lldp downstream trap', classifier=classifier,
                       action=action, flow=downstream_flow, port_no=port_no)
        if self.add_flow_to_device(downstream_flow, logical_flow):
            self.update_flow_info_to_kv_store(network_intf_id, onu_id, uni_id,
                                              flow_id, downstream_flow)

    def mk_classifier(self, classifier_info):

        classifier = openolt_pb2.Classifier()

        if ETH_TYPE in classifier_info:
            classifier.eth_type = classifier_info[ETH_TYPE]
        if IP_PROTO in classifier_info:
            classifier.ip_proto = classifier_info[IP_PROTO]
        if VLAN_VID in classifier_info:
            classifier.o_vid = classifier_info[VLAN_VID]
        if METADATA in classifier_info:
            classifier.i_vid = classifier_info[METADATA]
        if VLAN_PCP in classifier_info:
            classifier.o_pbits = classifier_info[VLAN_PCP]
        if UDP_SRC in classifier_info:
            classifier.src_port = classifier_info[UDP_SRC]
        if UDP_DST in classifier_info:
            classifier.dst_port = classifier_info[UDP_DST]
        if IPV4_DST in classifier_info:
            classifier.dst_ip = classifier_info[IPV4_DST]
        if IPV4_SRC in classifier_info:
            classifier.src_ip = classifier_info[IPV4_SRC]
        if PACKET_TAG_TYPE in classifier_info:
            if classifier_info[PACKET_TAG_TYPE] == SINGLE_TAG:
                classifier.pkt_tag_type = SINGLE_TAG
            elif classifier_info[PACKET_TAG_TYPE] == DOUBLE_TAG:
                classifier.pkt_tag_type = DOUBLE_TAG
            elif classifier_info[PACKET_TAG_TYPE] == UNTAGGED:
                classifier.pkt_tag_type = UNTAGGED
            else:
                classifier.pkt_tag_type = 'none'

        return classifier

    def mk_action(self, action_info):
        action = openolt_pb2.Action()

        if POP_VLAN in action_info:
            action.o_vid = action_info[VLAN_VID]
            action.cmd.remove_outer_tag = True
        elif PUSH_VLAN in action_info:
            action.o_vid = action_info[VLAN_VID]
            action.cmd.add_outer_tag = True
        elif TRAP_TO_HOST in action_info:
            action.cmd.trap_to_host = True
        else:
            self.log.info('Invalid-action-field', action_info=action_info)
            return
        return action

    def is_eap_enabled(self, intf_id, onu_id, uni_id):
        flows = self.logical_flows_proxy.get('/').items

        for flow in flows:
            eap_flow = False
            eap_intf_id = None
            eap_onu_id = None
            eap_uni_id = None
            for field in fd.get_ofb_fields(flow):
                if field.type == fd.ETH_TYPE:
                    if field.eth_type == EAP_ETH_TYPE:
                        eap_flow = True
                if field.type == fd.IN_PORT:
                    eap_intf_id = self.platform.intf_id_from_uni_port_num(
                        field.port)
                    eap_onu_id = self.platform.onu_id_from_port_num(field.port)
                    eap_uni_id = self.platform.uni_id_from_port_num(field.port)

            if eap_flow:
                self.log.debug('eap flow detected', onu_id=onu_id, uni_id=uni_id,
                               intf_id=intf_id, eap_intf_id=eap_intf_id,
                               eap_onu_id=eap_onu_id,
                               eap_uni_id=eap_uni_id)
            if eap_flow and intf_id == eap_intf_id and onu_id == eap_onu_id and uni_id == eap_uni_id:
                return True, flow

        return False, None

    def get_subscriber_vlan(self, port):
        self.log.debug('looking from subscriber flow for port', port=port)

        flows = self.logical_flows_proxy.get('/').items
        for flow in flows:
            in_port = fd.get_in_port(flow)
            out_port = fd.get_out_port(flow)
            if in_port == port and out_port is not None and \
                    self.platform.intf_id_to_port_type_name(out_port) \
                    == Port.ETHERNET_NNI:
                fields = fd.get_ofb_fields(flow)
                self.log.debug('subscriber flow found', fields=fields)
                for field in fields:
                    if field.type == OFPXMT_OFB_VLAN_VID:
                        self.log.debug('subscriber vlan found',
                                       vlan_id=field.vlan_vid)
                        return field.vlan_vid & 0x0fff
        self.log.debug('No subscriber flow found', port=port)
        return None

    def add_flow_to_device(self, flow, logical_flow):
        self.log.debug('pushing flow to device', flow=flow)
        try:
            self.stub.FlowAdd(flow)
        except grpc.RpcError as grpc_e:
            if grpc_e.code() == grpc.StatusCode.ALREADY_EXISTS:
                self.log.warn('flow already exists', e=grpc_e, flow=flow)
            else:
                self.log.error('failed to add flow',
                               logical_flow=logical_flow, flow=flow,
                               grpc_error=grpc_e)
            return False
        else:
            self.register_flow(logical_flow, flow)
            return True

    def update_flow_info_to_kv_store(self, intf_id, onu_id, uni_id, flow_id, flow):
        self.resource_mgr.update_flow_id_info_for_uni(intf_id, onu_id, uni_id,
                                                      flow_id, flow)

    def register_flow(self, logical_flow, device_flow):
        self.log.debug('registering flow in device',
                       logical_flow=logical_flow, device_flow=device_flow)
        stored_flow = copy.deepcopy(logical_flow)
        stored_flow.id = self.generate_stored_id(device_flow.flow_id,
                                                 device_flow.flow_type)
        self.log.debug('generated device flow id', id=stored_flow.id,
                       flow_id=device_flow.flow_id,
                       direction=device_flow.flow_type)
        stored_flow.cookie = logical_flow.id
        flows = self.flows_proxy.get('/')
        flows.items.extend([stored_flow])
        self.flows_proxy.update('/', flows)

    def find_next_flow(self, flow):
        table_id = fd.get_goto_table_id(flow)
        metadata = 0
        # Prior to ONOS 1.13.5, Metadata contained the UNI output port number. In
        # 1.13.5 and later, the lower 32-bits is the output port number and the
        # upper 32-bits is the inner-vid we are looking for. Use just the lower 32
        # bits.  Allows this code to work with pre- and post-1.13.5 ONOS OltPipeline

        for field in fd.get_ofb_fields(flow):
            if field.type == fd.METADATA:
                metadata = field.table_metadata & 0xFFFFFFFF
        if table_id is None:
            return None
        flows = self.logical_flows_proxy.get('/').items
        next_flows = []
        for f in flows:
            if f.table_id == table_id:
                # FIXME
                if fd.get_in_port(f) == fd.get_in_port(flow) and \
                        fd.get_out_port(f) == metadata:
                    next_flows.append(f)

        if len(next_flows) == 0:
            self.log.warning('no next flow found, it may be a timing issue',
                             flow=flow, number_of_flows=len(flows))
            if flow.id in self.retry_add_flow_list:
                self.log.debug('flow is already in retry list', flow_id=flow.id)
            else:
                self.retry_add_flow_list.append(flow.id)
                reactor.callLater(5, self.retry_add_flow, flow)
            return None

        next_flows.sort(key=lambda f: f.priority, reverse=True)

        return next_flows[0]

    def update_children_flows(self, device_rules_map):

        for device_id, (flows, groups) in device_rules_map.iteritems():
            if device_id != self.device_id:
                self.root_proxy.update('/devices/{}/flows'.format(device_id),
                                       Flows(items=flows.values()))
                self.root_proxy.update('/devices/{}/flow_groups'.format(
                    device_id), FlowGroups(items=groups.values()))

    def clear_flows_and_scheduler_for_logical_port(self, child_device, logical_port):
        ofp_port_name = logical_port.ofp_port.name
        port_no = logical_port.ofp_port.port_no
        pon_port = child_device.proxy_address.channel_id
        onu_id = child_device.proxy_address.onu_id
        uni_id = self.platform.uni_id_from_port_num(logical_port)

        # TODO: The DEFAULT_TECH_PROFILE_ID is assumed. Right way to do,
        # is probably to maintain a list of Tech-profile table IDs associated
        # with the UNI logical_port. This way, when the logical port is deleted,
        # all the associated tech-profile configuration with the UNI logical_port
        # can be cleared.
        tech_profile_instance = self.tech_profile[pon_port]. \
            get_tech_profile_instance(
            DEFAULT_TECH_PROFILE_TABLE_ID,
            ofp_port_name)
        flow_ids = self.resource_mgr.get_current_flow_ids_for_uni(pon_port, onu_id, uni_id)
        self.log.debug("outstanding-flows-to-be-cleared", flow_ids=flow_ids)
        for flow_id in flow_ids:
            flow_infos = self.resource_mgr.get_flow_id_info(pon_port, onu_id, uni_id, flow_id)
            for flow_info in flow_infos:
                direction = flow_info['flow_type']
                flow_to_remove = openolt_pb2.Flow(flow_id=flow_id,
                                                  flow_type=direction)
                try:
                    self.stub.FlowRemove(flow_to_remove)
                except grpc.RpcError as grpc_e:
                    if grpc_e.code() == grpc.StatusCode.NOT_FOUND:
                        self.log.debug('This flow does not exist on the switch, '
                                       'normal after an OLT reboot',
                                       flow=flow_to_remove)
                    else:
                        raise grpc_e

                self.resource_mgr.free_flow_id_for_uni(pon_port, onu_id, uni_id, flow_id)

        try:
            tconts = self.tech_profile[pon_port].get_tconts(tech_profile_instance)
            self.stub.RemoveTconts(openolt_pb2.Tconts(intf_id=pon_port,
                                                      onu_id=onu_id,
                                                      uni_id=uni_id,
                                                      port_no=port_no,
                                                      tconts=tconts))
        except grpc.RpcError as grpc_e:
            self.log.error('error-removing-tcont-scheduler-queues',
                           err=grpc_e)

    def generate_stored_id(self, flow_id, direction):
        if direction == UPSTREAM:
            self.log.debug('upstream flow, shifting id')
            return 0x1 << 15 | flow_id
        elif direction == DOWNSTREAM:
            self.log.debug('downstream flow, not shifting id')
            return flow_id
        else:
            self.log.warn('Unrecognized direction', direction=direction)
            return flow_id

    def decode_stored_id(self, id):
        if id >> 15 == 0x1:
            return id & 0x7fff, UPSTREAM
        else:
            return id, DOWNSTREAM

    def _populate_tech_profile_per_pon_port(self):
        for arange in self.resource_mgr.device_info.ranges:
            for intf_id in arange.intf_ids:
                self.tech_profile[intf_id] = \
                    self.resource_mgr.resource_mgrs[intf_id].tech_profile

        # Make sure we have as many tech_profiles as there are pon ports on
        # the device
        assert len(self.tech_profile) == self.resource_mgr.device_info.pon_ports

    def _get_flow_info_as_json_blob(self, flow, flow_store_cookie,
                                    flow_category=None):
        json_blob = MessageToDict(message=flow,
                                  preserving_proto_field_name=True)
        self.log.debug("flow-info", json_blob=json_blob)
        json_blob['flow_store_cookie'] = flow_store_cookie
        if flow_category is not None:
            json_blob['flow_category'] = flow_category
        flow_info = self.resource_mgr.get_flow_id_info(flow.access_intf_id,
                                                       flow.onu_id, flow.uni_id, flow.flow_id)

        if flow_info is None:
            flow_info = list()
            flow_info.append(json_blob)
        else:
            assert (isinstance(flow_info, list))
            flow_info.append(json_blob)

        return flow_info

    @staticmethod
    def _get_flow_store_cookie(classifier, gem_port=None):
        assert isinstance(classifier, dict)
        # We need unique flows per gem_port
        if gem_port is not None:
            to_hash = dumps(classifier, sort_keys=True) + str(gem_port)
        else:
            to_hash = dumps(classifier, sort_keys=True)
        return hashlib.md5(to_hash).hexdigest()[:12]

    def get_nni_intf_id(self):
        if self.nni_intf_id is not None:
            return self.nni_intf_id

        port_list = self.adapter_agent.get_ports(self.device_id, Port.ETHERNET_NNI)
        logical_port = self.adapter_agent.get_logical_port(self.logical_device_id,
                                                           port_list[0].label)
        self.nni_intf_id = self.platform.intf_id_from_nni_port_num(logical_port.ofp_port.port_no)
        self.log.debug("nni-intf-d ", nni_intf_id=self.nni_intf_id)
        return self.nni_intf_id
