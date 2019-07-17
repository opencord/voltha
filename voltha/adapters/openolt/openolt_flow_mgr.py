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
import ast
from simplejson import dumps

from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, \
    ofp_flow_stats, OFPMT_OXM, Flows, FlowGroups, \
    OFPXMT_OFB_VLAN_VID
from voltha.protos.device_pb2 import Port
import voltha.core.flow_decomposer as fd
from voltha.adapters.openolt.protos import openolt_pb2
from voltha.protos import tech_profile_pb2
from voltha.registry import registry
from common.tech_profile.tech_profile import Direction, TechProfile

# Flow categories
HSIA_FLOW = "HSIA_FLOW"
HSIA_TRANSPARENT = "HSIA_TRANSPARENT-{}"
DHCP_FLOW = "DHCP_FLOW"
EAPOL_FLOW = "EAPOL_FLOW"
LLDP_FLOW = "LLDP_FLOW"

EAP_ETH_TYPE = 0x888e
LLDP_ETH_TYPE = 0x88cc
IPV4_ETH_TYPE = 0x800
IPv6_ETH_TYPE = 0x86dd

IGMP_PROTO = 2

# FIXME - see also BRDCM_DEFAULT_VLAN in broadcom_onu.py
DEFAULT_MGMT_VLAN = 4091
RESERVED_VLAN = 4095

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

    def __init__(self, log, stub, device_id, logical_device_id,
                 platform, resource_mgr, data_model):
        self.data_model = data_model
        self.log = log
        self.stub = stub
        self.device_id = device_id
        self.logical_device_id = logical_device_id
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

    def update_logical_flows(self, flows_to_add, flows_to_remove,
                             device_rules_map):
        try:
            self.update_children_flows(device_rules_map)
        except Exception as e:
            self.log.error('Error updating children flows', error=e)

        self.log.debug('logical flows update', flows_to_add=flows_to_add,
                       flows_to_remove=flows_to_remove)

        for flow in flows_to_add:

            try:
                self.add_flow(flow)
            except Exception as e:
                self.log.error('failed to add flow', flow=flow, e=e)

        for flow in flows_to_remove:

            try:
                self.remove_flow(flow)
            except Exception as e:
                self.log.error('failed to remove flow', flow=flow, e=e)

        self.repush_all_different_flows()

    def add_flow(self, flow):
        self.log.debug('add flow', flow=flow)
        classifier_info = dict()
        action_info = dict()
        us_meter_id = None
        ds_meter_id = None

        for field in fd.get_ofb_fields(flow):
            if field.type == fd.ETH_TYPE:
                classifier_info[ETH_TYPE] = field.eth_type
                self.log.debug('field-type-eth-type',
                               eth_type=classifier_info[ETH_TYPE])
                if classifier_info[ETH_TYPE] == IPv6_ETH_TYPE:
                    self.log.debug('Not handling IPv6 flows')
                    return
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
                               push_tpid=action_info[TPID],
                               in_port=classifier_info[IN_PORT])
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
                elif _field.type == fd.VLAN_PCP:
                    self.log.debug('set-field-type-vlan-pcp',
                                   vlan_pcp=_field.vlan_pcp & 0x7)
                    action_info[VLAN_PCP] = (_field.vlan_pcp & 0x7)
                else:
                    self.log.error('unsupported-action-set-field-type',
                                   field_type=_field.type)
            else:
                self.log.error('unsupported-action-type',
                               action_type=action.type,
                               in_port=classifier_info[IN_PORT])

        if fd.get_goto_table_id(flow) is not None \
                and POP_VLAN not in action_info:
            self.log.debug('being taken care of by ONU', flow=flow)
            return

        flow_metadata = fd.get_metadata_from_write_metadata(flow)

        if OUTPUT not in action_info and flow_metadata is not None:
            # find flow in the next table
            next_flow = self.find_next_flow(flow, flow_metadata)
            if next_flow is None:
                return
            action_info[OUTPUT] = fd.get_out_port(next_flow)
            for field in fd.get_ofb_fields(next_flow):
                if field.type == fd.VLAN_VID:
                    classifier_info[METADATA] = field.vlan_vid & 0xfff

        self.log.debug('flow-ports',
                       classifier_inport=classifier_info[IN_PORT],
                       action_output=action_info[OUTPUT])
        (port_no, intf_id, onu_id, uni_id) \
            = self.platform.extract_access_from_flow(
            classifier_info[IN_PORT], action_info[OUTPUT])

        # LLDP flow has nothing to do with any particular subscriber.
        # So, lets not care about the Tech-profile, meters etc.
        # Just add the flow and return.
        if ETH_TYPE in classifier_info and \
                classifier_info[ETH_TYPE] == LLDP_ETH_TYPE:
            self.log.debug('lldp flow add')
            self.add_lldp_flow(flow, port_no)
            return

        if ETH_TYPE in classifier_info and \
                classifier_info[ETH_TYPE] == IPV4_ETH_TYPE and \
                IP_PROTO in classifier_info and \
                classifier_info[IP_PROTO] == 2:
            self.log.debug('igmp flow add ignored, not implemented yet')
            return

        if IP_PROTO in classifier_info and \
                classifier_info[IP_PROTO] == 17 and \
                UDP_SRC in classifier_info and \
                classifier_info[UDP_SRC] == 67:
            self.log.debug('trap-dhcp-from-nni-flow')
            self.add_dhcp_trap_nni(flow, classifier_info, port_no,
                                   network_intf_id=0)
            return

        # Metadata 8 bytes:
        #    Most Significant 2 Bytes = Inner VLAN
        #    Next 2 Bytes = Tech Profile ID(TPID)
        #    Least Significant 4 Bytes = Port ID
        # Flow METADATA carries Tech-Profile (TP) ID and is mandatory in all
        # subscriber related flows.
        # Note: If we are here, assert that the flow_metadata is not None
        assert flow_metadata is not None

        # Retrieve the TP-ID if one exists for the subscriber already
        tp_id = self.resource_mgr.get_tech_profile_id_for_onu(intf_id, onu_id, uni_id)

        if tp_id is not None:
            # Assert that the tp_id received in flow metadata is same is the tp_id in use
            # TODO:
            # For now, tp_id updates, require that we tear down the service and
            # and re-provision the service, i.e., dynamic TP updates not supported.

            assert tp_id == fd.get_tp_id_from_metadata(flow_metadata), \
                "tp-updates-not-supported"
        else:
            tp_id = fd.get_tp_id_from_metadata(flow_metadata)
            self.log.info("received-tp-id-from-flow", tp_id=tp_id)

        if self.platform.is_upstream(action_info[OUTPUT]):
            us_meter_id = fd.get_meter_id_from_flow(flow)
        else:
            ds_meter_id = fd.get_meter_id_from_flow(flow)

        self.divide_and_add_flow(intf_id, onu_id, uni_id, port_no,
                                 classifier_info, action_info, flow, tp_id, us_meter_id, ds_meter_id)

    def _is_uni_port(self, port_no):
        try:
            port = self.data_model.get_logical_port(self.logical_device_id,
                                                       'uni-{}'.format(port_no))
            if port is not None:
                return (not port.root_port), port.device_id
            else:
                return False, None
        except Exception as e:
            self.log.debug("port-not-found", e=e)
            return False, None

    def _is_upstream_flow(self, port_no):
        return self._is_uni_port(port_no)[0]

    def _is_downstream_flow(self, port_no):
        return not self._is_upstream_flow(port_no)

    def _clear_flow_id_from_rm(self, flow, flow_id, flow_direction):
        try:
            pon_intf, onu_id, uni_id, eth_type \
                = self.platform.flow_extract_info(flow, flow_direction)
        except ValueError:
            self.log.error("failure-extracting-flow-info")
            return
        else:
            if eth_type == LLDP_ETH_TYPE:
                network_intf_id = self.data_model.olt_nni_intf_id()
                onu_id = -1
                uni_id = -1

                self.resource_mgr.free_flow_id(network_intf_id, onu_id, uni_id, flow_id)
                return

            flows = self.resource_mgr.get_flow_id_info(pon_intf, onu_id, uni_id, flow_id)
            assert (isinstance(flows, list))
            self.log.debug("retrieved-flows", flows=flows)
            for idx in range(len(flows)):
                if flow_direction == flows[idx]['flow_type']:
                    flows.pop(idx)
                    self.update_flow_info_to_kv_store(pon_intf, onu_id,
                                                      uni_id, flow_id, flows)
                    if len(flows) > 0:
                        # There are still flows referencing the same flow_id.
                        # So the flow should not be freed yet.
                        # For ex: Case of HSIA where same flow is shared
                        # between DS and US.
                        return

            self.resource_mgr.free_flow_id(pon_intf, onu_id, uni_id, flow_id)
            flow_list = self.resource_mgr.get_current_flow_ids(pon_intf, onu_id, uni_id)
            if flow_list is None:
                tp_id = self.resource_mgr.get_tech_profile_id_for_onu(pon_intf, onu_id, uni_id)
                tp_instance = self.get_tech_profile_instance(pon_intf, onu_id, uni_id, tp_id)
                self.log.info("all-flows-cleared-for-onu")
                self.log.info("initiate-sched-queue-teardown")
                self.remove_us_scheduler_queues(pon_intf, onu_id, uni_id, tp_instance)
                self.remove_ds_scheduler_queues(pon_intf, onu_id, uni_id, tp_instance)

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

    def get_tp_path(self, intf_id, ofp_port_name, techprofile_id):
        return self.tech_profile[intf_id]. \
            get_tp_path(techprofile_id,
                        ofp_port_name)

    def delete_tech_profile_instance(self, intf_id, onu_id, uni_id,
                                     ofp_port_name=None):
        # Remove the TP instance associated with the ONU
        if ofp_port_name is None:
            ofp_port_name = self.data_model.serial_number(intf_id, onu_id)

        tp_id = self.resource_mgr.get_tech_profile_id_for_onu(intf_id, onu_id,
                                                              uni_id)
        tp_path = self.get_tp_path(intf_id, ofp_port_name, tp_id)
        self.log.debug(" tp-path-in-delete", tp_path=tp_path)
        return self.tech_profile[intf_id].delete_tech_profile_instance(tp_path)

    def is_no_l2_modification_flow(self, classifier, action):
        no_l2_classifier_set = {IN_PORT, METADATA, VLAN_VID}
        no_l2_action_set = {OUTPUT}
        incoming_classifier_set = set(classifier.keys())
        incoming_action_set = set(action.keys())

        if no_l2_classifier_set.issubset(incoming_classifier_set) and \
            no_l2_action_set.issubset(incoming_action_set) and \
                len(incoming_action_set) == 1:
            return True
        return False

    def divide_and_add_flow(self, intf_id, onu_id, uni_id, port_no, classifier,
                            action, flow, tp_id, us_meter_id, ds_meter_id):

        self.log.debug('sorting flow', intf_id=intf_id, onu_id=onu_id,
                       uni_id=uni_id, port_no=port_no,
                       classifier=classifier, action=action,
                       tp_id=tp_id, us_meter=us_meter_id,
                       ds_meter=ds_meter_id)

        tp_instance = self.get_tech_profile_instance(intf_id, onu_id, uni_id, tp_id)
        if tp_instance is None:
            self.log.error("flow-not-added--tp-instance-unavailable")
            return

        pon_intf_onu_id = (intf_id, onu_id, uni_id)
        alloc_id = \
            self.resource_mgr.get_current_alloc_ids_for_onu(pon_intf_onu_id)
        gem_ports = \
            self.resource_mgr.get_current_gemport_ids_for_onu(pon_intf_onu_id)

        if alloc_id is None or gem_ports is None:
            self.log.error("alloc-id-or-gem-ports-unavailable",
                           alloc_id=alloc_id, gem_ports=gem_ports)
            return

        self.create_us_scheduler_queues(intf_id, onu_id, uni_id, tp_instance, us_meter_id)
        self.create_ds_scheduler_queues(intf_id, onu_id, uni_id, tp_instance, ds_meter_id)

        self.log.debug('Generated required alloc and gemport ids',
                       alloc_id=alloc_id, gemports=gem_ports)

        ds_gem_port_attr_list = tp_instance.downstream_gem_port_attribute_list
        us_gem_port_attr_list = tp_instance.upstream_gem_port_attribute_list
        kwargs = dict()
        kwargs['intf_id'] = intf_id
        kwargs['onu_id'] = onu_id
        kwargs['uni_id'] = uni_id
        kwargs['port_no'] = port_no
        kwargs['classifier'] = classifier
        kwargs['action'] = action
        kwargs['logical_flow'] = flow
        kwargs['alloc_id'] = alloc_id

        if IP_PROTO in classifier:
            if classifier[IP_PROTO] == 17:
                self.log.debug('dhcp flow add')
                if VLAN_PCP in classifier:
                    gemport_id = self._get_gem_port_for_pcp(
                        classifier[VLAN_PCP], us_gem_port_attr_list
                    )
                    self.add_dhcp_trap_uni(intf_id, onu_id, uni_id, port_no,
                                           classifier, action, flow, alloc_id,
                                           gemport_id)
                else:
                    self._install_flow_on_all_gemports(self.add_dhcp_trap_uni,
                                                       kwargs,
                                                       us_gem_port_attr_list)

            elif classifier[IP_PROTO] == 2:
                self.log.warn('igmp flow add ignored, not implemented yet')
                return
            else:
                self.log.warn("Invalid-Classifier-to-handle",
                              classifier=classifier,
                              action=action)
                return

        elif ETH_TYPE in classifier:
            if classifier[ETH_TYPE] == EAP_ETH_TYPE:
                self.log.debug('eapol flow add')
                vlan_id = classifier[VLAN_VID]

                if vlan_id is None:
                    vlan_id = DEFAULT_MGMT_VLAN

                if VLAN_PCP in classifier:
                    gemport_id = self._get_gem_port_for_pcp(
                        classifier[VLAN_PCP], us_gem_port_attr_list
                    )
                    self.add_eapol_flow(
                        intf_id, onu_id, uni_id, port_no, flow, alloc_id, gemport_id,
                        vlan_id=vlan_id)
                else:
                    kwargs['vlan_id'] = vlan_id
                    self._install_flow_on_all_gemports(self.add_eapol_flow,
                                                       kwargs,
                                                       us_gem_port_attr_list)

        elif PUSH_VLAN in action:
            if VLAN_PCP in classifier:
                gemport_id = self._get_gem_port_for_pcp(
                    classifier[VLAN_PCP], us_gem_port_attr_list
                )
                self.add_upstream_data_flow(intf_id, onu_id, uni_id, port_no, classifier,
                                            action, flow, alloc_id, gemport_id)
            else:
                self._install_flow_on_all_gemports(self.add_upstream_data_flow,
                                                   kwargs, us_gem_port_attr_list
                                                   )

        elif POP_VLAN in action:
            if VLAN_PCP in classifier:
                gemport_id = self._get_gem_port_for_pcp(
                    classifier[VLAN_PCP], ds_gem_port_attr_list
                )
                self.add_downstream_data_flow(intf_id, onu_id, uni_id, port_no, classifier,
                                              action, flow, alloc_id, gemport_id)
            else:
                self._install_flow_on_all_gemports(self.add_downstream_data_flow,
                                                   kwargs, ds_gem_port_attr_list
                                                   )

        elif self.is_no_l2_modification_flow(classifier, action) and \
                self._is_upstream_flow(classifier[IN_PORT]):
            kwargs['is_l2_mod_flow'] = False
            if VLAN_PCP in classifier:
                kwargs['gemport_id'] = self._get_gem_port_for_pcp(
                    classifier[VLAN_PCP], us_gem_port_attr_list
                )
                self.add_upstream_data_flow(**kwargs)
            else:
                self._install_flow_on_all_gemports(self.add_upstream_data_flow,
                                                   kwargs, us_gem_port_attr_list
                                                   )
        elif self.is_no_l2_modification_flow(classifier, action) and \
                self._is_downstream_flow(classifier[IN_PORT]):
            kwargs['is_l2_mod_flow'] = False
            if VLAN_PCP in classifier:
                kwargs['gemport_id'] = self._get_gem_port_for_pcp(
                    classifier[VLAN_PCP], ds_gem_port_attr_list
                )
                self.add_downstream_data_flow(**kwargs)
            else:
                self._install_flow_on_all_gemports(self.add_downstream_data_flow,
                                                   kwargs, ds_gem_port_attr_list
                                                   )

        else:
            self.log.debug('Invalid-flow-type-to-handle',
                           classifier=classifier,
                           action=action, flow=flow)
            return

        # Download tech-profile to ONU
        self.download_tech_profile(intf_id, onu_id, uni_id)

    def download_tech_profile(self, intf_id, onu_id, uni_id):

        (ofp_port_name, ofp_port_no) = \
            self.data_model.get_ofp_port_name(intf_id, onu_id, uni_id)
        if ofp_port_name is None:
            self.log.error("port-name-not-found")
            return

        tp_id = self.resource_mgr.get_tech_profile_id_for_onu(intf_id, onu_id, uni_id)
        tp_path = self.get_tp_path(intf_id, ofp_port_name, tp_id)

        self.log.debug('Load-tech-profile-request-to-brcm-handler',
                       tp_path=tp_path)
        self.data_model.onu_download_tech_profile(
            intf_id, onu_id, uni_id, tp_path)

    def get_scheduler(self, tech_profile_instance, direction, meter_id):
        if direction == Direction.UPSTREAM:
            scheduler = tech_profile_instance.us_scheduler
        elif direction == Direction.DOWNSTREAM:
            scheduler = tech_profile_instance.ds_scheduler
        else:
            raise Exception("invalid-direction")

        meter_band = self.data_model.meter_band(meter_id)

        traffic_shaping_info = None

        if meter_band is not None:
            cir = meter_band.bands[0].rate
            cbs = meter_band.bands[0].burst_size
            eir = meter_band.bands[1].rate
            ebs = meter_band.bands[1].burst_size
            pir = cir + eir
            pbs = cbs + ebs

            traffic_shaping_info = tech_profile_pb2.TrafficShapingInfo(
                cir=cir,
                cbs=cbs,
                pir=pir,
                pbs=pbs
            )

        scheduler_config = tech_profile_pb2.SchedulerConfig(
            direction=TechProfile.get_parameter(
                'direction', scheduler.direction),
            additional_bw=TechProfile.get_parameter(
                'additional_bw', scheduler.additional_bw),
            priority=scheduler.priority,
            weight=scheduler.weight,
            sched_policy=TechProfile.get_parameter(
                'q_sched_policy', scheduler.q_sched_policy)
        )

        traffic_scheduler = tech_profile_pb2.TrafficScheduler(
            direction=scheduler.direction,
            scheduler=scheduler_config,
            alloc_id=scheduler.alloc_id,
            traffic_shaping_info=traffic_shaping_info
        )

        return traffic_scheduler

    @staticmethod
    def get_traffic_queues(tech_profile_instance, direction):
        if direction == Direction.UPSTREAM:
            gemport_attribute_list = tech_profile_instance. \
                upstream_gem_port_attribute_list
            tp_scheduler_direction = tech_profile_instance.us_scheduler.direction
        elif direction == Direction.DOWNSTREAM:
            gemport_attribute_list = tech_profile_instance. \
                downstream_gem_port_attribute_list
            tp_scheduler_direction = tech_profile_instance.ds_scheduler.direction
        else:
            raise Exception("invalid-direction")
        traffic_queues = list()
        for i in range(len(gemport_attribute_list)):
            traffic_queues.append(tech_profile_pb2.TrafficQueue(
                direction=TechProfile.get_parameter('direction',
                                                    tp_scheduler_direction),
                gemport_id=gemport_attribute_list[i].gemport_id,
                pbit_map=gemport_attribute_list[i].pbit_map,
                aes_encryption=ast.literal_eval(gemport_attribute_list[i].
                                                aes_encryption),
                sched_policy=TechProfile.get_parameter(
                    'sched_policy', gemport_attribute_list[i].
                        scheduling_policy),
                priority=gemport_attribute_list[i].priority_q,
                weight=gemport_attribute_list[i].weight,
                discard_policy=TechProfile.get_parameter(
                    'discard_policy', gemport_attribute_list[i].
                        discard_policy)))

        return traffic_queues

    def create_us_scheduler_queues(self, intf_id, onu_id, uni_id, tp_instance, us_meter_id):
        if us_meter_id is None:
            self.log.debug("us-meter-unavailable--no-action")
            return

        kv_store_meter_id = self.resource_mgr.get_meter_id_for_onu(UPSTREAM,
                                                                   intf_id,
                                                                   onu_id, uni_id)

        # Lets make a simple assumption that if the meter-id is present on the KV store,
        # then the scheduler and queues configuration is applied on the OLT device
        # in the given direction.
        if kv_store_meter_id is not None:
            # TODO: Dynamic meter update not supported for now
            # TODO: The subscriber has to be un-provisioned and re-provisioned for meter update
            assert kv_store_meter_id == us_meter_id
            self.log.debug("scheduler-already-created-in-us")
            return

        traffic_sched = self.get_scheduler(tp_instance, Direction.UPSTREAM, us_meter_id)
        try:
            ofp_port_no = self.platform.mk_uni_port_num(intf_id,
                                                        onu_id, uni_id)

            self.stub.CreateTrafficSchedulers(
                tech_profile_pb2.TrafficSchedulers(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_scheds=[traffic_sched]
                ))
        except grpc.RpcError as grpc_e:
            if grpc_e.code() == grpc.StatusCode.ALREADY_EXISTS:
                self.log.warn("us-scheduler-already-exists")
            else:
                self.log.error("failure-to-create-us-scheduler")
                return

        # On receiving the CreateTrafficQueues request, the driver should create corresponding
        # downstream queues.
        try:
            self.stub.CreateTrafficQueues(
                tech_profile_pb2.TrafficQueues(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_queues=
                    OpenOltFlowMgr.get_traffic_queues(tp_instance, Direction.UPSTREAM)
                ))
        except grpc.RpcError as grpc_e:
            if grpc_e.code() == grpc.StatusCode.ALREADY_EXISTS:
                self.log.warn("ds-queues-already-exists")
            else:
                self.log.error("failure-to-create-ds-queues")
                return

        # After we succesfully applied the scheduler configuration on the OLT device,
        # store the meter id on the KV store, for further reference
        self.resource_mgr.update_meter_id_for_onu(UPSTREAM, intf_id, onu_id, uni_id, us_meter_id)

    def create_ds_scheduler_queues(self, intf_id, onu_id, uni_id, tp_instance, ds_meter_id):
        if ds_meter_id is None:
            self.log.debug("ds-meter-unavailable--no-action")
            return

        kv_store_meter_id = self.resource_mgr.get_meter_id_for_onu(DOWNSTREAM,
                                                                   intf_id,
                                                                   onu_id, uni_id)
        # Lets make a simple assumption that if the meter-id is present on the KV store,
        # then the scheduler and queues configuration is applied on the OLT device
        if kv_store_meter_id is not None:
            # TODO: Dynamic meter update not supported for now
            # TODO: The subscriber has to be un-provisioned and re-provisioned for meter update
            assert kv_store_meter_id == ds_meter_id
            self.log.debug("scheduler-already-created-in-ds")
            return

        traffic_sched = self.get_scheduler(tp_instance, Direction.DOWNSTREAM, ds_meter_id)
        _, ofp_port_no = self.data_model.get_ofp_port_name(intf_id, onu_id, uni_id)
        try:
            self.stub.CreateTrafficSchedulers(
                tech_profile_pb2.TrafficSchedulers(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_scheds=[traffic_sched]
                ))
        except grpc.RpcError as grpc_e:
            if grpc_e.code() == grpc.StatusCode.ALREADY_EXISTS:
                self.log.warn("ds-scheduler-already-exists")
            else:
                self.log.error("failure-to-create-ds-scheduler")
                return

        # On receiving the CreateTrafficQueues request, the driver should create corresponding
        # downstream queues.
        try:
            self.stub.CreateTrafficQueues(
                tech_profile_pb2.TrafficQueues(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_queues=
                    OpenOltFlowMgr.get_traffic_queues(tp_instance, Direction.DOWNSTREAM)
                ))
        except grpc.RpcError as grpc_e:
            if grpc_e.code() == grpc.StatusCode.ALREADY_EXISTS:
                self.log.warn("ds-queues-already-exists")
            else:
                self.log.error("failure-to-create-ds-queues")
                return

        # After we successfully applied the scheduler configuration on the OLT device,
        # store the meter id on the KV store, for further reference
        self.resource_mgr.update_meter_id_for_onu(DOWNSTREAM, intf_id, onu_id, uni_id, ds_meter_id)

    def remove_us_scheduler_queues(self, intf_id, onu_id, uni_id, tp_instance):
        us_meter_id = self.resource_mgr.get_meter_id_for_onu(UPSTREAM,
                                                             intf_id,
                                                             onu_id, uni_id)
        traffic_sched = self.get_scheduler(tp_instance, Direction.UPSTREAM, us_meter_id)
        _, ofp_port_no = self.data_model.get_ofp_port_name(intf_id, onu_id, uni_id)

        try:
            self.stub.RemoveTrafficQueues(
                tech_profile_pb2.TrafficQueues(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_queues=
                    OpenOltFlowMgr.get_traffic_queues(tp_instance, Direction.UPSTREAM)
                ))
            self.log.debug("removed-upstream-Queues")
        except grpc.RpcError as e:
            self.log.error("failure-to-remove-us-queues", e=e)

        try:
            self.stub.RemoveTrafficSchedulers(
                tech_profile_pb2.TrafficSchedulers(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_scheds=[traffic_sched]
                ))
            self.log.debug("removed-upstream-Schedulers")
        except grpc.RpcError as e:
            self.log.error("failure-to-remove-us-scheduler", e=e)

        self.resource_mgr.remove_meter_id_for_onu(UPSTREAM, intf_id, onu_id, uni_id)

    def remove_ds_scheduler_queues(self, intf_id, onu_id, uni_id, tp_instance):
        ds_meter_id = self.resource_mgr.get_meter_id_for_onu(DOWNSTREAM,
                                                             intf_id,
                                                             onu_id, uni_id)

        traffic_sched = self.get_scheduler(tp_instance, Direction.DOWNSTREAM, ds_meter_id)
        _, ofp_port_no = self.data_model.get_ofp_port_name(intf_id, onu_id, uni_id)

        try:
            self.stub.RemoveTrafficQueues(
                tech_profile_pb2.TrafficQueues(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_queues=
                    OpenOltFlowMgr.get_traffic_queues(tp_instance, Direction.DOWNSTREAM)
                ))
            self.log.debug("removed-downstream-Queues")
        except grpc.RpcError as grpc_e:
            self.log.error("failure-to-remove-ds-queues")

        try:
            self.stub.RemoveTrafficSchedulers(
                tech_profile_pb2.TrafficSchedulers(
                    intf_id=intf_id,
                    onu_id=onu_id,
                    uni_id=uni_id,
                    port_no=ofp_port_no,
                    traffic_scheds=[traffic_sched]
                ))
            self.log.debug("removed-downstream-Schedulers")
        except grpc.RpcError as grpc_e:
            self.log.error("failure-to-remove-ds-scheduler")

        self.resource_mgr.remove_meter_id_for_onu(DOWNSTREAM, intf_id, onu_id, uni_id)

    def get_tech_profile_instance(self, intf_id, onu_id, uni_id, tp_id):
        (ofp_port_name, ofp_port_no) \
            = self.data_model.get_ofp_port_name(intf_id, onu_id, uni_id)
        if ofp_port_name is None:
            self.log.error("port-name-not-found")
            return None

        # Check tech profile instance already exists for derived port name
        tech_profile_instance = self.tech_profile[intf_id]. \
            get_tech_profile_instance(tp_id, ofp_port_name)

        if tech_profile_instance is None:
            # create tech profile instance
            tech_profile_instance = self.tech_profile[intf_id]. \
                create_tech_profile_instance(tp_id, ofp_port_name,
                                             intf_id)
            if tech_profile_instance is None:
                raise Exception('Tech-profile-instance-creation-failed')

            self.resource_mgr.update_tech_profile_id_for_onu(intf_id, onu_id,
                                                             uni_id, tp_id)

            # Fetch alloc id and gemports from tech profile instance
            alloc_id = tech_profile_instance.us_scheduler.alloc_id
            gem_port_ids = []

            for i in range(len(
                    tech_profile_instance.upstream_gem_port_attribute_list)):
                gem_port_ids.append(
                    tech_profile_instance.upstream_gem_port_attribute_list[i].
                        gemport_id)

                # Update the allocated alloc_id and gem_port_id for the ONU/UNI to KV
                # store
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

                for gemport_id in gem_port_ids:
                    self.data_model.gemport_id_add(intf_id, onu_id, gemport_id)
        else:
            self.log.debug(
                'Tech-profile-instance-already-exist-for-given port-name',
                ofp_port_name=ofp_port_name)

        return tech_profile_instance

    def get_alloc_id_gem_port(self, intf_id, onu_id):
        pon_intf_onu_id = (intf_id, onu_id)
        # If we already have allocated alloc_id and gem_ports earlier, render them
        alloc_id = \
            self.resource_mgr.get_current_alloc_ids_for_onu(pon_intf_onu_id)
        gem_port_ids = \
            self.resource_mgr.get_current_gemport_ids_for_onu(pon_intf_onu_id)
        return alloc_id, gem_port_ids

    def add_upstream_data_flow(self, intf_id, onu_id, uni_id, port_no, classifier,
                               action, logical_flow, alloc_id, gemport_id, is_l2_mod_flow=True):

        if is_l2_mod_flow:
            classifier[PACKET_TAG_TYPE] = SINGLE_TAG
        else:
            classifier[PACKET_TAG_TYPE] = DOUBLE_TAG

        self.add_hsia_flow(intf_id, onu_id, uni_id, port_no, classifier,
                           action, UPSTREAM,
                           logical_flow, alloc_id, gemport_id)

    def add_downstream_data_flow(self, intf_id, onu_id, uni_id, port_no, classifier,
                                 action, logical_flow, alloc_id, gemport_id, is_l2_mod_flow=True):
        if is_l2_mod_flow:
            classifier[PACKET_TAG_TYPE] = DOUBLE_TAG
            classifier[POP_VLAN] = True
            action[VLAN_VID] = classifier[VLAN_VID]

        else:
            classifier[PACKET_TAG_TYPE] = DOUBLE_TAG

        self.add_hsia_flow(intf_id, onu_id, uni_id, port_no, classifier,
                           action, DOWNSTREAM,
                           logical_flow, alloc_id, gemport_id)

    def add_hsia_flow(self, intf_id, onu_id, uni_id, port_no, classifier,
                      action, direction, logical_flow, alloc_id, gemport_id):

        flow_store_cookie = self._get_flow_store_cookie(classifier,
                                                        gemport_id)

        if self.resource_mgr.is_flow_cookie_on_kv_store(intf_id, onu_id,
                                                        uni_id,
                                                        flow_store_cookie):
            self.log.debug('flow-exists--not-re-adding')
        else:
            # One of the OLT platform (Broadcom BAL) requires that symmetric
            # flows require the same flow_id to be used across UL and DL.
            # Since HSIA flow is the only symmetric flow currently, we need to
            # re-use the flow_id across both direction. The 'flow_category'
            # takes priority over flow_cookie to find any available HSIA_FLOW
            # id for the ONU.

            flow_category = HSIA_FLOW

            if self.is_no_l2_modification_flow(classifier, action):
                flow_category = HSIA_TRANSPARENT.format(classifier[VLAN_VID])

            flow_id = self.resource_mgr.get_flow_id(intf_id, onu_id, uni_id,
                                                    flow_category=flow_category,
                                                    flow_pcp=classifier[VLAN_PCP])
            if flow_id is None:
                self.log.error("hsia-flow-unavailable")
                return

            flow = openolt_pb2.Flow(
                access_intf_id=intf_id, onu_id=onu_id, uni_id=uni_id,
                flow_id=flow_id, flow_type=direction, alloc_id=alloc_id,
                network_intf_id=self.data_model.olt_nni_intf_id(),
                gemport_id=gemport_id,
                classifier=self.mk_classifier(classifier),
                action=self.mk_action(action), priority=logical_flow.priority,
                port_no=port_no, cookie=logical_flow.cookie)

            if self.add_flow_to_device(flow, logical_flow, flow_store_cookie):
                flow_info = self._get_flow_info_as_json_blob(flow,
                                                             flow_store_cookie,
                                                             flow_category)
                self.update_flow_info_to_kv_store(flow.access_intf_id,
                                                  flow.onu_id, flow.uni_id,
                                                  flow.flow_id, flow_info)

    def add_dhcp_trap_uni(self, intf_id, onu_id, uni_id, port_no, classifier,
                          action, logical_flow, alloc_id, gemport_id):

        self.log.debug('add dhcp upstream trap', classifier=classifier,
                       intf_id=intf_id, onu_id=onu_id, uni_id=uni_id,
                       action=action)

        action.clear()
        action[TRAP_TO_HOST] = True
        classifier[UDP_SRC] = 68
        classifier[UDP_DST] = 67
        classifier[PACKET_TAG_TYPE] = SINGLE_TAG
        classifier.pop(VLAN_VID, None)

        flow_store_cookie = self._get_flow_store_cookie(classifier,
                                                        gemport_id)

        if self.resource_mgr.is_flow_cookie_on_kv_store(intf_id, onu_id,
                                                        uni_id,
                                                        flow_store_cookie):
            self.log.debug('flow-exists--not-re-adding')
        else:
            flow_id = self.resource_mgr.get_flow_id(
                intf_id, onu_id, uni_id,
                flow_store_cookie=flow_store_cookie,
            )
            dhcp_flow = openolt_pb2.Flow(
                onu_id=onu_id, uni_id=uni_id, flow_id=flow_id,
                flow_type=UPSTREAM, access_intf_id=intf_id,
                gemport_id=gemport_id, alloc_id=alloc_id,
                network_intf_id=self.data_model.olt_nni_intf_id(),
                priority=logical_flow.priority,
                classifier=self.mk_classifier(classifier),
                action=self.mk_action(action),
                port_no=port_no,
                cookie=logical_flow.cookie)

            if self.add_flow_to_device(dhcp_flow, logical_flow, flow_store_cookie):
                flow_info = self._get_flow_info_as_json_blob(dhcp_flow,
                                                             flow_store_cookie,
                                                             DHCP_FLOW)
                self.update_flow_info_to_kv_store(dhcp_flow.access_intf_id,
                                                  dhcp_flow.onu_id,
                                                  dhcp_flow.uni_id,
                                                  dhcp_flow.flow_id,
                                                  flow_info)

    def add_eapol_flow(self, intf_id, onu_id, uni_id, port_no, logical_flow,
                       alloc_id, gemport_id, vlan_id=DEFAULT_MGMT_VLAN, classifier=None, action=None):

        uplink_classifier = dict()
        uplink_classifier[ETH_TYPE] = EAP_ETH_TYPE
        uplink_classifier[PACKET_TAG_TYPE] = SINGLE_TAG
        uplink_classifier[VLAN_VID] = vlan_id
        if classifier is not None:
            uplink_classifier[VLAN_PCP] = classifier[VLAN_PCP]

        uplink_action = dict()
        uplink_action[TRAP_TO_HOST] = True

        flow_store_cookie = self._get_flow_store_cookie(uplink_classifier,
                                                        gemport_id)
        if self.resource_mgr.is_flow_cookie_on_kv_store(intf_id, onu_id,
                                                        uni_id,
                                                        flow_store_cookie):
            self.log.debug('flow-exists--not-re-adding')
        else:
            # Add Upstream EAPOL Flow.
            uplink_flow_id = self.resource_mgr.get_flow_id(
                intf_id, onu_id, uni_id,
                flow_store_cookie=flow_store_cookie
            )

            upstream_flow = openolt_pb2.Flow(
                access_intf_id=intf_id, onu_id=onu_id, uni_id=uni_id,
                flow_id=uplink_flow_id, flow_type=UPSTREAM, alloc_id=alloc_id,
                network_intf_id=self.data_model.olt_nni_intf_id(),
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

            if self.add_flow_to_device(upstream_flow, logical_flow, flow_store_cookie):
                flow_info = self._get_flow_info_as_json_blob(upstream_flow,
                                                             flow_store_cookie,
                                                             EAPOL_FLOW)
                self.update_flow_info_to_kv_store(upstream_flow.access_intf_id,
                                                  upstream_flow.onu_id,
                                                  upstream_flow.uni_id,
                                                  upstream_flow.flow_id,
                                                  flow_info)

        # Add Downstream EAPOL Flow, Only for first EAP flow (BAL
        # requirement)
        # On one of the platforms (Broadcom BAL), when same DL classifier
        # vlan was used across multiple ONUs, eapol flow re-adds after
        # flow delete (cases of onu reboot/disable) fails.
        # In order to generate unique vlan, a combination of intf_id
        # onu_id and uni_id is used.
        # uni_id defaults to 0, so add 1 to it.
        special_vlan_downstream_flow = 4090 - intf_id * onu_id * (uni_id + 1)
        # Assert that we do not generate invalid vlans under no condition
        assert special_vlan_downstream_flow >= 2

        downlink_classifier = dict()
        downlink_classifier[PACKET_TAG_TYPE] = SINGLE_TAG
        downlink_classifier[ETH_TYPE] = EAP_ETH_TYPE
        downlink_classifier[VLAN_VID] = special_vlan_downstream_flow

        downlink_action = dict()
        downlink_action[PUSH_VLAN] = True
        downlink_action[VLAN_VID] = vlan_id

        flow_store_cookie = self._get_flow_store_cookie(
            downlink_classifier, gemport_id)
        if self.resource_mgr.is_flow_cookie_on_kv_store(
                intf_id, onu_id, uni_id, flow_store_cookie):
            self.log.debug('flow-exists--not-re-adding')
        else:
            downlink_flow_id = self.resource_mgr.get_flow_id(
                intf_id, onu_id, uni_id,
                flow_store_cookie=flow_store_cookie
            )

            downstream_flow = openolt_pb2.Flow(
                access_intf_id=intf_id, onu_id=onu_id, uni_id=uni_id,
                flow_id=downlink_flow_id, flow_type=DOWNSTREAM,
                alloc_id=alloc_id,
                network_intf_id=self.data_model.olt_nni_intf_id(),
                gemport_id=gemport_id,
                classifier=self.mk_classifier(downlink_classifier),
                action=self.mk_action(downlink_action),
                priority=logical_flow.priority,
                port_no=port_no,
                cookie=logical_flow.cookie)

            downstream_logical_flow = ofp_flow_stats(
                id=logical_flow.id, cookie=logical_flow.cookie,
                table_id=logical_flow.table_id,
                priority=logical_flow.priority, flags=logical_flow.flags)

            downstream_logical_flow.match.oxm_fields.extend(
                fd.mk_oxm_fields(
                    [fd.in_port(fd.get_out_port(logical_flow)),
                     fd.vlan_vid(special_vlan_downstream_flow | 0x1000)]))
            downstream_logical_flow.match.type = OFPMT_OXM

            downstream_logical_flow.instructions.extend(
                fd.mk_instructions_from_actions([fd.output(
                    self.platform.mk_uni_port_num(intf_id, onu_id,
                                                  uni_id))]))

            if self.add_flow_to_device(downstream_flow,
                                       downstream_logical_flow, flow_store_cookie):
                flow_info = self._get_flow_info_as_json_blob(
                    downstream_flow, flow_store_cookie, EAPOL_FLOW)
                self.update_flow_info_to_kv_store(
                    downstream_flow.access_intf_id, downstream_flow.onu_id,
                    downstream_flow.uni_id, downstream_flow.flow_id,
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
        self.flows_proxy.update('/', Flows(items=[]))
        self.log.debug("purged-all-device-flows")

        self.logical_flows_proxy.update('/', Flows(items=[]))
        self.log.debug("purged-all-logical-flows")

    """ Add a downstream DHCP trap flow on the NNI interface
    """
    def add_dhcp_trap_nni(self, logical_flow, classifier,
                          port_no, network_intf_id=0):
        self.log.info("trap-dhcp-of-nni-flow")
        classifier[PACKET_TAG_TYPE] = DOUBLE_TAG
        action = dict()
        action[TRAP_TO_HOST] = True

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

        if self.resource_mgr.is_flow_cookie_on_kv_store(
                network_intf_id, onu_id, uni_id, flow_store_cookie):
            self.log.debug('flow-exists--not-re-adding')
        else:
            flow_id = self.resource_mgr.get_flow_id(
                network_intf_id, onu_id, uni_id,
                flow_store_cookie=flow_store_cookie)

            downstream_flow = openolt_pb2.Flow(
                access_intf_id=-1,  # access_intf_id not required
                onu_id=onu_id,  # onu_id not required
                uni_id=uni_id,  # uni_id not used
                flow_id=flow_id,
                flow_type=DOWNSTREAM,
                network_intf_id=network_intf_id,
                gemport_id=-1,  # gemport_id not required
                classifier=self.mk_classifier(classifier),
                action=self.mk_action(action),
                priority=logical_flow.priority,
                port_no=port_no,
                cookie=logical_flow.cookie)

            self.log.debug('add dhcp downstream trap', classifier=classifier,
                           action=action, flow=downstream_flow,
                           port_no=port_no)
            if self.add_flow_to_device(downstream_flow, logical_flow, flow_store_cookie):
                flow_info = self._get_flow_info_as_json_blob(downstream_flow,
                                                             flow_store_cookie, DHCP_FLOW)
                self.update_flow_info_to_kv_store(
                    network_intf_id, onu_id, uni_id, flow_id, flow_info)

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

        if self.resource_mgr.is_flow_cookie_on_kv_store(
                network_intf_id, onu_id, uni_id, flow_store_cookie):
            self.log.debug('flow-exists--not-re-adding')
        else:
            flow_id = self.resource_mgr.get_flow_id(
                network_intf_id, onu_id, uni_id, flow_store_cookie=flow_store_cookie)

            downstream_flow = openolt_pb2.Flow(
                access_intf_id=-1,  # access_intf_id not required
                onu_id=onu_id,  # onu_id not required
                uni_id=uni_id,  # uni_id not used
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
                           action=action, flow=downstream_flow,
                           port_no=port_no)
            if self.add_flow_to_device(downstream_flow, logical_flow, flow_store_cookie):
                flow_info = self._get_flow_info_as_json_blob(downstream_flow,
                                                             flow_store_cookie,
                                                             LLDP_FLOW)
                self.update_flow_info_to_kv_store(
                    network_intf_id, onu_id, uni_id, flow_id, flow_info)

    @staticmethod
    def mk_classifier(classifier_info):

        classifier = openolt_pb2.Classifier()

        if ETH_TYPE in classifier_info:
            classifier.eth_type = classifier_info[ETH_TYPE]
        if IP_PROTO in classifier_info:
            classifier.ip_proto = classifier_info[IP_PROTO]
        if VLAN_VID in classifier_info and \
                classifier_info[VLAN_VID] != RESERVED_VLAN:
            classifier.o_vid = classifier_info[VLAN_VID]
        if METADATA in classifier_info and \
                classifier_info[METADATA] != RESERVED_VLAN:
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
            if VLAN_PCP in action_info:
                action.o_pbits = action_info[VLAN_PCP]
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
                self.log.debug('eap flow detected', onu_id=onu_id,
                               uni_id=uni_id, intf_id=intf_id,
                               eap_intf_id=eap_intf_id, eap_onu_id=eap_onu_id,
                               eap_uni_id=eap_uni_id)
            if eap_flow and intf_id == eap_intf_id \
                    and onu_id == eap_onu_id and uni_id == eap_uni_id:
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

    def add_flow_to_device(self, flow, logical_flow, flow_store_cookie=None):
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
                # If the flow addition failed on the device, immediately
                # free up the flow_id resource from the pool
                intf_id = flow.access_intf_id if flow.access_intf_id > 0 else flow.network_intf_id
                onu_id = flow.onu_id
                uni_id = flow.uni_id
                flow_id = flow.flow_id
                self.resource_mgr.free_flow_id(intf_id, onu_id, uni_id, flow_id)

            return False
        else:
            intf_onu_id = (flow.access_intf_id if flow.access_intf_id > 0 else flow.network_intf_id,
                           flow.onu_id, flow.uni_id)
            logical_flow.intf_tuple.append(str(intf_onu_id))
            if flow_store_cookie is not None:
                logical_flow.flow_store_cookie = flow_store_cookie

            self.register_flow(logical_flow, flow)
            return True

    def update_flow_info_to_kv_store(self, intf_id, onu_id, uni_id, flow_id,
                                     flow):
        self.resource_mgr.update_flow_id_info(intf_id, onu_id, uni_id,
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

    def find_next_flow(self, flow, metadata):
        table_id = fd.get_goto_table_id(flow)
        # Prior to ONOS 1.13.5, Metadata contained the UNI output port number.
        # In 1.13.5 and later, the lower 32-bits is the output port number and
        # the # upper 32-bits is the inner-vid we are looking for. Use just the
        # lower 32 # bits.  Allows this code to work with pre- and post-1.13.5
        # ONOS OltPipeline

        port = metadata & 0xFFFFFFFF
        if table_id is None:
            return None
        flows = self.logical_flows_proxy.get('/').items
        next_flows = []
        for f in flows:
            if f.table_id == table_id:
                # FIXME
                if fd.get_in_port(f) == fd.get_in_port(flow) and \
                        fd.get_out_port(f) == port:
                    next_flows.append(f)

        if len(next_flows) == 0:
            self.log.warning('no next flow found, it may be a timing issue',
                             flow=flow, number_of_flows=len(flows))
            if flow.id in self.retry_add_flow_list:
                self.log.debug('flow is already in retry list',
                               flow_id=flow.id)
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

    def clear_flows_and_scheduler_for_logical_port(self, child_device,
                                                   logical_port):
        ofp_port_name = logical_port.ofp_port.name
        port_no = logical_port.ofp_port.port_no
        pon_port = child_device.proxy_address.channel_id
        onu_id = child_device.proxy_address.onu_id
        uni_id = self.platform.uni_id_from_port_num(port_no)

        tp_id = self.resource_mgr.get_tech_profile_id_for_onu(pon_port, onu_id,
                                                              uni_id)
        tech_profile_instance = self.tech_profile[pon_port]. \
            get_tech_profile_instance(
            tp_id,
            ofp_port_name)
        flow_ids = self.resource_mgr.get_current_flow_ids(pon_port, onu_id,
                                                          uni_id)
        self.log.debug("outstanding-flows-to-be-cleared", flow_ids=flow_ids)
        if flow_ids:
            for flow_id in flow_ids:
                flow_infos = self.resource_mgr.get_flow_id_info(pon_port, onu_id,
                                                                uni_id, flow_id)
                for flow_info in flow_infos:
                    direction = flow_info['flow_type']
                    flow_to_remove = openolt_pb2.Flow(flow_id=flow_id,
                                                      flow_type=direction)
                    try:
                        self.stub.FlowRemove(flow_to_remove)
                    except grpc.RpcError as grpc_e:
                        if grpc_e.code() == grpc.StatusCode.NOT_FOUND:
                            self.log.debug('This flow does not exist on switch, '
                                           'normal after an OLT reboot',
                                           flow=flow_to_remove)
                        else:
                            raise grpc_e

        self.remove_us_scheduler_queues(pon_port, onu_id, uni_id, tech_profile_instance)
        self.remove_ds_scheduler_queues(pon_port, onu_id, uni_id, tech_profile_instance)

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
        assert len(self.tech_profile) \
               == self.resource_mgr.device_info.pon_ports

    def _get_flow_info_as_json_blob(self, flow, flow_store_cookie,
                                    flow_category=None):
        json_blob = MessageToDict(message=flow,
                                  preserving_proto_field_name=True)
        self.log.debug("flow-info", json_blob=json_blob)
        json_blob['flow_store_cookie'] = flow_store_cookie
        if flow_category is not None:
            json_blob['flow_category'] = flow_category

        # For flows which trap out of the NNI, the access_intf_id is invalid
        # (set to -1). In such cases, we need to refer to the network_intf_id.
        if flow.access_intf_id != -1:
            flow_info = self.resource_mgr.get_flow_id_info(
                flow.access_intf_id, flow.onu_id, flow.uni_id, flow.flow_id)
        else:
            # Case of LLDP trap flow from the NNI. We can't use
            # flow.access_intf_id in that case, as it is invalid.
            # We use flow.network_intf_id.
            flow_info = self.resource_mgr.get_flow_id_info(
                flow.network_intf_id, flow.onu_id, flow.uni_id, flow.flow_id)

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

    @staticmethod
    def _get_gem_port_for_pcp(pcp, get_gem_port_for_pcp):
        """
        Return gem_port id corresponding to a given pcp bit

        :param pcp: Represents the p_bit
        :param get_gem_port_for_pcp: Represents a list of gemport_attributes (DS or US)
        :return: Gemport ID servicing the given pcp if found, else None
        """
        for gem_port_attr in get_gem_port_for_pcp:
            # The pbit_map appears as "0b00011010" in the Tech-Profile instance.
            # The initial '0b' has to be stripped.
            # The remaining string is reversed, then enumerated and matched against pcp index.
            for i, p in enumerate(reversed(gem_port_attr.pbit_map[2:])):
                if i == pcp and p == '1':
                    return gem_port_attr.gemport_id
        return None

    @staticmethod
    def _install_flow_on_all_gemports(func, kwargs, gem_attr_list):
        for gem_attr in gem_attr_list:
            # The pbit_map appears as "0b00011010" in the Tech-Profile instance.
            # The initial '0b' has to be stripped.
            # The remaining string is reversed, then enumerated and matched against pbit 1.
            for i, p in enumerate(reversed(gem_attr.pbit_map[2:])):
                if p == '1':
                    kwargs['classifier'][VLAN_PCP] = i
                    # Add the gemport corresponding to this PCP
                    kwargs['gemport_id'] = gem_attr.gemport_id
                    func(**kwargs)

