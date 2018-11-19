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

from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, \
    ofp_flow_stats, OFPMT_OXM, Flows, FlowGroups, OFPXMT_OFB_IN_PORT, \
    OFPXMT_OFB_VLAN_VID
from voltha.protos.device_pb2 import Port
import voltha.core.flow_decomposer as fd
from bbsimolt_platform import BBSimOltPlatform
from voltha.adapters.openolt.protos import openolt_pb2
from voltha.registry import registry

HSIA_FLOW_INDEX = 0  # FIXME
DHCP_FLOW_INDEX = 1  # FIXME
DHCP_DOWNLINK_FLOW_INDEX = 6  # FIXME
EAPOL_FLOW_INDEX = 2  # FIXME
EAPOL_DOWNLINK_FLOW_INDEX = 3  # FIXME
EAPOL_DOWNLINK_SECONDARY_FLOW_INDEX = 4  # FIXME
EAPOL_UPLINK_SECONDARY_FLOW_INDEX = 5  # FIXME
LLDP_FLOW_INDEX = 7  # FIXME

EAP_ETH_TYPE = 0x888e
LLDP_ETH_TYPE = 0x88cc

# FIXME - see also BRDCM_DEFAULT_VLAN in broadcom_onu.py
DEFAULT_MGMT_VLAN = 4091


class BBSimOltFlowMgr(object):

    def __init__(self, log, stub, device_id, logical_device_id):
        self.log = log
        self.stub = stub
        self.device_id = device_id
        self.logical_device_id = logical_device_id
        self.logical_flows_proxy = registry('core').get_proxy(
            '/logical_devices/{}/flows'.format(self.logical_device_id))
        self.flows_proxy = registry('core').get_proxy(
            '/devices/{}/flows'.format(self.device_id))
        self.root_proxy = registry('core').get_proxy('/')
        self.platform = BBSimOltPlatform(self.log)

    def add_flow(self, flow):
        self.log.debug('add flow', flow=flow)
        classifier_info = dict()
        action_info = dict()

        for field in fd.get_ofb_fields(flow):
            if field.type == fd.ETH_TYPE:
                classifier_info['eth_type'] = field.eth_type
                self.log.debug('field-type-eth-type',
                               eth_type=classifier_info['eth_type'])
            elif field.type == fd.IP_PROTO:
                classifier_info['ip_proto'] = field.ip_proto
                self.log.debug('field-type-ip-proto',
                               ip_proto=classifier_info['ip_proto'])
            elif field.type == fd.IN_PORT:
                classifier_info['in_port'] = field.port
                self.log.debug('field-type-in-port',
                               in_port=classifier_info['in_port'])
            elif field.type == fd.VLAN_VID:
                classifier_info['vlan_vid'] = field.vlan_vid & 0xfff
                self.log.debug('field-type-vlan-vid',
                               vlan=classifier_info['vlan_vid'])
            elif field.type == fd.VLAN_PCP:
                classifier_info['vlan_pcp'] = field.vlan_pcp
                self.log.debug('field-type-vlan-pcp',
                               pcp=classifier_info['vlan_pcp'])
            elif field.type == fd.UDP_DST:
                classifier_info['udp_dst'] = field.udp_dst
                self.log.debug('field-type-udp-dst',
                               udp_dst=classifier_info['udp_dst'])
            elif field.type == fd.UDP_SRC:
                classifier_info['udp_src'] = field.udp_src
                self.log.debug('field-type-udp-src',
                               udp_src=classifier_info['udp_src'])
            elif field.type == fd.IPV4_DST:
                classifier_info['ipv4_dst'] = field.ipv4_dst
                self.log.debug('field-type-ipv4-dst',
                               ipv4_dst=classifier_info['ipv4_dst'])
            elif field.type == fd.IPV4_SRC:
                classifier_info['ipv4_src'] = field.ipv4_src
                self.log.debug('field-type-ipv4-src',
                               ipv4_dst=classifier_info['ipv4_src'])
            elif field.type == fd.METADATA:
                classifier_info['metadata'] = field.table_metadata
                self.log.debug('field-type-metadata',
                               metadata=classifier_info['metadata'])
            else:
                raise NotImplementedError('field.type={}'.format(
                    field.type))

        for action in fd.get_actions(flow):
            if action.type == fd.OUTPUT:
                action_info['output'] = action.output.port
                self.log.debug('action-type-output',
                               output=action_info['output'],
                               in_port=classifier_info['in_port'])
            elif action.type == fd.POP_VLAN:
                if fd.get_goto_table_id(flow) is None:
                    self.log.debug('being taken care of by ONU', flow=flow)
                    return
                action_info['pop_vlan'] = True
                self.log.debug('action-type-pop-vlan',
                               in_port=classifier_info['in_port'])
            elif action.type == fd.PUSH_VLAN:
                action_info['push_vlan'] = True
                action_info['tpid'] = action.push.ethertype
                self.log.debug('action-type-push-vlan',
                               push_tpid=action_info['tpid'],
                               in_port=classifier_info['in_port'])
                if action.push.ethertype != 0x8100:
                    self.log.error('unhandled-tpid',
                                   ethertype=action.push.ethertype)
            elif action.type == fd.SET_FIELD:
                # action_info['action_type'] = 'set_field'
                _field = action.set_field.field.ofb_field
                assert (action.set_field.field.oxm_class ==
                        OFPXMC_OPENFLOW_BASIC)
                self.log.debug('action-type-set-field', field=_field,
                               in_port=classifier_info['in_port'])
                if _field.type == fd.VLAN_VID:
                    self.log.debug('set-field-type-vlan-vid',
                                   vlan_vid=_field.vlan_vid & 0xfff)
                    action_info['vlan_vid'] = (_field.vlan_vid & 0xfff)
                else:
                    self.log.error('unsupported-action-set-field-type',
                                   field_type=_field.type)
            else:
                self.log.error('unsupported-action-type',
                               action_type=action.type,
                               in_port=classifier_info['in_port'])

        if fd.get_goto_table_id(flow) is not None and not 'pop_vlan' in \
                action_info:
            self.log.debug('being taken care of by ONU', flow=flow)
            return

        if not 'output' in action_info and 'metadata' in classifier_info:
            # find flow in the next table
            next_flow = self.find_next_flow(flow)
            if next_flow is None:
                return
            action_info['output'] = fd.get_out_port(next_flow)
            for field in fd.get_ofb_fields(next_flow):
                if field.type == fd.VLAN_VID:
                    classifier_info['metadata'] = field.vlan_vid & 0xfff

        (intf_id, onu_id) = self.platform.extract_access_from_flow(
            classifier_info['in_port'], action_info['output'])

        self.divide_and_add_flow(intf_id, onu_id, classifier_info,
                                 action_info, flow)

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

    def divide_and_add_flow(self, intf_id, onu_id, classifier,
                            action, flow):

        self.log.debug('sorting flow', intf_id=intf_id, onu_id=onu_id,
                       classifier=classifier, action=action)

        if 'ip_proto' in classifier:
            if classifier['ip_proto'] == 17:
                self.log.debug('dhcp flow add')
                self.add_dhcp_trap(intf_id, onu_id, classifier,
                                   action, flow)
            elif classifier['ip_proto'] == 2:
                self.log.warn('igmp flow add ignored, not implemented yet')
            else:
                self.log.warn("Invalid-Classifier-to-handle",
                              classifier=classifier,
                              action=action)
        elif 'eth_type' in classifier:
            if classifier['eth_type'] == EAP_ETH_TYPE:
                self.log.debug('eapol flow add')
                self.add_eapol_flow(intf_id, onu_id, flow)
                vlan_id = self.get_subscriber_vlan(fd.get_in_port(flow))
                if vlan_id is not None:
                    self.add_eapol_flow(
                        intf_id, onu_id, flow,
                        uplink_eapol_id=EAPOL_UPLINK_SECONDARY_FLOW_INDEX,
                        downlink_eapol_id=EAPOL_DOWNLINK_SECONDARY_FLOW_INDEX,
                        vlan_id=vlan_id)
            if classifier['eth_type'] == LLDP_ETH_TYPE:
                self.log.debug('lldp flow add')
                self.add_lldp_flow(intf_id, onu_id, flow, classifier,
                                   action)

        elif 'push_vlan' in action:
            self.add_upstream_data_flow(intf_id, onu_id, classifier, action,
                                        flow)
        elif 'pop_vlan' in action:
            self.add_downstream_data_flow(intf_id, onu_id, classifier,
                                          action, flow)
        else:
            self.log.debug('Invalid-flow-type-to-handle',
                           classifier=classifier,
                           action=action, flow=flow)

    def add_upstream_data_flow(self, intf_id, onu_id, uplink_classifier,
                               uplink_action, logical_flow):

        uplink_classifier['pkt_tag_type'] = 'single_tag'

        self.add_hsia_flow(intf_id, onu_id, uplink_classifier,
                           uplink_action, 'upstream', HSIA_FLOW_INDEX,
                           logical_flow)

        # Secondary EAP on the subscriber vlan
        (eap_active, eap_logical_flow) = self.is_eap_enabled(intf_id, onu_id)
        if eap_active:
            self.add_eapol_flow(
                intf_id, onu_id, eap_logical_flow,
                uplink_eapol_id=EAPOL_UPLINK_SECONDARY_FLOW_INDEX,
                downlink_eapol_id=EAPOL_DOWNLINK_SECONDARY_FLOW_INDEX,
                vlan_id=uplink_classifier['vlan_vid'])

    def add_downstream_data_flow(self, intf_id, onu_id, downlink_classifier,
                                 downlink_action, flow):
        downlink_classifier['pkt_tag_type'] = 'double_tag'
        # Needed ???? It should be already there
        downlink_action['pop_vlan'] = True
        downlink_action['vlan_vid'] = downlink_classifier['vlan_vid']

        self.add_hsia_flow(intf_id, onu_id, downlink_classifier,
                           downlink_action, 'downstream', HSIA_FLOW_INDEX,
                           flow)

    # To-Do right now only one GEM port is supported, so below method
    # will take care of handling all the p bits.
    # We need to revisit when mulitple gem port per p bits is needed.
    # Waiting for Technology profile
    def add_hsia_flow(self, intf_id, onu_id, classifier, action,
                      direction, hsia_id, logical_flow):

        gemport_id = self.platform.mk_gemport_id(intf_id, onu_id)
        flow_id = self.platform.mk_flow_id(intf_id, onu_id, hsia_id)

        flow = openolt_pb2.Flow(
                onu_id=onu_id, flow_id=flow_id, flow_type=direction,
                access_intf_id=intf_id, gemport_id=gemport_id,
                priority=logical_flow.priority,
                classifier=self.mk_classifier(classifier),
                action=self.mk_action(action))

        self.add_flow_to_device(flow, logical_flow)

    def add_dhcp_trap(self, intf_id, onu_id, classifier, action, logical_flow):

        self.log.debug('add dhcp upstream trap', classifier=classifier,
                       action=action)

        action.clear()
        action['trap_to_host'] = True
        classifier['pkt_tag_type'] = 'single_tag'
        classifier.pop('vlan_vid', None)

        gemport_id = self.platform.mk_gemport_id(intf_id, onu_id)
        flow_id = self.platform.mk_flow_id(intf_id, onu_id, DHCP_FLOW_INDEX)

        upstream_flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=flow_id, flow_type="upstream",
            access_intf_id=intf_id, gemport_id=gemport_id,
            priority=logical_flow.priority,
            classifier=self.mk_classifier(classifier),
            action=self.mk_action(action))

        self.add_flow_to_device(upstream_flow, logical_flow)

        # FIXME - ONOS should send explicit upstream and downstream
        #         exact dhcp trap flow.

        downstream_logical_flow = copy.deepcopy(logical_flow)
        for oxm_field in downstream_logical_flow.match.oxm_fields:
            if oxm_field.ofb_field.type == OFPXMT_OFB_IN_PORT:
                oxm_field.ofb_field.port = \
                    self.platform.intf_id_to_port_no(0, Port.ETHERNET_NNI)

        classifier['udp_src'] = 67
        classifier['udp_dst'] = 68
        classifier['pkt_tag_type'] = 'double_tag'
        action.pop('push_vlan', None)

        flow_id = self.platform.mk_flow_id(intf_id, onu_id,
                                      DHCP_DOWNLINK_FLOW_INDEX)

        downstream_flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=flow_id, flow_type="downstream",
            access_intf_id=intf_id, network_intf_id=0, gemport_id=gemport_id,
            priority=logical_flow.priority, classifier=self.mk_classifier(
                classifier),
            action=self.mk_action(action))

        self.add_flow_to_device(downstream_flow, downstream_logical_flow)

    def add_eapol_flow(self, intf_id, onu_id, logical_flow,
                       uplink_eapol_id=EAPOL_FLOW_INDEX,
                       downlink_eapol_id=EAPOL_DOWNLINK_FLOW_INDEX,
                       vlan_id=DEFAULT_MGMT_VLAN):



        uplink_classifier = {}
        uplink_classifier['eth_type'] = EAP_ETH_TYPE
        uplink_classifier['pkt_tag_type'] = 'single_tag'
        uplink_classifier['vlan_vid'] = vlan_id

        uplink_action = {}
        uplink_action['trap_to_host'] = True

        gemport_id = self.platform.mk_gemport_id(intf_id, onu_id)

        # Add Upstream EAPOL Flow.

        uplink_flow_id = self.platform.mk_flow_id(intf_id, onu_id, uplink_eapol_id)

        upstream_flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=uplink_flow_id, flow_type="upstream",
            access_intf_id=intf_id, gemport_id=gemport_id,
            priority=logical_flow.priority,
            classifier=self.mk_classifier(uplink_classifier),
            action=self.mk_action(uplink_action))

        logical_flow = copy.deepcopy(logical_flow)
        logical_flow.match.oxm_fields.extend(fd.mk_oxm_fields([fd.vlan_vid(
            vlan_id | 0x1000)]))
        logical_flow.match.type = OFPMT_OXM

        self.add_flow_to_device(upstream_flow, logical_flow)

        if vlan_id == DEFAULT_MGMT_VLAN:

            # Add Downstream EAPOL Flow, Only for first EAP flow

            downlink_classifier = {}
            downlink_classifier['pkt_tag_type'] = 'single_tag'
            downlink_classifier['vlan_vid'] = 4000 - onu_id



            downlink_action = {}
            downlink_action['push_vlan'] = True
            downlink_action['vlan_vid'] = vlan_id

            downlink_flow_id = self.platform.mk_flow_id(intf_id, onu_id,
                                                   downlink_eapol_id)

            downstream_flow = openolt_pb2.Flow(
                onu_id=onu_id, flow_id=downlink_flow_id, flow_type="downstream",
                access_intf_id=intf_id, gemport_id=gemport_id,
                priority=logical_flow.priority,
                classifier=self.mk_classifier(downlink_classifier),
                action=self.mk_action(downlink_action))

            downstream_logical_flow = ofp_flow_stats(id=logical_flow.id,
                 cookie=logical_flow.cookie, table_id=logical_flow.table_id,
                 priority=logical_flow.priority, flags=logical_flow.flags)

            downstream_logical_flow.match.oxm_fields.extend(fd.mk_oxm_fields([
                fd.in_port(fd.get_out_port(logical_flow)),
                fd.vlan_vid((4000 - onu_id) | 0x1000)]))
            downstream_logical_flow.match.type = OFPMT_OXM

            downstream_logical_flow.instructions.extend(
                fd.mk_instructions_from_actions([fd.output(
                self.platform.mk_uni_port_num(intf_id, onu_id))]))

            self.add_flow_to_device(downstream_flow, downstream_logical_flow)

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
                self.log.debug('Problem readding this flow', error=e)

    def reset_flows(self):
        self.flows_proxy.update('/', Flows())

    def add_lldp_flow(self, intf_id, onu_id, logical_flow, classifier, action):

        self.log.debug('add lldp downstream trap', classifier=classifier,
                       action=action)

        action.clear()
        action['trap_to_host'] = True
        classifier['pkt_tag_type'] = 'untagged'

        gemport_id = self.platform.mk_gemport_id(onu_id)
        flow_id = self.platform.mk_flow_id(intf_id, onu_id, LLDP_FLOW_INDEX)

        downstream_flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=flow_id, flow_type="downstream",
            access_intf_id=3, network_intf_id=0, gemport_id=gemport_id,
            priority=logical_flow.priority,
            classifier=self.mk_classifier(classifier),
            action=self.mk_action(action))

        self.log.debug('add lldp downstream trap', access_intf_id=intf_id,
                       onu_id=onu_id, flow_id=flow_id)
        self.stub.FlowAdd(downstream_flow)

    def mk_classifier(self, classifier_info):

        classifier = openolt_pb2.Classifier()

        if 'eth_type' in classifier_info:
            classifier.eth_type = classifier_info['eth_type']
        if 'ip_proto' in classifier_info:
            classifier.ip_proto = classifier_info['ip_proto']
        if 'vlan_vid' in classifier_info:
            classifier.o_vid = classifier_info['vlan_vid']
        if 'metadata' in classifier_info:
            classifier.i_vid = classifier_info['metadata']
        if 'vlan_pcp' in classifier_info:
            classifier.o_pbits = classifier_info['vlan_pcp']
        if 'udp_src' in classifier_info:
            classifier.src_port = classifier_info['udp_src']
        if 'udp_dst' in classifier_info:
            classifier.dst_port = classifier_info['udp_dst']
        if 'ipv4_dst' in classifier_info:
            classifier.dst_ip = classifier_info['ipv4_dst']
        if 'ipv4_src' in classifier_info:
            classifier.src_ip = classifier_info['ipv4_src']
        if 'pkt_tag_type' in classifier_info:
            if classifier_info['pkt_tag_type'] == 'single_tag':
                classifier.pkt_tag_type = 'single_tag'
            elif classifier_info['pkt_tag_type'] == 'double_tag':
                classifier.pkt_tag_type = 'double_tag'
            elif classifier_info['pkt_tag_type'] == 'untagged':
                classifier.pkt_tag_type = 'untagged'
            else:
                classifier.pkt_tag_type = 'none'

        return classifier

    def mk_action(self, action_info):
        action = openolt_pb2.Action()

        if 'pop_vlan' in action_info:
            action.o_vid = action_info['vlan_vid']
            action.cmd.remove_outer_tag = True
        elif 'push_vlan' in action_info:
            action.o_vid = action_info['vlan_vid']
            action.cmd.add_outer_tag = True
        elif 'trap_to_host' in action_info:
            action.cmd.trap_to_host = True
        else:
            self.log.info('Invalid-action-field', action_info=action_info)
            return
        return action

    def is_eap_enabled(self, intf_id, onu_id):
        flows = self.logical_flows_proxy.get('/').items

        for flow in flows:
            eap_flow = False
            eap_intf_id = None
            eap_onu_id = None
            for field in fd.get_ofb_fields(flow):
                if field.type == fd.ETH_TYPE:
                    if field.eth_type == EAP_ETH_TYPE:
                        eap_flow = True
                if field.type == fd.IN_PORT:
                    eap_intf_id = self.platform.intf_id_from_uni_port_num(
                        field.port)
                    eap_onu_id = self.platform.onu_id_from_port_num(field.port)

            if eap_flow:
                self.log.debug('eap flow detected', onu_id=onu_id,
                               intf_id=intf_id, eap_intf_id=eap_intf_id,
                               eap_onu_id=eap_onu_id)
            if eap_flow and intf_id == eap_intf_id and onu_id == eap_onu_id:
                return (True, flow)

        return (False, None)

    def get_subscriber_vlan(self, port):
        self.log.debug('looking from subscriber flow for port', port=port)

        flows = self.logical_flows_proxy.get('/').items
        for flow in flows:
            in_port = fd.get_in_port(flow)
            out_port = fd.get_out_port(flow)

            if in_port == port and \
                self.platform.intf_id_to_port_type_name(out_port) == Port.ETHERNET_NNI:
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
        self.stub.FlowAdd(flow)
        self.register_flow(logical_flow, flow)

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
            reactor.callLater(5, self.add_flow, flow)
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

    def generate_stored_id(self, flow_id, direction):
        if direction == 'upstream':
            self.log.debug('upstream flow, shifting id')
            return 0x1 << 15 | flow_id
        elif direction == 'downstream':
            self.log.debug('downstream flow, not shifting id')
            return flow_id
        else:
            self.log.warn('Unrecognized direction', direction=direction)
            return flow_id

    def decode_stored_id(self, id):
        if id >> 15 == 0x1:
            return (id & 0x7fff, 'upstream')
        else:
            return (id, 'downstream')
