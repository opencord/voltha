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

from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC
import voltha.core.flow_decomposer as fd
import openolt_platform as platform
from voltha.adapters.openolt.protos import openolt_pb2
from voltha.registry import registry

HSIA_FLOW_INDEX = 0  # FIXME
DHCP_FLOW_INDEX = 1  # FIXME
EAPOL_FLOW_INDEX = 2  # FIXME
EAPOL_DOWNLINK_FLOW_INDEX = 3  # FIXME
EAPOL_DOWNLINK_SECONDARY_FLOW_INDEX = 4  # FIXME
EAPOL_UPLINK_SECONDARY_FLOW_INDEX = 5  # FIXME


EAP_ETH_TYPE = 0x888e

# FIXME - see also BRDCM_DEFAULT_VLAN in broadcom_onu.py
DEFAULT_MGMT_VLAN = 4091


class OpenOltFlowMgr(object):

    def __init__(self, log, stub, device_id):
        self.log = log
        self.stub = stub
        self.device_id = device_id
        self.flow_proxy = registry('core').get_proxy(
            '/devices/{}/flows'.format(self.device_id))

    def add_flow(self, flow, is_down_stream):
        self.log.debug('add flow', flow=flow, is_down_stream=is_down_stream)
        classifier_info = dict()
        action_info = dict()

        in_port = fd.get_in_port(flow)
        assert in_port is not None

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
                action_info['pop_vlan'] = True
                self.log.debug('action-type-pop-vlan', in_port=in_port)
            elif action.type == fd.PUSH_VLAN:
                action_info['push_vlan'] = True
                action_info['tpid'] = action.push.ethertype
                self.log.debug('action-type-push-vlan',
                               push_tpid=action_info['tpid'], in_port=in_port)
                if action.push.ethertype != 0x8100:
                    self.log.error('unhandled-tpid',
                                   ethertype=action.push.ethertype)
            elif action.type == fd.SET_FIELD:
                # action_info['action_type'] = 'set_field'
                _field = action.set_field.field.ofb_field
                assert (action.set_field.field.oxm_class ==
                        OFPXMC_OPENFLOW_BASIC)
                self.log.debug('action-type-set-field',
                               field=_field, in_port=in_port)
                if _field.type == fd.VLAN_VID:
                    self.log.debug('set-field-type-vlan-vid',
                                   vlan_vid=_field.vlan_vid & 0xfff)
                    action_info['vlan_vid'] = (_field.vlan_vid & 0xfff)
                else:
                    self.log.error('unsupported-action-set-field-type',
                                   field_type=_field.type)
            else:
                self.log.error('unsupported-action-type',
                               action_type=action.type, in_port=in_port)

        # FIXME - Why ignore downstream flows?
        if is_down_stream is False:
            intf_id = platform.intf_id_from_uni_port_num(
                classifier_info['in_port'])
            onu_id = platform.onu_id_from_port_num(
                classifier_info['in_port'])
            self.divide_and_add_flow(intf_id, onu_id,
                                     flow.priority, classifier_info,
                                     action_info)
        # else:
        #    self.log.info('ignore downstream flow', flow=flow,
        #            classifier_info=classifier_info,
        #            action_info=action_info)

    # FIXME - No need for divide_and_add_flow if
    # both upstream and downstream flows
    # are acted upon (not just upstream flows).
    def divide_and_add_flow(self, intf_id, onu_id, priority, classifier,
                            action):
        if 'ip_proto' in classifier:
            if classifier['ip_proto'] == 17:
                self.log.debug('dhcp flow add')
                self.add_dhcp_trap(intf_id, onu_id, priority, classifier,
                                   action)
            elif classifier['ip_proto'] == 2:
                self.log.debug('igmp flow add ignored')
            else:
                self.log.debug("Invalid-Classifier-to-handle",
                               classifier=classifier,
                               action=action)
        elif 'eth_type' in classifier:
            if classifier['eth_type'] == EAP_ETH_TYPE:
                self.log.debug('eapol flow add')
                self.add_eapol_flow(intf_id, onu_id, priority)

        elif 'push_vlan' in action:
            self.add_data_flow(intf_id, onu_id, priority, classifier, action)
        else:
            self.log.debug('Invalid-flow-type-to-handle',
                           classifier=classifier,
                           action=action)

    def add_data_flow(self, intf_id, onu_id, priority, uplink_classifier, uplink_action):

        downlink_classifier = dict(uplink_classifier)
        downlink_action = dict(uplink_action)

        uplink_classifier['pkt_tag_type'] = 'single_tag'

        downlink_classifier['pkt_tag_type'] = 'double_tag'
        downlink_classifier['vlan_vid'] = uplink_action['vlan_vid']
        downlink_classifier['metadata'] = uplink_classifier['vlan_vid']
        del downlink_action['push_vlan']
        downlink_action['pop_vlan'] = True

        # To-Do right now only one GEM port is supported, so below method
        # will take care of handling all the p bits.
        # We need to revisit when mulitple gem port per p bits is needed.
        self.add_hsia_flow(intf_id, onu_id, priority, uplink_classifier, uplink_action,
                           downlink_classifier, downlink_action,
                           HSIA_FLOW_INDEX)

        # Secondary EAP on the subscriber vlan
        (eap_active, eap_priority) = self.is_eap_enabled(intf_id, onu_id)
        if eap_active:
            self.add_eapol_flow(intf_id, onu_id, eap_priority,
                uplink_eapol_id=EAPOL_UPLINK_SECONDARY_FLOW_INDEX,
                downlink_eapol_id=EAPOL_DOWNLINK_SECONDARY_FLOW_INDEX,
                vlan_id=uplink_classifier['vlan_vid'])

    def add_hsia_flow(self, intf_id, onu_id, priority, uplink_classifier, uplink_action,
                      downlink_classifier, downlink_action, hsia_id):

        gemport_id = platform.mk_gemport_id(onu_id)
        flow_id = platform.mk_flow_id(intf_id, onu_id, hsia_id)

        self.log.debug('add upstream flow', onu_id=onu_id,
                       classifier=uplink_classifier, action=uplink_action,
                       gemport_id=gemport_id, flow_id=flow_id)

        flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=flow_id, flow_type="upstream",
            access_intf_id=intf_id, gemport_id=gemport_id, priority=priority,
            classifier=self.mk_classifier(uplink_classifier),
            action=self.mk_action(uplink_action))

        self.stub.FlowAdd(flow)

        self.log.debug('add downstream flow', classifier=downlink_classifier,
                       action=downlink_action, gemport_id=gemport_id,
                       flow_id=flow_id)

        flow = openolt_pb2.Flow(
                onu_id=onu_id, flow_id=flow_id, flow_type="downstream",
                access_intf_id=intf_id, gemport_id=gemport_id,
                priority=priority,
                classifier=self.mk_classifier(downlink_classifier),
                action=self.mk_action(downlink_action))

        self.stub.FlowAdd(flow)

    def add_dhcp_trap(self, intf_id, onu_id, priority, classifier, action):

        self.log.debug('add dhcp trap', classifier=classifier, action=action)

        action.clear()
        action['trap_to_host'] = True
        classifier['pkt_tag_type'] = 'single_tag'
        classifier.pop('vlan_vid', None)

        gemport_id = platform.mk_gemport_id(onu_id)
        flow_id = platform.mk_flow_id(intf_id, onu_id, DHCP_FLOW_INDEX)

        upstream_flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=flow_id, flow_type="upstream",
            access_intf_id=intf_id, gemport_id=gemport_id, priority=priority,
            classifier=self.mk_classifier(classifier),
            action=self.mk_action(action))

        self.stub.FlowAdd(upstream_flow)

    def add_eapol_flow(self, intf_id, onu_id, priority,
                       uplink_eapol_id=EAPOL_FLOW_INDEX,
                       downlink_eapol_id=EAPOL_DOWNLINK_FLOW_INDEX,
                       vlan_id=DEFAULT_MGMT_VLAN):

        # self.log.debug('add eapol flow pre-process',
        #                classifier=uplink_classifier)
        #                #action=uplink_action)

        downlink_classifier = {}
        downlink_classifier['eth_type'] = EAP_ETH_TYPE
        downlink_classifier['pkt_tag_type'] = 'single_tag'
        downlink_classifier['vlan_vid'] = vlan_id

        downlink_action = {}
        downlink_action['push_vlan'] = True
        downlink_action['vlan_vid'] = vlan_id

        uplink_classifier = {}
        uplink_classifier['eth_type'] = EAP_ETH_TYPE
        uplink_classifier['pkt_tag_type'] = 'single_tag'
        uplink_classifier['vlan_vid'] = vlan_id

        uplink_action = {}
        uplink_action['trap_to_host'] = True

        gemport_id = platform.mk_gemport_id(onu_id)


        # Add Upstream EAPOL Flow.

        uplink_flow_id = platform.mk_flow_id(intf_id, onu_id, uplink_eapol_id)

        upstream_flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=uplink_flow_id, flow_type="upstream",
            access_intf_id=intf_id, gemport_id=gemport_id, priority=priority,
            classifier=self.mk_classifier(uplink_classifier),
            action=self.mk_action(uplink_action))

        self.stub.FlowAdd(upstream_flow)

        # Add Downstream EAPOL Flow.
        downlink_flow_id = platform.mk_flow_id(intf_id, onu_id,
                                               downlink_eapol_id)

        downstream_flow = openolt_pb2.Flow(
            onu_id=onu_id, flow_id=downlink_flow_id, flow_type="downstream",
            access_intf_id=intf_id, gemport_id=gemport_id,
            classifier=self.mk_classifier(downlink_classifier),
            action=self.mk_action(downlink_action))

        self.stub.FlowAdd(downstream_flow)

        self.log.debug('eap flows', upstream_flow=upstream_flow,
                       downstream_flow=downstream_flow)

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
            self.log.info('Invalid-action-field')
            return
        return action

    def is_eap_enabled(self, intf_id, onu_id):
        flows = self.flow_proxy.get('/').items

        for flow in flows:
            eap_flow = False
            eap_intf_id = None
            eap_onu_id = None
            for field in fd.get_ofb_fields(flow):
                if field.type == fd.ETH_TYPE:
                    if field.eth_type == EAP_ETH_TYPE:
                        eap_flow = True
                if field.type == fd.IN_PORT:
                    eap_intf_id = platform.intf_id_from_uni_port_num(field.port)
                    eap_onu_id = platform.onu_id_from_port_num(field.port)

            if eap_flow:
                self.log.debug('eap flow detected', onu_id=onu_id,
                               intf_id=intf_id, eap_intf_id=eap_intf_id,
                               eap_onu_id=eap_onu_id)
            if eap_flow and intf_id == eap_intf_id and onu_id == eap_onu_id:
                return (True, flow.priority)

        return (False, 0)