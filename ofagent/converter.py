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
Convert loxi objects to openflow_13 messages and back.
"""
from copy import copy

from google.protobuf.descriptor import FieldDescriptor

import loxi.of13 as of13
from protobuf_to_dict import protobuf_to_dict, TYPE_CALLABLE_MAP
from protos import openflow_13_pb2 as pb2


type_callable_map = copy(TYPE_CALLABLE_MAP)
type_callable_map.update({
    FieldDescriptor.TYPE_STRING: str
})

def pb2dict(pb):
    """
    Convert protobuf to a dict of values good for instantiating
    loxi objects (or any other objects). We specialize the protobuf_to_dict
    library call with our modified decoders.
    :param pb: protobuf as loaded into Python
    :return: dict of values
    """
    return protobuf_to_dict(pb, type_callable_map)

def to_loxi(grpc_object):
    cls = grpc_object.__class__
    converter = to_loxi_converters[cls]
    return converter(grpc_object)

def to_grpc(loxi_object):
    cls = loxi_object.__class__
    converter = to_grpc_converters[cls]
    return converter(loxi_object)

def ofp_port_to_loxi_port_desc(pb):
    kw = pb2dict(pb)
    return of13.common.port_desc(**kw)

def ofp_port_status_to_loxi_port_status(pb):
    return of13.message.port_status(
        reason=pb.reason,
        desc=ofp_port_to_loxi_port_desc(pb.desc)
    )

def make_loxi_match(match):
    assert match.get('type', pb2.OFPMT_STANDARD) == pb2.OFPMT_OXM
    loxi_match_fields = []
    for oxm_field in match.get('oxm_fields', []):
        assert oxm_field['oxm_class'] == pb2.OFPXMC_OPENFLOW_BASIC
        ofb_field = oxm_field['ofb_field']
        field_type = ofb_field.get('type', 0)
        if field_type == pb2.OFPXMT_OFB_ETH_TYPE:
            loxi_match_fields.append(
                of13.oxm.eth_type(value=ofb_field['eth_type']))
        elif field_type == pb2.OFPXMT_OFB_IN_PORT:
            loxi_match_fields.append(
                of13.oxm.in_port(value=ofb_field['port']))
        else:
            raise NotImplementedError(
                'OXM match field for type %s' % field_type)
    return of13.match_v3(oxm_list=loxi_match_fields)

def ofp_flow_stats_to_loxi_flow_stats(pb):
    kw = pb2dict(pb)

    def make_loxi_action(a):
        type = a.get('type', 0)
        if type == pb2.OFPAT_OUTPUT:
            output = a['output']
            return of13.action.output(**output)
        else:
            raise NotImplementedError(
                'Action decoder for action OFPAT_* %d' % type)

    def make_loxi_instruction(inst):
        type = inst['type']
        if type == pb2.OFPIT_APPLY_ACTIONS:
            return of13.instruction.apply_actions(
                actions=[make_loxi_action(a)
                         for a in inst['actions']['actions']])
        else:
            raise NotImplementedError('Instruction type %d' % type)

    kw['match'] = make_loxi_match(kw['match'])
    kw['instructions'] = [make_loxi_instruction(i) for i in kw['instructions']]
    del kw['id']
    return of13.flow_stats_entry(**kw)


def ofp_packet_in_to_loxi_packet_in(pb):
    packet_in = of13.message.packet_in(
        buffer_id=pb.buffer_id,
        reason=pb.reason,
        table_id=pb.table_id,
        cookie=pb.cookie,
        match=make_loxi_match(pb2dict(pb.match)),
        data=pb.data
    )
    return packet_in


def ofp_group_entry_to_loxi_group_entry(pb):
    return of13.group_stats_entry(
        group_id=pb.stats.group_id,
        ref_count=pb.stats.ref_count,
        packet_count=pb.stats.packet_count,
        byte_count=pb.stats.byte_count,
        duration_sec=pb.stats.duration_sec,
        duration_nsec=pb.stats.duration_nsec,
        bucket_stats=[to_loxi(bstat) for bstat in pb.stats.bucket_stats])

def ofp_bucket_counter_to_loxy_bucket_counter(pb):
    return of13.bucket_counter(
        packet_count=pb.packet_count,
        byte_count=pb.byte_count)


to_loxi_converters = {
    pb2.ofp_port: ofp_port_to_loxi_port_desc,
    pb2.ofp_port_status: ofp_port_status_to_loxi_port_status,
    pb2.ofp_flow_stats: ofp_flow_stats_to_loxi_flow_stats,
    pb2.ofp_packet_in: ofp_packet_in_to_loxi_packet_in,
    pb2.ofp_group_entry: ofp_group_entry_to_loxi_group_entry,
    pb2.ofp_bucket_counter: ofp_bucket_counter_to_loxy_bucket_counter
}


def loxi_flow_mod_to_ofp_flow_mod(lo):
    return pb2.ofp_flow_mod(
        cookie=lo.cookie,
        cookie_mask=lo.cookie_mask,
        table_id=lo.table_id,
        command=lo._command,
        idle_timeout=lo.idle_timeout,
        hard_timeout=lo.hard_timeout,
        priority=lo.priority,
        buffer_id=lo.buffer_id,
        out_port=lo.out_port,
        out_group=lo.out_group,
        flags=lo.flags,
        match=to_grpc(lo.match),
        instructions=[to_grpc(i) for i in lo.instructions])


def loxi_group_mod_to_ofp_group_mod(lo):
    return pb2.ofp_group_mod(
        command=lo.command,
        type=lo.group_type,
        group_id=lo.group_id,
        buckets=[to_grpc(b) for b in lo.buckets])


def loxi_packet_out_to_ofp_packet_out(lo):
    return pb2.ofp_packet_out(
        buffer_id=lo.buffer_id,
        in_port=lo.in_port,
        actions=[to_grpc(a) for a in lo.actions],
        data=lo.data)


def loxi_match_v3_to_ofp_match(lo):
    return pb2.ofp_match(
        type=pb2.OFPMT_OXM,
        oxm_fields=[to_grpc(f) for f in lo.oxm_list])


def loxi_bucket_to_ofp_bucket(lo):
    return pb2.ofp_bucket(
        weight=lo.weight,
        watch_port=lo.watch_port,
        watch_group=lo.watch_group,
        actions=[to_grpc(a) for a in lo.actions])


def loxi_oxm_eth_type_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_ETH_TYPE,
            eth_type=lo.value))


def loxi_oxm_in_port_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_IN_PORT,
            port=lo.value))


def loxi_oxm_ip_proto_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_IP_PROTO,
            ip_proto=lo.value))


def loxi_oxm_vlan_vid_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_VLAN_VID,
            vlan_vid=lo.value))


def loxi_oxm_vlan_pcp_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_VLAN_PCP,
            vlan_pcp=lo.value))


def loxi_oxm_ipv4_dst_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_IPV4_DST,
            ipv4_dst=lo.value))


def loxi_apply_actions_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_APPLY_ACTIONS,
        actions=pb2.ofp_instruction_actions(
            actions=[to_grpc(a) for a in lo.actions]))


def loxi_goto_table_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_GOTO_TABLE,
        goto_table=pb2.ofp_instruction_goto_table(table_id=lo.table_id))


def loxi_output_action_to_ofp_action(lo):
    return pb2.ofp_action(
        type=pb2.OFPAT_OUTPUT,
        output=pb2.ofp_action_output(port=lo.port, max_len=lo.max_len))


def loxi_group_action_to_ofp_action(lo):
    return pb2.ofp_action(
        type=pb2.OFPAT_GROUP,
        group=pb2.ofp_action_group(group_id=lo.group_id))


def loxi_set_field_action_to_ofp_action(lo):
    return pb2.ofp_action(
        type=pb2.OFPAT_SET_FIELD,
        set_field=pb2.ofp_action_set_field(field=to_grpc(lo.field)))


def loxi_pop_vlan_action_to_ofp_action(lo):
    return pb2.ofp_action(type=pb2.OFPAT_POP_VLAN)


def loxi_push_vlan_action_to_ofp_action(lo):
    return pb2.ofp_action(
        type=pb2.OFPAT_PUSH_VLAN,
        push=pb2.ofp_action_push(ethertype=lo.ethertype))


to_grpc_converters = {

    of13.message.flow_add: loxi_flow_mod_to_ofp_flow_mod,
    of13.message.flow_delete: loxi_flow_mod_to_ofp_flow_mod,
    of13.message.flow_delete_strict: loxi_flow_mod_to_ofp_flow_mod,
    of13.message.flow_modify: loxi_flow_mod_to_ofp_flow_mod,
    of13.message.flow_modify_strict: loxi_flow_mod_to_ofp_flow_mod,

    of13.message.group_add: loxi_group_mod_to_ofp_group_mod,
    of13.message.group_delete: loxi_group_mod_to_ofp_group_mod,
    of13.message.group_modify: loxi_group_mod_to_ofp_group_mod,
    of13.message.packet_out: loxi_packet_out_to_ofp_packet_out,

    of13.common.match_v3: loxi_match_v3_to_ofp_match,
    of13.common.bucket: loxi_bucket_to_ofp_bucket,

    of13.oxm.eth_type: loxi_oxm_eth_type_to_ofp_oxm,
    of13.oxm.in_port: loxi_oxm_in_port_to_ofp_oxm,
    of13.oxm.ip_proto: loxi_oxm_ip_proto_to_ofp_oxm,
    of13.oxm.vlan_vid: loxi_oxm_vlan_vid_to_ofp_oxm,
    of13.oxm.vlan_pcp: loxi_oxm_vlan_pcp_to_ofp_oxm,
    of13.oxm.ipv4_dst: loxi_oxm_ipv4_dst_to_ofp_oxm,

    of13.instruction.apply_actions: loxi_apply_actions_to_ofp_instruction,
    of13.instruction.goto_table: loxi_goto_table_to_ofp_instruction,

    of13.action.output: loxi_output_action_to_ofp_action,
    of13.action.group: loxi_group_action_to_ofp_action,
    of13.action.set_field: loxi_set_field_action_to_ofp_action,
    of13.action.pop_vlan: loxi_pop_vlan_action_to_ofp_action,
    of13.action.push_vlan: loxi_push_vlan_action_to_ofp_action,
}
