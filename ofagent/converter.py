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
    converter = to_loxi_converters[cls.__name__]
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

def ofp_flow_removed_to_loxi_flow_removed(pb):
    return of13.message.flow_removed(
        cookie=pb.cookie,
        priority=pb.priority,
        reason=pb.reason,
        table_id=pb.table_id,
        match=make_loxi_match(pb2dict(pb.match))
    )

def ofp_port_stats_to_loxi_port_stats(pb):
    kw = pb2dict(pb)
    return of13.port_stats_entry(**kw)


def ofp_meter_stats_to_loxi_meter_stats(pb):
    return of13.meter_stats(
        meter_id=pb.meter_id,
        flow_count=pb.flow_count,
        packet_in_count=pb.packet_in_count,
        byte_in_count=pb.byte_in_count,
        duration_sec=pb.duration_sec,
        duration_nsec=pb.duration_nsec,
        band_stats=[to_loxi(band_stat) for band_stat in pb.band_stats])


def ofp_meter_band_stats_to_loxi_meter_stats(pb):
    return of13.meter_band_stats(
        packet_band_count=pb.packet_band_count,
        byte_band_count=pb.byte_band_count
    )


def make_loxi_field(oxm_field):
    assert oxm_field['oxm_class'] == pb2.OFPXMC_OPENFLOW_BASIC
    ofb_field = oxm_field['ofb_field']
    field_type = ofb_field.get('type', 0)

    if field_type == pb2.OFPXMT_OFB_ETH_TYPE:
        return (
            of13.oxm.eth_type(value=ofb_field['eth_type']))

    elif field_type == pb2.OFPXMT_OFB_IN_PORT:
        return (
            of13.oxm.in_port(value=ofb_field['port']))

    elif field_type == pb2.OFPXMT_OFB_IP_PROTO:
        return (
            of13.oxm.ip_proto(value=ofb_field['ip_proto']))

    elif field_type == pb2.OFPXMT_OFB_VLAN_VID:
        if ofb_field.get('has_mask', 0):
            return of13.oxm.vlan_vid_masked(value=ofb_field['vlan_vid'],
                                            value_mask=ofb_field['vlan_vid_mask'])
        return (
            of13.oxm.vlan_vid(value=ofb_field['vlan_vid']))

    elif field_type == pb2.OFPXMT_OFB_VLAN_PCP:
        return (
            of13.oxm.vlan_pcp(value=ofb_field['vlan_pcp']))

    elif field_type == pb2.OFPXMT_OFB_IPV4_SRC:
        return (
            of13.oxm.ipv4_src(value=ofb_field['ipv4_src']))

    elif field_type == pb2.OFPXMT_OFB_IPV4_DST:
        return (
            of13.oxm.ipv4_dst(value=ofb_field['ipv4_dst']))

    elif field_type == pb2.OFPXMT_OFB_UDP_SRC:
        return (
            of13.oxm.udp_src(value=ofb_field['udp_src']))

    elif field_type == pb2.OFPXMT_OFB_UDP_DST:
        return (
            of13.oxm.udp_dst(value=ofb_field['udp_dst']))

    elif field_type == pb2.OFPXMT_OFB_METADATA:
        return (
            of13.oxm.metadata(value=ofb_field['table_metadata']))

    else:
        raise NotImplementedError(
            'OXM match field for type %s' % field_type)


def make_loxi_match(match):
    assert match.get('type', pb2.OFPMT_STANDARD) == pb2.OFPMT_OXM
    loxi_match_fields = []
    for oxm_field in match.get('oxm_fields', []):
        loxi_match_fields.append(make_loxi_field(oxm_field))
    return of13.match_v3(oxm_list=loxi_match_fields)


def make_loxi_action(a):
    if type(a) is not dict:
        a = pb2dict(a)

    typ = a.get('type', 0)

    if typ == pb2.OFPAT_OUTPUT:
        output_kws = a['output']
        return of13.action.output(**output_kws)

    elif typ == pb2.OFPAT_POP_VLAN:
        return of13.action.pop_vlan()

    elif typ == pb2.OFPAT_PUSH_VLAN:
        push_vlan_kws = a['push']
        return of13.action.push_vlan(**push_vlan_kws)

    elif typ == pb2.OFPAT_SET_FIELD:
        loxi_field = make_loxi_field(a['set_field']['field'])
        return of13.action.set_field(loxi_field)

    elif typ == pb2.OFPAT_GROUP:
        group_kws = a['group']
        return of13.action.group(**group_kws)

    else:
        raise NotImplementedError(
            'Action decoder for action OFPAT_* %d' % typ)


def ofp_flow_stats_to_loxi_flow_stats(pb):
    kw = pb2dict(pb)

    def make_loxi_instruction(inst):
        type = inst['type']
        if type == pb2.OFPIT_APPLY_ACTIONS:
            return of13.instruction.apply_actions(
                actions=[make_loxi_action(a)
                         for a in inst['actions']['actions']])
        elif type == pb2.OFPIT_CLEAR_ACTIONS:
            return of13.instruction.clear_actions()
        elif type == pb2.OFPIT_GOTO_TABLE:
            return of13.instruction.goto_table(
                table_id=inst['goto_table']['table_id'])
        elif type == pb2.OFPIT_WRITE_ACTIONS:
            return of13.instruction.write_actions(
                actions=[make_loxi_action(a)
                         for a in inst['actions']['actions']])
        elif type == pb2.OFPIT_WRITE_METADATA:
            if 'metadata' in inst['write_metadata']:
                return of13.instruction.write_metadata(
                        metadata=inst['write_metadata']['metadata'])
            else:
                return of13.instruction.write_metadata(0)
        elif type == pb2.OFPIT_METER:
            return of13.instruction.meter(
                meter_id=inst['meter']['meter_id'])

        else:
            raise NotImplementedError('Instruction type %d' % type)

    kw['match'] = make_loxi_match(kw['match'])
    # if the flow action is drop, then the instruction is not found in the dict
    if 'instructions' in kw:
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


def ofp_group_desc_to_loxi_group_desc(pb):
    return of13.group_desc_stats_entry(
        group_type=pb.type,
        group_id=pb.group_id,
        buckets=[to_loxi(bucket) for bucket in pb.buckets])


def ofp_group_stats_to_loxi_group_stats(pb):
    return of13.group_stats_entry(
        group_id=pb.group_id,
        ref_count=pb.ref_count,
        packet_count=pb.packet_count,
        byte_count=pb.byte_count,
        duration_sec=pb.duration_sec,
        duration_nsec=pb.duration_nsec,
        bucket_stats=[to_loxi(bstat) for bstat in pb.bucket_stats])


def ofp_bucket_counter_to_loxy_bucket_counter(pb):
    return of13.bucket_counter(
        packet_count=pb.packet_count,
        byte_count=pb.byte_count)


def ofp_bucket_to_loxi_bucket(pb):
    return of13.bucket(
        weight=pb.weight,
        watch_port=pb.watch_port,
        watch_group=pb.watch_group,
        actions=[to_loxi(action) for action in pb.actions]
    )


to_loxi_converters = {
    'ofp_port': ofp_port_to_loxi_port_desc,
    'ofp_port_status': ofp_port_status_to_loxi_port_status,
    'ofp_flow_removed': ofp_flow_removed_to_loxi_flow_removed,
    'ofp_flow_stats': ofp_flow_stats_to_loxi_flow_stats,
    'ofp_packet_in': ofp_packet_in_to_loxi_packet_in,
    'ofp_group_stats': ofp_group_stats_to_loxi_group_stats,
    'ofp_group_desc': ofp_group_desc_to_loxi_group_desc,
    'ofp_bucket_counter': ofp_bucket_counter_to_loxy_bucket_counter,
    'ofp_bucket': ofp_bucket_to_loxi_bucket,
    'ofp_action': make_loxi_action,
    'ofp_port_stats': ofp_port_stats_to_loxi_port_stats,
    'ofp_meter_stats': ofp_meter_stats_to_loxi_meter_stats,
    'ofp_meter_band_stats': ofp_meter_band_stats_to_loxi_meter_stats
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


def loxi_meter_mod_to_ofp_meter_mod(lo):
    return pb2.ofp_meter_mod(
        command=lo.command,
        flags=lo.flags,
        meter_id=lo.meter_id,
        bands=[to_grpc(i) for i in lo.meters])


def loxi_meter_band_drop_to_ofp_meter_band_drop(lo):
    return pb2.ofp_meter_band_header(
        type=lo.type,
        rate=lo.rate,
        burst_size=lo.burst_size)


def loxi_meter_band_dscp_remark_to_ofp_meter_band_dscp_remark(lo):
    return pb2.ofp_meter_band_header(
        type=lo.type,
        rate=lo.rate,
        burst_size=lo.burst_size,
        dscp_remark=pb2.ofp_meter_band_dscp_remark(prec_level=lo.prec_level))


def loxi_meter_band_experimenter_to_ofp_meter_band_experimenter(lo):
    return pb2.ofp_meter_band_header(
        type=lo.type,
        rate=lo.rate,
        burst_size=lo.burst_size,
        experimenter=pb2.ofp_meter_band_experimenter(experimenter=lo.experimenter))


def loxi_meter_multipart_request_to_ofp_meter_multipart_request(lo):
    return pb2.ofp_meter_multipart_request(
        meter_id=lo.meter_id)


def loxi_meter_stats_to_ofp_meter_stats(lo):
    return pb2.ofp_meter_stats(
        meter_id=lo.meter_id,
        flow_count=lo.flow_count,
        packet_in_count =lo.packet_in_count,
        byte_in_count=lo.byte_in_count,
        duration_sec=lo.duration_sec,
        duration_nsec=lo.duration_nsec,
        band_stats=lo.band_stats)


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


def loxi_oxm_vlan_vid_masked_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_VLAN_VID,
            has_mask=True,
            vlan_vid=lo.value,
            vlan_vid_mask=lo.value_mask))


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


def loxi_oxm_udp_dst_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_UDP_DST,
            udp_dst=lo.value))


def loxi_oxm_udp_src_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_UDP_SRC,
            udp_src=lo.value))


def loxi_oxm_metadata_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_METADATA,
            table_metadata=lo.value))


def loxi_apply_actions_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_APPLY_ACTIONS,
        actions=pb2.ofp_instruction_actions(
            actions=[to_grpc(a) for a in lo.actions]))

def loxi_clear_actions_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_CLEAR_ACTIONS)


def loxi_goto_table_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_GOTO_TABLE,
        goto_table=pb2.ofp_instruction_goto_table(table_id=lo.table_id))


def loxi_write_metadata_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_WRITE_METADATA,
        write_metadata=pb2.ofp_instruction_write_metadata(
            metadata=lo.metadata,
            metadata_mask=lo.metadata_mask))


def loxi_meter_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_METER,
        meter=pb2.ofp_instruction_meter(meter_id=lo.meter_id))


def loxi_output_action_to_ofp_action(lo):
    return pb2.ofp_action(
        type=pb2.OFPAT_OUTPUT,
        output=pb2.ofp_action_output(port=lo.port, max_len=lo.max_len))


def loxi_write_actions_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_WRITE_ACTIONS,
        actions=pb2.ofp_instruction_actions(
            actions=[to_grpc(a) for a in lo.actions]))


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
    of13.message.meter_mod: loxi_meter_mod_to_ofp_meter_mod,
    of13.message.meter_stats_request: loxi_meter_stats_to_ofp_meter_stats,

    of13.message.group_add: loxi_group_mod_to_ofp_group_mod,
    of13.message.group_delete: loxi_group_mod_to_ofp_group_mod,
    of13.message.group_modify: loxi_group_mod_to_ofp_group_mod,
    of13.message.packet_out: loxi_packet_out_to_ofp_packet_out,

    of13.meter_band.drop: loxi_meter_band_drop_to_ofp_meter_band_drop,
    of13.meter_band.dscp_remark: loxi_meter_band_dscp_remark_to_ofp_meter_band_dscp_remark,
    of13.meter_band.experimenter: loxi_meter_band_experimenter_to_ofp_meter_band_experimenter,

    of13.common.match_v3: loxi_match_v3_to_ofp_match,
    of13.common.bucket: loxi_bucket_to_ofp_bucket,

    of13.oxm.eth_type: loxi_oxm_eth_type_to_ofp_oxm,
    of13.oxm.in_port: loxi_oxm_in_port_to_ofp_oxm,
    of13.oxm.ip_proto: loxi_oxm_ip_proto_to_ofp_oxm,
    of13.oxm.vlan_vid: loxi_oxm_vlan_vid_to_ofp_oxm,
    of13.oxm.vlan_vid_masked: loxi_oxm_vlan_vid_masked_to_ofp_oxm,
    of13.oxm.vlan_pcp: loxi_oxm_vlan_pcp_to_ofp_oxm,
    of13.oxm.ipv4_dst: loxi_oxm_ipv4_dst_to_ofp_oxm,
    of13.oxm.udp_src: loxi_oxm_udp_src_to_ofp_oxm,
    of13.oxm.udp_dst: loxi_oxm_udp_dst_to_ofp_oxm,
    of13.oxm.metadata: loxi_oxm_metadata_to_ofp_oxm,

    of13.instruction.apply_actions: loxi_apply_actions_to_ofp_instruction,
    of13.instruction.clear_actions: loxi_clear_actions_to_ofp_instruction,
    of13.instruction.write_actions: loxi_write_actions_to_ofp_instruction,
    of13.instruction.goto_table: loxi_goto_table_to_ofp_instruction,
    of13.instruction.write_metadata: loxi_write_metadata_to_ofp_instruction,
    of13.instruction.meter: loxi_meter_to_ofp_instruction,

    of13.action.output: loxi_output_action_to_ofp_action,
    of13.action.group: loxi_group_action_to_ofp_action,
    of13.action.set_field: loxi_set_field_action_to_ofp_action,
    of13.action.pop_vlan: loxi_pop_vlan_action_to_ofp_action,
    of13.action.push_vlan: loxi_push_vlan_action_to_ofp_action,
}
