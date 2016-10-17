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

def ofp_flow_stats_to_loxi_flow_stats(pb):
    kw = pb2dict(pb)
    print 'QQQQQQQQQQQ', kw

    def make_loxi_match(match):
        assert match['type'] == pb2.OFPMT_OXM
        loxi_match_fields = []
        for oxm_field in match['oxm_fields']:
            assert oxm_field['oxm_class'] == pb2.OFPXMC_OPENFLOW_BASIC
            ofb_field = oxm_field['ofb_field']
            field_type = ofb_field.get('type', 0)
            if field_type == pb2.OFPXMT_OFB_ETH_TYPE:
                loxi_match_fields.append(
                    of13.oxm.eth_type(value=ofb_field['eth_type']))
            else:
                raise NotImplementedError(
                    'OXM match field for type %s' % field_type)
        return of13.match_v3(oxm_list=loxi_match_fields)

    def make_loxi_action(a):
        print 'AAAAAAAAAA', a
        type = a.get('type', 0)
        if type == pb2.OFPAT_OUTPUT:
            output = a['output']
            return of13.action.output(**output)
        else:
            raise NotImplementedError(
                'Action decoder for action OFPAT_* %d' % type)

    def make_loxi_instruction(inst):
        print 'IIIIIIIIIIIIIIII', inst
        type = inst['type']
        if type == pb2.OFPIT_APPLY_ACTIONS:
            return of13.instruction.apply_actions(
                actions=[make_loxi_action(a)
                         for a in inst['actions']['actions']])
        else:
            raise NotImplementedError('Instruction type %d' % type)

    kw['match'] = make_loxi_match(kw['match'])
    kw['instructions'] = [make_loxi_instruction(i) for i in kw['instructions']]
    return of13.flow_stats_entry(**kw)

to_loxi_converters = {
    pb2.ofp_port: ofp_port_to_loxi_port_desc,
    pb2.ofp_flow_stats: ofp_flow_stats_to_loxi_flow_stats
}

def loxi_flow_mod_to_ofp_flow_mod(loxi_flow_mod):
    return pb2.ofp_flow_mod(
        cookie=loxi_flow_mod.cookie,
        cookie_mask=loxi_flow_mod.cookie_mask,
        table_id=loxi_flow_mod.table_id,
        command=loxi_flow_mod._command,
        idle_timeout=loxi_flow_mod.idle_timeout,
        hard_timeout=loxi_flow_mod.hard_timeout,
        priority=loxi_flow_mod.priority,
        buffer_id=loxi_flow_mod.buffer_id,
        out_port=loxi_flow_mod.out_port,
        out_group=loxi_flow_mod.out_group,
        flags=loxi_flow_mod.flags,
        match=to_grpc(loxi_flow_mod.match),
        instructions=[to_grpc(i) for i in loxi_flow_mod.instructions]
    )

def loxi_match_v3_to_ofp_match(loxi_match):
    return pb2.ofp_match(
        type=pb2.OFPMT_OXM,
        oxm_fields=[to_grpc(f) for f in loxi_match.oxm_list]
    )

def loxi_oxm_eth_type_to_ofp_oxm(lo):
    return pb2.ofp_oxm_field(
        oxm_class=pb2.OFPXMC_OPENFLOW_BASIC,
        ofb_field=pb2.ofp_oxm_ofb_field(
            type=pb2.OFPXMT_OFB_ETH_TYPE,
            eth_type=lo.value
        )
    )

def loxi_apply_actions_to_ofp_instruction(lo):
    return pb2.ofp_instruction(
        type=pb2.OFPIT_APPLY_ACTIONS,
        actions=pb2.ofp_instruction_actions(
            actions=[to_grpc(a) for a in lo.actions]
        )
    )

def loxi_output_action_to_ofp_action(lo):
    return pb2.ofp_action(
        type=pb2.OFPAT_OUTPUT,
        output=pb2.ofp_action_output(
            port=lo.port,
            max_len=lo.max_len
        )
    )

to_grpc_converters = {
    of13.message.flow_add: loxi_flow_mod_to_ofp_flow_mod,
    of13.common.match_v3: loxi_match_v3_to_ofp_match,
    of13.oxm.eth_type: loxi_oxm_eth_type_to_ofp_oxm,
    of13.instruction.apply_actions: loxi_apply_actions_to_ofp_instruction,
    of13.action.output: loxi_output_action_to_ofp_action
}
