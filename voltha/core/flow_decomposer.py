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
A mix-in class implementing flow decomposition
"""
from collections import OrderedDict
from copy import copy, deepcopy
from hashlib import md5

from voltha.protos import openflow_13_pb2 as ofp

# aliases
ofb_field = ofp.ofp_oxm_ofb_field
action = ofp.ofp_action

# OFPAT_* shortcuts
OUTPUT = ofp.OFPAT_OUTPUT
COPY_TTL_OUT = ofp.OFPAT_COPY_TTL_OUT
COPY_TTL_IN = ofp.OFPAT_COPY_TTL_IN
SET_MPLS_TTL = ofp.OFPAT_SET_MPLS_TTL
DEC_MPLS_TTL = ofp.OFPAT_DEC_MPLS_TTL
PUSH_VLAN = ofp.OFPAT_PUSH_VLAN
POP_VLAN = ofp.OFPAT_POP_VLAN
PUSH_MPLS = ofp.OFPAT_PUSH_MPLS
POP_MPLS = ofp.OFPAT_POP_MPLS
SET_QUEUE = ofp.OFPAT_SET_QUEUE
GROUP = ofp.OFPAT_GROUP
SET_NW_TTL = ofp.OFPAT_SET_NW_TTL
NW_TTL = ofp.OFPAT_DEC_NW_TTL
SET_FIELD = ofp.OFPAT_SET_FIELD
PUSH_PBB = ofp.OFPAT_PUSH_PBB
POP_PBB = ofp.OFPAT_POP_PBB
EXPERIMENTER = ofp.OFPAT_EXPERIMENTER

# OFPXMT_OFB_* shortcuts (incomplete)
IN_PORT = ofp.OFPXMT_OFB_IN_PORT
IN_PHY_PORT = ofp.OFPXMT_OFB_IN_PHY_PORT
METADATA = ofp.OFPXMT_OFB_METADATA
ETH_DST = ofp.OFPXMT_OFB_ETH_DST
ETH_SRC = ofp.OFPXMT_OFB_ETH_SRC
ETH_TYPE = ofp.OFPXMT_OFB_ETH_TYPE
VLAN_VID = ofp.OFPXMT_OFB_VLAN_VID
VLAN_PCP = ofp.OFPXMT_OFB_VLAN_PCP
IP_DSCP = ofp.OFPXMT_OFB_IP_DSCP
IP_ECN = ofp.OFPXMT_OFB_IP_ECN
IP_PROTO = ofp.OFPXMT_OFB_IP_PROTO
IPV4_SRC = ofp.OFPXMT_OFB_IPV4_SRC
IPV4_DST = ofp.OFPXMT_OFB_IPV4_DST
TCP_SRC = ofp.OFPXMT_OFB_TCP_SRC
TCP_DST = ofp.OFPXMT_OFB_TCP_DST
UDP_SRC = ofp.OFPXMT_OFB_UDP_SRC
UDP_DST = ofp.OFPXMT_OFB_UDP_DST
SCTP_SRC = ofp.OFPXMT_OFB_SCTP_SRC
SCTP_DST = ofp.OFPXMT_OFB_SCTP_DST
ICMPV4_TYPE = ofp.OFPXMT_OFB_ICMPV4_TYPE
ICMPV4_CODE = ofp.OFPXMT_OFB_ICMPV4_CODE
ARP_OP = ofp.OFPXMT_OFB_ARP_OP
ARP_SPA = ofp.OFPXMT_OFB_ARP_SPA
ARP_TPA = ofp.OFPXMT_OFB_ARP_TPA
ARP_SHA = ofp.OFPXMT_OFB_ARP_SHA
ARP_THA = ofp.OFPXMT_OFB_ARP_THA
IPV6_SRC = ofp.OFPXMT_OFB_IPV6_SRC
IPV6_DST = ofp.OFPXMT_OFB_IPV6_DST
IPV6_FLABEL = ofp.OFPXMT_OFB_IPV6_FLABEL
ICMPV6_TYPE = ofp.OFPXMT_OFB_ICMPV6_TYPE
ICMPV6_CODE = ofp.OFPXMT_OFB_ICMPV6_CODE
IPV6_ND_TARGET = ofp.OFPXMT_OFB_IPV6_ND_TARGET
OFB_IPV6_ND_SLL = ofp.OFPXMT_OFB_IPV6_ND_SLL
IPV6_ND_TLL = ofp.OFPXMT_OFB_IPV6_ND_TLL
MPLS_LABEL = ofp.OFPXMT_OFB_MPLS_LABEL
MPLS_TC = ofp.OFPXMT_OFB_MPLS_TC
MPLS_BOS = ofp.OFPXMT_OFB_MPLS_BOS
PBB_ISID = ofp.OFPXMT_OFB_PBB_ISID
TUNNEL_ID = ofp.OFPXMT_OFB_TUNNEL_ID
IPV6_EXTHDR = ofp.OFPXMT_OFB_IPV6_EXTHDR

# ofp_action_* shortcuts

def output(port, max_len=ofp.OFPCML_MAX):
    return action(
        type=OUTPUT,
        output=ofp.ofp_action_output(port=port, max_len=max_len)
    )

def mpls_ttl(ttl):
    return action(
        type=SET_MPLS_TTL,
        mpls_ttl=ofp.ofp_action_mpls_ttl(mpls_ttl=ttl)
    )

def push_vlan(eth_type):
    return action(
        type=PUSH_VLAN,
        push=ofp.ofp_action_push(ethertype=eth_type)
    )

def pop_vlan():
    return action(
        type=POP_VLAN
    )

def pop_mpls(eth_type):
    return action(
        type=POP_MPLS,
        pop_mpls=ofp.ofp_action_pop_mpls(ethertype=eth_type)
    )

def group(group_id):
    return action(
        type=GROUP,
        group=ofp.ofp_action_group(group_id=group_id)
    )

def nw_ttl(nw_ttl):
    return action(
        type=NW_TTL,
        nw_ttl=ofp.ofp_action_nw_ttl(nw_ttl=nw_ttl)
    )

def set_field(field):
    return action(
        type=SET_FIELD,
        set_field=ofp.ofp_action_set_field(
            field=ofp.ofp_oxm_field(
                oxm_class=ofp.OFPXMC_OPENFLOW_BASIC,
                ofb_field=field))
    )

def experimenter(experimenter, data):
    return action(
        type=EXPERIMENTER,
        experimenter=ofp.ofp_action_experimenter(
            experimenter=experimenter, data=data)
    )


# ofb_field generators (incomplete set)

def in_port(_in_port):
    return ofb_field(type=IN_PORT, port=_in_port)

def eth_type(_eth_type):
    return ofb_field(type=ETH_TYPE, eth_type=_eth_type)

def vlan_vid(_vlan_vid):
    return ofb_field(type=VLAN_VID, vlan_vid=_vlan_vid)

def vlan_pcp(_vlan_pcp):
    return ofb_field(type=VLAN_PCP, vlan_pcp=_vlan_pcp)

def ip_dscp(_ip_dscp):
    return ofb_field(type=IP_DSCP, ip_dscp=_ip_dscp)

def ip_ecn(_ip_ecn):
    return ofb_field(type=IP_ECN, ip_ecn=_ip_ecn)

def ip_proto(_ip_proto):
    return ofb_field(type=IP_PROTO, ip_proto=_ip_proto)

def ipv4_src(_ipv4_src):
    return ofb_field(type=IPV4_SRC, ipv4_src=_ipv4_src)

def ipv4_dst(_ipv4_dst):
    return ofb_field(type=IPV4_DST, ipv4_dst=_ipv4_dst)

def tcp_src(_tcp_src):
    return ofb_field(type=TCP_SRC, tcp_src=_tcp_src)

def tcp_dst(_tcp_dst):
    return ofb_field(type=TCP_DST, tcp_dst=_tcp_dst)

def udp_src(_udp_src):
    return ofb_field(type=UDP_SRC, udp_src=_udp_src)

def udp_dst(_udp_dst):
    return ofb_field(type=UDP_DST, udp_dst=_udp_dst)

def sctp_src(_sctp_src):
    return ofb_field(type=SCTP_SRC, sctp_src=_sctp_src)

def sctp_dst(_sctp_dst):
    return ofb_field(type=SCTP_DST, sctp_dst=_sctp_dst)

def icmpv4_type(_icmpv4_type):
    return ofb_field(type=ICMPV4_TYPE, icmpv4_type=_icmpv4_type)

def icmpv4_code(_icmpv4_code):
    return ofb_field(type=ICMPV4_CODE, icmpv4_code=_icmpv4_code)

def arp_op(_arp_op):
    return ofb_field(type=ARP_OP, arp_op=_arp_op)

def arp_spa(_arp_spa):
    return ofb_field(type=ARP_SPA, arp_spa=_arp_spa)

def arp_tpa(_arp_tpa):
    return ofb_field(type=ARP_TPA, arp_tpa=_arp_tpa)

def arp_sha(_arp_sha):
    return ofb_field(type=ARP_SHA, arp_sha=_arp_sha)

def arp_tha(_arp_tha):
    return ofb_field(type=ARP_THA, arp_tha=_arp_tha)

# TODO finish for rest of match fields


# frequently used extractors:

def get_actions(flow):
    """Extract list of ofp_action objects from flow spec object"""
    assert isinstance(flow, ofp.ofp_flow_stats)
    # we have the following hard assumptions for now
    for instruction in flow.instructions:
        if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
            return instruction.actions.actions

def get_ofb_fields(flow):
    assert isinstance(flow, ofp.ofp_flow_stats)
    assert flow.match.type == ofp.OFPMT_OXM
    ofb_fields = []
    for field in flow.match.oxm_fields:
        assert field.oxm_class == ofp.OFPXMC_OPENFLOW_BASIC
        ofb_fields.append(field.ofb_field)
    return ofb_fields

def get_out_port(flow):
    for action in get_actions(flow):
        if action.type == OUTPUT:
            return action.output.port
    return None

def get_in_port(flow):
    for field in get_ofb_fields(flow):
        if field.type == IN_PORT:
            return field.port
    return None

def get_goto_table_id(flow):
    for instruction in flow.instructions:
        if instruction.type == ofp.OFPIT_GOTO_TABLE:
            return instruction.goto_table.table_id
    return None


# test and extract next table and group information

def has_next_table(flow):
    return get_goto_table_id(flow) is not None

def get_group(flow):
    for action in get_actions(flow):
        if action.type == GROUP:
            return action.group.group_id
    return None

def has_group(flow):
    return get_group(flow) is not None


def mk_simple_flow_mod(match_fields, actions, command=ofp.OFPFC_ADD,
                       next_table_id=None, **kw):
    """
    Convenience function to generare ofp_flow_mod message with OXM BASIC match
    composed from the match_fields, and single APPLY_ACTIONS instruction with
    a list if ofp_action objects.
    :param match_fields: list(ofp_oxm_ofb_field)
    :param actions: list(ofp_action)
    :param command: one of OFPFC_*
    :param kw: additional keyword-based params to ofp_flow_mod
    :return: initialized ofp_flow_mod object
    """
    instructions = [
        ofp.ofp_instruction(
            type=ofp.OFPIT_APPLY_ACTIONS,
            actions=ofp.ofp_instruction_actions(actions=actions)
        )
    ]
    if next_table_id is not None:
        instructions.append(ofp.ofp_instruction(
            type=ofp.OFPIT_GOTO_TABLE,
            goto_table=ofp.ofp_instruction_goto_table(table_id=next_table_id)
        ))

    return ofp.ofp_flow_mod(
        command=command,
        match=ofp.ofp_match(
            type=ofp.OFPMT_OXM,
            oxm_fields=[
                ofp.ofp_oxm_field(
                    oxm_class=ofp.OFPXMC_OPENFLOW_BASIC,
                    ofb_field=field
                ) for field in match_fields
            ]
        ),
        instructions=instructions,
        **kw
    )


def mk_multicast_group_mod(group_id, buckets, command=ofp.OFPGC_ADD):
    group = ofp.ofp_group_mod(
        command=command,
        type=ofp.OFPGT_ALL,
        group_id=group_id,
        buckets=buckets
    )
    return group


def hash_flow_stats(flow):
    """
    Return unique 64-bit integer hash for flow covering the following
    attributes: 'table_id', 'priority', 'flags', 'cookie', 'match'
    """
    hex = md5('{},{},{},{},{}'.format(
        flow.table_id,
        flow.priority,
        flow.flags,
        flow.cookie,
        flow.match.SerializeToString()
    )).hexdigest()
    return int(hex[:16], 16)


def flow_stats_entry_from_flow_mod_message(mod):
    flow = ofp.ofp_flow_stats(
        table_id=mod.table_id,
        priority=mod.priority,
        idle_timeout=mod.idle_timeout,
        hard_timeout=mod.hard_timeout,
        flags=mod.flags,
        cookie=mod.cookie,
        match=mod.match,
        instructions=mod.instructions
    )
    flow.id = hash_flow_stats(flow)
    return flow


def group_entry_from_group_mod(mod):
    group = ofp.ofp_group_entry(
        desc=ofp.ofp_group_desc(
            type=mod.type,
            group_id=mod.group_id,
            buckets=mod.buckets
        ),
        stats=ofp.ofp_group_stats(
            group_id=mod.group_id
            # TODO do we need to instantiate bucket bins?
        )
    )
    return group


def mk_flow_stat(**kw):
    return flow_stats_entry_from_flow_mod_message(mk_simple_flow_mod(**kw))


def mk_group_stat(**kw):
    return group_entry_from_group_mod(mk_multicast_group_mod(**kw))

class RouteHop(object):
    __slots__ = ('_device', '_ingress_port', '_egress_port')
    def __init__(self, device, ingress_port, egress_port):
        self._device = device
        self._ingress_port = ingress_port
        self._egress_port = egress_port
    @property
    def device(self): return self._device
    @property
    def ingress_port(self): return self._ingress_port
    @property
    def egress_port(self): return self._egress_port
    def __eq__(self, other):
        return (
            self._device == other._device and
            self._ingress_port == other._ingress_port and
            self._egress_port == other._egress_port)


class FlowDecomposer(object):

    def __init__(self, *args, **kw):
        self.logical_device_id = 'this shall be overwritten in derived class'
        super(FlowDecomposer, self).__init__(*args, **kw)

    # ~~~~~~~~~~~~~~~~~~~~ methods exposed *to* derived class ~~~~~~~~~~~~~~~~~

    def decompose_rules(self, flows, groups):
        """
        Generate per-device flows and flow-groups from the flows and groups
        defined on a logical device
        :param flows: logical device flows
        :param groups: logical device flow groups
        :return: dict(device_id ->
            (OrderedDict-of-device-flows, OrderedDict-of-device-flow-groups))
        """

        device_rules = deepcopy(self.get_all_default_rules())
        group_map = dict((g.desc.group_id, g) for g in groups)

        for flow in flows:
            for device_id, (_flows, _groups) \
                    in self.decompose_flow(flow, group_map).iteritems():
                fl_lst, gr_lst = device_rules.setdefault(
                    device_id, (OrderedDict(), OrderedDict()))
                for _flow in _flows:
                    if _flow.id not in fl_lst:
                        fl_lst[_flow.id] = _flow
                for _group in _groups:
                    if _group.group_id not in gr_lst:
                        gr_lst[_group.group_id] = _group
        return device_rules

    def decompose_flow(self, flow, group_map):
        assert isinstance(flow, ofp.ofp_flow_stats)

        ####################################################################
        #
        # TODO this is a very limited, heuristics based implementation
        #
        ####################################################################

        in_port_no = get_in_port(flow)
        out_port_no = get_out_port(flow)  # may be None

        route = self.get_route(in_port_no, out_port_no)

        assert len(route) == 2
        ingress_hop, egress_hop = route

        def is_downstream():
            return ingress_hop.device.root

        def is_upstream():
            return not is_downstream()

        device_rules = {}  # accumulator

        if out_port_no is not None and \
                        (out_port_no & 0x7fffffff) == ofp.OFPP_CONTROLLER:

            # UPSTREAM CONTROLLER-BOUND FLOW

            # we assume that the ingress device is already pushing a
            # customer-specific vlan (c-vid), based on its default flow
            # rules so there is nothing else to do on the ONU

            # on the olt, we need to push a new tag and set it to 4000
            # which for now represents in-bound channel to the controller
            # (via Voltha)
            # TODO make the 4000 configurable
            fl_lst, _ = device_rules.setdefault(
                egress_hop.device.id, ([], []))
            fl_lst.append(mk_flow_stat(
                priority=flow.priority,
                cookie=flow.cookie,
                match_fields=[
                    in_port(egress_hop.ingress_port.port_no)
                ] + [
                    field for field in get_ofb_fields(flow)
                    if field.type not in (IN_PORT, VLAN_VID)
                ],
                actions=[
                    push_vlan(0x8100),
                    set_field(vlan_vid(ofp.OFPVID_PRESENT | 4000)),
                    output(egress_hop.egress_port.port_no)]
            ))

        else:
            # NOT A CONTROLLER-BOUND FLOW
            if is_upstream():

                # We assume that anything that is upstream needs to get Q-in-Q
                # treatment and that this is expressed via two flow rules,
                # the first using the goto-statement. We also assume that the
                # inner tag is applied at the ONU, while the outer tag is
                # applied at the OLT
                if has_next_table(flow):
                    assert out_port_no is None
                    fl_lst, _ = device_rules.setdefault(
                        ingress_hop.device.id, ([], []))
                    fl_lst.append(mk_flow_stat(
                        priority=flow.priority,
                        cookie=flow.cookie,
                        match_fields=[
                            in_port(ingress_hop.ingress_port.port_no)
                        ] + [
                            field for field in get_ofb_fields(flow)
                            if field.type not in (IN_PORT,)
                        ],
                        actions=[
                            action for action in get_actions(flow)
                        ] + [
                            output(ingress_hop.egress_port.port_no)
                        ]
                    ))

                else:
                    assert out_port_no is not None
                    fl_lst, _ = device_rules.setdefault(
                        egress_hop.device.id, ([], []))
                    fl_lst.append(mk_flow_stat(
                        priority=flow.priority,
                        cookie=flow.cookie,
                        match_fields=[
                            in_port(egress_hop.ingress_port.port_no),
                        ] + [
                            field for field in get_ofb_fields(flow)
                            if field.type not in (IN_PORT, )
                        ],
                        actions=[
                            action for action in get_actions(flow)
                            if action.type != OUTPUT
                        ] + [
                            output(egress_hop.egress_port.port_no)
                        ]
                    ))

            else:  # downstream
                if has_next_table(flow):
                    assert out_port_no is None
                    fl_lst, _ = device_rules.setdefault(
                        ingress_hop.device.id, ([], []))
                    fl_lst.append(mk_flow_stat(
                        priority=flow.priority,
                        cookie=flow.cookie,
                        match_fields=[
                            in_port(ingress_hop.ingress_port.port_no)
                        ] + [
                            field for field in get_ofb_fields(flow)
                            if field.type not in (IN_PORT,)
                        ],
                        actions=[
                            action for action in get_actions(flow)
                        ] + [
                            output(ingress_hop.egress_port.port_no)
                        ]
                    ))
                elif out_port_no is not None:  # unicast case
                    fl_lst, _ = device_rules.setdefault(
                        egress_hop.device.id, ([], []))
                    fl_lst.append(mk_flow_stat(
                        priority=flow.priority,
                        cookie=flow.cookie,
                        match_fields=[
                            in_port(egress_hop.ingress_port.port_no)
                        ] + [
                            field for field in get_ofb_fields(flow)
                            if field.type not in (IN_PORT,)
                        ],
                        actions=[
                            action for action in get_actions(flow)
                            if action.type not in (OUTPUT,)
                        ] + [
                            output(egress_hop.egress_port.port_no)
                        ]

                    ))

                else:  # multicast case
                    grp_id = get_group(flow)
                    assert grp_id is not None

                    fl_lst, _ = device_rules.setdefault(
                        ingress_hop.device.id, ([], []))
                    fl_lst.append(mk_flow_stat(
                        priority=flow.priority,
                        cookie=flow.cookie,
                        match_fields=[
                            in_port(ingress_hop.ingress_port.port_no)
                        ] + [
                            field for field in get_ofb_fields(flow)
                            if field.type not in (IN_PORT, ETH_TYPE, IPV4_DST)
                        ],
                        actions=[
                            action for action in get_actions(flow)
                            if action.type not in (GROUP,)
                        ] + [
                            pop_vlan(),
                            output(ingress_hop.egress_port.port_no)
                        ]
                    ))

                    # having no group yet is the same as having a group with
                    # no buckets
                    group = group_map.get(grp_id, ofp.ofp_group_entry())

                    for bucket in group.desc.buckets:
                        found_pop_vlan = False
                        other_actions = []
                        for action in bucket.actions:
                            if action.type == POP_VLAN:
                                found_pop_vlan = True
                            elif action.type == OUTPUT:
                                out_port_no = action.output.port
                            else:
                                other_actions.append(action)
                        # re-run route request to determine egress device and
                        # ports
                        route2 = self.get_route(in_port_no, out_port_no)

                        assert len(route2) == 2
                        ingress_hop2, egress_hop = route2
                        assert ingress_hop == ingress_hop2

                        fl_lst, _ = device_rules.setdefault(
                            egress_hop.device.id, ([], []))
                        fl_lst.append(mk_flow_stat(
                            priority=flow.priority,
                            cookie=flow.cookie,
                            match_fields=[
                                in_port(egress_hop.ingress_port.port_no)
                            ] + [
                                field for field in get_ofb_fields(flow)
                                if field.type not in (IN_PORT, VLAN_VID, VLAN_PCP)
                            ],
                            actions=other_actions + [
                                output(egress_hop.egress_port.port_no)
                            ]
                        ))

        return device_rules

    # ~~~~~~~~~~~~ methods expected to be provided by derived class ~~~~~~~~~~~

    def get_all_default_rules(self):
        raise NotImplementedError('derived class must provide')

    def get_default_rules(self, device_id):
        raise NotImplementedError('derived class must provide')

    def get_route(self, ingress_port_no, egress_port_no):
        raise NotImplementedError('derived class must provide')


