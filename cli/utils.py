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

import sys

from google.protobuf.json_format import MessageToDict
from termcolor import cprint, colored

from cli.table import TablePrinter


_printfn = lambda l: sys.stdout.write(l + '\n')


def pb2dict(pb_msg):
    d = MessageToDict(pb_msg, including_default_value_fields=1,
                      preserving_proto_field_name=1)
    return d


def p_cookie(cookie):
    cookie =  '%x' % int(cookie)
    if len(cookie) > 8:
        return '~' + cookie[len(cookie)-8:]
    else:
        return cookie

'''
    OFPP_NORMAL     = 0x7ffffffa;  /* Forward using non-OpenFlow pipeline. */
    OFPP_FLOOD      = 0x7ffffffb;  /* Flood using non-OpenFlow pipeline. */
    OFPP_ALL        = 0x7ffffffc;  /* All standard ports except input port. */
    OFPP_CONTROLLER = 0x7ffffffd;  /* Send to controller. */
    OFPP_LOCAL      = 0x7ffffffe;  /* Local openflow "port". */
    OFPP_ANY        = 0x7fffffff;  /* Special value used in some requests when
'''


def p_port(port):
    if port & 0x7fffffff == 0x7ffffffa:
        return 'NORMAL'
    elif port & 0x7fffffff == 0x7ffffffb:
        return 'FLOOD'
    elif port & 0x7fffffff == 0x7ffffffc:
        return 'ALL'
    elif port & 0x7fffffff == 0x7ffffffd:
        return 'CONTROLLER'
    elif port & 0x7fffffff == 0x7ffffffe:
        return 'LOCAL'
    elif port & 0x7fffffff == 0x7fffffff:
        return 'ANY'
    else:
        return str(port)


def p_vlan_vid(vlan_vid):
    if vlan_vid == 0:
        return 'untagged'
    assert vlan_vid & 4096 == 4096
    return str(vlan_vid - 4096)


def p_ipv4(x):
    return '.'.join(str(v) for v in [
        (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
    ])


field_printers = {
    'IN_PORT': lambda f: (100, 'in_port', p_port(f['port'])),
    'VLAN_VID': lambda f: (101, 'vlan_vid', p_vlan_vid(f['vlan_vid'])),
    'VLAN_PCP': lambda f: (102, 'vlan_pcp', str(f['vlan_pcp'])),
    'ETH_TYPE': lambda f: (103, 'eth_type', '%X' % f['eth_type']),
    'IP_PROTO': lambda f: (104, 'ip_proto', str(f['ip_proto'])),
    'IPV4_DST': lambda f: (105, 'ipv4_dst', p_ipv4(f['ipv4_dst'])),
    'UDP_SRC': lambda f: (106, 'udp_src', str(f['udp_src'])),
    'UDP_DST': lambda f: (107, 'udp_dst', str(f['udp_dst'])),
    'TCP_SRC': lambda f: (108, 'tcp_src', str(f['tcp_src'])),
    'TCP_DST': lambda f: (109, 'tcp_dst', str(f['tcp_dst'])),
    'METADATA': lambda f: (110, 'metadata', str(f['table_metadata'])),
}


def p_field(field):
    assert field['oxm_class'].endswith('OPENFLOW_BASIC')
    ofb = field['ofb_field']
    assert not ofb['has_mask']
    type = ofb['type'][len('OFPXMT_OFB_'):]
    weight, field_name, value = field_printers[type](ofb)
    return 1000 + weight, 'set_' + field_name, value


action_printers = {
    'SET_FIELD': lambda a: p_field(a['set_field']['field']),
    'POP_VLAN': lambda a: (2000, 'pop_vlan', 'Yes'),
    'PUSH_VLAN': lambda a: (2001, 'push_vlan', '%x' % a['push']['ethertype']),
    'GROUP': lambda a: (3000, 'group', p_port(a['group']['group_id'])),
    'OUTPUT': lambda a: (4000, 'output', p_port(a['output']['port'])),
}


def print_flows(what, id, type, flows, groups, printfn=_printfn, flows_info=[], fields_to_omit=[]):

    header = ''.join([
        '{} '.format(what),
        colored(id, color='green', attrs=['bold']),
        ' (type: ',
        colored(type, color='blue'),
        ')'
    ]) + '\nFlows ({}):'.format(len(flows))

    table = TablePrinter()
    for i, flow in enumerate(flows):

        if flows_info:
            flow_info = flows_info[i]
        else:
            flow_info = dict()

        if 'table_id' not in fields_to_omit:
            table.add_cell(i, 0, 'table_id', value=str(flow['table_id']))
        if 'flow_id' not in fields_to_omit and 'flow_id' in flow_info:
            table.add_cell(i, 1, 'flow_id', value=str(flow_info['flow_id']))
        if 'flow_category' not in fields_to_omit and 'flow_category' in flow_info:
            table.add_cell(i, 2, 'flow_category', value=str(flow_info['flow_category']))
        if 'flow_type' not in fields_to_omit and 'flow_type' in flow_info:
            table.add_cell(i, 3, 'flow_type', value=str(flow_info['flow_type']))
        if 'priority' not in fields_to_omit:
            table.add_cell(i, 4, 'priority', value=str(flow['priority']))
        if 'gemport_id' not in fields_to_omit and 'gemport_id' in flow_info:
            table.add_cell(i, 5, 'gemport_id', value=str(flow_info['gemport_id']))
        if 'alloc_id' not in fields_to_omit and 'alloc_id' in flow_info:
            table.add_cell(i, 6, 'alloc_id', value=str(flow_info['alloc_id']))
        if 'o_pbits' not in fields_to_omit and 'o_pbits' in flow_info:
            table.add_cell(i, 7, 'o_pbits', value=str(flow_info['o_pbits']))
        if 'pon_intf_onu_id' not in fields_to_omit and 'pon_intf_onu_id' in flow_info:
            table.add_cell(i, 8, 'intf_onu_id', value=str(flow_info['pon_intf_onu_id']))
        if 'cookie' not in fields_to_omit:
            table.add_cell(i, 9, 'cookie', p_cookie(flow['cookie']))

        assert flow['match']['type'] == 'OFPMT_OXM'
        for field in flow['match']['oxm_fields']:
            assert field['oxm_class'].endswith('OPENFLOW_BASIC')
            ofb = field['ofb_field']
            type = ofb['type'][len('OFPXMT_OFB_'):]
            table.add_cell(i, *field_printers[type](ofb))

        for instruction in flow['instructions']:
            itype = instruction['type']
            if itype == 4 or itype == 3:
                for action in instruction['actions']['actions']:
                    atype = action['type'][len('OFPAT_'):]
                    table.add_cell(i, *action_printers[atype](action))
            elif itype == 1:
                if 'goto-table' not in fields_to_omit:
                    table.add_cell(i, 10000, 'goto-table',
                                   instruction['goto_table']['table_id'])
            elif itype == 2:
                if 'write-metadata' not in fields_to_omit:
                    table.add_cell(i, 10001, 'write-metadata',
                                   instruction['write_metadata']['metadata'])
            elif itype == 5:
                if 'clear-actions' not in fields_to_omit:
                    table.add_cell(i, 10002, 'clear-actions', [])
            elif itype == 6:
                if 'meter' not in fields_to_omit:
                    table.add_cell(i, 10003, 'meter',
                                   instruction['meter']['meter_id'])
            else:
                raise NotImplementedError(
                    'not handling instruction type {}'.format(itype))

    table.print_table(header, printfn)


def print_groups(what, id, type, groups, printfn=_printfn):
    header = ''.join([
        '{} '.format(what),
        colored(id, color='green', attrs=['bold']),
        ' (type: ',
        colored(type, color='blue'),
        ')'
    ]) + '\nGroups ({}):'.format(len(groups))

    table = TablePrinter()
    for i, group in enumerate(groups):
        output_ports = []
        for bucket in group['desc']['buckets']:
            for action in bucket['actions']:
                if action['type'] == 'OFPAT_OUTPUT':
                   output_ports.append(action['output']['port'])
        table.add_cell(i, 0, 'group_id', value=str(group['desc']['group_id']))
        table.add_cell(i, 1, 'buckets', value=str(dict(output=output_ports)))

    table.print_table(header, printfn)


def print_meters(what, id, type, meters, printfn=_printfn):
    header = ''.join([
        '{} '.format(what),
        colored(id, color='green', attrs=['bold']),
        ' (type: ',
        colored(type, color='blue'),
        ')'
    ]) + '\nMeters ({}):'.format(len(meters))

    table = TablePrinter()
    for i, meter in enumerate(meters):
        bands = []
        for meter_band in meter['config']['bands']:
            bands.append(meter_band)
        table.add_cell(i, 0, 'meter_id', value=str(meter['config']['meter_id']))
        table.add_cell(i, 1, 'meter_bands', value=str(dict(bands=bands)))

    table.print_table(header, printfn)

def dict2line(d):
    assert isinstance(d, dict)
    return ', '.join('{}: {}'.format(k, v) for k, v in sorted(d.items()))

def enum2name(msg_obj, enum_type, enum_value):
    descriptor = msg_obj.DESCRIPTOR.enum_types_by_name[enum_type]
    name = descriptor.values_by_number[enum_value].name
    return name
