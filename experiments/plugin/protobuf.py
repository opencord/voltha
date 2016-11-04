#!/usr/bin/env python
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

"""pyang plugin to convert a yang schema to a protobuf schema

   - basic support for leaf, leaf-list, containers, list

   - this plugin requires pyang to be present and is run using pyang as
   follows:

   $ pyang --plugindir /voltha/experiments/plugin -f protobuf  -o
   <protofile> -p /voltha/tests/utests/netconf/yang
   /voltha/tests/utests/netconf/yang/<yang file>

   - pyang validates the yanhg definition first and then invoke this plugin
   to convert the yang model into protobuf.
   
"""

from pyang import plugin, statements, error
from pyang.util import unique_prefixes


# Register the Protobuf plugin
def pyang_plugin_init():
    plugin.register_plugin(ProtobufPlugin())


class Protobuf():
    def __init__(self):
        self.tree = {}
        self.containers = []
        self.ylist = []
        self.messages = []
        self.enums = []
        self.headers = []
        self.services = []
        self.rpcs = []

    def set_headers(self, module_name):
        self.headers.append('syntax = "proto3";')
        self.headers.append('package {};'.format(module_name.replace('-',
                                                                     '_')))

    def _print_container(self, container, out, level=0):
        spaces = '    ' * level
        out.append(''.join([spaces, 'message {} '.format(container.name)]))
        out.append(''.join('{\n'))
        self._print_leaf(container.leafs, out, spaces)

        for l in container.ylist:
            self._print_list(l, out, level)

        for inner in container.containers:
            self._print_container(inner, out, level + 1)

        out.append(''.join([spaces, '}\n']))

    def _print_list(self, ylist, out, level=0):
        spaces = '    ' * level
        out.append('message {} '.format(ylist.name))
        out.append('{\n')
        self._print_leaf(ylist.leafs, out, spaces)

        for l in ylist.ylist:
            self._print_list(l, out, level + 1)

        out.append('}\n')

    def _print_leaf(self, leafs, out, spaces):
        for idx, l in enumerate(leafs):
            leafspaces = ''.join([spaces, '    '])
            if l.type == "enum":
                out.append(''.join([leafspaces, 'enum {}\n'.format(l.name)]))
                out.append(''.join([leafspaces, '{\n']))
                self._print_enumeration(l.enumeration, out, leafspaces)
                out.append(''.join([leafspaces, '}\n']))
            else:
                out.append(''.join([leafspaces, '{}{} {} = {} ;\n'.format(
                    'repeated ' if l.leaf_list else '',
                    l.type,
                    l.name,
                    idx + 1)]))

    def _print_enumeration(self, yang_enum, out, spaces):
        enumspaces = ''.join([spaces, '    '])
        for idx, e in enumerate(yang_enum):
            out.append(''.join([enumspaces, '{}\n'.format(e)]))

    def print_proto(self):
        out = []
        for h in self.headers:
            out.append('{}\n'.format(h))
        out.append('\n')
        for m in self.messages:
            out.append('{}\n'.format(m))
        if self.messages:
            out.append('\n')
        for l in self.ylist:
            self._print_list(l, out)
        if self.ylist:
            out.append('\n')
        for c in self.containers:
            self._print_container(c, out)
        if self.containers:
            out.append('\n')

        return out


class YangContainer():
    def __init__(self):
        self.name = None
        self.containers = []
        self.enums = []
        self.leafs = []
        self.ylist = []


class YangList():
    def __init__(self):
        self.name = None
        self.leafs = []
        self.containers = []
        self.ylist = []


class YangLeaf():
    def __init__(self):
        self.name = None
        self.type = None
        self.leaf_list = False
        self.enumeration = []
        self.description = None


class YangEnumeration():
    def __init__(self):
        self.value = []


class ProtobufPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['protobuf'] = self

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):
        """Main control function.
        """
        self.real_prefix = unique_prefixes(ctx)

        for m in modules:
            # m.pprint()
            # statements.print_tree(m)
            proto = Protobuf()
            proto.set_headers(m.i_modulename)
            self.process_substatements(m, proto, None)
            self.process_children(m, proto, None)
            out = proto.print_proto()
            for i in out:
                fd.write(i)

    def process_substatements(self, node, parent, pmod):
        """Process all substmts.
        """
        for st in node.substmts:
            if st.keyword in ["rpc", "notification"]: continue
            if st.keyword in ["choice", "case"]:
                self.process_substatements(st, parent, pmod)
                continue

            if st.i_module.i_modulename == pmod:
                nmod = pmod
            else:
                nmod = st.i_module.i_modulename

            if st.keyword in ["container", "grouping"]:
                c = YangContainer()
                c.name = st.arg
                self.process_substatements(st, c, nmod)
                parent.containers.append(c)
            elif st.keyword == "list":
                l = YangList()
                l.name = st.arg
                self.process_substatements(st, l, nmod)
                parent.ylist.append(l)
            elif st.keyword in ["leaf", "leaf-list"]:
                self.process_leaf(st, parent, st.keyword == "leaf-list")

    def process_children(self, node, parent, pmod):
        """Process all children of `node`, except "rpc" and "notification".
        """
        for ch in node.i_children:
            if ch.keyword in ["rpc", "notification"]: continue
            if ch.keyword in ["choice", "case"]:
                self.process_children(ch, parent, pmod)
                continue
            if ch.i_module.i_modulename == pmod:
                nmod = pmod
            else:
                nmod = ch.i_module.i_modulename
            if ch.keyword in ["container", "grouping"]:
                c = YangContainer()
                c.name = ch.arg
                self.process_children(ch, c, nmod)
                parent.containers.append(c)
                # self.process_container(ch, p, nmod)
            elif ch.keyword == "list":
                l = YangList()
                l.name = ch.arg
                self.process_children(ch, l, nmod)
                parent.ylist.append(l)
            elif ch.keyword in ["leaf", "leaf-list"]:
                self.process_leaf(ch, parent, ch.keyword == "leaf-list")

    def process_leaf(self, node, parent, leaf_list=False):
        # Leaf have specific sub statements
        leaf = YangLeaf()
        leaf.name = node.arg
        leaf.type = self.get_protobuf_type(node.search_one("type"))
        if leaf.type == "enum":
            self.process_enumeration(node, leaf)
        # leaf.type = self.base_type(node.search_one("type"))
        leaf.description = node.search_one("description")
        leaf.leaf_list = leaf_list
        parent.leafs.append(leaf)

    def process_enumeration(self, node, leaf):
        enumeration_dict = {}
        start_node = None
        for child in node.substmts:
            if child.keyword == "type":
                start_node = child;
                break

        for enum in start_node.search('enum'):
            val = enum.search_one('value')
            if val is not None:
                enumeration_dict[enum.arg] = int(val.arg)
            else:
                enumeration_dict[enum.arg] = '0'

        for key, value in enumerate(enumeration_dict):
            leaf.enumeration.append('{} = {} ;'.format(value, key))

    def get_protobuf_type(self, type):
        type = self.base_type(type)
        if type in self.protobuf_types_map.keys():
            return self.protobuf_types_map[type]
        else:
            return type

    def base_type(self, type):
        """Return the base type of `type`."""
        while 1:
            if type.arg == "leafref":
                node = type.i_type_spec.i_target_node
            elif type.i_typedef is None:
                break
            else:
                node = type.i_typedef
            type = node.search_one("type")
        if type.arg == "decimal64":
            return [type.arg, int(type.search_one("fraction-digits").arg)]
        elif type.arg == "union":
            # TODO convert union properly
            return type.arg
            # return [type.arg,
            #         [self.base_type(x) for x in type.i_type_spec.types]]
        else:
            return type.arg

    protobuf_types_map = dict(
        binary='Any',
        bits='bytes',
        boolean='bool',
        decimal64='sint64',
        empty='string',
        int8='int32',
        int16='int32',
        int32='int32',
        int64='int64',
        string='string',
        uint8='uint32',
        uint16='uint32',
        uint32='uint32',
        uint64='uint64',
        union='string',  # TODO : not correct mapping
        enumeration='enum'
    )
