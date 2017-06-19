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

"""
XPon level CLI commands
"""
from optparse import make_option
from cmd2 import Cmd, options
from simplejson import dumps

from google.protobuf.empty_pb2 import Empty
from cli.table import print_pb_as_table, print_pb_list_as_table
from cli.utils import print_flows, pb2dict
from voltha.protos import third_party
from voltha.protos.bbf_fiber_base_pb2 import \
    AllChannelgroupConfig, ChannelgroupConfig, \
    AllChannelpairConfig, ChannelpairConfig, \
    AllChannelpartitionConfig, ChannelpartitionConfig, \
    AllChannelterminationConfig, ChannelterminationConfig, \
    AllOntaniConfig, OntaniConfig, AllVOntaniConfig , \
    VOntaniConfig, AllVEnetConfig , VEnetConfig

_ = third_party
from voltha.protos import voltha_pb2, bbf_fiber_types_pb2, ietf_interfaces_pb2
import sys
from google.protobuf.json_format import MessageToDict

# Since proto3 won't send fields that are set to 0/false/"" any object that
# might have those values set in them needs to be replicated here such that the
# fields can be adequately

class XponCli(Cmd):

    def __init__(self, get_channel, device_id):
        Cmd.__init__(self)
        self.get_channel = get_channel
        self.device_id = device_id
        self.prompt = '(' + self.colorize(
            self.colorize('voltha-xpon {}'.format(device_id), 'green'), 'bold') + ') '

    def cmdloop(self):
        self._cmdloop()

    def get_interface_based_on_device(self):
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        temp_list = []
        cg_list = []
        cpart_list = []
        cp_list = []
        vont_list = []
        ont_list = []
        v_enet_list = []
        ct = stub.GetAllChannelterminationConfig(voltha_pb2.ID(id=self.device_id))
        cps = stub.GetAllChannelpairConfig(Empty()).channelpair_config
        cparts = stub.GetAllChannelpartitionConfig(Empty()).channelpartition_config
        cgs = stub.GetAllChannelgroupConfig(Empty()).channelgroup_config
        onts = stub.GetAllOntaniConfig(Empty()).ontani_config
        vonts = stub.GetAllVOntaniConfig(Empty()).v_ontani_config
        venets = stub.GetAllVEnetConfig(Empty()).v_enet_config

        for cterm in ct.channeltermination_config:
            temp_list.append(cterm.data.channelpair_ref)
        for cp in cps:
            if cp.name in temp_list:
                cp_list.append(cp)
        temp_list = []

        for cp in cp_list:
            temp_list.append(cp.data.channelpartition_ref)
        for cpart in cparts:
            if cpart.name in temp_list:
                cpart_list.append(cpart)
        temp_list = []

        for cpart in cpart_list:
            temp_list.append(cpart.data.channelgroup_ref)
        for cg in cgs:
            if cg.name in temp_list:
                cg_list.append(cg)
        temp_list = []

        for vont in vonts:
            if vont.data.parent_ref in cpart_list or \
                vont.data.preferred_chanpair in cp_list:
                vont_list.append(vont)

        for ont in onts:
            if ont.name in vont_list:
                ont_list.append(ont)
                temp_list.append(ont.name)

        for venet in venets:
            if venet.data.v_ontani_ref in temp_list:
                v_enet_list.append(venet)
        temp_list = []

        return cg_list, cpart_list, cp_list, ct.channeltermination_config, vont_list, ont_list, v_enet_list

    do_exit = Cmd.do_quit

    def do_quit(self, line):
        return self._STOP_AND_EXIT

    def do_show(self, line):
        """Show detailed information of each interface based on device ID or all interfaces"""
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        if line.strip():
            self.device_id = line.strip()
        if self.device_id:
            cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
            print_pb_list_as_table("Channel Groups for device ID = {}:".format(self.device_id),
                                   cg, {}, self.poutput)
            print_pb_list_as_table("Channel Partitions for device ID = {}:".format(self.device_id),
                                   cpart, {}, self.poutput)
            print_pb_list_as_table("Channel Pairs: for device ID = {}:".format(self.device_id),
                                   cp, {}, self.poutput)
            print_pb_list_as_table("Channel Terminations for device ID = {}:".format(self.device_id),
                                   ct, {}, self.poutput)
            print_pb_list_as_table("VOnt Anis for device ID = {}:".format(self.device_id),
                                   vont, {}, self.poutput)
            print_pb_list_as_table("Ont Anis for device ID = {}:".format(self.device_id),
                                   ont, {}, self.poutput)
            print_pb_list_as_table("VEnets for device ID = {}:".format(self.device_id),
                                   venet, {}, self.poutput)
        else:
            interface = stub.GetAllChannelgroupConfig(Empty())
            print_pb_list_as_table("Channel Groups:",
                                   interface.channelgroup_config,
                                   {}, self.poutput)
            interface = stub.GetAllChannelpartitionConfig(Empty())
            print_pb_list_as_table("Channel Partitions:",
                                   interface.channelpartition_config,
                                   {}, self.poutput)
            interface = stub.GetAllChannelpairConfig(Empty())
            print_pb_list_as_table("Channel Pairs:",
                                   interface.channelpair_config,
                                   {}, self.poutput)
            devices = stub.ListDevices(Empty())
            for d in devices.items:
                interface = stub.GetAllChannelterminationConfig(voltha_pb2.ID(id=d.id))
                print_pb_list_as_table("Channel Terminations for device ID = {}:".format(d.id),
                                   interface.channeltermination_config,
                                   {}, self.poutput)
            interface = stub.GetAllVOntaniConfig(Empty())
            print_pb_list_as_table("VOnt Anis:",
                                   interface.v_ontani_config,
                                   {}, self.poutput)
            interface = stub.GetAllOntaniConfig(Empty())
            print_pb_list_as_table("Ont Anis:",
                                   interface.ontani_config,
                                   {}, self.poutput)
            interface = stub.GetAllVEnetConfig(Empty())
            print_pb_list_as_table("VEnets:",
                                   interface.v_enet_config,
                                   {}, self.poutput)

    def help_channel_group(self):
        self.poutput(
'''
channel_group [get | create | update | delete] [-n <name>] [-d <description>] [-a <admin state>]
              [-l <link up down trap enable type>] [-p <polling period>] [-s <system id>]
              [-r <raman mitigation>]

get:    displays existing channel groups
        Required flags: None
create: creates channel group with the parameters specified with -n, -d, -a, -l, -p, -s and -r.
        Required flags: <name>
update: updates existing channel group specified with parameter -n by changing its parameter values 
        specified with -d, -a, -l, -p, -s and -r.
        Required flags: <name>
delete: deletes channel group specified with parameter -n.
        Required flags: <name>

-n: <string> name of channel group.
-d: <string> description of channel group.
-a: <string> admin state of channel group.
-l: <enum>   link up down trap enable type. 
-p: <int>    polling period for channel group.
-s: <string> system id for channel group.
-r: <enum>   raman mitigation for channel group.

Example:

channel_group create -n cg-1 -a up -p 100 -s 000000 -r raman_none
'''
        )

    @options([
        make_option('-n', '--name', action="store", dest='name', type='string',
                    help='name of channel group', default=None),
        make_option('-d', '--description', action="store", dest='description',
                    type='string', help='description of channel group', default=None),
        make_option('-a', '--admin_state', action="store", dest='enabled', type='string',
                    help='admin state of channel group', default=None),
        make_option('-l', '--trap', action="store", dest='link_up_down_trap_enable',
                    type='string', help='link up down trap enable type', default=None),
        make_option('-p', '--pp', action='store', dest='polling_period',
                    type='int', help='polling period of channel group', default=None),
        make_option('-s', '--sid', action='store', dest='system_id',
                    type='string', help='system id of channel group', default=None),
        make_option('-r', '--rm', action='store', dest='raman_mitigation',
                    type='string', help='raman mitigation of channel group', default=None),
    ])

    def do_channel_group(self, line, opts):
        """channel group get, create -flags <attributes>, update -flags <attributes>, delete -n <name>"""
        # Ensure that a valid sub-command was provided
        if line.strip() not in {"get", "create", "update", "delete"}:
            self.poutput(self.colorize('Error: ', 'red') + \
                        self.colorize(self.colorize(line.strip(), 'blue'),
                                      'bold') + ' is not recognized')
            return

        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())

        if line.strip() == "get":
            if self.device_id:
                cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
                print_pb_list_as_table("Channel Groups for device ID = {}:".format(self.device_id),
                                       cg, {}, self.poutput)
            else:
                interface = stub.GetAllChannelgroupConfig(Empty())
                print_pb_list_as_table("Channel Groups:",
                                       interface.channelgroup_config,
                                       {}, self.poutput)
            return
        #if not opts.name:
        #    self.poutput(self.colorize('Error: ', 'red') + \
        #                self.colorize(self.colorize('Name is required parameter', 'blue'),
        #                              'bold'))
        #    return
        #if interface_instance:
        #    self.poutput(self.colorize('Unable. Please commit or reset: ', 'yellow') + \
        #                self.colorize(interface_instance.name, 'blue'))
        #    return
        interface_instance = ChannelgroupConfig(name = opts.name)
        interface_instance.interface.name = opts.name
        if opts.description:
            interface_instance.interface.description = opts.description
        interface_instance.interface.type = "channelgroup"
        if opts.enabled:
            if opts.enabled == "up":
                interface_instance.interface.enabled = True
            elif opts.enabled == "down":
                interface_instance.interface.enabled = False
            else:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize('Invalid admin state parameter for channel group', 'blue'),
                                          'bold'))
                return
        if opts.link_up_down_trap_enable:
            types = ["trap_disabled", "trap_enabled"]
            try:
                assert opts.link_up_down_trap_enable in types, \
                        'Invalid Enum value for Channel Group link up down trap enable type \'{}\''\
                        .format(opts.link_up_down_trap_enable)
                interface_instance.interface.link_up_down_trap_enable = \
                    ietf_interfaces_pb2._INTERFACE_LINKUPDOWNTRAPENABLETYPE.values_by_name[opts.link_up_down_trap_enable.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if opts.polling_period:
            interface_instance.data.polling_period = opts.polling_period
        if opts.raman_mitigation:
            raman_mitigations = ["raman_none", "raman_miller", "raman_8b10b"]
            try:
                assert opts.raman_mitigation in raman_mitigations, \
                        'Invalid Enum value for Channel Group raman mitigation \'{}\''.format(opts.raman_mitigation)
                interface_instance.data.raman_mitigation = \
                    bbf_fiber_types_pb2._RAMANMITIGATIONTYPE.values_by_name[opts.raman_mitigation.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return
        if opts.system_id:
            interface_instance.data.system_id = opts.system_id

        if line.strip() == "create":
            stub.CreateChannelgroup(interface_instance)
        elif line.strip() == "update":
            stub.UpdateChannelgroup(interface_instance)
        elif line.strip() == "delete":
            stub.DeleteChannelgroup(interface_instance)
        return

    def help_channel_partition(self):
        self.poutput(
'''
channel_partition  [get | create | update | delete] [-n <name>] [-d <description>] [-a <admin state>]
                   [-l <link up down trap enable type>] [-r <differential fiber distance>]
                   [-o <closest ont distance>] [-f <fec downstream>] [-m <multicast aes indicator>]
                   [-u <authentication method>] [-c <channel group reference>]

get:    displays existing channel partitions
        Required flags: None
create: creates channel partition with the parameters specified with -n, -d, -a, -l, -r, -o, -f, -m, -u and -c.
        Required flags: <name>, <channel group reference>
update: updates existing channel partition specified with parameter -n by changing its parameter values
        specified with -d, -a, -l, -r, -o, -f, -m, -u and -c.
        Required flags: <name>
delete: deletes channel group specified with parameter -n.
        Required flags: <name>

-n: <string> name of channel partition.
-d: <string> description of channel partition.
-a: <string> admin state of channel partition.
-l: <enum>   link up down trap enable type.
-r: <int>    differential fiber distance.
-o: <int>    closest ont distance.
-f: <bool>   forward and error correction downstream.
-m: <bool>   multicast aes indicator of channel partition.
-u: <enum>   authentication method.
-c: <string> channel group reference for this channel partition.

Example:

channel_partition create -n cpart-1-1 -a up -r 20 -o 0 -f false -m false -u serial_number -c cg-1
'''
        )

    @options([
        make_option('-n', '--name', action="store", dest='name', type='string',
                    help='name of channel partition', default=None),
        make_option('-d', '--description', action="store", dest='description',
                    type='string', help='description of channel partition', default=None),
        make_option('-a', '--admin_state', action="store", dest='enabled', type='string',
                    help='admin state of channel partition', default=None),
        make_option('-l', '--trap', action="store", dest='link_up_down_trap_enable',
                    type='string', help='link up down trap enable type', default=None),
        make_option('-r', '--diff_fib_dist', action='store', dest='differential_fiber_distance',
                    type='int', help='differential fiber distance', default=None),
        make_option('-o', '--ont_dist', action='store', dest='closest_ont_distance',
                    type='int', help='closest ont distance', default=None),
        make_option('-f', '--fec_ds', action='store', dest='fec_downstream',
                    type='string', help='forward and error correction downstream', default=None),
        make_option('-m', '--mc_aes', action='store', dest='multicast_aes_indicator',
                    type='string', help='multicast aes indicator of channel partition', default=None),
        make_option('-u', '--auth', action='store', dest='authentication_method',
                    type='string', help='authentication method', default=None),
        make_option('-c', '--cg_ref', action='store', dest='channelgroup_ref',
                    type='string', help='channel group reference for this channel partition', default=None),
    ])

    def do_channel_partition(self, line, opts):
        """channel partition get, create -flags <attributes>, update -flags <attributes>, delete -n <name>"""
        # Ensure that a valid sub-command was provided
        if line.strip() not in {"get", "create", "update", "delete"}:
            self.poutput(self.colorize('Error: ', 'red') + \
                        self.colorize(self.colorize(line.strip(), 'blue'),
                                      'bold') + ' is not recognized')
            return

        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())

        if line.strip() == "get":
            if self.device_id:
                cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
                print_pb_list_as_table("Channel Partitions for device ID = {}:".format(self.device_id),
                                       cpart, {}, self.poutput)
            else:
                interface = stub.GetAllChannelpartitionConfig(Empty())
                print_pb_list_as_table("Channel Partitions:",
                                       interface.channelpartition_config,
                                       {}, self.poutput)
            return

        interface_instance = ChannelpartitionConfig(name = opts.name)
        interface_instance.interface.name = opts.name
        if opts.description:
            interface_instance.interface.description = opts.description
        interface_instance.interface.type = "channelpartition"
        if opts.enabled:
            if opts.enabled == "up":
                interface_instance.interface.enabled = True
            elif opts.enabled == "down":
                interface_instance.interface.enabled = False
            else:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize('Invalid admin state parameter for channel partition', 'blue'),
                                          'bold'))
                return
        if opts.link_up_down_trap_enable:
            types = ["trap_disabled", "trap_enabled"]
            try:
                assert opts.link_up_down_trap_enable in types, \
                        'Invalid Enum value for Channel Partition link up down trap enable type \'{}\''\
                        .format(opts.link_up_down_trap_enable)
                interface_instance.interface.link_up_down_trap_enable = \
                    ietf_interfaces_pb2._INTERFACE_LINKUPDOWNTRAPENABLETYPE.values_by_name[opts.link_up_down_trap_enable.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if opts.differential_fiber_distance:
            interface_instance.data.differential_fiber_distance = opts.differential_fiber_distance
        if opts.closest_ont_distance:
            interface_instance.data.closest_ont_distance = opts.closest_ont_distance
        if opts.fec_downstream:
            if opts.fec_downstream == 'true':
                interface_instance.data.fec_downstream = True
            elif opts.fec_downstream == 'false':
                interface_instance.data.fec_downstream = False
            else:
                m = 'Invalid boolean value for Channel Partition fec_downstream \'{}\''\
                    .format(opts.fec_downstream)
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(m, 'blue'),
                                          'bold'))
                return
        if opts.multicast_aes_indicator:
            if opts.multicast_aes_indicator == 'true':
                interface_instance.data.multicast_aes_indicator = True
            elif opts.multicast_aes_indicator == 'false':
                interface_instance.data.multicast_aes_indicator = False
            else:
                m = 'Invalid boolean value for Channel Partition multicast_aes_indicator \'{}\''\
                    .format(opts.multicast_aes_indicator)
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(m, 'blue'),
                                          'bold'))
                return
        if opts.authentication_method:
            auth_method_types = ["serial_number", "loid", "registration_id", "omci", "dot1x"]
            try:
                assert opts.authentication_method in auth_method_types, \
                        'Invalid Enum value for Channel Partition authentication method \'{}\''.format(opts.authentication_method)
                interface_instance.data.authentication_method = \
                    bbf_fiber_types_pb2._AUTHMETHODTYPE.values_by_name[opts.authentication_method.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return
        if opts.channelgroup_ref:
            interface_instance.data.channelgroup_ref = opts.channelgroup_ref

        if line.strip() == "create":
            stub.CreateChannelpartition(interface_instance)
        elif line.strip() == "update":
            stub.UpdateChannelpartition(interface_instance)
        elif line.strip() == "delete":
            stub.DeleteChannelpartition(interface_instance)
        return

    def help_channel_pair(self):
        self.poutput(
'''
channel_pair [get | create | update | delete] [-n <name>] [-d <description>] [-a <admin state>]
             [-l <link up down trap enable type>] [-r <channel pair line rate>]
             [-t <channel pair type>] [-g <channel group reference>] [-i <gpon pon id interval>]
             [-p <channel partition reference>] [-o <gpon pon id odn class>]

get:    displays existing channel pairs
        Required flags: None
create: creates channel pair with the parameters specified with -n, -d, -a, -l, -r, -t, -g, -i, -p and -o.
        Required flags: <name>, <channel pair type>
update: updates existing channel pair specified with parameter -n by changing its parameter values
        specified with -d, -a, -l, -r, -t, -g, -i, -p and -o.
        Required flags: <name>
delete: deletes channel group specified with parameter -n.
        Required flags: <name>

-n: <string> name of channel pair.
-d: <string> description of channel pair.
-a: <string> admin state of channel pair.
-l: <enum>   link up down trap enable type.
-r: <string> channel pair line rate.
-t: <string> channel pair type.
-g: <string> channel group reference.
-i: <int>    gpon pon id interval.
-p: <string> channel partition reference.
-o: <enum>   gpon pon id odn class.

Example:

channel_pair create -n cp-1 -a up -r unplanned_cp_speed -t channelpair -g cg-1 -i 0 -p cpart-1-1 -o class_a
'''
        )

    @options([
        make_option('-n', '--name', action="store", dest='name', type='string',
                    help='name of channel pair', default=None),
        make_option('-d', '--description', action="store", dest='description',
                    type='string', help='description of channel pair', default=None),
        make_option('-a', '--admin_state', action="store", dest='enabled', type='string',
                    help='admin state of channel pair', default=None),
        make_option('-l', '--trap', action="store", dest='link_up_down_trap_enable',
                    type='string', help='link up down trap enable type', default=None),
        make_option('-r', '--cp_line_rate', action='store', dest='channelpair_linerate',
                    type='string', help='channel pair linerate', default=None),
        make_option('-t', '--cp_type', action='store', dest='channelpair_type',
                    type='string', help='channel pair type', default=None),
        make_option('-g', '--cg_ref', action='store', dest='channelgroup_ref',
                    type='string', help='channel group reference', default=None),
        make_option('-i', '--interval', action='store', dest='gpon_ponid_interval',
                    type='int', help='gpon pon id interval', default=None),
        make_option('-p', '--cpart_ref', action='store', dest='channelpartition_ref',
                    type='string', help='channel partition reference', default=None),
        make_option('-o', '--odn_class', action='store', dest='gpon_ponid_odn_class',
                    type='string', help='gpon pon id odn class', default=None),
    ])

    def do_channel_pair(self, line, opts):
        """channel pair get, create -flags <attributes>, update -flags <attributes>, delete -n <name>"""
        # Ensure that a valid sub-command was provided
        if line.strip() not in {"get", "create", "update", "delete"}:
            self.poutput(self.colorize('Error: ', 'red') + \
                        self.colorize(self.colorize(line.strip(), 'blue'),
                                      'bold') + ' is not recognized')
            return

        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())

        if line.strip() == "get":
            if self.device_id:
                cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
                print_pb_list_as_table("Channel Pairs for device ID = {}:".format(self.device_id),
                                       cp, {}, self.poutput)
            else:
                interface = stub.GetAllChannelpairConfig(Empty())
                print_pb_list_as_table("Channel Pairs:",
                                       interface.channelpair_config,
                                       {}, self.poutput)
            return

        interface_instance = ChannelpairConfig(name = opts.name)
        interface_instance.interface.name = opts.name
        if opts.description:
            interface_instance.interface.description = opts.description
        interface_instance.interface.type = "channelpair"
        if opts.enabled:
            if opts.enabled == "up":
                interface_instance.interface.enabled = True
            elif opts.enabled == "down":
                interface_instance.interface.enabled = False
            else:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize('Invalid admin state parameter for channel pair', 'blue'),
                                          'bold'))
                return
        if opts.link_up_down_trap_enable:
            types = ["trap_disabled", "trap_enabled"]
            try:
                assert opts.link_up_down_trap_enable in types, \
                        'Invalid Enum value for Channel Pair link up down trap enable type \'{}\''\
                        .format(opts.link_up_down_trap_enable)
                interface_instance.interface.link_up_down_trap_enable = \
                    ietf_interfaces_pb2._INTERFACE_LINKUPDOWNTRAPENABLETYPE.values_by_name[opts.link_up_down_trap_enable.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if opts.channelpair_linerate:
            interface_instance.data.channelpair_linerate = opts.channelpair_linerate
        if opts.channelpair_type:
            interface_instance.data.channelpair_type = opts.channelpair_type
        if opts.channelgroup_ref:
            interface_instance.data.channelgroup_ref = opts.channelgroup_ref
        if opts.gpon_ponid_interval:
            interface_instance.data.gpon_ponid_interval = opts.gpon_ponid_interval
        if opts.channelpartition_ref:
            interface_instance.data.channelpartition_ref = opts.channelpartition_ref
        if opts.gpon_ponid_odn_class:
            class_types = ["class_a", "class_b", "class_b_plus", "class_c", "class_c_plus", "class_auto"]
            try:
                assert opts.gpon_ponid_odn_class in class_types, \
                        'Invalid enum value for Channel Pair gpon pon id odn class \'{}\''.format(opts.gpon_ponid_odn_class)
                interface_instance.data.gpon_ponid_odn_class = \
                    bbf_fiber_types_pb2._PONIDODNCLASSTYPE.values_by_name[opts.gpon_ponid_odn_class.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if line.strip() == "create":
            stub.CreateChannelpair(interface_instance)
        elif line.strip() == "update":
            stub.UpdateChannelpair(interface_instance)
        elif line.strip() == "delete":
            stub.DeleteChannelpair(interface_instance)
        return

    def help_channel_termination(self):
        self.poutput(
'''
channel_termination [get | create | update | delete] [-i <id>] [-n <name>]
                    [-d <description>] [-a <admin state>] [-l <link up down trap enable type>]
                    [-r <channel pair reference>] [-m <meant for type_b primary role>]
                    [-w <ngpon2 time wavelength division multiplexing admin label>]
                    [-p <ngpon2 ptp admin label>] [-s <xgs pon id>]
                    [-x <xgpon pon id>] [-g <gpon pon id>] [-t <pon tag>]
                    [-b <ber calc period>] [-l <location>] [-u <url to reach>]

get:    displays existing channel pairs
        Required flags: None
create: creates channel pair with the parameters specified with -i -n, -d, -a, -l, -r, -m, -w, -p, -s, -x, -g, -t, -b, -c and -u
        Required flags: <id>, <name>
update: updates existing channel termination specified with -i and -n parameters by changing
        its parameter values specified with -d, -a, -l, -r, -m, -w, -p, -s, -x, -g, -b, -c, and -u
        Required flags: <id>, <name>
delete: deletes channel termination specified with parameter -i and -n.
        Required flags: <id>, <name>

-i: <string> device id.
-n: <string> name of channel termination.
-d: <string> description of channel termination.
-a: <string> admin state of channel termination.
-l: <enum>   link up down trap enable type.
-r: <string> channel pair reference for this channel termination.
-m: <bool>   meant for type_b primary role.
-w: <int>    ngpon2 time wavelength division multiplexing admin label.
-p: <int>    ngpon2 precision time protocol admin label.
-s: <int>    xgs pon id.
-x: <int>    xgpon pon id.
-g: <string> gpon pon id.
-t: <string> pon tag.
-b: <int>    bit error rate calculation period.
-c: <string> location of channel termination.
-u: <string> url to reach channel termination.

Example:

channel_termination create -i f90bb953f988 -n cterm-1 -a up -r cp-1 -m false -w 0 -p 0 -s 0 -x 0 -b 0 -c raleigh -u localhost

'''
        )

    @options([
        make_option('-i', '--id', action="store", dest='id', type='string',
                    help='device id', default=None),
        make_option('-n', '--name', action="store", dest='name', type='string',
                    help='name of channel pair', default=None),
        make_option('-d', '--description', action="store", dest='description',
                    type='string', help='description of channel termination', default=None),
        make_option('-a', '--admin_state', action="store", dest='enabled', type='string',
                    help='admin state of channel termination', default=None),
        make_option('-l', '--trap', action="store", dest='link_up_down_trap_enable',
                    type='string', help='link up down trap enable type', default=None),
        make_option('-r', '--cp_ref', action='store', dest='channelpair_ref',
                    type='string', help='channel pair reference for this channel termination', default=None),
        make_option('-m', '--type_b', action='store', dest='meant_for_type_b_primary_role',
                    type='string', help='meant for type_b primary role', default=None),
        make_option('-w', '--t_w_d_m', action='store', dest='ngpon2_twdm_admin_label',
                    type='int', help='ngpon2 time wavelength division multiplexing admin label', default=None),
        make_option('-p', '--ptp', action='store', dest='ngpon2_ptp_admin_label',
                    type='int', help='ngpon2 precision time protocol admin label', default=None),
        make_option('-s', '--xgs', action='store', dest='xgs_ponid',
                    type='int', help='xgs pon id', default=None),
        make_option('-x', '--xgpon', action='store', dest='xgpon_ponid',
                    type='int', help='xgpon pon id', default=None),
        make_option('-g', '--gpon_pon', action='store', dest='gpon_ponid',
                    type='string', help='gpon pon id', default=None),
        make_option('-t', '--pon', action='store', dest='pon_tag',
                    type='string', help='pon tag', default=None),
        make_option('-b', '--ber', action='store', dest='ber_calc_period',
                    type='int', help='bit error rate calculation period', default=None),
        make_option('-c', '--location', action='store', dest='location',
                    type='string', help='location of channel termination', default=None),
        make_option('-u', '--url', action='store', dest='url_to_reach',
                    type='string', help='url to reach channel termination', default=None),
    ])

    def do_channel_termination(self, line, opts):
        """channel termination get, create -flags <attributes>, update -flags <attributes>, delete -i <id> -n <name>"""
        # Ensure that a valid sub-command was provided
        if line.strip() not in {"get", "create", "update", "delete"}:
            self.poutput(self.colorize('Error: ', 'red') + \
                        self.colorize(self.colorize(line.strip(), 'blue'),
                                      'bold') + ' is not recognized')
            return

        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())

        if line.strip() == "get":
            if self.device_id:
                cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
                print_pb_list_as_table("Channel Terminations for device ID = {}:".format(self.device_id),
                                       ct, {}, self.poutput)
            elif opts.id:
                ct = stub.GetAllChannelterminationConfig(voltha_pb2.ID(id=opts.id)).channeltermination_config
                print_pb_list_as_table("Channel Terminations for device ID = {}:".format(opts.id),
                                       ct, {}, self.poutput)
            else:
                devices = stub.ListDevices(Empty())
                for d in devices.items:
                    interface = stub.GetAllChannelterminationConfig(voltha_pb2.ID(id=d.id))
                    print_pb_list_as_table("Channel Terminations for device ID = {}:".format(d.id),
                                       interface.channeltermination_config,
                                       {}, self.poutput)
            return

        interface_instance = ChannelterminationConfig(id = opts.id, name = opts.name)
        interface_instance.interface.name = opts.name
        if opts.description:
            interface_instance.interface.description = opts.description
        interface_instance.interface.type = "channel-termination"
        if opts.enabled:
            if opts.enabled == "up":
                interface_instance.interface.enabled = True
            elif opts.enabled == "down":
                interface_instance.interface.enabled = False
            else:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize('Invalid admin state parameter for channel termination', 'blue'),
                                          'bold'))
                return
        if opts.link_up_down_trap_enable:
            types = ["trap_disabled", "trap_enabled"]
            try:
                assert opts.link_up_down_trap_enable in types, \
                        'Invalid Enum value for Channel Termination link up down trap enable type \'{}\''\
                        .format(opts.link_up_down_trap_enable)
                interface_instance.interface.link_up_down_trap_enable = \
                    ietf_interfaces_pb2._INTERFACE_LINKUPDOWNTRAPENABLETYPE.values_by_name[opts.link_up_down_trap_enable.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if opts.channelpair_ref:
            interface_instance.data.channelpair_ref = opts.channelpair_ref
        if opts.meant_for_type_b_primary_role:
            if opts.meant_for_type_b_primary_role == 'true':
                interface_instance.data.meant_for_type_b_primary_role = True
            elif opts.meant_for_type_b_primary_role == 'false':
                interface_instance.data.meant_for_type_b_primary_role = False
            else:
                m = 'Invalid boolean value for Channel Termination meant_for_type_b_primary_role \'{}\''\
                    .format(opts.meant_for_type_b_primary_role)
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(m, 'blue'),
                                          'bold'))
                return
        if opts.ngpon2_twdm_admin_label:
            interface_instance.data.ngpon2_twdm_admin_label = opts.ngpon2_twdm_admin_label
        if opts.ngpon2_ptp_admin_label:
            interface_instance.data.ngpon2_ptp_admin_label = opts.ngpon2_ptp_admin_label
        if opts.xgs_ponid:
            interface_instance.data.xgs_ponid = opts.xgs_ponid
        if opts.xgpon_ponid:
            interface_instance.data.xgpon_ponid = opts.xgpon_ponid
        if opts.gpon_ponid:
            interface_instance.data.gpon_ponid = opts.gpon_ponid
        if opts.pon_tag:
            interface_instance.data.pon_tag = opts.pon_tag
        if opts.ber_calc_period:
            interface_instance.data.ber_calc_period = opts.ber_calc_period
        if opts.location:
            interface_instance.data.location = opts.location
        if opts.url_to_reach:
            interface_instance.data.url_to_reach = opts.url_to_reach

        if line.strip() == "create":
            stub.CreateChanneltermination(interface_instance)
        elif line.strip() == "update":
            stub.UpdateChanneltermination(interface_instance)
        elif line.strip() == "delete":
            stub.DeleteChanneltermination(interface_instance)
        return

    def help_vont_ani(self):
        self.poutput(
'''
vont_ani [get | create | update | delete] [-n <name>] [-d <description>] [-a <admin state>]
         [-l <link up down trap enable type>] [-p <parent reference>]
         [-s <expected serial number>] [-i <expected registration id>]
         [-r <preferred channel pair>] [-t <protection channel pair>]
         [-u <upstream channel speed>] [-o <onu id>]

get:    displays existing vont anis
        Required flags: None
create: creates vont ani with the parameters specified with -n, -d, -a, -l, -p, -s, -i, -r, -t, -u and -o.
        Required flags: <name>
update: updates existing vont ani specified with parameter -n by changing its parameter values
        specified with -d, -a, -l, -p, -s, -i, -r, -t, -u and -o.
        Required flags: <name>
delete: deletes vont ani specified with parameter -n.
        Required flags: <name>

-n: <string> name of vont ani.
-d: <string> description of vont ani.
-a: <string> admin state of vont ani.
-l: <enum>   link up down trap enable type.
-p: <string> parent reference of vont ani must be type of channel partition.
-s: <string> expected serial number of ONT.
-i: <string> expected registration id of ONT.
-r: <string> preferred channel pair must be type of channel pair.
-t: <string> protection channel pair must be type of channel pair.
-u: <int>    upstream channel speed of traffic.
-o <int>     ONU id.

Example:

vont_ani create -n ontani-1-1-1 -a up -p cpart-1-1 -s ALCL00000001 -r cp-1 -u 0 -o 1
'''
        )

    @options([
        make_option('-n', '--name', action="store", dest='name', type='string',
                    help='name of vont ani', default=None),
        make_option('-d', '--description', action="store", dest='description',
                    type='string', help='description of vont ani', default=None),
        make_option('-a', '--admin_state', action="store", dest='enabled', type='string',
                    help='admin state of vont ani', default=None),
        make_option('-l', '--trap', action="store", dest='link_up_down_trap_enable',
                    type='string', help='link up down trap enable type', default=None),
        make_option('-p', '--parent_ref', action='store', dest='parent_ref',
                    type='string', help='parent reference of vont ani must be type of channel partition',
                    default=None),
        make_option('-s', '--e_ser_num', action='store', dest='expected_serial_number',
                    type='string', help='expected serial number of ONT', default=None),
        make_option('-i', '--e_reg_id', action='store', dest='expected_registration_id',
                    type='string', help='expected registration id of ONT', default=None),
        make_option('-r', '--pref_cp', action='store', dest='preferred_chanpair',
                    type='string', help='preferred channel pair must be type of channel pair',
                    default=None),
        make_option('-t', '--prot_cp', action='store', dest='protection_chanpair',
                    type='string', help='protection channel pair must be type of channel pair',
                    default=None),
        make_option('-u', '--up_cs', action='store', dest='upstream_channel_speed',
                    type='int', help='upstream channel speed of traffic', default=None),
        make_option('-o', '--onu_id', action='store', dest='onu_id',
                    type='int', help='onu id', default=None),
    ])

    def do_vont_ani(self, line, opts):
        """vont ani get, create -flags <attributes>, update -flags <attributes>, delete -n <name>"""
        # Ensure that a valid sub-command was provided
        if line.strip() not in {"get", "create", "update", "delete"}:
            self.poutput(self.colorize('Error: ', 'red') + \
                        self.colorize(self.colorize(line.strip(), 'blue'),
                                      'bold') + ' is not recognized')
            return

        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())

        if line.strip() == "get":
            if self.device_id:
                cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
                print_pb_list_as_table("VOnt Anis for device ID = {}:".format(self.device_id),
                                       vont, {}, self.poutput)
            else:
                interface = stub.GetAllVOntaniConfig(Empty())
                print_pb_list_as_table("VOnt Anis:",
                                       interface.v_ontani_config,
                                       {}, self.poutput)
            return

        interface_instance = VOntaniConfig(name = opts.name)
        interface_instance.interface.name = opts.name
        if opts.description:
            interface_instance.interface.description = opts.description
        interface_instance.interface.type = "v-ontani"
        if opts.enabled:
            if opts.enabled == "up":
                interface_instance.interface.enabled = True
            elif opts.enabled == "down":
                interface_instance.interface.enabled = False
            else:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize('Invalid admin state parameter for vont ani', 'blue'),
                                          'bold'))
                return
        if opts.link_up_down_trap_enable:
            types = ["trap_disabled", "trap_enabled"]
            try:
                assert opts.link_up_down_trap_enable in types, \
                        'Invalid Enum value for VOnt Ani link up down trap enable type \'{}\''\
                        .format(opts.link_up_down_trap_enable)
                interface_instance.interface.link_up_down_trap_enable = \
                    ietf_interfaces_pb2._INTERFACE_LINKUPDOWNTRAPENABLETYPE.values_by_name[opts.link_up_down_trap_enable.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if opts.parent_ref:
            interface_instance.data.parent_ref = opts.parent_ref
        if opts.expected_serial_number:
            interface_instance.data.expected_serial_number = opts.expected_serial_number
        if opts.expected_registration_id:
            interface_instance.data.expected_registration_id = opts.expected_registration_id
        if opts.preferred_chanpair:
            interface_instance.data.preferred_chanpair = opts.preferred_chanpair
        if opts.protection_chanpair:
            interface_instance.data.protection_chanpair = opts.protection_chanpair
        if opts.upstream_channel_speed:
            interface_instance.data.upstream_channel_speed = opts.upstream_channel_speed
        if opts.onu_id:
            interface_instance.data.onu_id = opts.onu_id

        if line.strip() == "create":
            stub.CreateVOntani(interface_instance)
        elif line.strip() == "update":
            stub.UpdateVOntani(interface_instance)
        elif line.strip() == "delete":
            stub.DeleteVOntani(interface_instance)
        return

    def help_ont_ani(self):
        self.poutput(
'''
ont_ani [get | create | update | delete] [-n <name>] [-d <description>] [-a <admin state>]
        [-l <link up down trap enable type>] [-u <upstream fec indicator>]
        [-m <management gem port aes indicator>]

get:    displays existing ont anis
        Required flags: None
create: creates ont ani with the parameters specified with -n, -d, -a, -l, -u and -m.
        Required flags: <name>
update: updates existing ont ani specified with parameter -n by changing its parameter values
        specified with -d, -a, -l, -u and -m.
        Required flags: <name>
delete: deletes ont ani specified with parameter -n.
        Required flags: <name>

-n: <string> name of ont ani.
-d: <string> description of ont ani.
-a: <string> admin state of ont ani.
-l: <enum>   link up down trap enable type.
-u: <bool>   upstream traffic fec indicator.
-m: <bool>   management gem port aes indicator.

Example:

ont_ani create -n ontani-1-1-1 -a up -u true -m true
'''
        )

    @options([
        make_option('-n', '--name', action="store", dest='name', type='string',
                    help='name of ont ani', default=None),
        make_option('-d', '--description', action="store", dest='description',
                    type='string', help='description of ont ani', default=None),
        make_option('-a', '--admin_state', action="store", dest='enabled', type='string',
                    help='admin state of ont ani', default=None),
        make_option('-l', '--trap', action="store", dest='link_up_down_trap_enable',
                    type='string', help='link up down trap enable type', default=None),
        make_option('-u', '--up_fec', action='store', dest='upstream_fec_indicator',
                    type='string', help='upstream traffic fec indicator', default=None),
        make_option('-m', '--maes', action='store', dest='mgnt_gemport_aes_indicator',
                    type='string', help='management gem port aes indicator', default=None),
    ])

    def do_ont_ani(self, line, opts):
        """ont ani get, create -flags <attributes>, update -flags <attributes>, delete -n <name>"""
        # Ensure that a valid sub-command was provided
        if line.strip() not in {"get", "create", "update", "delete"}:
            self.poutput(self.colorize('Error: ', 'red') + \
                        self.colorize(self.colorize(line.strip(), 'blue'),
                                      'bold') + ' is not recognized')
            return

        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())

        if line.strip() == "get":
            if self.device_id:
                cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
                print_pb_list_as_table("Ont Anis for device ID = {}:".format(self.device_id),
                                       ont, {}, self.poutput)
            else:
                interface = stub.GetAllOntaniConfig(Empty())
                print_pb_list_as_table("Ont Anis:",
                                       interface.ontani_config,
                                       {}, self.poutput)
            return

        interface_instance = OntaniConfig(name = opts.name)
        interface_instance.interface.name = opts.name
        if opts.description:
            interface_instance.interface.description = opts.description
        interface_instance.interface.type = "ontani"
        if opts.enabled:
            if opts.enabled == "up":
                interface_instance.interface.enabled = True
            elif opts.enabled == "down":
                interface_instance.interface.enabled = False
            else:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize('Invalid admin state parameter for ont ani', 'blue'),
                                          'bold'))
                return
        if opts.link_up_down_trap_enable:
            types = ["trap_disabled", "trap_enabled"]
            try:
                assert opts.link_up_down_trap_enable in types, \
                        'Invalid Enum value for Ont Ani link up down trap enable type \'{}\''\
                        .format(opts.link_up_down_trap_enable)
                interface_instance.interface.link_up_down_trap_enable = \
                    ietf_interfaces_pb2._INTERFACE_LINKUPDOWNTRAPENABLETYPE.values_by_name[opts.link_up_down_trap_enable.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if opts.upstream_fec_indicator:
            if opts.upstream_fec_indicator == 'true':
                interface_instance.data.upstream_fec_indicator = True
            elif opts.upstream_fec_indicator == 'false':
                interface_instance.data.upstream_fec_indicator = False
            else:
                m = 'Invalid boolean value for Ont Ani upstream_fec_indicator \'{}\''\
                    .format(opts.upstream_fec_indicator)
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(m, 'blue'),
                                          'bold'))
                return
        if opts.mgnt_gemport_aes_indicator:
            if opts.mgnt_gemport_aes_indicator == 'true':
                interface_instance.data.mgnt_gemport_aes_indicator = True
            elif opts.mgnt_gemport_aes_indicator == 'false':
                interface_instance.data.mgnt_gemport_aes_indicator = False
            else:
                m = 'Invalid boolean value for Ont Ani mgnt_gemport_aes_indicator \'{}\''\
                    .format(opts.mgnt_gemport_aes_indicator)
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(m, 'blue'),
                                          'bold'))
                return

        if line.strip() == "create":
            stub.CreateOntani(interface_instance)
        elif line.strip() == "update":
            stub.UpdateOntani(interface_instance)
        elif line.strip() == "delete":
            stub.DeleteOntani(interface_instance)
        return

    def help_v_enet(self):
        self.poutput(
'''
v_enet [get | create | update | delete] [-n <name>] [-d <description>] [-a <admin state>]
       [-l <link up down trap enable type>] [-r <ont ani reference>]

get:    displays existing venets
        Required flags: None
create: creates venet with the parameters specified with -n, -d, -a, -l, and -r.
        Required flags: <name>
update: updates existing venet specified with parameter -n by changing its parameter values
        specified with -d, -a, -l, -r.
        Required flags: <name>
delete: deletes venet specified with parameter -n.
        Required flags: <name>

-n: <string> name of venet.
-d: <string> description of venet.
-a: <string> admin state of venet.
-l: <enum>   link up down trap enable type.
-r: <string> ont ani reference of this venet.

Example:

v_enet create -n venet-1 -a up -r ontani-1-1-1
'''
        )

    @options([
        make_option('-n', '--name', action="store", dest='name', type='string',
                    help='name of venet', default=None),
        make_option('-d', '--description', action="store", dest='description',
                    type='string', help='description of venet', default=None),
        make_option('-a', '--admin_state', action="store", dest='enabled', type='string',
                    help='admin state of venet', default=None),
        make_option('-l', '--trap', action="store", dest='link_up_down_trap_enable',
                    type='string', help='link up down trap enable type', default=None),
        make_option('-r', '--ont_ref', action='store', dest='v_ontani_ref',
                    type='string', help='ont ani reference', default=None),
    ])

    def do_v_enet(self, line, opts):
        """v_enet get, create -flags <attributes>, update -flags <attributes>, delete -n <name>"""
        # Ensure that a valid sub-command was provided
        if line.strip() not in {"get", "create", "update", "delete"}:
            self.poutput(self.colorize('Error: ', 'red') + \
                        self.colorize(self.colorize(line.strip(), 'blue'),
                                      'bold') + ' is not recognized')
            return

        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())

        if line.strip() == "get":
            if self.device_id:
                cg, cpart, cp, ct, vont, ont, venet = self.get_interface_based_on_device()
                print_pb_list_as_table("VEnet for device ID = {}:".format(self.device_id),
                                       venet, {}, self.poutput)
            else:
                interface = stub.GetAllVEnetConfig(Empty())
                print_pb_list_as_table("VEnets:",
                                       interface.v_enet_config,
                                       {}, self.poutput)
            return

        interface_instance = VEnetConfig(name = opts.name)
        interface_instance.interface.name = opts.name
        if opts.description:
            interface_instance.interface.description = opts.description
        interface_instance.interface.type = "v-enet"
        if opts.enabled:
            if opts.enabled == "up":
                interface_instance.interface.enabled = True
            elif opts.enabled == "down":
                interface_instance.interface.enabled = False
            else:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize('Invalid admin state parameter for venet', 'blue'),
                                          'bold'))
                return
        if opts.link_up_down_trap_enable:
            types = ["trap_disabled", "trap_enabled"]
            try:
                assert opts.link_up_down_trap_enable in types, \
                        'Invalid Enum value for Venet link up down trap enable type \'{}\''\
                        .format(opts.link_up_down_trap_enable)
                interface_instance.interface.link_up_down_trap_enable = \
                    ietf_interfaces_pb2._INTERFACE_LINKUPDOWNTRAPENABLETYPE.values_by_name[opts.link_up_down_trap_enable.upper()].number
            except AssertionError, e:
                self.poutput(self.colorize('Error: ', 'red') + \
                            self.colorize(self.colorize(e.message, 'blue'),
                                          'bold'))
                return

        if opts.v_ontani_ref:
            interface_instance.data.v_ontani_ref = opts.v_ontani_ref

        if line.strip() == "create":
            stub.CreateVEnet(interface_instance)
        elif line.strip() == "update":
            stub.UpdateVEnet(interface_instance)
        elif line.strip() == "delete":
            stub.DeleteVEnet(interface_instance)
        return
