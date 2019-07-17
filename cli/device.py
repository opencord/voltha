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
Device level CLI commands
"""
from optparse import make_option
from cmd2 import Cmd, options
from simplejson import dumps

from cli.table import print_pb_as_table, print_pb_list_as_table
from cli.utils import print_flows, pb2dict, enum2name
from voltha.protos import third_party

_ = third_party
from voltha.protos import voltha_pb2, common_pb2
import sys
import json
import unicodedata
import ast
from google.protobuf.json_format import MessageToDict

# Since proto3 won't send fields that are set to 0/false/"" any object that
# might have those values set in them needs to be replicated here such that the
# fields can be adequately

FLOW_ID_INFO_PATH = '{}/{}/flow_id_info/{}'
FLOW_IDS_PATH = '{}/{}/flow_ids'
technology = 'xgspon'
PATH_PREFIX0 = 'service/voltha/resource_manager/{}'
PATH_PREFIX = PATH_PREFIX0.format(technology)
PATH = '{}/{}'


class DeviceCli(Cmd):

    def __init__(self, device_id, get_stub, etcd):
        Cmd.__init__(self)
        self.get_stub = get_stub
        self.device_id = device_id
        self.prompt = '(' + self.colorize(
            self.colorize('device {}'.format(device_id), 'red'), 'bold') + ') '
        self.pm_config_last = None
        self.pm_config_dirty = False
        self.etcd = etcd

    def cmdloop(self):
        self._cmdloop()

    def get_device(self, depth=0):
        stub = self.get_stub()
        res = stub.GetDevice(voltha_pb2.ID(id=self.device_id),
                             metadata=(('get-depth', str(depth)), ))
        return res

    do_exit = Cmd.do_quit

    def do_quit(self, line):
        if self.pm_config_dirty:
            self.poutput("Uncommited changes for " + \
                         self.colorize(
                             self.colorize("perf_config,", "blue"),
                             "bold") + " please either " + self.colorize(
                             self.colorize("commit", "blue"), "bold") + \
                         " or " + self.colorize(
                             self.colorize("reset", "blue"), "bold") + \
                         " your changes using " + \
                         self.colorize(
                             self.colorize("perf_config", "blue"), "bold"))
            return False
        else:
            return self._STOP_AND_EXIT

    def do_show(self, line):
        """Show detailed device information"""
        print_pb_as_table('Device {}'.format(self.device_id),
                          self.get_device(depth=-1))

    def do_ports(self, line):
        """Show ports of device"""
        device = self.get_device(depth=-1)
        omit_fields = {
        }
        print_pb_list_as_table('Device ports:', device.ports,
                               omit_fields, self.poutput)

    def complete_perf_config(self, text, line, begidx, endidx):
        sub_cmds = {"show", "set", "commit", "reset"}
        sub_opts = {"-f", "-e", "-d", "-o"}
        # Help the interpreter complete the paramters.
        completions = []
        if not self.pm_config_last:
            device = self.get_device(depth=-1)
            self.pm_config_last = device.pm_configs
        m_names = [d.name for d in self.pm_config_last.metrics]
        cur_cmd = line.strip().split(" ")
        try:
            if not text and len(cur_cmd) == 1:
                completions = ("show", "set", "commit", "reset")
            elif len(cur_cmd) == 2:
                if "set" == cur_cmd[1]:
                    completions = [d for d in sub_opts]
                else:
                    completions = [d for d in sub_cmds if d.startswith(text)]
            elif len(cur_cmd) > 2 and cur_cmd[1] == "set":
                if cur_cmd[len(cur_cmd)-1] == "-":
                    completions = [list(d)[1] for d in sub_opts]
                elif cur_cmd[len(cur_cmd)-1] == "-f":
                    completions = ("\255","Please enter a sampling frequency in 10ths of a second")
                elif cur_cmd[len(cur_cmd)-2] == "-f":
                    completions = [d for d in sub_opts]
                elif cur_cmd[len(cur_cmd)-1] in {"-e","-d","-o"}:
                    if self.pm_config_last.grouped:
                        pass
                    else:
                        completions = [d.name for d in self.pm_config_last.metrics]
                elif cur_cmd[len(cur_cmd)-2] in {"-e","-d"}:
                    if text and text not in m_names:
                        completions = [d for d in m_names if d.startswith(text)]
                    else:
                        completions = [d for d in sub_opts]
                elif cur_cmd[len(cur_cmd)-2] == "-o":
                    if cur_cmd[len(cur_cmd)-1] in [d.name for d in self.pm_config_last.metrics]:
                        completions = ("\255","Please enter a sampling frequency in 10ths of a second")
                    else:
                        completions = [d for d in m_names if d.startswith(text)]
                elif cur_cmd[len(cur_cmd)-3] == "-o":
                    completions = [d for d in sub_opts]
        except:
            e = sys.exc_info()
            print(e)
        return completions


    def help_perf_config(self):
        self.poutput(
'''
perf_config [show | set | commit | reset] [-f <default frequency>] [{-e <metric/group
            name>}] [{-d <metric/group name>}] [{-o <metric/group name> <override
            frequency>}]

show: displays the performance configuration of the device
set: changes the parameters specified with -e, -d, and -o
reset: reverts any changes made since the last commit
commit: commits any changes made which applies them to the device.

-e: enable collection of the specified metric, more than one -e may be
            specified.
-d: disable collection of the specified metric, more than on -d may be
            specified.
-o: override the collection frequency of the specified metric, more than one -o
            may be specified. Note that -o isn't valid unless
            frequency_override is set to True for the device.

Changes made by set are held locally until a commit or reset command is issued.
A commit command will write the configuration to the device and it takes effect
immediately. The reset command will undo any changes since the start of the
device session.

If grouped is true then the -d, -e and -o commands refer to groups and not
individual metrics.
'''
        )

    @options([
        make_option('-f', '--default_freq', action="store", dest='default_freq',
                    type='long', default=None),
        make_option('-e', '--enable', action='append', dest='enable',
                    default=None),
        make_option('-d', '--disable', action='append', dest='disable',
                    default=None),
        make_option('-o', '--override', action='append', dest='override',
                    nargs=2, default=None, type='string'),
    ])
    def do_perf_config(self, line, opts):
        """Show and set the performance monitoring configuration of the device"""

        device = self.get_device(depth=-1)
        if not self.pm_config_last:
            self.pm_config_last = device.pm_configs

        # Ensure that a valid sub-command was provided
        if line.strip() not in {"set", "show", "commit", "reset", ""}:
                self.poutput(self.colorize('Error: ', 'red') +
                             self.colorize(self.colorize(line.strip(), 'blue'),
                                           'bold') + ' is not recognized')
                return

        # Ensure no options are provided when requesting to view the config
        if line.strip() == "show" or line.strip() == "":
            if opts.default_freq or opts.enable or opts.disable:
                self.poutput(opts.disable)
                self.poutput(self.colorize('Error: ', 'red') + 'use ' +
                             self.colorize(self.colorize('"set"', 'blue'),
                                           'bold') + ' to change settings')
                return

        if line.strip() == "set":  # Set the supplied values
            metric_list = set()
            if opts.enable is not None:
                metric_list |= {metric for metric in opts.enable}
            if opts.disable is not None:
                metric_list |= {metric for metric in opts.disable}
            if opts.override is not None:
                metric_list |= {metric for metric, _ in opts.override}

            # The default frequency
            if opts.default_freq:
                self.pm_config_last.default_freq = opts.default_freq
                self.pm_config_dirty = True

            # Field or group visibility
            if self.pm_config_last.grouped:
                for g in self.pm_config_last.groups:
                    if opts.enable:
                        if g.group_name in opts.enable:
                            g.enabled = True
                            self.pm_config_dirty = True
                            metric_list.discard(g.group_name)
                for g in self.pm_config_last.groups:
                    if opts.disable:
                        if g.group_name in opts.disable:
                            g.enabled = False
                            self.pm_config_dirty = True
                            metric_list.discard(g.group_name)
            else:
                for m in self.pm_config_last.metrics:
                    if opts.enable:
                        if m.name in opts.enable:
                            m.enabled = True
                            self.pm_config_dirty = True
                            metric_list.discard(m.name)
                for m in self.pm_config_last.metrics:
                    if opts.disable:
                        if m.name in opts.disable:
                            m.enabled = False
                            self.pm_config_dirty = True
                            metric_list.discard(m.name)

            # Frequency overrides.
            if opts.override:
                if self.pm_config_last.freq_override:
                    oo = dict()
                    for o in opts.override:
                        oo[o[0]] = o[1]
                    if self.pm_config_last.grouped:
                        for g in self.pm_config_last.groups:
                            if g.group_name in oo:
                                try:
                                    g.group_freq = int(oo[g.group_name])
                                except ValueError:
                                    self.poutput(self.colorize('Warning: ',
                                                               'yellow') +
                                                 self.colorize(oo[g.group_name],
                                                               'blue') +
                                                 " is not an integer... ignored")
                                del oo[g.group_name]
                                self.pm_config_dirty = True
                                metric_list.discard(g.group_name)
                    else:
                        for m in self.pm_config_last.metrics:
                            if m.name in oo:
                                try:
                                    m.sample_freq = int(oo[m.name])
                                except ValueError:
                                    self.poutput(self.colorize('Warning: ',
                                                               'yellow') +
                                                 self.colorize(oo[m.name],
                                                               'blue') +
                                                 " is not an integer... ignored")
                                del oo[m.name]
                                self.pm_config_dirty = True
                                metric_list.discard(m.name)

                    # If there's anything left the input was typoed
                    if self.pm_config_last.grouped:
                        field = 'group'
                    else:
                        field = 'metric'
                    for o in oo:
                        self.poutput(self.colorize('Warning: ', 'yellow') +
                                     'the parameter' + ' ' +
                                     self.colorize(o, 'blue') + ' is not ' +
                                     'a ' + field + ' name... ignored')
                    if oo:
                        return

                else:  # Frequency overrides not enabled
                    self.poutput(self.colorize('Error: ', 'red') +
                                 'Individual overrides are only ' +
                                 'supported if ' +
                                 self.colorize('freq_override', 'blue') +
                                 ' is set to ' + self.colorize('True', 'blue'))
                    return

            if len(metric_list):
                metric_name_list = ", ".join(str(metric) for metric in metric_list)
                self.poutput(self.colorize('Error: ', 'red') +
                             'Metric/Metric Group{} '.format('s' if len(metric_list) > 1 else '') +
                             self.colorize(metric_name_list, 'blue') +
                             ' {} not found'.format('were' if len(metric_list) > 1 else 'was'))
                return

            self.poutput("Success")
            return

        elif line.strip() == "commit" and self.pm_config_dirty:
            stub = self.get_stub()
            stub.UpdateDevicePmConfigs(self.pm_config_last)
            self.pm_config_last = self.get_device(depth=-1).pm_configs
            self.pm_config_dirty = False

        elif line.strip() == "reset" and self.pm_config_dirty:
            self.pm_config_last = self.get_device(depth=-1).pm_configs
            self.pm_config_dirty = False

        omit_fields = {'groups', 'metrics', 'id'}
        print_pb_as_table('PM Config:', self.pm_config_last, omit_fields,
                          self.poutput,show_nulls=True)
        if self.pm_config_last.grouped:
            #self.poutput("Supported metric groups:")
            for g in self.pm_config_last.groups:
                if self.pm_config_last.freq_override:
                    omit_fields = {'metrics'}
                else:
                    omit_fields = {'group_freq','metrics'}
                print_pb_as_table('', g, omit_fields, self.poutput,
                                  show_nulls=True)
                if g.enabled:
                    state = 'enabled'
                else:
                    state = 'disabled'
                print_pb_list_as_table(
                    'Metric group {} is {}'.format(g.group_name,state),
                    g.metrics, {'enabled', 'sample_freq'}, self.poutput,
                    dividers=100, show_nulls=True)
        else:
            if self.pm_config_last.freq_override:
                omit_fields = {}
            else:
                omit_fields = {'sample_freq'}
            print_pb_list_as_table('Supported metrics:', self.pm_config_last.metrics,
                                   omit_fields, self.poutput, dividers=100,
                                   show_nulls=True)

    def get_flow_id(self, id_str):
        # original representation of the flow id
        # there is a mask for upstream flow ids of openolt adapter as 0x1 << 15 | flow_id
        # ponsim and other flow does not need any modification
        if int(id_str) >= 0x1 << 15:
            flow_id = int(id_str) ^ 0x1 << 15
        else:
            flow_id = int(id_str)

        return flow_id

    def flow_exist(self, pon_intf_onu_id, flow_id):
        # checks whether the flow still exists in ETCD or not
        flow_ids_path = FLOW_IDS_PATH.format(self.device_id, pon_intf_onu_id)
        path_to_flow_ids = PATH.format(PATH_PREFIX, flow_ids_path)
        (flow_ids, _) = self.etcd.get(path_to_flow_ids)
        if flow_ids is None:
            return False
        else:
            if flow_id in eval(flow_ids):
                return True
            else:
                return False

    def update_repeated_ids_dict(self,flow_id, repeated_ids):
        # updates how many times an id is seen
        if str(flow_id) in repeated_ids:
            repeated_ids[str(flow_id)] += 1
        else:
            repeated_ids[str(flow_id)] = 1
        return repeated_ids

    def get_flow_index(self,flow, flow_info_all):
        if 'flow_store_cookie' in flow:
            for i, flow_info in enumerate(flow_info_all):
                if unicodedata.normalize('NFKD', flow['flow_store_cookie']).encode('ascii', 'ignore') == flow_info['flow_store_cookie']:
                    return i
            return None
        else: #only one flow or those flows that are not added to device
            return 0

    def do_flows(self, line):
        """Show flow table for device"""
        device = pb2dict(self.get_device(-1))
        flows_info = list()
        flows = device['flows']['items']
        for i, flow in enumerate(flows):
            flow_info = dict()
            if unicodedata.normalize('NFKD', device['type']).encode('ascii', 'ignore') == 'openolt':
                flow_id = self.get_flow_id(flow['id'])
            else:
                flow_id = int(flow['id'])

            flow_info.update({'flow_id' : str(flow_id)})

            if 'intf_tuple' in flow and len(flow['intf_tuple']) > 0:    # we have extra flow info in ETCD!!!
                pon_intf_onu_id = unicodedata.normalize('NFKD', flow['intf_tuple'][0]).encode('ascii', 'ignore')
                flow_info.update({'pon_intf_onu_id': pon_intf_onu_id})

                # check if the flow info still exists in ETCD
                if self.flow_exist(pon_intf_onu_id, flow_id):
                    flow_id_info_path = FLOW_ID_INFO_PATH.format(self.device_id, pon_intf_onu_id, flow_id)
                    path_to_flow_info = PATH.format(PATH_PREFIX, flow_id_info_path)
                    (flow_info_all, _) = self.etcd.get(path_to_flow_info)
                    flow_info_all = ast.literal_eval(flow_info_all)
                    flow_info_index = self.get_flow_index(flow, flow_info_all)

                    if flow_info_index is not None:
                        flow_info_all = flow_info_all[flow_info_index]
                        if 'gemport_id' in flow_info_all:
                            flow_info.update({'gemport_id': flow_info_all['gemport_id']})

                        if 'alloc_id' in flow_info_all:
                            flow_info.update({'alloc_id': flow_info_all['alloc_id']})

                        if 'flow_type' in flow_info_all:
                            flow_info.update({'flow_type': flow_info_all['flow_type']})

                        if 'o_pbits' in flow_info_all['classifier']:
                            flow_info.update({'o_pbits': flow_info_all['classifier']['o_pbits']})

                        if 'flow_category' in flow_info_all:
                            flow_info.update({'flow_category': flow_info_all['flow_category']})

            flows_info.append(flow_info)
        print_flows(
            'Device',
            self.device_id,
            type=device['type'],
            flows=device['flows']['items'],
            groups=device['flow_groups']['items'],
            flows_info=flows_info,
            fields_to_omit = ['table_id', 'goto-table']
        )

    def do_images(self, line):
        """Show software images on the device"""
        device = self.get_device(depth=-1)
        omit_fields = {}
        print_pb_list_as_table('Software Images:', device.images.image,
                               omit_fields, self.poutput, show_nulls=True)

    @options([
        make_option('-u', '--url', action='store', dest='url',
                    help="URL to get sw image"),
        make_option('-n', '--name', action='store', dest='name',
                    help="Image name"),
        make_option('-c', '--crc', action='store', dest='crc',
                    help="CRC code to verify with", default=0),
        make_option('-v', '--version', action='store', dest='version',
                    help="Image version", default=0),
        make_option('-d', '--dir', action='store', dest='dir',
                    help="local directory"),
    ])
    def do_img_dnld_request(self, line, opts):
        """
        Request image download to a device
        """
        device = self.get_device(depth=-1)
        self.poutput('device_id {}'.format(device.id))
        self.poutput('name {}'.format(opts.name))
        self.poutput('url {}'.format(opts.url))
        self.poutput('crc {}'.format(opts.crc))
        self.poutput('version {}'.format(opts.version))
        self.poutput('local dir {}'.format(opts.dir))
        try:
            device_id = device.id
            if device_id and opts.name and opts.url:
                kw = dict(id=device_id)
                kw['name'] = opts.name
                kw['url'] = opts.url
            else:
                self.poutput('Device ID and URL are needed')
                raise Exception('Device ID and URL are needed')
            if opts.dir:
                kw['local_dir'] = opts.dir
        except Exception as e:
            self.poutput('Error request img dnld {}.  Error:{}'.format(device_id, e))
            return
        kw['crc'] = long(opts.crc)
        kw['image_version'] = opts.version
        response = None
        try:
            request = voltha_pb2.ImageDownload(**kw)
            stub = self.get_stub()
            response = stub.DownloadImage(request)
        except Exception as e:
            self.poutput('Error download image {}. Error:{}'.format(kw['id'], e))
            return
        name = enum2name(common_pb2.OperationResp,
                        'OperationReturnCode', response.code)
        self.poutput('response: {}'.format(name))
        self.poutput('{}'.format(response))

    @options([
        make_option('-n', '--name', action='store', dest='name',
                    help="Image name"),
    ])
    def do_img_dnld_status(self, line, opts):
        """
        Get a image download status
        """
        device = self.get_device(depth=-1)
        self.poutput('device_id {}'.format(device.id))
        self.poutput('name {}'.format(opts.name))
        try:
            device_id = device.id
            if device_id and opts.name:
                kw = dict(id=device_id)
                kw['name'] = opts.name
            else:
                self.poutput('Device ID, Image Name are needed')
                raise Exception('Device ID, Image Name are needed')
        except Exception as e:
            self.poutput('Error get img dnld status {}.  Error:{}'.format(device_id, e))
            return
        status = None
        try:
            img_dnld = voltha_pb2.ImageDownload(**kw)
            stub = self.get_stub()
            status = stub.GetImageDownloadStatus(img_dnld)
        except Exception as e:
            self.poutput('Error get img dnld status {}. Error:{}'.format(device_id, e))
            return
        fields_to_omit = {
              'crc',
              'local_dir',
        }
        try:
            print_pb_as_table('ImageDownload Status:', status, fields_to_omit, self.poutput)
        except Exception, e:
            self.poutput('Error {}.  Error:{}'.format(device_id, e))

    def do_img_dnld_list(self, line):
        """
        List all image download records for a given device
        """
        device = self.get_device(depth=-1)
        device_id = device.id
        self.poutput('Get all img dnld records {}'.format(device_id))
        try:
            stub = self.get_stub()
            img_dnlds = stub.ListImageDownloads(voltha_pb2.ID(id=device_id))
        except Exception, e:
            self.poutput('Error list img dnlds {}.  Error:{}'.format(device_id, e))
            return
        fields_to_omit = {
              'crc',
              'local_dir',
        }
        try:
            print_pb_list_as_table('ImageDownloads:', img_dnlds.items, fields_to_omit, self.poutput)
        except Exception, e:
            self.poutput('Error {}.  Error:{}'.format(device_id, e))


    @options([
        make_option('-n', '--name', action='store', dest='name',
                    help="Image name"),
    ])
    def do_img_dnld_cancel(self, line, opts):
        """
        Cancel a requested image download
        """
        device = self.get_device(depth=-1)
        self.poutput('device_id {}'.format(device.id))
        self.poutput('name {}'.format(opts.name))
        device_id = device.id
        try:
            if device_id and opts.name:
                kw = dict(id=device_id)
                kw['name'] = opts.name
            else:
                self.poutput('Device ID, Image Name are needed')
                raise Exception('Device ID, Image Name are needed')
        except Exception as e:
            self.poutput('Error cancel sw dnld {}. Error:{}'.format(device_id, e))
            return
        response = None
        try:
            img_dnld = voltha_pb2.ImageDownload(**kw)
            stub = self.get_stub()
            img_dnld = stub.GetImageDownload(img_dnld)
            response = stub.CancelImageDownload(img_dnld)
        except Exception as e:
            self.poutput('Error cancel sw dnld {}. Error:{}'.format(device_id, e))
            return
        name = enum2name(common_pb2.OperationResp,
                        'OperationReturnCode', response.code)
        self.poutput('response: {}'.format(name))
        self.poutput('{}'.format(response))

    def help_simulate_alarm(self):
        self.poutput(
'''
simulate_alarm <alarm_name> [-b <bit rate>] [-c] [-d <drift>] [-e <eqd>]
            [-i <interface id>] [-o <onu device id>] [-p <port type name>]

<name> is the name of the alarm to raise. Other rguments are alarm specific
and only have meaning in the context of a particular alarm. Below is a list
of the alarms that may be raised:

simulate_alarm los -i <interface_id> -p <port_type_name>
simulate_alarm dying_gasp -i <interface_id> -o <onu_device_id>
simulate_alarm onu_los -i <interface_id> -o <onu_device_id>
simulate_alarm onu_lopc_miss -i <interface_id> -o <onu_device_id>
simulate_alarm onu_lopc_mic -i <interface_id> -o <onu_device_id>
simulate_alarm onu_lob -i <interface_id> -o <onu_device_id>
simulate_alarm onu_signal_degrade -i <interface_id> -o <onu_device_id>
               -b <bit_rate>
simulate_alarm onu_drift_of_window -i <interface_id>
               -o <onu_device_id> -d <drift> -e <eqd>
simulate_alarm onu_signal_fail -i <interface_id> -o <onu_device_id>
               -b <bit_rate>
simulate_alarm onu_activation -i <interface_id> -o <onu_device_id>
simulate_alarm onu_startup -i <interface_id> -o <onu_device_id>
simulate_alarm onu_discovery -i <interface_id> -s <onu_serial_number>

If the -c option is specified then the alarm will be cleared. By default,
it will be raised. Note that only some alarms can be cleared.
'''
        )

    @options([
        make_option('-c', '--clear', action='store_true', default=False,
                    help="Clear alarm instead of raising"),
        make_option('-b', '--inverse_bit_error_rate', action='store', dest='inverse_bit_error_rate',
                    help="Inverse bit error rate", default=0, type="int"),
        make_option('-d', '--drift', action='store', dest='drift',
                    help="Drift", default=0, type="int"),
        make_option('-e', '--new_eqd', action='store', dest='new_eqd',
                    help="New EQD", default=0, type="int"),
        make_option('-i', '--intf_id', action='store', dest='intf_id',
                    help="Interface ID", default=""),
        make_option('-o', '--onu_device_id', action='store', dest='onu_device_id',
                    help="ONU device ID", default=""),
        make_option('-p', '--port_type_name', action='store', dest='port_type_name',
                    help="Port type name", default=""),
        make_option('-s', '--onu_serial_number', action='store', dest='onu_serial_number',
                    help="ONU Serial Number", default=""),
    ])
    def do_simulate_alarm(self, line, opts):
        indicator = line
        device = self.get_device(depth=-1)
        device_id = device.id

        alarm_args = {"los": ["intf_id", "port_type_name"],
                      "dying_gasp": ["intf_id", "onu_device_id"],
                      "onu_los": ["intf_id", "onu_device_id"],
                      "onu_lopc_miss": ["intf_id", "onu_device_id"],
                      "onu_lopc_mic": ["intf_id", "onu_device_id"],
                      "onu_lob": ["intf_id", "onu_device_id"],
                      "onu_signal_degrade": ["intf_id", "onu_device_id", "inverse_bit_error_rate"],
                      "onu_drift_of_window": ["intf_id", "onu_device_id", "drift", "new_eqd"],
                      "onu_signal_fail": ["intf_id", "onu_device_id", "inverse_bit_error_rate"],
                      "onu_activation": ["intf_id", "onu_device_id"],
                      "onu_startup": ["intf_id", "onu_device_id"],
                      "onu_discovery": ["intf_id", "onu_serial_number"]
                      }
        try:
            if indicator not in alarm_args:
                self.poutput("Unknown alarm indicator %s. Valid choices are %s." % (indicator,
                                                                                    ", ".join(alarm_args.keys())))
                raise Exception("Unknown alarm indicator %s" % indicator)

            for arg_name in alarm_args[indicator]:
                if not getattr(opts, arg_name):
                    self.poutput("Option %s is required for alarm %s. See help." % (arg_name, indicator))
                    raise Exception("Option %s is required for alarm %s" % (arg_name, indicator))

            # TODO: check for required arguments
            kw = dict(id=device_id)

            kw["indicator"] = indicator
            kw["intf_id"] = opts.intf_id
            kw["onu_device_id"] = opts.onu_device_id
            kw["port_type_name"] = opts.port_type_name
            kw["inverse_bit_error_rate"] = opts.inverse_bit_error_rate
            kw["drift"] = opts.drift
            kw["new_eqd"] = opts.new_eqd
            kw["onu_serial_number"] = opts.onu_serial_number

            if opts.clear:
                kw["operation"] = voltha_pb2.SimulateAlarmRequest.CLEAR
            else:
                kw["operation"] = voltha_pb2.SimulateAlarmRequest.RAISE
        except Exception as e:
            self.poutput('Error simulate alarm {}. Error:{}'.format(device_id, e))
            return
        response = None
        try:
            simulate_alarm = voltha_pb2.SimulateAlarmRequest(**kw)
            stub = self.get_stub()
            response = stub.SimulateAlarm(simulate_alarm)
        except Exception as e:
            self.poutput('Error simulate alarm {}. Error:{}'.format(kw['id'], e))
            return
        name = enum2name(common_pb2.OperationResp,
                        'OperationReturnCode', response.code)
        self.poutput('response: {}'.format(name))
        self.poutput('{}'.format(response))

    @options([
        make_option('-n', '--name', action='store', dest='name',
                    help="Image name"),
        make_option('-s', '--save', action='store', dest='save_config',
                    help="Save Config", default="True"),
        make_option('-d', '--dir', action='store', dest='local_dir',
                    help="Image on device location"),
    ])
    def do_img_activate(self, line, opts):
        """
        Activate an image update on device
        """
        device = self.get_device(depth=-1)
        device_id = device.id
        try:
            if device_id and opts.name and opts.local_dir:
                kw = dict(id=device_id)
                kw['name'] = opts.name
                kw['local_dir'] = opts.local_dir
            else:
                self.poutput('Device ID, Image Name, and Location are needed')
                raise Exception('Device ID, Image Name, and Location are needed')
        except Exception as e:
            self.poutput('Error activate image {}. Error:{}'.format(device_id, e))
            return
        kw['save_config'] = json.loads(opts.save_config.lower())
        self.poutput('activate image update {} {} {} {}'.format( \
                    kw['id'], kw['name'],
                    kw['local_dir'], kw['save_config']))
        response = None
        try:
            img_dnld = voltha_pb2.ImageDownload(**kw)
            stub = self.get_stub()
            img_dnld = stub.GetImageDownload(img_dnld)
            response = stub.ActivateImageUpdate(img_dnld)
        except Exception as e:
            self.poutput('Error activate image {}. Error:{}'.format(kw['id'], e))
            return
        name = enum2name(common_pb2.OperationResp,
                        'OperationReturnCode', response.code)
        self.poutput('response: {}'.format(name))
        self.poutput('{}'.format(response))

    @options([
        make_option('-n', '--name', action='store', dest='name',
                    help="Image name"),
        make_option('-s', '--save', action='store', dest='save_config',
                    help="Save Config", default="True"),
        make_option('-d', '--dir', action='store', dest='local_dir',
                    help="Image on device location"),
    ])
    def do_img_revert(self, line, opts):
        """
        Revert an image update on device
        """
        device = self.get_device(depth=-1)
        device_id = device.id
        try:
            if device_id and opts.name and opts.local_dir:
                kw = dict(id=device_id)
                kw['name'] = opts.name
                kw['local_dir'] = opts.local_dir
            else:
                self.poutput('Device ID, Image Name, and Location are needed')
                raise Exception('Device ID, Image Name, and Location are needed')
        except Exception as e:
            self.poutput('Error revert image {}. Error:{}'.format(device_id, e))
            return
        kw['save_config'] = json.loads(opts.save_config.lower())
        self.poutput('revert image update {} {} {} {}'.format( \
                    kw['id'], kw['name'],
                    kw['local_dir'], kw['save_config']))
        response = None
        try:
            img_dnld = voltha_pb2.ImageDownload(**kw)
            stub = self.get_stub()
            img_dnld = stub.GetImageDownload(img_dnld)
            response = stub.RevertImageUpdate(img_dnld)
        except Exception as e:
            self.poutput('Error revert image {}. Error:{}'.format(kw['id'], e))
            return
        name = enum2name(common_pb2.OperationResp,
                        'OperationReturnCode', response.code)
        self.poutput('response: {}'.format(name))
        self.poutput('{}'.format(response))
