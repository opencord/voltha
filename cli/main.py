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
import sys
from cmd2 import Cmd, make_option, options
import readline
import grpc
from simplejson import dumps

from voltha.protos import third_party
from voltha.protos import voltha_pb2
from google.protobuf.empty_pb2 import Empty
from google.protobuf.json_format import MessageToDict
_ = third_party
from cli.utils import print_flows


def pb2dict(pb_msg):
    d = MessageToDict(pb_msg, including_default_value_fields=1,
                      preserving_proto_field_name=1)
    return d


class VolthaCli(Cmd):

    prompt = 'voltha'
    history_file_name = '.voltha_cli_history'
    max_history_lines = 500

    Cmd.settable.update(dict(
        voltha_grpc='Voltha GRPC endpoint in form of <host>:<port>'
    ))

    voltha_grpc = 'localhost:50055'

    def __init__(self, *args, **kw):
        Cmd.__init__(self, *args, **kw)
        self.prompt = '(' + self.colorize(
            self.colorize(self.prompt, 'red'), 'bold') + ') '
        self.channel = None

    def load_history(self):
        """Load saved command history from local history file"""
        try:
            with file(self.history_file_name, 'r') as f:
                for line in f.readlines():
                    stripped_line = line.strip()
                    self.history.append(stripped_line)
                    readline.add_history(stripped_line)
        except IOError:
            pass  # ignore if file cannot be read

    def save_history(self):
        try:
            with file(self.history_file_name, 'w') as f:
                f.write('\n'.join(self.history[-self.max_history_lines:]))
        except IOError, e:
            print >> sys.stderr, 'Could not save history in {}: {}'.format(
                self.history_file_name, e.msg)
        else:
            print >> sys.stderr, 'History saved as {}'.format(
                self.history_file_name)

    def get_channel(self):
        if self.channel is None:
            self.channel = grpc.insecure_channel(self.voltha_grpc)
        return self.channel

    def do_reset_history(self, arg):
        """Reset CLI history"""
        while self.history:
            self.history.pop()

    def do_launch(self, arg):
        """If Voltha is not running yet, launch it"""
        pass

    def do_restart(self, arg):
        """Launch Voltha, but if it is already running, terminate it first"""
        pass

    def do_devices(self, arg):
        """List devices registered in Voltha"""
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.ListDevices(Empty())
        for device in res.items:
            print self.colorize('# ====== device {}'.format(device.id), 'blue')
            print dumps(pb2dict(device), indent=4, sort_keys=True)

    def do_logical_devices(self, arg):
        """List logical devices in Voltha"""
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.ListLogicalDevices(Empty())
        for logical_device in res.items:
            print self.colorize('# ====== logical device {}'.format(
                logical_device.id), 'blue')
            print dumps(pb2dict(logical_device), indent=4, sort_keys=True)

    def do_device(self, arg):
        """Enter device level command mode"""
        sub = DeviceCli(self.get_channel, arg)
        sub.cmdloop()

    def do_logical_device(self, arg):
        """Enter logical device level command mode"""
        sub = LogicalDeviceCli(self.get_channel, arg)
        sub.cmdloop()

    def do_debug(self, arg):
        """Launch PDB debug prompt in CLI (for CLI development)"""
        from pdb import set_trace
        set_trace()

    def do_health(self, arg):
        """Show connectivity status to Voltha status"""
        stub = voltha_pb2.HealthServiceStub(self.get_channel())
        res = stub.GetHealthStatus(Empty())
        print dumps(pb2dict(res), indent=4)


class DeviceCli(Cmd):

    def __init__(self, get_channel, device_id):
        Cmd.__init__(self)
        self.get_channel = get_channel
        self.device_id = device_id
        self.prompt = '(' + self.colorize(
            self.colorize('device {}'.format(device_id), 'red'), 'bold') + ') '

    def get_device(self, depth=0):
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.GetDevice(voltha_pb2.ID(id=self.device_id),
                             metadata=(('get-depth', str(depth)), ))
        return res

    def do_show(self, arg):
        """Show detailed device information"""
        print dumps(pb2dict(self.get_device(depth=-1)),
                    indent=4, sort_keys=True)

    def do_flows(self, arg):
        """Show flow table for device"""
        device = pb2dict(self.get_device(-1))
        print_flows(
            'Device',
            self.device_id,
            type=device['type'],
            flows=device['flows']['items'],
            groups=device['flow_groups']['items']
        )


class LogicalDeviceCli(Cmd):

    def __init__(self, get_channel, logical_device_id):
        Cmd.__init__(self)
        self.get_channel = get_channel
        self.logical_device_id = logical_device_id
        self.prompt = '(' + self.colorize(
            self.colorize('device {}'.format(logical_device_id), 'red'),
            'bold') + ') '

    def get_logical_device(self, depth=0):
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.GetLogicalDevice(voltha_pb2.ID(id=self.logical_device_id),
                                    metadata=(('get-depth', str(depth)), ))
        return res

    def do_show(self, arg):
        """Show detailed logical device information"""
        print dumps(pb2dict(self.get_logical_device(depth=-1)),
                    indent=4, sort_keys=True)

    def do_flows(self, arg):
        """Show flow table for logical device"""
        logical_device = pb2dict(self.get_logical_device(-1))
        print_flows(
            'Logical Device',
            self.logical_device_id,
            type='n/a',
            flows=logical_device['flows']['items'],
            groups=logical_device['flow_groups']['items']
        )


if __name__ == '__main__':
    c = VolthaCli()
    c.load_history()
    c.cmdloop()
    c.save_history()
