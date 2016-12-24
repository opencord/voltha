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
from cmd2 import Cmd
from simplejson import dumps

from cli.table import print_pb_as_table, print_pb_list_as_table
from cli.utils import print_flows, pb2dict
from voltha.protos import third_party

_ = third_party
from voltha.protos import voltha_pb2


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

    do_exit = Cmd.do_quit

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

    def do_flows(self, line):
        """Show flow table for device"""
        device = pb2dict(self.get_device(-1))
        print_flows(
            'Device',
            self.device_id,
            type=device['type'],
            flows=device['flows']['items'],
            groups=device['flow_groups']['items']
        )

