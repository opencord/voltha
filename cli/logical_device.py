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
Logical device level CLI commands
"""
from cmd2 import Cmd
from simplejson import dumps

from cli.utils import pb2dict
from cli.utils import print_flows
from voltha.protos import third_party

_ = third_party
from voltha.protos import voltha_pb2


class LogicalDeviceCli(Cmd):

    def __init__(self, get_channel, logical_device_id):
        Cmd.__init__(self)
        self.get_channel = get_channel
        self.logical_device_id = logical_device_id
        self.prompt = '(' + self.colorize(
            self.colorize('logical device {}'.format(logical_device_id), 'red'),
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

