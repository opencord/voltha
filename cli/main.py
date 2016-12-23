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
import readline
import sys
from optparse import make_option
from time import sleep

import grpc
import requests
from cmd2 import Cmd, options
from google.protobuf.empty_pb2 import Empty
from simplejson import dumps

from cli.device import DeviceCli
from cli.logical_device import LogicalDeviceCli
from voltha.core.flow_decomposer import *
from voltha.protos import third_party
from voltha.protos import voltha_pb2
from voltha.protos.openflow_13_pb2 import FlowTableUpdate

_ = third_party
from cli.utils import pb2dict


banner = """\
           _ _   _              _ _
  __ _____| | |_| |_  __ _   __| (_)
  \ V / _ \ |  _| ' \/ _` | / _| | |
   \_/\___/_|\__|_||_\__,_| \__|_|_|
(to exit type q, exit or quit or hit Ctrl-D)
"""

class VolthaCli(Cmd):

    prompt = 'voltha'
    history_file_name = '.voltha_cli_history'

    # Settable CLI parameters
    voltha_grpc = 'localhost:50055'
    voltha_sim_rest = 'localhost:18880'
    max_history_lines = 500
    default_device_id = None
    default_logical_device_id = None

    Cmd.settable.update(dict(
        voltha_grpc='Voltha GRPC endpoint in form of <host>:<port>',
        voltha_sim_rest='Voltha simulation back door for testing in form '
                        'of <host>:<port>',
        max_history_lines='Maximum number of history lines stored across '
                          'sessions',
        default_device_id='Device id used when no device id is specified',
        default_logical_device_id='Logical device id used when no device id '
                                  'is specified',
    ))

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

    def preloop(self):
        self.poutput(banner)

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
        device_id = arg or self.default_device_id
        if not device_id:
            raise Exception('<device-id> parameter needed')
        sub = DeviceCli(self.get_channel, device_id)
        sub.cmdloop()

    def do_logical_device(self, arg):
        """Enter logical device level command mode"""
        logical_device_id = arg or self.default_logical_device_id
        if not logical_device_id:
            raise Exception('<logical-device-id> parameter needed')
        sub = LogicalDeviceCli(self.get_channel, logical_device_id)
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

    def do_test(self, arg):
        """Enter test mode, which makes a bunch on new commands available"""
        sub = TestCli(self.history, self.get_channel)
        sub.cmdloop()


class TestCli(VolthaCli):

    def __init__(self, history, get_channel):
        VolthaCli.__init__(self)
        self.history = history
        self.get_channel = get_channel
        self.prompt = '(' + self.colorize(self.colorize('test', 'cyan'),
            'bold') + ') '

    @options([
        make_option('-t', '--device-type', action="store", dest='device_type',
                     help="Device type", default='simulated_olt'),
        make_option('-m', '--mac-address', action='store', dest='mac_address',
                    default='00:0c:e2:31:40:00'),
        make_option('-i', '--ip-address', action='store', dest='ip_address'),
    ])
    def do_preprovision_olt(self, arg, opts):
        """Preprovision a new OLT with given device type"""
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        kw = dict(type=opts.device_type)
        if opts.ip_address:
            kw['ipv4_address'] = opts.ip_address
        elif opts.mac_address:
            kw['mac_address'] = opts.mac_address
        else:
            raise Exception('Either IP address or Mac Address is needed')
        device = voltha_pb2.Device(**kw)
        device = stub.CreateDevice(device)
        print 'success (device id = {})'.format(device.id)
        self.default_device_id = device.id

    def do_activate_olt(self, arg):
        """
        Activate an OLT. If the <id> is not provided, it will be on the last
        pre-provisioned OLT.
        """
        device_id = arg or self.default_device_id
        print 'activating', device_id
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        stub.ActivateDevice(voltha_pb2.ID(id=device_id))

        # try to acquire logical device id
        while True:
            device = stub.GetDevice(voltha_pb2.ID(id=device_id))
            if device.oper_status == voltha_pb2.OperStatus.ACTIVE:
                assert device.parent_id
                self.default_logical_device_id = device.parent_id
                break
            print 'waiting for device to be activated...'
            sleep(1)
        print 'success (logical device id = {})'.format(
            self.default_logical_device_id)

    def do_arrive_onus(self, arg):
        """
        Simulate the arrival of ONUs
        """
        device_id = arg or self.default_device_id
        requests.get('http://{}/devices/{}/detect_onus'.format(
            self.voltha_sim_rest, device_id
        ))

    def do_install_eapol_flow(self, arg):
        """
        Install an EAPOL flow on the given logical device. If device is not
        given, it will be applied to logical device of the last pre-provisioned
        OLT device.
        """
        logical_device_id = arg or self.default_logical_device_id
        update = FlowTableUpdate(
            id=logical_device_id,
            flow_mod = mk_simple_flow_mod(
                priority=2000,
                match_fields=[in_port(101), eth_type(0x888e)],
                actions=[
                    push_vlan(0x8100),
                    set_field(vlan_vid(4096 + 4000)),
                    output(ofp.OFPP_CONTROLLER)
                ]
            )
        )
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.UpdateLogicalDeviceFlowTable(update)
        print 'success', res

    def do_send_simulated_upstream_eapol(self, arg):
        """
        Send an EAPOL upstream from a simulated OLT
        """
        device_id = arg or self.default_device_id
        requests.get('http://{}/devices/{}/test_eapol_in'.format(
            self.voltha_sim_rest, device_id
        ))

    def do_inject_eapol_start(self, arg):
        """
        Send out an an EAPOL start message into the given Unix interface
        """
        pass


if __name__ == '__main__':
    c = VolthaCli()
    c.load_history()
    c.cmdloop()
    c.save_history()
