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
from optparse import make_option
from time import sleep, time

import grpc
import requests
from cmd2 import Cmd, options
from google.protobuf.empty_pb2 import Empty
from simplejson import dumps

from cli.device import DeviceCli
from cli.logical_device import LogicalDeviceCli
from cli.table import TablePrinter, print_pb_table
from voltha.core.flow_decomposer import *
from voltha.protos import third_party
from voltha.protos import voltha_pb2
from voltha.protos.openflow_13_pb2 import FlowTableUpdate

_ = third_party
from cli.utils import pb2dict, dict2line

banner = """\
         _ _   _              _ _
__ _____| | |_| |_  __ _   __| (_)
\ V / _ \ |  _| ' \/ _` | / _| | |
 \_/\___/_|\__|_||_\__,_| \__|_|_|
(to exit type quit or hit Ctrl-D)
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

    # cleanup of superflous commands from cmd2
    del Cmd.do_cmdenvironment
    # del Cmd.do_eof
    del Cmd.do_exit
    del Cmd.do_q
    del Cmd.do_hi
    del Cmd.do_l
    del Cmd.do_li
    del Cmd.do_r
    del Cmd.do__load
    del Cmd.do__relative_load
    Cmd.do_edit = Cmd.do_ed


    def __init__(self, *args, **kw):

        Cmd.__init__(self, *args, **kw)
        self.prompt = '(' + self.colorize(
            self.colorize(self.prompt, 'blue'), 'bold') + ') '
        self.channel = None
        self.device_ids_cache = None
        self.device_ids_cache_ts = time()
        self.logical_device_ids_cache = None
        self.logical_device_ids_cache_ts = time()

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
            with open(self.history_file_name, 'w') as f:
                f.write('\n'.join(self.history[-self.max_history_lines:]))
        except IOError as e:
            self.perror('Could not save history in {}: {}'.format(
                self.history_file_name, e))
        else:
            self.perror('History saved as {}'.format(
                self.history_file_name))

    def perror(self, errmsg, statement=None):
        # Touch it up to make sure error is prefixed and colored
        Cmd.perror(self, self.colorize('***ERROR: ', 'red') + errmsg,
                   statement)

    def get_channel(self):
        if self.channel is None:
            self.channel = grpc.insecure_channel(self.voltha_grpc)
        return self.channel

    # ~~~~~~~~~~~~~~~~~ ACTUAL COMMAND IMPLEMENTATIONS ~~~~~~~~~~~~~~~~~~~~~~~~

    def do_reset_history(self, line):
        """Reset CLI history"""
        while self.history:
            self.history.pop()

    def do_launch(self, line):
        """If Voltha is not running yet, launch it"""
        raise NotImplementedError('not implemented yet')

    def do_restart(self, line):
        """Launch Voltha, but if it is already running, terminate it first"""
        pass

    def do_adapters(self, line):
        """List loaded adapter"""
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.ListAdapters(Empty())
        omit_fields = {}
        print_pb_table('Adapters:', res.items, omit_fields, self.poutput)

    def get_devices(self):
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.ListDevices(Empty())
        return res.items

    def get_logical_devices(self):
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.ListLogicalDevices(Empty())
        return res.items

    def do_devices(self, line):
        """List devices registered in Voltha"""
        devices = self.get_devices()
        omit_fields = {
            'adapter',
            'vendor',
            'model',
            'hardware_version',
            'software_version',
            'firmware_version',
            'serial_number'
        }
        print_pb_table('Devices:', devices, omit_fields, self.poutput)

    def do_logical_devices(self, line):
        """List logical devices in Voltha"""
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.ListLogicalDevices(Empty())
        omit_fields = {
            'desc.mfr_desc',
            'desc.hw_desc',
            'desc.sw_desc',
            'desc.dp_desc',
            'desc.serial_number',
            'switch_features.capabilities'
        }
        print_pb_table('Logical devices:', res.items, omit_fields,
                       self.poutput)

    def do_device(self, line):
        """Enter device level command mode"""
        device_id = line.strip() or self.default_device_id
        if not device_id:
            raise Exception('<device-id> parameter needed')
        sub = DeviceCli(self.get_channel, device_id)
        sub.cmdloop()

    def do_logical_device(self, line):
        """Enter logical device level command mode"""
        logical_device_id = line.strip() or self.default_logical_device_id
        if not logical_device_id:
            raise Exception('<logical-device-id> parameter needed')
        sub = LogicalDeviceCli(self.get_channel, logical_device_id)
        sub.cmdloop()

    def device_ids(self, force_refresh=False):
        if force_refresh or self.device_ids is None or \
                (time() - self.device_ids_cache_ts) > 1:
            self.device_ids_cache = [d.id for d in self.get_devices()]
            self.device_ids_cache_ts = time()
        return self.device_ids_cache

    def logical_device_ids(self, force_refresh=False):
        if force_refresh or self.logical_device_ids is None or \
                (time() - self.logical_device_ids_cache_ts) > 1:
            self.logical_device_ids_cache = [d.id for d
                                             in self.get_logical_devices()]
            self.logical_device_ids_cache_ts = time()
        return self.logical_device_ids_cache

    def complete_device(self, text, line, begidx, endidx):
        if not text:
            completions = self.device_ids()[:]
        else:
            completions = [d for d in self.device_ids() if d.startswith(text)]
        return completions

    def complete_logical_device(self, text, line, begidx, endidx):
        if not text:
            completions = self.logical_device_ids()[:]
        else:
            completions = [d for d in self.logical_device_ids()
                           if d.startswith(text)]
        return completions

    def do_pdb(self, line):
        """Launch PDB debug prompt in CLI (for CLI development)"""
        from pdb import set_trace
        set_trace()

    def do_health(self, line):
        """Show connectivity status to Voltha status"""
        stub = voltha_pb2.HealthServiceStub(self.get_channel())
        res = stub.GetHealthStatus(Empty())
        self.poutput(dumps(pb2dict(res), indent=4))

    def do_test(self, line):
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
    def do_preprovision_olt(self, line, opts):
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
        self.poutput('success (device id = {})'.format(device.id))
        self.default_device_id = device.id

    def do_activate_olt(self, line):
        """
        Activate an OLT. If the <id> is not provided, it will be on the last
        pre-provisioned OLT.
        """
        device_id = line or self.default_device_id
        self.poutput('activating {}'.format(device_id))
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        stub.ActivateDevice(voltha_pb2.ID(id=device_id))

        # try to acquire logical device id
        while True:
            device = stub.GetDevice(voltha_pb2.ID(id=device_id))
            if device.oper_status == voltha_pb2.OperStatus.ACTIVE:
                assert device.parent_id
                self.default_logical_device_id = device.parent_id
                break
            self.poutput('waiting for device to be activated...')
            sleep(.5)
        self.poutput('success (logical device id = {})'.format(
            self.default_logical_device_id))

    complete_activate_olt = VolthaCli.complete_device

    def do_arrive_onus(self, line):
        """
        Simulate the arrival of ONUs
        """
        device_id = line or self.default_device_id
        requests.get('http://{}/devices/{}/detect_onus'.format(
            self.voltha_sim_rest, device_id
        ))

    complete_arrive_onus = VolthaCli.complete_device

    def do_install_eapol_flow(self, line):
        """
        Install an EAPOL flow on the given logical device. If device is not
        given, it will be applied to logical device of the last pre-provisioned
        OLT device.
        """
        logical_device_id = line or self.default_logical_device_id
        update = FlowTableUpdate(
            id=logical_device_id,
            flow_mod = mk_simple_flow_mod(
                priority=2000,
                match_fields=[in_port(241), eth_type(0x888e)],
                actions=[
                    push_vlan(0x8100),
                    set_field(vlan_vid(4096 + 4000)),
                    output(ofp.OFPP_CONTROLLER)
                ]
            )
        )
        stub = voltha_pb2.VolthaLocalServiceStub(self.get_channel())
        res = stub.UpdateLogicalDeviceFlowTable(update)
        self.poutput('success ({})'.format(res))

    complete_install_eapol_flow = VolthaCli.complete_logical_device

    def do_send_simulated_upstream_eapol(self, line):
        """
        Send an EAPOL upstream from a simulated OLT
        """
        device_id = line or self.default_device_id
        requests.get('http://{}/devices/{}/test_eapol_in'.format(
            self.voltha_sim_rest, device_id
        ))

    complete_send_simulated_upstream_eapol = VolthaCli.complete_device

    def do_inject_eapol_start(self, line):
        """
        Send out an an EAPOL start message into the given Unix interface
        """
        pass


if __name__ == '__main__':
    c = VolthaCli()
    c.poutput(banner)
    c.load_history()
    c.cmdloop()
    c.save_history()
