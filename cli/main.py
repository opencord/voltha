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
import argparse
import os
import readline
import sys
from optparse import make_option
from time import sleep, time

import etcd3
import grpc
import requests
from cmd2 import Cmd, options
from consul import Consul
from google.protobuf.empty_pb2 import Empty
from simplejson import dumps

from cli.device import DeviceCli
from cli.xpon import XponCli
from cli.omci import OmciCli
from cli.alarm_filters import AlarmFiltersCli
from cli.logical_device import LogicalDeviceCli
from cli.table import print_pb_list_as_table
from voltha.protos import third_party
from voltha.protos import voltha_pb2, voltha_pb2_grpc, health_pb2_grpc
from voltha.protos.openflow_13_pb2 import FlowTableUpdate, FlowGroupTableUpdate

_ = third_party
from cli.utils import pb2dict

defs = dict(
    # config=os.environ.get('CONFIG', './cli.yml'),
    etcd=os.environ.get('ETCD', 'etcd-cluster.default.svc.cluster.local:2379'),
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    voltha_grpc_endpoint=os.environ.get('VOLTHA_GRPC_ENDPOINT',
                                        'localhost:50055'),
    voltha_sim_rest_endpoint=os.environ.get('VOLTHA_SIM_REST_ENDPOINT',
                                            'localhost:18880'),
    global_request=os.environ.get('GLOBAL_REQUEST', False)
)

banner = """\
         _ _   _            ___ _    ___
__ _____| | |_| |_  __ _   / __| |  |_ _|
\ V / _ \ |  _| ' \/ _` | | (__| |__ | |
 \_/\___/_|\__|_||_\__,_|  \___|____|___|
(to exit type quit or exit or hit Ctrl-D)
"""


class VolthaCli(Cmd):
    prompt = 'voltha'
    history_file_name = '.voltha_cli_history'

    # Settable CLI parameters
    voltha_grpc = 'localhost:50055'
    voltha_sim_rest = 'localhost:18880'
    global_request = False
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

    # cleanup of superfluous commands from cmd2
    del Cmd.do_cmdenvironment
    del Cmd.do_load
    del Cmd.do__relative_load

    def __init__(self, voltha_grpc, voltha_sim_rest, etcd, global_request=False):
        VolthaCli.voltha_grpc = voltha_grpc
        VolthaCli.voltha_sim_rest = voltha_sim_rest
        VolthaCli.global_request = global_request
        VolthaCli.etcd = etcd
        Cmd.__init__(self)
        self.prompt = '(' + self.colorize(
            self.colorize(self.prompt, 'blue'), 'bold') + ') '
        self.channel = None
        self.stub = None
        self.device_ids_cache = None
        self.device_ids_cache_ts = time()
        self.logical_device_ids_cache = None
        self.logical_device_ids_cache_ts = time()

    # we override cmd2's method to avoid its optparse conflicting with our
    # command line parsing
    def cmdloop(self):
        self._cmdloop()

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
            self.poutput('History saved as {}'.format(
                self.history_file_name))

    def perror(self, errmsg, statement=None):
        # Touch it up to make sure error is prefixed and colored
        Cmd.perror(self, self.colorize('***ERROR: ', 'red') + errmsg,
                   statement)

    def get_channel(self):
        if self.channel is None:
            self.channel = grpc.insecure_channel(self.voltha_grpc)
        return self.channel

    def get_stub(self):
        if self.stub is None:
            self.stub = \
                voltha_pb2_grpc.VolthaGlobalServiceStub(self.get_channel()) \
                    if self.global_request else \
                        voltha_pb2_grpc.VolthaLocalServiceStub(self.get_channel())
        return self.stub

    # ~~~~~~~~~~~~~~~~~ ACTUAL COMMAND IMPLEMENTATIONS ~~~~~~~~~~~~~~~~~~~~~~~~

    def do_reset_history(self, line):
        """Reset CLI history"""
        while self.history:
            self.history.pop()

    def do_exit(self,line):
        """exit from CLI"""
        quit()

    def do_launch(self, line):
        """If Voltha is not running yet, launch it"""
        raise NotImplementedError('not implemented yet')

    def do_restart(self, line):
        """Launch Voltha, but if it is already running, terminate it first"""
        pass

    def do_adapters(self, line):
        """List loaded adapter"""
        stub = self.get_stub()
        res = stub.ListAdapters(Empty())
        omit_fields = {'config.log_level', 'logical_device_ids'}
        print_pb_list_as_table('Adapters:', res.items, omit_fields, self.poutput)

    def get_devices(self):
        stub = self.get_stub()
        res = stub.ListDevices(Empty())
        return res.items

    def get_logical_devices(self):
        stub = self.get_stub()
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
            'images',
            'firmware_version',
            'vendor_id'
        }
        print_pb_list_as_table('Devices:', devices, omit_fields, self.poutput)

    def do_logical_devices(self, line):
        """List logical devices in Voltha"""
        stub = self.get_stub()
        res = stub.ListLogicalDevices(Empty())
        omit_fields = {
            'desc.mfr_desc',
            'desc.hw_desc',
            'desc.sw_desc',
            'desc.dp_desc',
            'desc.serial_number',
            'switch_features.capabilities'
        }
        presfns = {
            'datapath_id': lambda x: "{0:0{1}x}".format(int(x), 16)
        }
        print_pb_list_as_table('Logical devices:', res.items, omit_fields,
                               self.poutput, presfns=presfns)

    def do_device(self, line):
        """Enter device level command mode"""
        device_id = line.strip() or self.default_device_id
        if not device_id:
            raise Exception('<device-id> parameter needed')
        if device_id not in self.device_ids():
            self.poutput( self.colorize('Error: ', 'red') +
                            'There is no such device')
            raise Exception('<device-id> is not a valid one')
        sub = DeviceCli(device_id, self.get_stub, self.etcd)
        sub.cmdloop()

    def do_logical_device(self, line):
        """Enter logical device level command mode"""
        logical_device_id = line.strip() or self.default_logical_device_id
        if not logical_device_id:
            raise Exception('<logical-device-id> parameter needed')
        if logical_device_id not in self.logical_device_ids():
            self.poutput( self.colorize('Error: ', 'red') +
                            'There is no such device')
            raise Exception('<logical-device-id> is not a valid one')
        sub = LogicalDeviceCli(logical_device_id, self.get_stub)
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

    def do_xpon(self, line):
        """xpon <optional> [device_ID] - Enter xpon level command mode"""
        device_id = line.strip()
        if device_id:
            stub = self.get_stub()
            try:
                res = stub.GetDevice(voltha_pb2.ID(id=device_id))
            except Exception:
                self.poutput(
                    self.colorize('Error: ', 'red') + 'No device id ' +
                    self.colorize(device_id, 'blue') + ' is found')
                return
        sub = XponCli(self.get_channel, device_id)
        sub.cmdloop()

    def do_omci(self, line):
        """omci <device_ID> - Enter OMCI level command mode"""

        device_id = line.strip() or self.default_device_id
        if not device_id:
            raise Exception('<device-id> parameter needed')
        sub = OmciCli(device_id, self.get_stub)
        sub.cmdloop()

    def do_pdb(self, line):
        """Launch PDB debug prompt in CLI (for CLI development)"""
        from pdb import set_trace
        set_trace()

    def do_version(self, line):
        """Show the VOLTHA core version"""
        stub = self.get_stub()
        voltha = stub.GetVoltha(Empty())
        self.poutput('{}'.format(voltha.version))

    def do_health(self, line):
        """Show connectivity status to Voltha status"""
        stub = health_pb2_grpc.HealthServiceStub(self.get_channel())
        res = stub.GetHealthStatus(Empty())
        self.poutput(dumps(pb2dict(res), indent=4))

    @options([
        make_option('-t', '--device-type', action="store", dest='device_type',
                    help="Device type", default='simulated_olt'),
        make_option('-m', '--mac-address', action='store', dest='mac_address',
                    default='00:0c:e2:31:40:00'),
        make_option('-i', '--ip-address', action='store', dest='ip_address'),
        make_option('-H', '--host_and_port', action='store',
                    dest='host_and_port'),
    ])
    def do_preprovision_olt(self, line, opts):
        """Preprovision a new OLT with given device type"""
        stub = self.get_stub()
        kw = dict(type=opts.device_type)
        if opts.host_and_port:
            kw['host_and_port'] = opts.host_and_port
        elif opts.ip_address:
            kw['ipv4_address'] = opts.ip_address
        elif opts.mac_address:
            kw['mac_address'] = opts.mac_address.lower()
        else:
            raise Exception('Either IP address or Mac Address is needed')
        # Pass any extra arguments past '--' to the device as custom arguments
        kw['extra_args'] = line

        device = voltha_pb2.Device(**kw)
        device = stub.CreateDevice(device)
        self.poutput('success (device id = {})'.format(device.id))
        self.default_device_id = device.id

    def do_enable(self, line):
        """
        Enable a device. If the <id> is not provided, it will be on the last
        pre-provisioned device.
        """
        device_id = line or self.default_device_id
        if device_id not in self.device_ids():
            self.poutput('Error: There is no such preprovisioned device')
            return

        try:
            stub = self.get_stub()
            device = stub.GetDevice(voltha_pb2.ID(id=device_id))
            if device.admin_state == voltha_pb2.AdminState.ENABLED:
                if device.oper_status != voltha_pb2.OperStatus.ACTIVATING:
                    self.poutput('Error: Device is already enabled')
                    return
            else:
                stub.EnableDevice(voltha_pb2.ID(id=device_id))
                self.poutput('enabling {}'.format(device_id))

            while True:
                device = stub.GetDevice(voltha_pb2.ID(id=device_id))
                # If this is an OLT then acquire logical device id
                if device.oper_status == voltha_pb2.OperStatus.ACTIVE:
                    if device.type.endswith('_olt'):
                        assert device.parent_id
                        self.default_logical_device_id = device.parent_id
                        self.poutput('success (logical device id = {})'.format(
                            self.default_logical_device_id))
                    else:
                        self.poutput('success (device id = {})'.format(device.id))
                    break
                self.poutput('waiting for device to be enabled...')
                sleep(.5)
        except Exception as e:
            self.poutput('Error enabling {}.  Error:{}'.format(device_id, e))

    complete_activate_olt = complete_device

    def do_reboot(self, line):
        """
        Rebooting a device. ID of the device needs to be provided
        """
        device_id = line or self.default_device_id
        self.poutput('rebooting {}'.format(device_id))
        try:
            stub = self.get_stub()
            stub.RebootDevice(voltha_pb2.ID(id=device_id))
            self.poutput('rebooted {}'.format(device_id))
        except Exception as e:
            self.poutput('Error rebooting {}.  Error:{}'.format(device_id, e))

    def do_self_test(self, line):
        """
        Self Test a device. ID of the device needs to be provided
        """
        device_id = line or self.default_device_id
        self.poutput('Self Testing {}'.format(device_id))
        try:
            stub = self.get_stub()
            res = stub.SelfTest(voltha_pb2.ID(id=device_id))
            self.poutput('Self Tested {}'.format(device_id))
            self.poutput(dumps(pb2dict(res), indent=4))
        except Exception as e:
            self.poutput('Error in self test {}.  Error:{}'.format(device_id, e))

    def do_delete(self, line):
        """
        Deleting a device. ID of the device needs to be provided
        """
        device_id = line or self.default_device_id
        self.poutput('deleting {}'.format(device_id))
        try:
            stub = self.get_stub()
            stub.DeleteDevice(voltha_pb2.ID(id=device_id))
            self.poutput('deleted {}'.format(device_id))
        except Exception as e:
            self.poutput('Error deleting {}.  Error:{}'.format(device_id, e))

    def do_disable(self, line):
        """
        Disable a device. ID of the device needs to be provided
        """
        device_id = line
        if device_id not in self.device_ids():
            self.poutput('Error: There is no such device')
            return
        try:
            stub = self.get_stub()
            device = stub.GetDevice(voltha_pb2.ID(id=device_id))
            if device.admin_state == voltha_pb2.AdminState.DISABLED:
                self.poutput('Error: Device is already disabled')
                return
            stub.DisableDevice(voltha_pb2.ID(id=device_id))
            self.poutput('disabling {}'.format(device_id))

            # Do device query and verify that the device admin status is
            # DISABLED and Operational Status is unknown
            device = stub.GetDevice(voltha_pb2.ID(id=device_id))
            if device.admin_state == voltha_pb2.AdminState.DISABLED:
                self.poutput('disabled successfully {}'.format(device_id))
            else:
                self.poutput('disabling failed {}.  Admin State:{} '
                             'Operation State: {}'.format(device_id,
                                                          device.admin_state,
                                                          device.oper_status))
        except Exception as e:
            self.poutput('Error disabling {}.  Error:{}'.format(device_id, e))

    def do_test(self, line):
        """Enter test mode, which makes a bunch on new commands available"""
        sub = TestCli(self.history, self.voltha_grpc,
                      self.get_stub, self.voltha_sim_rest)
        sub.cmdloop()

    def do_alarm_filters(self, line):
        sub = AlarmFiltersCli(self.get_stub)
        sub.cmdloop()


class TestCli(VolthaCli):
    def __init__(self, history, voltha_grpc, get_stub, voltha_sim_rest):
        VolthaCli.__init__(self, voltha_grpc, voltha_sim_rest)
        self.history = history
        self.get_stub = get_stub
        self.prompt = '(' + self.colorize(self.colorize('test', 'cyan'),
                                          'bold') + ') '

    def get_device(self, device_id, depth=0):
        stub = self.get_stub()
        res = stub.GetDevice(voltha_pb2.ID(id=device_id),
                             metadata=(('get-depth', str(depth)),))
        return res

    def do_arrive_onus(self, line):
        """
        Simulate the arrival of ONUs (available only on simulated_olt)
        """
        device_id = line or self.default_device_id

        # verify that device is of type simulated_olt
        device = self.get_device(device_id)
        assert device.type == 'simulated_olt', (
            'Cannot use it on this device type (only on simulated_olt type)')

        requests.get('http://{}/devices/{}/detect_onus'.format(
            self.voltha_sim_rest, device_id
        ))

    complete_arrive_onus = VolthaCli.complete_device

    def get_logical_ports(self, logical_device_id):
        """
        Return the NNI port number and the first usable UNI port of logical
        device, and the vlan associated with the latter.
        """
        stub = self.get_stub()
        ports = stub.ListLogicalDevicePorts(
            voltha_pb2.ID(id=logical_device_id)).items
        nni = None
        unis = []
        for port in ports:
            if port.root_port:
                assert nni is None, "There shall be only one root port"
                nni = port.ofp_port.port_no
            else:
                uni = port.ofp_port.port_no
                uni_device = self.get_device(port.device_id)
                vlan = uni_device.vlan
                unis.append((uni, vlan))

        assert nni is not None, "No NNI port found"
        assert unis, "Not a single UNI?"

        return nni, unis

    def do_install_eapol_flow(self, line):
        """
        Install an EAPOL flow on the given logical device. If device is not
        given, it will be applied to logical device of the last pre-provisioned
        OLT device.
        """
        logical_device_id = line or self.default_logical_device_id

        # gather NNI and UNI port IDs
        nni_port_no, unis = self.get_logical_ports(logical_device_id)

        # construct and push flow rule
        stub = self.get_stub()
        for uni_port_no, _ in unis:
            update = FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=2000,
                    match_fields=[in_port(uni_port_no), eth_type(0x888e)],
                    actions=[
                        # push_vlan(0x8100),
                        # set_field(vlan_vid(4096 + 4000)),
                        output(ofp.OFPP_CONTROLLER)
                    ]
                )
            )
            res = stub.UpdateLogicalDeviceFlowTable(update)
            self.poutput('success for uni {} ({})'.format(uni_port_no, res))

    complete_install_eapol_flow = VolthaCli.complete_logical_device

    def do_install_all_controller_bound_flows(self, line):
        """
        Install all flow rules for controller bound flows, including EAPOL,
        IGMP and DHCP. If device is not given, it will be applied to logical
        device of the last pre-provisioned OLT device.
        """
        logical_device_id = line or self.default_logical_device_id

        # gather NNI and UNI port IDs
        nni_port_no, unis = self.get_logical_ports(logical_device_id)

        # construct and push flow rules
        stub = self.get_stub()

        for uni_port_no, _ in unis:
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=2000,
                    match_fields=[
                        in_port(uni_port_no),
                        eth_type(0x888e)
                    ],
                    actions=[output(ofp.OFPP_CONTROLLER)]
                )
            ))
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=1000,
                    match_fields=[
                        in_port(uni_port_no),
                        eth_type(0x800),
                        ip_proto(2)
                    ],
                    actions=[output(ofp.OFPP_CONTROLLER)]
                )
            ))
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=1000,
                    match_fields=[
                        in_port(uni_port_no),
                        eth_type(0x800),
                        ip_proto(17),
                        udp_dst(67)
                    ],
                    actions=[output(ofp.OFPP_CONTROLLER)]
                )
            ))
        self.poutput('success')

    complete_install_all_controller_bound_flows = \
        VolthaCli.complete_logical_device

    def do_install_all_sample_flows(self, line):
        """
        Install all flows that are representative of the virtualized access
        scenario in a PON network.
        """
        logical_device_id = line or self.default_logical_device_id

        # gather NNI and UNI port IDs
        nni_port_no, unis = self.get_logical_ports(logical_device_id)

        # construct and push flow rules
        stub = self.get_stub()

        for uni_port_no, c_vid in unis:
            # Controller-bound flows
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=2000,
                    match_fields=[in_port(uni_port_no), eth_type(0x888e)],
                    actions=[
                        # push_vlan(0x8100),
                        # set_field(vlan_vid(4096 + 4000)),
                        output(ofp.OFPP_CONTROLLER)
                    ]
                )
            ))
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=1000,
                    match_fields=[eth_type(0x800), ip_proto(2)],
                    actions=[output(ofp.OFPP_CONTROLLER)]
                )
            ))
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=1000,
                    match_fields=[eth_type(0x800), ip_proto(17), udp_dst(67)],
                    actions=[output(ofp.OFPP_CONTROLLER)]
                )
            ))

            # Unicast flows:
            # Downstream flow 1
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=500,
                    match_fields=[
                        in_port(nni_port_no),
                        vlan_vid(4096 + 1000),
                        metadata(c_vid)  # here to mimic an ONOS artifact
                    ],
                    actions=[pop_vlan()],
                    next_table_id=1
                )
            ))
            # Downstream flow 2
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=500,
                    table_id=1,
                    match_fields=[in_port(nni_port_no), vlan_vid(4096 + c_vid)],
                    actions=[set_field(vlan_vid(4096 + 0)), output(uni_port_no)]
                )
            ))
            # Upstream flow 1 for 0-tagged case
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=500,
                    match_fields=[in_port(uni_port_no), vlan_vid(4096 + 0)],
                    actions=[set_field(vlan_vid(4096 + c_vid))],
                    next_table_id=1
                )
            ))
            # Upstream flow 1 for untagged case
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=500,
                    match_fields=[in_port(uni_port_no), vlan_vid(0)],
                    actions=[push_vlan(0x8100), set_field(vlan_vid(4096 + c_vid))],
                    next_table_id=1
                )
            ))
            # Upstream flow 2 for s-tag
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=500,
                    table_id=1,
                    match_fields=[in_port(uni_port_no), vlan_vid(4096 + c_vid)],
                    actions=[
                        push_vlan(0x8100),
                        set_field(vlan_vid(4096 + 1000)),
                        output(nni_port_no)
                    ]
                )
            ))

        # Push a few multicast flows
        # 1st with one bucket for our uni 0
        stub.UpdateLogicalDeviceFlowGroupTable(FlowGroupTableUpdate(
            id=logical_device_id,
            group_mod=mk_multicast_group_mod(
                group_id=1,
                buckets=[
                    ofp.ofp_bucket(actions=[
                        pop_vlan(),
                        output(unis[0][0])
                    ])
                ]
            )
        ))
        stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
            id=logical_device_id,
            flow_mod=mk_simple_flow_mod(
                priority=1000,
                match_fields=[
                    in_port(nni_port_no),
                    eth_type(0x800),
                    vlan_vid(4096 + 140),
                    ipv4_dst(0xe4010101)
                ],
                actions=[group(1)]
            )
        ))

        # 2nd with one bucket for uni 0 and 1
        stub.UpdateLogicalDeviceFlowGroupTable(FlowGroupTableUpdate(
            id=logical_device_id,
            group_mod=mk_multicast_group_mod(
                group_id=2,
                buckets=[
                    ofp.ofp_bucket(actions=[pop_vlan(), output(unis[0][0])])
                    #                    ofp.ofp_bucket(actions=[pop_vlan(), output(unis[1][0])])
                ]
            )
        ))
        stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
            id=logical_device_id,
            flow_mod=mk_simple_flow_mod(
                priority=1000,
                match_fields=[
                    in_port(nni_port_no),
                    eth_type(0x800),
                    vlan_vid(4096 + 140),
                    ipv4_dst(0xe4020202)
                ],
                actions=[group(2)]
            )
        ))

        # 3rd with empty bucket
        stub.UpdateLogicalDeviceFlowGroupTable(FlowGroupTableUpdate(
            id=logical_device_id,
            group_mod=mk_multicast_group_mod(
                group_id=3,
                buckets=[]
            )
        ))
        stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
            id=logical_device_id,
            flow_mod=mk_simple_flow_mod(
                priority=1000,
                match_fields=[
                    in_port(nni_port_no),
                    eth_type(0x800),
                    vlan_vid(4096 + 140),
                    ipv4_dst(0xe4030303)
                ],
                actions=[group(3)]
            )
        ))

        self.poutput('success')

    complete_install_all_sample_flows = VolthaCli.complete_logical_device

    def do_install_dhcp_flows(self, line):
        """
        Install all dhcp flows that are representative of the virtualized access
        scenario in a PON network.
        """
        logical_device_id = line or self.default_logical_device_id

        # gather NNI and UNI port IDs
        nni_port_no, unis = self.get_logical_ports(logical_device_id)

        # construct and push flow rules
        stub = self.get_stub()

        # Controller-bound flows
        for uni_port_no, _ in unis:
            stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=1000,
                    match_fields=[
                        in_port(uni_port_no),
                        eth_type(0x800),
                        ip_proto(17),
                        udp_dst(67)
                    ],
                    actions=[output(ofp.OFPP_CONTROLLER)]
                )
            ))

        self.poutput('success')

    complete_install_dhcp_flows = VolthaCli.complete_logical_device

    def do_delete_all_flows(self, line):
        """
        Remove all flows and flow groups from given logical device
        """
        logical_device_id = line or self.default_logical_device_id
        stub = self.get_stub()
        stub.UpdateLogicalDeviceFlowTable(FlowTableUpdate(
            id=logical_device_id,
            flow_mod=ofp.ofp_flow_mod(
                command=ofp.OFPFC_DELETE,
                table_id=ofp.OFPTT_ALL,
                cookie_mask=0,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY
            )
        ))
        stub.UpdateLogicalDeviceFlowGroupTable(FlowGroupTableUpdate(
            id=logical_device_id,
            group_mod=ofp.ofp_group_mod(
                command=ofp.OFPGC_DELETE,
                group_id=ofp.OFPG_ALL
            )
        ))
        self.poutput('success')

    complete_delete_all_flows = VolthaCli.complete_logical_device

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

    parser = argparse.ArgumentParser()

    _help = '<hostname>:<port> to consul agent (default: %s)' % defs['consul']
    parser.add_argument(
        '-C', '--consul', action='store', default=defs['consul'], help=_help)

    _help = '<hostname>:<port> to etcd container (default: %s)' % defs['etcd']
    parser.add_argument(
        '-E', '--etcd', action='store', default=defs['etcd'], help=_help)

    _help = 'Lookup Voltha endpoints based on service entries in Consul'
    parser.add_argument(
        '-L', '--lookup', action='store_true', help=_help)

    _help = 'All requests to the Voltha gRPC service are global'
    parser.add_argument(
        '-G', '--global_request', action='store_true', help=_help)

    _help = '<hostname>:<port> of Voltha gRPC service (default={})'.format(
        defs['voltha_grpc_endpoint'])
    parser.add_argument('-g', '--grpc-endpoint', action='store',
                        default=defs['voltha_grpc_endpoint'], help=_help)

    _help = '<hostname>:<port> of Voltha simulated adapter backend for ' \
            'testing (default={})'.format(
        defs['voltha_sim_rest_endpoint'])
    parser.add_argument('-s', '--sim-rest-endpoint', action='store',
                        default=defs['voltha_sim_rest_endpoint'], help=_help)

    args = parser.parse_args()

    if args.lookup:
        host = args.consul.split(':')[0].strip()
        port = int(args.consul.split(':')[1].strip())
        consul = Consul(host=host, port=port)

        _, services = consul.catalog.service('voltha-grpc')
        if not services:
            print('No voltha-grpc service registered in consul; exiting')
            sys.exit(1)
        args.grpc_endpoint = '{}:{}'.format(services[0]['ServiceAddress'],
                                            services[0]['ServicePort'])

        _, services = consul.catalog.service('voltha-sim-rest')
        if not services:
            print('No voltha-sim-rest service registered in consul; exiting')
            sys.exit(1)
        args.sim_rest_endpoint = '{}:{}'.format(services[0]['ServiceAddress'],
                                                services[0]['ServicePort'])

    host = args.etcd.split(':')[0].strip()
    port = int(args.etcd.split(':')[1].strip())
    etcd = etcd3.client(host=host, port=port)
    c = VolthaCli(args.grpc_endpoint, args.sim_rest_endpoint, etcd,
                  args.global_request)
    c.poutput(banner)
    c.load_history()
    c.cmdloop()
    c.save_history()
