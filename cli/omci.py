#!/usr/bin/env python
#
# Copyright 2018 the original author or authors.
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
OpenOMCI level CLI commands
"""
from optparse import make_option
from cmd2 import Cmd, options
from datetime import datetime
from google.protobuf.empty_pb2 import Empty
from cli.table import print_pb_list_as_table
from voltha.protos import third_party
from voltha.protos import voltha_pb2
from voltha.protos.omci_mib_db_pb2 import MibDeviceData, MibClassData, \
    MibInstanceData
from os import linesep

_ = third_party


class OmciCli(Cmd):
    CREATED_KEY = 'created'
    MODIFIED_KEY = 'modified'
    MDS_KEY = 'mib_data_sync'
    LAST_SYNC_KEY = 'last_mib_sync'
    VERSION_KEY = 'version'
    DEVICE_ID_KEY = 'device_id'
    CLASS_ID_KEY = 'class_id'
    INSTANCE_ID_KEY = 'instance_id'
    ATTRIBUTES_KEY = 'attributes'
    TIME_FORMAT = '%Y%m%d-%H%M%S.%f'
    ME_KEY = 'managed_entities'
    MSG_TYPE_KEY = 'message_types'

    MSG_TYPE_TO_NAME = {
        4: 'Create',
        5: 'Create Complete',
        6: 'Delete',
        8: 'Set',
        9: 'Get',
        10: 'Get Complete',
        11: 'Get All Alarms',
        12: 'Get All Alarms Next',
        13: 'Mib Upload',
        14: 'Mib Upload Next',
        15: 'Mib Reset',
        16: 'Alarm Notification',
        17: 'Attribute Value Change',
        18: 'Test',
        19: 'Start Software Download',
        20: 'Download Section',
        21: 'End Software Download',
        22: 'Activate Software',
        23: 'Commit Software',
        24: 'Synchronize Time',
        25: 'Reboot',
        26: 'Get Next',
        27: 'Test Result',
        28: 'Get Current Data',
        29: 'Set Table'
    }

    def __init__(self, device_id, get_stub):
        Cmd.__init__(self)
        self.get_stub = get_stub
        self.device_id = device_id
        self.prompt = '(' + self.colorize(
            self.colorize('omci {}'.format(device_id), 'green'),
            'bold') + ') '

    def cmdloop(self, intro=None):
        self._cmdloop()

    do_exit = Cmd.do_quit

    def do_quit(self, line):
        return self._STOP_AND_EXIT

    def get_device_mib(self, device_id, depth=-1):
        stub = self.get_stub()

        try:
            res = stub.GetMibDeviceData(voltha_pb2.ID(id=device_id),
                                        metadata=(('get-depth', str(depth)), ))
        except Exception as e:
            pass

        return res

    def help_show_mib(self):
        self.poutput('show_mib [-d <device-id>] [-c <class-id> [-i <instance-id>]]' +
                     linesep + '-d: <device-id>   ONU Device ID' +
                     linesep + '-c: <class-id>    Managed Entity Class ID' +
                     linesep + '-i: <instance-id> ME Instance ID')

    @options([
        make_option('-d', '--device-id', action="store", dest='device_id', type='string',
                    help='ONU Device ID', default=None),
        make_option('-c', '--class-id', action="store", dest='class_id',
                    type='int', help='Managed Entity Class ID', default=None),
        make_option('-i', '--instance-id', action="store", dest='instance_id',
                    type='int', help='ME Instance ID', default=None)
    ])
    def do_show_mib(self, _line, opts):
        """
        Show OMCI MIB Database Information
        """
        device_id = opts.device_id or self.device_id

        if opts.class_id is not None and not 1 <= opts.class_id <= 0xFFFF:
            self.poutput(self.colorize('Error: ', 'red') +
                         self.colorize('Class ID must be 1..65535', 'blue'))
            return

        if opts.instance_id is not None and opts.class_id is None:
            self.poutput(self.colorize('Error: ', 'red') +
                         self.colorize('Class ID required if specifying an Instance ID',
                                       'blue'))
            return

        if opts.instance_id is not None and not 0 <= opts.instance_id <= 0xFFFF:
            self.poutput(self.colorize('Error: ', 'red') +
                         self.colorize('Instance ID must be 0..65535', 'blue'))
            return

        try:
            mib_db = self.get_device_mib(device_id, depth=-1)

        except Exception:   # UnboundLocalError if Device ID not found in DB
            self.poutput(self.colorize('Failed to get MIB database for ONU {}'
                                       .format(device_id), 'red'))
            return

        mib = self._device_to_dict(mib_db)

        self.poutput('OpenOMCI MIB Database for ONU {}'.format(device_id))

        if opts.class_id is None and opts.instance_id is None:
            self.poutput('Version            : {}'.format(mib[OmciCli.VERSION_KEY]))
            self.poutput('Created            : {}'.format(mib[OmciCli.CREATED_KEY]))
            self.poutput('Last In-Sync Time  : {}'.format(mib[OmciCli.LAST_SYNC_KEY]))
            self.poutput('MIB Data Sync Value: {}'.format(mib[OmciCli.MDS_KEY]))

        class_ids = [k for k in mib.iterkeys()
                     if isinstance(k, int) and
                     (opts.class_id is None or opts.class_id == k)]
        class_ids.sort()

        if len(class_ids) == 0 and opts.class_id is not None:
            self.poutput(self.colorize('Class ID {} not found in MIB Database'
                                       .format(opts.class_id), 'red'))
            return

        for cls_id in class_ids:
            class_data = mib[cls_id]
            self.poutput('  ----------------------------------------------')
            self.poutput('  Class ID     : {0} - ({0:#x}): {1}'.
                         format(cls_id, mib[OmciCli.ME_KEY].get(cls_id, 'Unknown')))
            inst_ids = [k for k in class_data.iterkeys()
                        if isinstance(k, int) and
                        (opts.instance_id is None or opts.instance_id == k)]
            inst_ids.sort()

            if len(inst_ids) == 0 and opts.instance_id is not None:
                self.poutput(self.colorize('Instance ID {} of Class ID {} not ' +
                                           'found in MIB Database'.
                                           format(opts.instance_id, opts.class_id),
                                           'red'))
                return

            for inst_id in inst_ids:
                inst_data = class_data[inst_id]
                self.poutput('    Instance ID: {0} - ({0:#x})'.format(inst_id))
                self.poutput('    Created    : {}'.format(inst_data[OmciCli.CREATED_KEY]))
                self.poutput('    Modified   : {}'.format(inst_data[OmciCli.MODIFIED_KEY]))

                attributes = inst_data[OmciCli.ATTRIBUTES_KEY]
                attr_names = attributes.keys()
                if len(attr_names):
                    attr_names.sort()
                    max_len = max([len(attr) for attr in attr_names])

                    for attr in attr_names:
                        name = self._cleanup_attribute_name(attr).ljust(max_len)
                        value = attributes[attr]
                        try:
                            ivalue = int(value)
                            self.poutput('      {0}: {1} - ({1:#x})'.format(name, ivalue))

                        except ValueError:
                            self.poutput('      {}: {}'.format(name, value))

                    if inst_id is not inst_ids[-1]:
                        self.poutput(linesep)

    def _cleanup_attribute_name(self, attr):
        """Change underscore to space and capitalize first character"""
        return ' '.join([v[0].upper() + v[1:] for v in attr.split('_')])

    def _instance_to_dict(self, instance):
        if not isinstance(instance, MibInstanceData):
            raise TypeError('{} is not of type MibInstanceData'.format(type(instance)))

        data = {
            OmciCli.INSTANCE_ID_KEY: instance.instance_id,
            OmciCli.CREATED_KEY: self._string_to_time(instance.created),
            OmciCli.MODIFIED_KEY: self._string_to_time(instance.modified),
            OmciCli.ATTRIBUTES_KEY: dict()
        }
        for attribute in instance.attributes:
            data[OmciCli.ATTRIBUTES_KEY][attribute.name] = str(attribute.value)

        return data

    def _class_to_dict(self, val):
        if not isinstance(val, MibClassData):
            raise TypeError('{} is not of type MibClassData'.format(type(val)))

        data = {
            OmciCli.CLASS_ID_KEY: val.class_id,
        }
        for instance in val.instances:
            data[instance.instance_id] = self._instance_to_dict(instance)
        return data

    def _device_to_dict(self, val):
        if not isinstance(val, MibDeviceData):
            raise TypeError('{} is not of type MibDeviceData'.format(type(val)))

        data = {
            OmciCli.DEVICE_ID_KEY: val.device_id,
            OmciCli.CREATED_KEY: self._string_to_time(val.created),
            OmciCli.LAST_SYNC_KEY: self._string_to_time(val.last_sync_time),
            OmciCli.MDS_KEY: val.mib_data_sync,
            OmciCli.VERSION_KEY: val.version,
            OmciCli.ME_KEY: dict(),
            OmciCli.MSG_TYPE_KEY: set()
        }
        for class_data in val.classes:
            data[class_data.class_id] = self._class_to_dict(class_data)

        for managed_entity in val.managed_entities:
            data[OmciCli.ME_KEY][managed_entity.class_id] = managed_entity.name

        for msg_type in val.message_types:
            data[OmciCli.MSG_TYPE_KEY].add(msg_type.message_type)

        return data

    def _string_to_time(self, time):
        return datetime.strptime(time, OmciCli.TIME_FORMAT) if len(time) else None

    def help_show_me(self):
        self.poutput('show_me [-d <device-id>]' +
                     linesep + '-d: <device-id>   ONU Device ID')

    @options([
        make_option('-d', '--device-id', action="store", dest='device_id', type='string',
                    help='ONU Device ID', default=None),
    ])
    def do_show_me(self, _line, opts):
        """ Show supported OMCI Managed Entities"""

        device_id = opts.device_id or self.device_id

        try:
            mib_db = self.get_device_mib(device_id, depth=1)
            mib = self._device_to_dict(mib_db)

        except Exception:   # UnboundLocalError if Device ID not found in DB
            self.poutput(self.colorize('Failed to get supported ME information for ONU {}'
                                       .format(device_id), 'red'))
            return

        class_ids = [class_id for class_id in mib[OmciCli.ME_KEY].keys()]
        class_ids.sort()

        self.poutput('Supported Managed Entities for ONU {}'.format(device_id))
        for class_id in class_ids:
            self.poutput('    {0} - ({0:#x}): {1}'.format(class_id,
                                                          mib[OmciCli.ME_KEY][class_id]))

    def help_show_msg_types(self):
        self.poutput('show_msg_types [-d <device-id>]' +
                     linesep + '-d: <device-id>   ONU Device ID')

    @options([
        make_option('-d', '--device-id', action="store", dest='device_id', type='string',
                    help='ONU Device ID', default=None),
    ])
    def do_show_msg_types(self, _line, opts):
        """ Show supported OMCI Message Types"""
        device_id = opts.device_id or self.device_id

        try:
            mib_db = self.get_device_mib(device_id, depth=1)
            mib = self._device_to_dict(mib_db)

        except Exception:   # UnboundLocalError if Device ID not found in DB
            self.poutput(self.colorize('Failed to get supported Message Types for ONU {}'
                                       .format(device_id), 'red'))
            return

        msg_types = [msg_type for msg_type in mib[OmciCli.MSG_TYPE_KEY]]
        msg_types.sort()

        self.poutput('Supported Message Types for ONU {}'.format(device_id))
        for msg_type in msg_types:
            self.poutput('    {0} - ({0:#x}): {1}'.
                         format(msg_type,
                                OmciCli.MSG_TYPE_TO_NAME.get(msg_type, 'Unknown')))

    def get_devices(self):
        stub = self.get_stub()
        res = stub.ListDevices(Empty())
        return res.items

    def do_devices(self, line):
        """List devices registered in Voltha reduced for OMCI menu"""
        devices = self.get_devices()
        omit_fields = {
            'adapter',
            'model',
            'hardware_version',
            'images',
            'firmware_version',
            'serial_number',
            'vlan',
            'root',
            'extra_args',
            'proxy_address',
        }
        print_pb_list_as_table('Devices:', devices, omit_fields, self.poutput)

    def help_devices(self):
        self.poutput('TODO: Provide some help')

    def poutput(self, msg):
        """Convenient shortcut for self.stdout.write(); adds newline if necessary."""
        if msg:
            self.stdout.write(msg)
            if msg[-1] != '\n':
                self.stdout.write('\n')
