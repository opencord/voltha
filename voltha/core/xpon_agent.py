# Copyright 2017 the original author or authors.
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

import structlog
import sys
import functools

from voltha.registry import registry
from voltha.core.config.config_proxy import CallbackType
from voltha.protos.bbf_fiber_base_pb2 import ChannelgroupConfig, \
    ChannelpartitionConfig, ChannelpairConfig, ChannelterminationConfig, \
    OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.protos.device_pb2 import Device
from voltha.protos.common_pb2 import AdminState

log = structlog.get_logger()

class XponAgent(object):

    interface_stack = {ChannelgroupConfig: {
                           'path': '/channel_groups/{}',
                               'path_keys': ['name'],
                           'parent': None, 'parent_path': None,
                               'parent_path_keys': [None],
                            'child': ChannelpartitionConfig,
                                'child_path': ['/channel_partitions'],
                            'olt_link': None, 'olt_link_path': None,
                                'olt_link_path_keys': [None],
                                'olt_device_id': 'from_child',
                            'onu_link': None, 'onu_link_path': None,
                                'onu_link_path_keys': [None],
                                'onu_device_id': 'na'},
                       ChannelpartitionConfig: {
                           'path': '/channel_partitions/{}',
                               'path_keys': ['name'],
                           'parent': ChannelgroupConfig,
                               'parent_path': '/channel_groups/{}',
                               'parent_path_keys': ['data.channelgroup_ref'],
                            'child': ChannelpairConfig,
                                'child_path': ['/channel_pairs'],
                            'olt_link': None, 'olt_link_path': None,
                                'olt_link_path_keys': [None],
                                'olt_device_id': 'from_child',
                            'onu_link': None, 'onu_link_path': None,
                                'onu_link_path_keys': [None],
                                'onu_device_id': 'na'},
                       ChannelpairConfig: {
                           'path': '/channel_pairs/{}', 'path_keys': ['name'],
                           'parent': ChannelpartitionConfig,
                               'parent_path': '/channel_partitions/{}',
                               'parent_path_keys':\
                                   ['data.channelpartition_ref'],
                            'child': ChannelterminationConfig,
                                'child_path':\
                                    ['/devices', 'channel_terminations'],
                            'olt_link': None, 'olt_link_path': None,
                                'olt_link_path_keys': [None],
                                'olt_device_id': 'from_child',
                            'onu_link': None,
                                'onu_link_path': None,
                                'onu_link_path_keys': [None],
                                'onu_device_id': 'na'},
                       ChannelterminationConfig: {
                           'path': '/devices/{}/channel_terminations/{}',
                               'path_keys': ['id', 'name'],
                           'parent': ChannelpairConfig,
                               'parent_path': '/channel_pairs/{}',
                               'parent_path_keys':\
                                   ['data.channelpair_ref'],
                            'child': None, 'child_path': [None],
                            'olt_link': None, 'olt_link_path': None,
                                'olt_link_path_keys': [None],
                                'olt_device_id': 'self',
                            'onu_link': None, 'onu_link_path': None,
                                'onu_link_path_keys': [None],
                                'onu_device_id': 'na'},
                       VOntaniConfig: {
                           'path': '/v_ont_anis/{}', 'path_keys': ['name'],
                           'parent': ChannelpartitionConfig,
                               'parent_path': '/channel_partitions/{}',
                               'parent_path_keys': ['data.parent_ref'],
                            'child': VEnetConfig, 'child_path': ['/v_enets'],
                            'olt_link': ChannelpairConfig,
                                'olt_link_path': '/channel_pairs/{}',
                                'olt_link_path_keys':\
                                    ['data.preferred_chanpair'],
                                'olt_device_id': 'from_link',
                            'onu_link': None, 'onu_link_path': None,
                                'onu_link_path_keys': [None],
                                'onu_device_id': 'self'},
                       OntaniConfig: {
                           'path': '/ont_anis/{}', 'path_keys': ['name'],
                           'parent': None, 'parent_path': None,
                               'parent_path_keys': [None],
                            'child': None, 'child_path': [None],
                            'olt_link': VOntaniConfig,
                                'olt_link_path': '/v_ont_anis/{}',
                                'olt_link_path_keys': ['name'],
                                'olt_device_id' : 'from_link',
                            'onu_link': VOntaniConfig,
                                'onu_link_path': '/v_ont_anis/{}',
                                'onu_link_path_keys': ['name'],
                                'onu_device_id': 'from_link'},
                       VEnetConfig: {
                           'path': '/v_enets/{}', 'path_keys': ['name'],
                           'parent': VOntaniConfig,
                               'parent_path': '/v_ont_anis/{}',
                               'parent_path_keys': ['data.v_ontani_ref'],
                            'child': None, 'child_path': [None],
                            'olt_link': None, 'olt_link_path': None,
                                'olt_link_path_keys': [None],
                                'olt_device_id': 'from_parent',
                            'onu_link': None, 'onu_link_path': None,
                                'onu_link_path_keys': [None],
                                'onu_device_id': 'from_parent'}
                      }

    def __init__(self, core):
        self.core = core
        self.preData = None
        self.inReplay = False
        return

    def get_device_adapter_agent(self, device):
        assert device.adapter != ''
        adapter_agent = registry('adapter_loader').get_agent(device.adapter)
        log.debug('get-device-adapter-agent', device=device,
                  adapter_agent=adapter_agent)
        return adapter_agent

    def get_interface_path(self, data):
        interface = self.interface_stack[type(data)]
        id_val = {}
        count = 0
        for key in interface['path_keys']:
            id_val[count] = getattr(data, key)
            count+=1
        path = interface['path'].format(*id_val.values())
        return path

    def _child_predicate(self, data, child):
        return self.get_parent_data(child).name == data.name

    def _get_child_data_by_path (self, data, path):
        children = self.core.get_proxy('/').get(path)
        return next((child for child in children
                     if self._child_predicate(data, child)), None)

    def get_device(self, data, device_type):
        if data is None:
            return None
        interface_node = self.interface_stack[type(data)]
        device = None
        if interface_node['{}_device_id'.format(device_type)] == 'self':
            if device_type == 'olt':
                device = self.core.get_proxy('/').get('/devices/{}'.
                                                      format(data.id))
                return device
            elif device_type == 'onu':
                devs = self.core.get_proxy('/').get('/devices')
                for dev in devs:
                    if dev.serial_number == data.data.expected_serial_number:
                        return dev
        if device is None:
            if interface_node['{}_device_id'.
                              format(device_type)] == 'from_parent':
                device = self.get_device(self.get_parent_data(data),
                                         device_type)
            elif interface_node['{}_device_id'.
                                format(device_type)] == 'from_child':
                device = self.get_device(self.get_child_data(data),
                                         device_type)
            elif interface_node['{}_device_id'.
                                format(device_type)] == 'from_link':
                device = self.get_device(self.get_link_data(data, device_type),
                                         device_type)
        return device

    def get_parent_data(self, data):
        if data is None:
            return None
        interface_node = self.interface_stack[type(data)]
        if interface_node['parent'] is None:
            return None
        id_val = {}
        count = 0
        for key in interface_node['parent_path_keys']:
            id_val[count] = self.rgetattr(data, key)
            count+=1
        parent_path = interface_node['parent_path'].format(*id_val.values())
        try:
            parent_data = self.core.get_proxy('/').get(parent_path)
            return parent_data
        except KeyError:
            log.info('xpon-agent-warning-interface-cannot-get-parent',
                     data=data)
            return None

    def get_child_data(self, data):
        interface_node = self.interface_stack[type(data)]
        if len(interface_node['child_path']) > 1:
            top_children = self.core.get_proxy('/').get('{}'.format(
                interface_node['child_path'][0]))
            for top_child in top_children:
                child = self._get_child_data_by_path(data, '{}/{}/{}'.format(
                    interface_node['child_path'][0], top_child.id,
                    interface_node['child_path'][1]))
                if child is not None:
                    return child
        else:
            child = self._get_child_data_by_path(data, '{}'.format(
                interface_node['child_path'][0]))
        if child is None:
            log.info('xpon-agent-warning-interface-cannot-get-child',
                     data=data)
        return child

    def get_link_data(self, data, device_type):
        interface_node = self.interface_stack[type(data)]
        if interface_node['{}_link'.format(device_type)] is None:
            return None
        id_val = {}
        count = 0
        for key in interface_node['{}_link_path_keys'.format(device_type)]:
            id_val[count] = self.rgetattr(data, key)
            count+=1
        link_path = interface_node['{}_link_path'.format(device_type)].format(
            *id_val.values())
        try:
            link_data = self.core.get_proxy('/').get(link_path)
            return link_data
        except KeyError:
            log.info('xpon-agent-warning-interface-cannot-get-{}-link-data'.
                     format(device_type), data=data)
            return None

    def rgetattr(self, obj, attr):
        def _getattr(obj, name):
            return getattr(obj, name)
        return functools.reduce(_getattr, [obj]+attr.split('.'))

    def is_valid_interface(self, data):
        valid = False
        for key in self.interface_stack.keys():
            valid |= isinstance(data, key)
        return valid

    def register_interface(self, device_id, path, update=True):
        log.info('register-interface:', device_id=device_id, path=path)
        try:
            interface_proxy = self.core.get_proxy(path)
            if update:
                interface_proxy.register_callback(CallbackType.POST_UPDATE,
                                                  self.update_interface,
                                                  device_id)
            else:
                interface_proxy.register_callback(CallbackType.POST_ADD,
                                                  self.create_interface,
                                                  device_id)
                interface_proxy.register_callback(CallbackType.POST_REMOVE,
                                                  self.remove_interface,
                                                  device_id)
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def unregister_interface(self, device_id, path, update=True):
        log.info('unregister-interface:', device_id=device_id, path=path)
        try:
            interface_proxy = self.core.get_proxy(path)
            if update:
                interface_proxy.unregister_callback(CallbackType.POST_UPDATE,
                                                    self.update_interface,
                                                    device_id)
            else:
                interface_proxy.unregister_callback(CallbackType.POST_ADD,
                                                    self.create_interface,
                                                    device_id)
                interface_proxy.unregister_callback(CallbackType.POST_REMOVE,
                                                    self.remove_interface,
                                                    device_id)
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def create_interface_in_device(self, device, data):
        adapter_agent = self.get_device_adapter_agent(device)
        adapter_agent.create_interface(device=device, data=data)

    def create_interface(self, data, device_id=None):
        if device_id is None:
            device = self.get_device(data, 'olt')
        else:
            device = self.core.get_proxy('/').get('/devices/{}'.
                                                  format(device_id))
        if not self.is_valid_interface(data):
            log.info('xpon-agent-create-interface-invalid-interface-type',
                     type=type(data).__name__)
            return
        self.register_interface(device_id=device_id,
                                path=self.get_interface_path(data))
        if device is not None:
            if(isinstance(data, ChannelterminationConfig)):
                self.create_channel_termination(device, data)
            elif(isinstance(data, VOntaniConfig)):
                self.create_onu_interfaces(device, data)
            else:
                log.info(
                    'xpon-agent-creating-interface-at-olt-device:',
                    device_id=device_id, data=data)
                self.create_interface_in_device(device, data)
                interface_node = self.interface_stack[type(data)]
                if interface_node['onu_device_id'] != 'na':
                    onu_device = self.get_device(data, 'onu')
                    log.info(
                        'xpon-agent-creating-interface-at-onu-device:',
                        onu_device_id=onu_device.id, data=data)
                    self.create_interface_in_device(onu_device, data)

    def update_interface(self, data, device_id):
        if not self.is_valid_interface(data):
            log.info('xpon-agent-update-interface-invalid-interface-type',
                     type=type(data).__name__)
            return
        if device_id is None:
            device_id = self.get_device(data, 'olt').id
        if device_id is not None:
            device = self.core.get_proxy('/').get('/devices/{}'.
                                                  format(device_id))
            adapter_agent = self.get_device_adapter_agent(device)
            interfaces = []
            ont_interfaces = []
            parent_data = self.get_parent_data(data)
            pre_parent_data = self.get_parent_data(self.preData)
            if parent_data is not None and pre_parent_data is None:
                while parent_data is not None:
                    interfaces.insert(0, parent_data)
                    parent_data = self.get_parent_data(parent_data)

                for interface in interfaces:
                    log.info('xpon-agent-creating-interface',
                             device_id=device_id, data=interface)
                    self.create_interface_in_device(device, interface)
                venet_items = self.core.get_proxy('/').get('/v_enets')
                for venet in venet_items:
                    if device_id == self.get_device(venet, 'olt').id:
                        ont_interfaces.insert(0, venet)
                        parent_data = self.get_parent_data(venet)
                        while not isinstance(parent_data, ChannelpairConfig):
                            ont_interfaces.insert(0, parent_data)
                            parent_data = self.get_parent_data(parent_data)
                        for ont_interface in ont_interfaces:
                            log.info('xpon-agent-creating-ont-interface',
                                     device_id=device_id, data=ont_interface)
                            self.create_interface_in_device(device,
                                                            ont_interface)
            log.info('xpon-agent-updating-interface',
                     device_id=device_id, data=data)
            adapter_agent.update_interface(device=device, data=data)

    def remove_interface(self, data, device_id=None):
        if device_id is None:
            device = self.get_device(data, 'olt')
        else:
            device = self.core.get_proxy('/').get('/devices/{}'.
                                                  format(device_id))
        if not self.is_valid_interface(data):
            log.info('xpon-agent-remove-interface-invalid-interface-type',
                     type=type(data).__name__)
            return
        if device is not None:
            log.info('xpon-agent-remove-interface:',
                     device_id=device.id, data=data)
            if(isinstance(data, ChannelterminationConfig)):
                self.remove_channel_termination(data, device_id)
            else:
                adapter_agent = self.get_device_adapter_agent(device)
                adapter_agent.remove_interface(device=device, data=data)
                if isinstance(data, VOntaniConfig):
                    self.delete_onu_device(device=device, v_ont_ani=data)

    def create_channel_termination(self, device, data):
        channel_pair = self.get_parent_data(data)
        channel_part = self.get_parent_data(channel_pair)
        channel_group = self.get_parent_data(channel_part)
        if channel_group is not None:
            log.info('xpon-agent-creating-channel-group',
                     device_id=device.id, channel_group=channel_group)
            self.create_interface_in_device(device, channel_group)
        if channel_part is not None:
            log.info('xpon-agent-creating-channel-partition:',
                     device_id=device.id, channel_part=channel_part)
            self.create_interface_in_device(device, channel_part)
        if channel_pair is not None:
            log.info('xpon-agent-creating-channel-pair:',
                     device_id=device.id, channel_pair=channel_pair)
            self.create_interface_in_device(device, channel_pair)
        log.info('xpon-agent-creating-channel-termination:',
                 device_id=device.id, data=data)
        self.create_interface_in_device(device, data)
        v_ont_anis = self.core.get_proxy('/').get('/v_ont_anis')
        for v_ont_ani in v_ont_anis:
            olt_device = self.get_device(v_ont_ani, 'olt')
            if olt_device.id == device.id:
                self.create_onu_interfaces(olt_device, v_ont_ani)

    def create_onu_interfaces(self, olt_device, data):
        if not self.inReplay:
            self.create_onu_device(device=olt_device, v_ont_ani=data)
        log.info(
            'xpon-agent-creating-v-ont-ani-at-olt-device:',
            olt_device_id=olt_device.id, v_ont_ani=data)
        self.create_interface_in_device(olt_device, data)
        onu_device = self.get_device(data, 'onu')
        log.info(
            'xpon-agent-creating-v-ont-ani-at-onu-device:',
            onu_device_id=onu_device.id, data=data)
        self.create_interface_in_device(onu_device, data)
        try:
            ont_ani = self.core.get_proxy('/').get('/ont_anis/{}'.
                                                   format(data.name))
            if ont_ani is not None:
                log.info(
                    'xpon-agent-creating-ont-ani-at-olt-device:',
                    olt_device_id=olt_device.id, ont_ani=ont_ani)
                self.create_interface_in_device(olt_device, ont_ani)
                log.info(
                    'xpon-agent-creating-ont-ani-at-onu-device:',
                    onu_device_id=onu_device.id, ont_ani=ont_ani)
                self.create_interface_in_device(onu_device, ont_ani)
            v_enets = self.core.get_proxy('/').get('/v_enets')
            for v_enet in v_enets:
                if self.get_parent_data(v_enet).name == data.name:
                    log.info(
                        'xpon-agent-creating-v-enet-at-olt-device:',
                        olt_device_id=olt_device.id, v_enet=v_enet)
                    self.create_interface_in_device(olt_device, v_enet)
                    log.info(
                        'xpon-agent-creating-v-enet-at-onu-device:',
                        onu_device_id=onu_device.id, v_enet=v_enet)
                    self.create_interface_in_device(onu_device, v_enet)
        except KeyError:
            log.info(
                'xpon-agent-create-onu-interfaces-no-ont-ani-link-exists')

    def remove_channel_termination(self, data, device_id):
        device = self.core.get_proxy('/').get('/devices/{}'.format(device_id))
        adapter_agent = self.get_device_adapter_agent(device)
        channel_pair = self.get_parent_data(data)
        if channel_pair is None:
            log.info(
                'xpon-agent-removing-channel-termination:',
                device_id=device_id, data=data)
            adapter_agent.remove_interface(device=device, data=data)
            return
        v_ont_anis = self.core.get_proxy('/').get('/v_ont_anis')
        for v_ont_ani in v_ont_anis:
            if self.get_link_data(v_ont_ani, 'olt').name == channel_pair.name:
                v_enets = self.core.get_proxy('/').get('/v_enets')
                for v_enet in v_enets:
                    if self.get_parent_data(v_enet).name == v_ont_ani.name:
                        log.info(
                            'xpon-agent-removing-v-enet:',
                            device_id=device_id, data=v_enet)
                        adapter_agent.remove_interface(device=device,
                                                       data=v_enet)
                try:
                    ont_ani = self.core.get_proxy('/').get(
                        '/ont_anis/{}'.format(v_ont_ani.name))
                    log.info(
                        'xpon-agent-removing-ont-ani:',
                        device_id=device_id, data=ont_ani)
                    adapter_agent.remove_interface(device=device, data=ont_ani)
                except KeyError:
                    log.info(
                    'xpon-agent-remove-channel-termination-ont-ani-not-found')
                log.info(
                    'xpon-agent-removing-vont-ani:',
                    device_id=device_id, data=v_ont_ani)
                adapter_agent.remove_interface(device=device, data=v_ont_ani)
                self.delete_onu_device(device=device, v_ont_ani=v_ont_ani)
        log.info(
            'xpon-agent-removing-channel-termination:',
            device_id=device_id, data=data)
        adapter_agent.remove_interface(device=device, data=data)
        log.info(
            'xpon-agent-removing-channel-pair:',
            device_id=device_id, data=channel_pair)
        adapter_agent.remove_interface(device=device, data=channel_pair)
        channel_partition = self.get_parent_data(channel_pair)
        if channel_partition is not None:
            log.info(
                'xpon-agent-removing-channel-partition:',
                device_id=device_id, data=channel_partition)
            adapter_agent.remove_interface(device=device,
                                           data=channel_partition)
        channel_group = self.get_parent_data(channel_partition)
        if channel_group is not None:
            log.info(
                'xpon-agent-removing-channel-group:',
                device_id=device_id, data=channel_group)
            adapter_agent.remove_interface(device=device, data=channel_group)

    def replay_interface(self, device_id):
        self.inReplay = True
        ct_items = self.core.get_proxy('/').get(
            '/devices/{}/channel_terminations'.format(device_id))
        for ct in ct_items:
            self.create_interface(data=ct, device_id=device_id)
        self.inReplay = False

    def get_port_num(self, device_id, label):
        log.info('get-port-num:', label=label, device_id=device_id)
        ports = self.core.get_proxy('/').get('/devices/{}/ports'.
                                             format(device_id))
        log.info('get-port-num:', label=label, device_id=device_id,
                 ports=ports)
        for port in ports:
            if port.label == label:
                return port.port_no
        return 0

    def create_onu_device(self, device, v_ont_ani):
        log.info('create-onu-device', device_id=device.id, v_ont_ani=v_ont_ani)
        adapter_agent = self.get_device_adapter_agent(device)
        parent_chnl_pair_id = self.get_port_num(
            device.id, v_ont_ani.data.preferred_chanpair)
        log.info('create-onu-device:', parent_chnl_pair_id=parent_chnl_pair_id)
        vendor_id = v_ont_ani.data.expected_serial_number[:4]
        proxy_address = Device.ProxyAddress(
            device_id=device.id, channel_id=parent_chnl_pair_id,
            onu_id=v_ont_ani.data.onu_id, onu_session_id=v_ont_ani.data.onu_id)
        adapter_agent.add_onu_device(
            parent_device_id=device.id, parent_port_no=parent_chnl_pair_id,
            vendor_id=vendor_id, proxy_address=proxy_address,
            root=True, serial_number=v_ont_ani.data.expected_serial_number,
            admin_state=AdminState.ENABLED if v_ont_ani.interface.enabled
                                           else AdminState.DISABLED)
        return

    def delete_onu_device(self, device, v_ont_ani):
        log.info('delete-onu-device', device_id=device.id, v_ont_ani=v_ont_ani)
        adapter_agent = self.get_device_adapter_agent(device)
        onu_device = adapter_agent.get_child_device(
            parent_device_id=device.id,
            serial_number=v_ont_ani.data.expected_serial_number)
        if onu_device is not None:
            adapter_agent.delete_child_device(device.id, onu_device.id)
        return
