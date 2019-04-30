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
    OntaniConfig, VOntaniConfig, VEnetConfig, \
    AllTrafficDescriptorProfileData, AllTcontsConfigData, AllGemportsConfigData
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData

from voltha.protos.device_pb2 import Device
from voltha.protos.common_pb2 import AdminState

log = structlog.get_logger()

class XponAgent(object):

    interface_stack = {
        ChannelgroupConfig: {
            'path': '/channel_groups/{}', 'path_keys': ['name'],
            'parent': None, 'parent_path': None, 'parent_path_keys': [None],
            'child': {
                1: {'config': ChannelpartitionConfig,
                    'child_path': ['/channel_partitions']}},
            'olt_link': None, 'olt_link_path': None,
                'olt_link_path_keys': [None], 'olt_device_id': 'from_child',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'na'},
        ChannelpartitionConfig: {
            'path': '/channel_partitions/{}', 'path_keys': ['name'],
            'parent': ChannelgroupConfig, 'parent_path': '/channel_groups/{}',
                'parent_path_keys': ['data.channelgroup_ref'],
            'child': {
                1: {'config': ChannelpairConfig,
                    'child_path': ['/channel_pairs']}},
            'olt_link': None, 'olt_link_path': None,
                'olt_link_path_keys': [None], 'olt_device_id': 'from_child',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'na'},
        ChannelpairConfig: {
            'path': '/channel_pairs/{}', 'path_keys': ['name'],
            'parent': ChannelpartitionConfig,
                'parent_path': '/channel_partitions/{}',
                'parent_path_keys': ['data.channelpartition_ref'],
            'child': {
                1: {'config': ChannelterminationConfig,
                    'child_path': ['/devices', 'channel_terminations']}},
            'olt_link': None, 'olt_link_path': None,
                'olt_link_path_keys': [None], 'olt_device_id': 'from_child',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'na'},
        ChannelterminationConfig: {
            'path': '/devices/{}/channel_terminations/{}',
                'path_keys': ['id', 'name'],
            'parent': ChannelpairConfig, 'parent_path': '/channel_pairs/{}',
                'parent_path_keys': ['data.channelpair_ref'],
            'child': None, 'child_path': [None],
            'olt_link': None, 'olt_link_path': None,
                'olt_link_path_keys': [None], 'olt_device_id': 'self',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'na'},
        VOntaniConfig: {
            'path': '/v_ont_anis/{}', 'path_keys': ['name'],
            'parent': ChannelpartitionConfig,
                'parent_path': '/channel_partitions/{}',
                'parent_path_keys': ['data.parent_ref'],
            'child': {
                1: {'config': VEnetConfig, 'child_path': ['/v_enets']},
                2: {'config': TcontsConfigData, 'child_path': ['/tconts']}},
            'olt_link': ChannelpairConfig,
                'olt_link_path': '/channel_pairs/{}',
                'olt_link_path_keys': ['data.preferred_chanpair'],
                'olt_device_id': 'from_link',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'self'},
        OntaniConfig: {
            'path': '/ont_anis/{}', 'path_keys': ['name'],
            'parent': None, 'parent_path': None, 'parent_path_keys': [None],
            'child': None, 'child_path': [None],
            'olt_link': VOntaniConfig, 'olt_link_path': '/v_ont_anis/{}',
                'olt_link_path_keys': ['name'], 'olt_device_id' : 'from_link',
            'onu_link': VOntaniConfig, 'onu_link_path': '/v_ont_anis/{}',
                'onu_link_path_keys': ['name'], 'onu_device_id': 'from_link'},
        VEnetConfig: {
            'path': '/v_enets/{}', 'path_keys': ['name'],
            'parent': VOntaniConfig, 'parent_path': '/v_ont_anis/{}',
                'parent_path_keys': ['data.v_ontani_ref'],
            'child': {
                1: {'config': GemportsConfigData,
                    'child_path': ['/gemports']}},
            'olt_link': None, 'olt_link_path': None,
                'olt_link_path_keys': [None], 'olt_device_id': 'from_parent',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'from_parent'},
        TcontsConfigData: {
            'path': '/tconts/{}', 'path_keys': ['name'],
            'parent': VOntaniConfig, 'parent_path': '/v_ont_anis/{}',
                'parent_path_keys': ['interface_reference'],
            'child': None, 'child_path': [None],
            'olt_link': None, 'olt_link_path': None,
                'olt_link_path_keys': [None], 'olt_device_id': 'from_parent',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'from_parent'},
        GemportsConfigData: {
            'path': '/gemports/{}', 'path_keys': ['name'],
            'parent': VEnetConfig, 'parent_path': '/v_enets/{}',
                'parent_path_keys': ['itf_ref'],
            'child': None, 'child_path': [None],
            'olt_link': None, 'olt_link_path': None,
                'olt_link_path_keys': [None], 'olt_device_id': 'from_parent',
            'onu_link': None, 'onu_link_path': None,
                'onu_link_path_keys': [None], 'onu_device_id': 'from_parent'}
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
            if not parent_data:
                return None
            return parent_data
        except KeyError:
            log.info('xpon-agent-warning-interface-cannot-get-parent',
                     data=data)
            return None

    def get_child_data(self, data):
        interface_node = self.interface_stack[type(data)]
        child = None
        if len(interface_node['child'][1]['child_path']) > 1:
            top_children = self.core.get_proxy('/').get('{}'.format(
                interface_node['child'][1]['child_path'][0]))
            for top_child in top_children:
                child = self._get_child_data_by_path(data, '{}/{}/{}'.format(
                    interface_node['child'][1]['child_path'][0], top_child.id,
                    interface_node['child'][1]['child_path'][1]))
                if child is not None:
                    return child
        else:
            child = self._get_child_data_by_path(data, '{}'.format(
                interface_node['child'][1]['child_path'][0]))
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
        if device is None:
            return
        log.info('xpon-agent-create-interface-in-device',
                 device_id=device.id, type=type(data).__name__, data=data)
        adapter_agent = self.get_device_adapter_agent(device)
        if (isinstance(data, TcontsConfigData)):
            # Adapter interfaces for TCONT always need traffic-descriptor
            traffic_descriptor_data = self.core.get_proxy('/').get(
                '/traffic_descriptor_profiles/{}'.
                format(data.traffic_descriptor_profile_ref))
            adapter_agent.create_tcont(
                device=device, tcont_data=data,
                traffic_descriptor_data=traffic_descriptor_data)
        elif (isinstance(data, TrafficDescriptorProfileData)):
            # Do nothing for now
            log.info(
                'create-interface-in-device-traffic-descriptor-do-nothing',
                device=device, data=data)
        elif (isinstance(data, GemportsConfigData)):
            adapter_agent.create_gemport(device=device, data=data)
        elif (isinstance(data, (ChannelgroupConfig, ChannelpartitionConfig,
                                ChannelpairConfig, ChannelterminationConfig,
                                OntaniConfig, VOntaniConfig, VEnetConfig))):
            adapter_agent.create_interface(device=device, data=data)
        else:
            # Not handled yet
            log.info('create-interface-in-device: Not handling',
                     device=device, data=data)

    def update_interface_in_device(self, device, data):
        if device is None:
            return
        log.info('xpon-agent-update-interface-in-device',
                 device_id=device.id, type=type(data).__name__, data=data)
        adapter_agent = self.get_device_adapter_agent(device)
        if (isinstance(data, TcontsConfigData)):
            # Adapter interfaces for TCONT always need traffic-descriptor
            traffic_descriptor_data = self.core.get_proxy('/').get(
                '/traffic_descriptor_profiles/{}'.
                format(data.traffic_descriptor_profile_ref))
            adapter_agent.update_tcont(
                device=device, tcont_data=data,
                traffic_descriptor_data=traffic_descriptor_data)
        elif (isinstance(data, TrafficDescriptorProfileData)):
            # Do nothing for now
            log.info(
                'update-interface-in-device-traffic-descriptor-do-nothing',
                device=device, data=data)
        elif (isinstance(data, GemportsConfigData)):
            adapter_agent.update_gemport(device=device, data=data)
        elif (isinstance(data, (ChannelgroupConfig, ChannelpartitionConfig,
                                ChannelpairConfig, ChannelterminationConfig,
                                OntaniConfig, VOntaniConfig, VEnetConfig))):
            adapter_agent.update_interface(device=device, data=data)
        else:
            # Not handled yet
            log.info('create-interface-in-device: Not handling',
                     device=device, data=data)

    def remove_interface_in_device(self, device, data):
        if device is None:
            return
        log.info('xpon-agent-remove-interface-in-device',
                 device_id=device.id, type=type(data).__name__, data=data)
        adapter_agent = self.get_device_adapter_agent(device)
        if (isinstance(data, TcontsConfigData)):
            # Adapter interfaces for TCONT always need traffic-descriptor
            traffic_descriptor_data = self.core.get_proxy('/').get(
                '/traffic_descriptor_profiles/{}'.
                format(data.traffic_descriptor_profile_ref))
            adapter_agent.remove_tcont(
                device=device, tcont_data=data,
                traffic_descriptor_data=traffic_descriptor_data)
        elif (isinstance(data, TrafficDescriptorProfileData)):
            # Do nothing for now
            log.info(
                'remove-interface-in-device-traffic-descriptor-do-nothing',
                device=device, data=data)
        elif (isinstance(data, GemportsConfigData)):
            adapter_agent.remove_gemport(device=device, data=data)
        elif (isinstance(data, (ChannelgroupConfig, ChannelpartitionConfig,
                                ChannelpairConfig, ChannelterminationConfig,
                                OntaniConfig, VOntaniConfig, VEnetConfig))):
            adapter_agent.remove_interface(device=device, data=data)
        else:
            # Not handled yet
            log.info('remove-interface-in-device: Not handling',
                     device=device, data=data)

    def create_interface(self, data, device_id=None):
        if not self.is_valid_interface(data):
            log.info('xpon-agent-create-interface-invalid-interface-type',
                     type=type(data).__name__)
            return
        if device_id is None:
            olt_device = self.get_device(data, 'olt')
        else:
            olt_device = self.core.get_proxy('/').get('/devices/{}'.
                                                      format(device_id))
        device_id = None if olt_device is None else olt_device.id
        self.register_interface(device_id=device_id,
                                path=self.get_interface_path(data))
        if olt_device is not None:
            if(isinstance(data, ChannelterminationConfig)):
                self.create_channel_termination(olt_device, data)
            elif(isinstance(data, VOntaniConfig)):
                self.create_onu_interfaces(data=data, olt_device=olt_device)
            else:
                log.info(
                    'xpon-agent-creating-interface-at-olt-device:',
                    olt_device_id=olt_device.id, data=data)
                self.create_interface_in_device(olt_device, data)
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
            olt_device = self.get_device(data, 'olt')
        else:
            olt_device = self.core.get_proxy('/').get('/devices/{}'.
                                                      format(device_id))
        if olt_device is not None:
            log.info('xpon-agent-updating-interface-at-olt-device',
                     olt_device_id=olt_device.id, data=data)
            self.update_interface_in_device(olt_device, data)
            interface_node = self.interface_stack[type(data)]
            if interface_node['onu_device_id'] != 'na':
                onu_device = self.get_device(data, 'onu')
                log.info('xpon-agent-updating-interface-at-onu-device:',
                         onu_device_id=onu_device.id, data=data)
                self.update_interface_in_device(onu_device, data)
                if isinstance(data, VOntaniConfig):
                    self.update_onu_device(olt_device, onu_device, data)

    def remove_interface(self, data, device_id=None):
        if not self.is_valid_interface(data):
            log.info('xpon-agent-remove-interface-invalid-interface-type',
                     type=type(data).__name__)
            return
        if device_id is None:
            olt_device = self.get_device(data, 'olt')
        else:
            olt_device = self.core.get_proxy('/').get('/devices/{}'.
                                                      format(device_id))
        if olt_device is not None:
            log.info('xpon-agent-remove-interface:',
                     olt_device_id=olt_device.id, data=data)
            if(isinstance(data, ChannelterminationConfig)):
                self.remove_channel_termination(olt_device, data)
            else:
                interface_node = self.interface_stack[type(data)]
                if interface_node['onu_device_id'] != 'na':
                    onu_device = self.get_device(data, 'onu')
                    log.info(
                        'xpon-agent-removing-interface-at-onu-device:',
                        onu_device_id=onu_device.id, data=data)
                    self.remove_interface_in_device(onu_device, data)
                log.info(
                    'xpon-agent-removing-interface-at-olt-device:',
                    olt_device_id=olt_device.id, data=data)
                self.remove_interface_in_device(olt_device, data)
                if isinstance(data, VOntaniConfig):
                    self.delete_onu_device(olt_device, onu_device)

    def create_channel_termination(self, olt_device, data):
        channel_pair = self.get_parent_data(data)
        channel_part = self.get_parent_data(channel_pair)
        channel_group = self.get_parent_data(channel_part)
        if channel_group is not None:
            log.info('xpon-agent-creating-channel-group',
                     olt_device_id=olt_device.id, channel_group=channel_group)
            self.create_interface_in_device(olt_device, channel_group)
        if channel_part is not None:
            log.info('xpon-agent-creating-channel-partition:',
                     olt_device_id=olt_device.id, channel_part=channel_part)
            self.create_interface_in_device(olt_device, channel_part)
        if channel_pair is not None:
            log.info('xpon-agent-creating-channel-pair:',
                     olt_device_id=olt_device.id, channel_pair=channel_pair)
            self.create_interface_in_device(olt_device, channel_pair)
        log.info('xpon-agent-creating-channel-termination:',
                 olt_device_id=olt_device.id, data=data)
        self.create_interface_in_device(olt_device, data)
        if channel_pair is None:
            return
        v_ont_anis = self.core.get_proxy('/').get('/v_ont_anis')
        for v_ont_ani in v_ont_anis:
            if self.get_link_data(v_ont_ani, 'olt').name == channel_pair.name:
                self.create_onu_interfaces(data=v_ont_ani, olt_device=olt_device)

    def create_onu_interfaces(self, data, olt_device=None, onu_device=None):
        if not self.inReplay:
            self.create_onu_device(device=olt_device, v_ont_ani=data)
            onu_device = self.get_device(data, 'onu')
        self.create_interface_in_device(olt_device, data)
        self.create_interface_in_device(onu_device, data)
        try:
            ont_ani = self.core.get_proxy('/').get('/ont_anis/{}'.
                                                   format(data.name))
            if ont_ani is not None:
                self.create_interface_in_device(olt_device, ont_ani)
                self.create_interface_in_device(onu_device, ont_ani)
            tconts = self.core.get_proxy('/').get('/tconts')
            for tcont in tconts:
                if self.get_parent_data(tcont).name == data.name:
                    self.create_interface_in_device(olt_device, tcont)
                    self.create_interface_in_device(onu_device, tcont)
            v_enets = self.core.get_proxy('/').get('/v_enets')
            for v_enet in v_enets:
                if self.get_parent_data(v_enet).name == data.name:
                    self.create_interface_in_device(olt_device, v_enet)
                    self.create_interface_in_device(onu_device, v_enet)
                    gemports = self.core.get_proxy('/').get('/gemports')
                    for gemport in gemports:
                        if self.get_parent_data(gemport).name == v_enet.name:
                            self.create_interface_in_device(olt_device,
                                                            gemport)
                            self.create_interface_in_device(onu_device,
                                                            gemport)
        except KeyError:
            log.info(
                'xpon-agent-create-onu-interfaces-no-ont-ani-link-exists')

    def remove_channel_termination(self, olt_device, data):
        channel_pair = self.get_parent_data(data)
        if channel_pair is None:
            log.info(
                'xpon-agent-removing-channel-termination:',
                olt_device_id=olt_device.id, data=data)
            self.remove_interface_in_device(olt_device, data)
            return
        self.remove_onu_interfaces(olt_device, channel_pair)
        log.info(
            'xpon-agent-removing-channel-termination:',
            olt_device_id=olt_device.id, data=data)
        self.remove_interface_in_device(olt_device, data)
        log.info(
            'xpon-agent-removing-channel-pair:',
            olt_device_id=olt_device.id, channel_pair=channel_pair)
        self.remove_interface_in_device(olt_device, channel_pair)
        channel_partition = self.get_parent_data(channel_pair)
        if channel_partition is not None:
            log.info(
                'xpon-agent-removing-channel-partition:',
                olt_device_id=olt_device.id,
                channel_partition=channel_partition)
            self.remove_interface_in_device(olt_device, channel_partition)
        channel_group = self.get_parent_data(channel_partition)
        if channel_group is not None:
            log.info(
                'xpon-agent-removing-channel-group:',
                olt_device_id=olt_device.id, channel_group=channel_group)
            self.remove_interface_in_device(olt_device, channel_group)

    def remove_onu_interfaces(self, olt_device, data):
        v_ont_anis = self.core.get_proxy('/').get('/v_ont_anis')
        for v_ont_ani in v_ont_anis:
            if self.get_link_data(v_ont_ani, 'olt').name == data.name:
                onu_device = self.get_device(v_ont_ani, 'onu')
                v_enets = self.core.get_proxy('/').get('/v_enets')
                for v_enet in v_enets:
                    if self.get_parent_data(v_enet).name == v_ont_ani.name:
                        gemports = self.core.get_proxy('/').get('/gemports')
                        for gemport in gemports:
                            if self.get_parent_data(gemport).name == \
                                v_enet.name:
                                log.info(
                                    'xpon-agent-remove-gemport-at-onu-device:',
                                    onu_device_id=onu_device.id,
                                    gemport=gemport)
                                self.remove_interface_in_device(onu_device,
                                                                gemport)
                                log.info(
                                    'xpon-agent-remove-gemport-at-olt-device:',
                                    olt_device_id=olt_device.id,
                                    gemport=gemport)
                                self.remove_interface_in_device(olt_device,
                                                                gemport)
                        log.info(
                            'xpon-agent-removing-v-enet-at-onu-device:',
                            onu_device_id=onu_device.id, data=v_enet)
                        self.remove_interface_in_device(onu_device, v_enet)
                        log.info(
                            'xpon-agent-removing-v-enet-at-olt-device:',
                            olt_device_id=olt_device.id, data=v_enet)
                        self.remove_interface_in_device(olt_device, v_enet)
                tconts = self.core.get_proxy('/').get('/tconts')
                for tcont in tconts:
                    if self.get_parent_data(tcont).name == v_ont_ani.name:
                        log.info(
                            'xpon-agent-removing-tcont-at-onu-device:',
                            onu_device_id=onu_device.id, tcont=tcont)
                        self.remove_interface_in_device(onu_device, tcont)
                        log.info(
                            'xpon-agent-removing-tcont-at-olt-device:',
                            olt_device_id=olt_device.id, tcont=tcont)
                        self.remove_interface_in_device(olt_device, tcont)
                try:
                    ont_ani = self.core.get_proxy('/').get(
                        '/ont_anis/{}'.format(v_ont_ani.name))
                    log.info(
                        'xpon-agent-removing-ont-ani-at-onu-device:',
                        onu_device_id=onu_device.id, data=ont_ani)
                    self.remove_interface_in_device(onu_device, ont_ani)
                    log.info(
                        'xpon-agent-removing-ont-ani-at-olt-device:',
                        olt_device_id=olt_device.id, data=ont_ani)
                    self.remove_interface_in_device(olt_device, ont_ani)
                except KeyError:
                    log.info(
                    'xpon-agent-remove-channel-termination-ont-ani-not-found')
                log.info(
                    'xpon-agent-removing-v-ont-ani-at-onu-device:',
                    onu_device_id=onu_device.id, data=v_ont_ani)
                self.remove_interface_in_device(onu_device, v_ont_ani)
                log.info(
                    'xpon-agent-removing-v-ont-ani-at-olt-device:',
                    olt_device_id=olt_device.id, data=v_ont_ani)
                self.remove_interface_in_device(olt_device, v_ont_ani)
                self.delete_onu_device(olt_device, onu_device)

    def replay_interface(self, device_id):
        self.inReplay = True
        if not self.is_onu_device_id(device_id):
            ct_items = self.core.get_proxy('/').get(
                '/devices/{}/channel_terminations'.format(device_id))
            for ct in ct_items:
                self.create_interface(data=ct, device_id=device_id)
        else:
            onu_device = self.core.get_proxy('/').get('/devices/{}'.
                                                      format(device_id))
            v_ont_anis = self.core.get_proxy('/').get('/v_ont_anis')
            for v_ont_ani in v_ont_anis:
                if v_ont_ani.data.expected_serial_number == \
                        onu_device.serial_number:
                    #self._create_onu_interfaces(onu_device, v_ont_ani)
                    self.create_onu_interfaces(data=v_ont_ani, onu_device=onu_device)
                    break
        self.inReplay = False

    def is_onu_device_id(self, device_id):
        device = self.core.get_proxy('/').get('/devices/{}'.format(device_id))
        return True if device.type.endswith("_onu") else False

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

    def get_channel_group_for_vont_ani(self, v_ont_ani):
        _cp = self.core.get_proxy('/').get('/channel_partitions/{}'.format(
            v_ont_ani.data.parent_ref))
        assert _cp is not None
        _cg = self.core.get_proxy('/').get('/channel_groups/{}'.format(
            _cp.data.channelgroup_ref))
        assert _cg is not None
        return _cg.cg_index

    def create_onu_device(self, device, v_ont_ani):
        log.info('create-onu-device', device_id=device.id, v_ont_ani=v_ont_ani)
        adapter_agent = self.get_device_adapter_agent(device)
        parent_chnl_pair_id = self.get_port_num(
            device.id, v_ont_ani.data.preferred_chanpair)
        log.info('create-onu-device:', parent_chnl_pair_id=parent_chnl_pair_id)
        vendor_id = v_ont_ani.data.expected_serial_number[:4]
        proxy_address = Device.ProxyAddress(
            device_id=device.id,
            channel_group_id=self.get_channel_group_for_vont_ani(v_ont_ani),
            channel_id=parent_chnl_pair_id,
            channel_termination=v_ont_ani.data.preferred_chanpair,
            onu_id=v_ont_ani.data.onu_id, onu_session_id=v_ont_ani.data.onu_id)
        adapter_agent.add_onu_device(
            parent_device_id=device.id, parent_port_no=parent_chnl_pair_id,
            vendor_id=vendor_id, proxy_address=proxy_address,
            root=True, serial_number=v_ont_ani.data.expected_serial_number,
            admin_state=AdminState.ENABLED if v_ont_ani.interface.enabled
                                           else AdminState.PREPROVISIONED)
        return

    def update_onu_device(self, olt_device, onu_device, v_ont_ani):
        log.info('update-onu-device', olt_device_id=olt_device.id,
                 onu_device_id=onu_device.id, v_ont_ani=v_ont_ani)
        adapter_agent = self.get_device_adapter_agent(olt_device)
        new_admin_state = AdminState.ENABLED if v_ont_ani.interface.enabled \
            else AdminState.DISABLED
        if onu_device.admin_state != new_admin_state:
            log.info('update-onu-device-admin-state',
                     onu_device_id=onu_device.id,
                     new_admin_state=new_admin_state)
            onu_device.admin_state = new_admin_state
            self.core.get_proxy('/').update('/devices/{}'.format(onu_device.id),
                                            onu_device)

    def delete_onu_device(self, olt_device, onu_device):
        log.info('delete-onu-device', olt_device_id=olt_device.id,
                 onu_device_id=onu_device.id)
        adapter_agent = self.get_device_adapter_agent(olt_device)
        adapter_agent.delete_child_device(olt_device.id, onu_device.id)
        return
