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
from voltha.protos.bbf_fiber_base_pb2 import ChannelgroupConfig, ChannelpartitionConfig, \
    ChannelpairConfig, ChannelterminationConfig, OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.protos.device_pb2 import Device
from voltha.protos.common_pb2 import AdminState

log = structlog.get_logger()

class XponAgent(object):

    interfaces = {ChannelgroupConfig: {'path': '/channel_groups/{}', 'path_keys': ['name'], 'device_id' : ''},
                  ChannelpartitionConfig: {'path': '/channel_partitions/{}', 'path_keys': ['name'], 'device_id' : ''},
                  ChannelpairConfig: {'path': '/channel_pairs/{}', 'path_keys': ['name'], 'device_id' : ''},
                  ChannelterminationConfig: {'path': '/devices/{}/channel_terminations/{}', 'path_keys': ['id', 'name'], 'device_id' : 'id'},
                  OntaniConfig: {'path': '/ont_anis/{}', 'path_keys': ['name'], 'device_id' : ''},
                  VOntaniConfig: {'path': '/v_ont_anis/{}', 'path_keys': ['name'], 'device_id' : ''},
                  VEnetConfig: {'path': '/v_enets/{}', 'path_keys': ['name'], 'device_id' : ''}
                  }

    interface_stack = {ChannelgroupConfig: {'parent': None, 'parent_path' : None, 'parent_path_keys': [None]},
                       ChannelpartitionConfig: {'parent': ChannelgroupConfig, 'parent_path' : '/channel_groups/{}', 'parent_path_keys': ['data.channelgroup_ref']},
                       ChannelpairConfig: {'parent': ChannelpartitionConfig, 'parent_path': '/channel_partitions/{}', 'parent_path_keys': ['data.channelpartition_ref']},
                       ChannelterminationConfig: {'parent': ChannelpairConfig, 'parent_path': '/channel_pairs/{}', 'parent_path_keys': ['data.channelpair_ref']},
                       #VOntaniConfig: {'parent': ChannelpartitionConfig, 'parent_path': '/channel_partitions/{}', 'parent_path_keys': ['data.channelpartition_ref']},
                       VOntaniConfig: {'parent': ChannelpairConfig, 'parent_path': '/channel_pairs/{}', 'parent_path_keys': ['data.preferred_chanpair']},
                       OntaniConfig: {'parent': VOntaniConfig, 'parent_path': '/v_ont_anis/{}', 'parent_path_keys': ['name']},
                       VEnetConfig: {'parent': VOntaniConfig, 'parent_path': '/v_ont_anis/{}', 'parent_path_keys': ['data.v_ontani_ref']}
                      }

    def __init__(self, core):
        self.core = core
        self.preData = None
        self.inReplay = False
        return

    def get_device_adapter_agent(self, device_id):
        device = self.core.get_proxy('/devices/{}'.format(device_id)).get()
        assert device.adapter != ''
        adapter_agent = registry('adapter_loader').get_agent(device.adapter)
        log.debug('get-device-adapter-agent', device=device, adapter_agent=adapter_agent)
        return device, adapter_agent

    def get_interface_path(self, data):
        val = self.interfaces[type(data)]
        id_val = {}
        count = 0
        for key in val['path_keys']:
            id_val[count] = getattr(data, key)
            count+=1
        path = val['path'].format(*id_val.values())
        return path

    def get_device_id(self, data):
        val = self.interfaces[type(data)]
        device_id = None if val['device_id'] is '' else getattr(data, val['device_id'])
        if device_id is None:
            if(isinstance(data, ChannelpairConfig)):
                device_items = self.core.get_proxy('/').get('/devices')
                for device_item in device_items:
                    items = self.core.get_proxy('/').get(
                        '/devices/{}/channel_terminations'.format(device_item.id))
                    for item in items:
                        if item.data.channelpair_ref == data.name:
                            return self.get_device_id(item)
                return None
            elif(isinstance(data, ChannelpartitionConfig)):
                items = self.core.get_proxy('/').get('/channel_pairs')
                for item in items:
                    if item.data.channelpartition_ref == data.name:
                        return self.get_device_id(item)
                return None
            elif(isinstance(data, ChannelgroupConfig)):
                items = self.core.get_proxy('/').get('/channel_partitions')
                for item in items:
                    if item.data.channelgroup_ref == data.name:
                        return self.get_device_id(item)
                return None
            # Take care of ont ani and v ont ani
            elif(isinstance(data, VOntaniConfig)):
                channel_part_items = self.core.get_proxy('/').get('/channel_partitions')
                channel_pair_items = self.core.get_proxy('/').get('/channel_pairs')
                for channel_part_item in channel_part_items:
                    if channel_part_item.name == data.data.parent_ref:
                        return self.get_device_id(channel_part_item)
                for channel_pair_item in channel_pair_items:
                    if channel_pair_item.name == data.data.preferred_chanpair or \
                        channel_pair_item.name == data.data.protection_chanpair:
                            return self.get_device_id(channel_pair_item)
                return None
            elif(isinstance(data, OntaniConfig)):
                v_ont_ani_items = self.core.get_proxy('/').get('/v_ont_anis')
                for v_ont_ani_item in v_ont_ani_items:
                    if v_ont_ani_item.name == data.name:
                        return self.get_device_id(v_ont_ani_item)
                return None
            elif(isinstance(data, VEnetConfig)):
                v_ont_ani_items = self.core.get_proxy('/').get('/v_ont_anis')
                for v_ont_ani_item in v_ont_ani_items:
                    if v_ont_ani_item.name == data.data.v_ontani_ref:
                        return self.get_device_id(v_ont_ani_item)
                return None
        return device_id

    def get_parent_data(self, data):
        if data is None:
            return None
        val = self.interface_stack[type(data)]
        if val['parent'] is None:
            return None
        id_val = {}
        count = 0
        for key in val['parent_path_keys']:
            id_val[count] = self.rgetattr(data, key)
            count+=1
        parent_path = val['parent_path'].format(*id_val.values())
        try:
            parent_data = self.core.get_proxy('/').get(parent_path)
            return parent_data
        except ValueError:
            log.info('xpon-agent-warning-interface-cannot-get-parent', data=data)
            return None

    def rgetattr(self, obj, attr):
        def _getattr(obj, name):
            return getattr(obj, name)
        return functools.reduce(_getattr, [obj]+attr.split('.'))

    def is_valid_interface(self, data):
        valid = False
        for key in self.interfaces.keys():
            valid |= isinstance(data, key)
        return valid

    def register_interface(self, device_id, path, update=True):
        log.info('register-interface:', device_id=device_id, path=path)
        try:
            interface_proxy = self.core.get_proxy(path)
            if update:
                interface_proxy.register_callback(CallbackType.POST_UPDATE, self.update_interface, device_id)
            else:
                interface_proxy.register_callback(CallbackType.POST_ADD, self.create_interface, device_id)
                interface_proxy.register_callback(CallbackType.POST_REMOVE, self.remove_interface, device_id)
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def unregister_interface(self, device_id, path, update=True):
        log.info('unregister-interface:', device_id=device_id, path=path)
        try:
            interface_proxy = self.core.get_proxy(path)
            if update:
                interface_proxy.unregister_callback(CallbackType.POST_UPDATE, self.update_interface, device_id)
            else:
                interface_proxy.unregister_callback(CallbackType.POST_ADD, self.create_interface, device_id)
                interface_proxy.unregister_callback(CallbackType.POST_REMOVE, self.remove_interface, device_id)
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def create_interface(self, data, device_id=None):
        if device_id is None:
            device_id = self.get_device_id(data)
        if not self.is_valid_interface(data):
            log.info('xpon-agent-create-interface-invalid-interface-type', type=type(data).__name__)
            return
        self.register_interface(device_id=device_id, path=self.get_interface_path(data))
        if device_id is not None:
            if(isinstance(data, ChannelterminationConfig)):
                self.create_channel_termination(data, device_id)
            elif(isinstance(data, VOntaniConfig)):
                self.create_v_ont_ani(data, device_id)
            else:
                log.info('xpon-agent-create-interface:', device_id=device_id, data=data)
                device, adapter_agent = self.get_device_adapter_agent(device_id)
                adapter_agent.create_interface(device=device, data=data)

    def update_interface(self, data, device_id):
        if not self.is_valid_interface(data):
            log.info('xpon-agent-update-interface-invalid-interface-type', type=type(data).__name__)
            return
        if device_id is None:
            device_id = self.get_device_id(data)
        if device_id is not None:
            # This can be any interface
            device, adapter_agent = self.get_device_adapter_agent(device_id)
            interfaces = []
            ont_interfaces = []
            parent_data = self.get_parent_data(data)
            pre_parent_data = self.get_parent_data(self.preData)
            if parent_data is not None and pre_parent_data is None:
                while parent_data is not None:
                    interfaces.insert(0, parent_data)
                    parent_data = self.get_parent_data(parent_data)

                for interface in interfaces:
                    log.info('xpon-agent-creating-interface', device_id=device_id, data=interface)
                    adapter_agent.create_interface(device=device, data=interface)

                venet_items = self.core.get_proxy('/').get('/v_enets')
                for venet in venet_items:
                    if device_id == self.get_device_id(venet):
                        ont_interfaces.insert(0, venet)
                        parent_data = self.get_parent_data(venet)
                        while not isinstance(parent_data, ChannelpairConfig):
                            ont_interfaces.insert(0, parent_data)
                            parent_data = self.get_parent_data(parent_data)

                        for ont_interface in ont_interfaces:
                            log.info('xpon-agent-creating-ont-interface', device_id=device_id, data=ont_interface)
                            adapter_agent.create_interface(device=device, data=ont_interface)

            log.info('xpon-agent-updating-interface', device_id=device_id, data=data)
            adapter_agent.update_interface(device=device, data=data)

    def remove_interface(self, data, device_id=None):
        if device_id is None:
            device_id = self.get_device_id(data)
        if not self.is_valid_interface(data):
            log.info('xpon-agent-remove-interface-invalid-interface-type', type=type(data).__name__)
            return
        log.info('xpon-agent-remove-interface:', device_id=device_id, data=data)
        if device_id is not None:
            if(isinstance(data, ChannelterminationConfig)):
                self.remove_channel_termination(data, device_id)
            else:
                device, adapter_agent = self.get_device_adapter_agent(device_id)
                adapter_agent.remove_interface(device=device, data=data)
                if isinstance(data, VOntaniConfig):
                    self.delete_onu_device(device_id=device_id, v_ont_ani=data)

    def create_channel_termination(self, data, device_id):
        device, adapter_agent = self.get_device_adapter_agent(device_id)
        channel_pair = self.get_parent_data(data)
        channel_part = self.get_parent_data(channel_pair)
        channel_group = self.get_parent_data(channel_part)

        if channel_group:
            log.info('xpon-agent-creating-channel-group', device_id=device_id, data=channel_group)
            adapter_agent.create_interface(device=device, data=channel_group)
        if channel_part:
            log.info('xpon-agent-creating-channel-partition:', device_id=device_id, data=channel_part)
            adapter_agent.create_interface(device=device, data=channel_part)
        if channel_pair:
            log.info('xpon-agent-creating-channel-pair:', device_id=device_id, data=channel_pair)
            adapter_agent.create_interface(device=device, data=channel_pair)
        log.info('xpon-agent-creating-channel-termination:', device_id=device_id, data=data)
        adapter_agent.create_interface(device=device, data=data)
        # Take care of ont ani and v ont ani
        vont_items = self.core.get_proxy('/').get('/v_ont_anis')
        for vont in vont_items:
            vont_id = self.get_device_id(vont)
            if device_id == vont_id:
                self.create_v_ont_ani(vont, device_id)

    def create_v_ont_ani(self, data, device_id):
        if not self.inReplay:
           self.create_onu_device(device_id=device_id, v_ont_ani=data)
        device, adapter_agent = self.get_device_adapter_agent(device_id)
        venets = self.core.get_proxy('/').get('/v_enets')
        log.info('xpon-agent-creating-vont-ani:', device_id=device_id, data=data)
        adapter_agent.create_interface(device=device, data=data)

        try:
            ont_ani = self.core.get_proxy('/').get('/ont_anis/{}'.format(data.name))
            log.info('xpon-agent-create-v-ont-ani-creating-ont-ani:', device_id=device_id, data=ont_ani)
            adapter_agent.create_interface(device=device, data=ont_ani)
        except KeyError:
            log.info('xpon-agent-create-v-ont-ani-there-is-no-ont-ani-to-create')

        for venet in venets:
            if venet.data.v_ontani_ref == data.name:
                log.info('xpon-agent-create-v-ont-ani-creating-v-enet:', device_id=device_id, data=venet)
                adapter_agent.create_interface(device=device, data=venet)

    def remove_channel_termination(self, data, device_id):
        device, adapter_agent = self.get_device_adapter_agent(device_id)
        log.info('xpon-agent-removing-channel-termination:', device_id=device_id, data=data)
        adapter_agent.remove_interface(device=device, data=data)

        if data.data.channelpair_ref:
            channel_pair = self.get_parent_data(data)
            log.info('xpon-agent-removing-channel-pair:', device_id=device_id, data=channel_pair)
            adapter_agent.remove_interface(device=device, data=channel_pair)
            # Remove vontani and ontani if it has reference to cpair
            items = self.core.get_proxy('/').get('/v_ont_anis')
            for item in items:
                if (item.data.preferred_chanpair == channel_pair.name or \
                    item.data.protection_chanpair == channel_pair.name):
                    log.info('xpon-agent-removing-vont-ani:', device_id=device_id, data=item)
                    adapter_agent.remove_interface(device=device, data=item)
                    self.delete_onu_device(device_id=device_id, v_ont_ani=item)

                    venets_items = self.core.get_proxy('/').get('/v_enets')
                    for venet in venets_items:
                        if item.name == venet.data.v_ontani_ref:
                            log.info('xpon-agent-removing-v-enet:', device_id=device_id, data=venet)
                            adapter_agent.remove_interface(device=device, data=venet)

                    ontani_items = self.core.get_proxy('/').get('/ont_anis')
                    for ontani_item in ontani_items:
                        if ontani_item.name == item.name:
                            log.info('xpon-agent-removing-ont-ani:', device_id=device_id, data=ontani_item)
                            adapter_agent.remove_interface(device=device, data=ontani_item)
            # Remove cpart if exists
            if channel_pair.data.channelpartition_ref:
                channel_part = self.get_parent_data(channel_pair)
                log.info('xpon-agent-removing-channel-partition:', device_id=device_id, data=channel_part)
                adapter_agent.remove_interface(device=device, data=channel_part)

                if channel_part.data.channelgroup_ref:
                    channel_group = self.get_parent_data(channel_part)
                    log.info('xpon-agent-removing-channel-group:', device_id=device_id, data=channel_group)
                    adapter_agent.remove_interface(device=device, data=channel_group)

    def replay_interface(self, device_id):
        self.inReplay = True
        ct_items = self.core.get_proxy('/').get('/devices/{}/channel_terminations'.format(device_id))
        for ct in ct_items:
            self.create_interface(data=ct, device_id=device_id)
        self.inReplay = False

    def get_port_num(self, device_id, label):
        log.info('get-port-num:', label=label, device_id=device_id)
        ports = self.core.get_proxy('/').get('/devices/{}/ports'.format(device_id))
        log.info('get-port-num:', label=label, device_id=device_id, ports=ports)
        for port in ports:
            if port.label == label:
                return port.port_no
        return 0

    def create_onu_device(self, device_id, v_ont_ani):
        log.info('create-onu-device', v_ont_ani=v_ont_ani, device=device_id)
        device, adapter_agent = self.get_device_adapter_agent(device_id)
        parent_chnl_pair_id = self.get_port_num(device.id, v_ont_ani.data.preferred_chanpair)
        log.info('create-onu-device:', parent_chnl_pair_id=parent_chnl_pair_id)
        onu_type = v_ont_ani.data.expected_serial_number[:4]
        proxy_address = Device.ProxyAddress(device_id=device.id, channel_id=parent_chnl_pair_id,
                                           onu_id=v_ont_ani.data.onu_id, onu_session_id=v_ont_ani.data.onu_id)
        adapter_agent.child_device_detected(parent_device_id=device.id, parent_port_no=parent_chnl_pair_id,
                                            child_device_type=onu_type,
                                            proxy_address=proxy_address,
                                            root=True, serial_number=v_ont_ani.data.expected_serial_number,
                                            admin_state=AdminState.ENABLED if v_ont_ani.interface.enabled else AdminState.DISABLED
                                            )
        return

    def delete_onu_device(self, device_id, v_ont_ani):
        log.info('delete-onu-device', v_ont_ani=v_ont_ani, device=device_id)
        device, adapter_agent = self.get_device_adapter_agent(device_id)
        onu_device = adapter_agent.get_child_device(parent_device_id=device_id, serial_number=v_ont_ani.data.expected_serial_number)
        if onu_device is not None:
            adapter_agent.delete_child_device(device_id, onu_device.id)
        return
