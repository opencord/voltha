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
from voltha.protos.bbf_fiber_base_pb2 import channelgroup_config, channelpartition_config, \
    channelpair_config, channeltermination_config, ontani_config, v_ontani_config, v_enet_config
from voltha.protos.device_pb2 import Device
from voltha.protos.common_pb2 import AdminState

log = structlog.get_logger()

class XponAgent(object):

    interfaces = {channelgroup_config: {'path': '/channel_groups/{}', 'path_keys': ['name'], 'device_id' : ''},
                  channelpartition_config: {'path': '/channel_partitions/{}', 'path_keys': ['name'], 'device_id' : ''},
                  channelpair_config: {'path': '/channel_pairs/{}', 'path_keys': ['name'], 'device_id' : ''},
                  channeltermination_config: {'path': '/devices/{}/channel_terminations/{}', 'path_keys': ['id', 'name'], 'device_id' : 'id'},
                  ontani_config: {'path': '/ont_anis/{}', 'path_keys': ['name'], 'device_id' : ''},
                  v_ontani_config: {'path': '/v_ont_anis/{}', 'path_keys': ['name'], 'device_id' : ''},
                  v_enet_config: {'path': '/v_enets/{}', 'path_keys': ['name'], 'device_id' : ''}
                  }

    interface_stack = {channelgroup_config: {'parent': None, 'parent_path' : None, 'parent_path_keys': [None]},
                       channelpartition_config: {'parent': channelgroup_config, 'parent_path' : '/channel_groups/{}', 'parent_path_keys': ['data.channelgroup_ref']},
                       channelpair_config: {'parent': channelpartition_config, 'parent_path': '/channel_partitions/{}', 'parent_path_keys': ['data.channelpartition_ref']},
                       channeltermination_config: {'parent': channelpair_config, 'parent_path': '/channel_pairs/{}', 'parent_path_keys': ['data.channelpair_ref']},
                       #v_ontani_config: {'parent': channelpartition_config, 'parent_path': '/channel_partitions/{}', 'parent_path_keys': ['data.channelpartition_ref']},
                       v_ontani_config: {'parent': channelpair_config, 'parent_path': '/channel_pairs/{}', 'parent_path_keys': ['data.preferred_chanpair']},
                       ontani_config: {'parent': v_ontani_config, 'parent_path': '/v_ont_anis/{}', 'parent_path_keys': ['name']},
                       v_enet_config: {'parent': v_ontani_config, 'parent_path': '/v_ont_anis/{}', 'parent_path_keys': ['data.v_ontani_ref']}
                      }

    def __init__(self, core):
        self.core = core
        self.preData = None
        self.inReplay = False
        return

    def getDeviceAdapterAgent(self, device_id):
        device = self.core.get_proxy('/devices/{}'.format(device_id)).get()
        assert device.adapter != ''
        adapter_agent = registry('adapter_loader').get_agent(device.adapter)
        log.debug('getDeviceAdapterAgent', device=device, adapter_agent=adapter_agent)
        return device, adapter_agent

    def getInterfacePath(self, data):
        val = self.interfaces[type(data)]
        idVal = {}
        count = 0
        for key in val['path_keys']:
            idVal[count] = getattr(data, key)
            count+=1
        path = val['path'].format(*idVal.values())
        return path

    def getDeviceId(self, data):
        val = self.interfaces[type(data)]
        device_id = None if val['device_id'] is '' else getattr(data, val['device_id'])
        if device_id is None:
            if(isinstance(data, channelpair_config)):
                device_items = self.core.get_proxy('/').get('/devices')
                for device_item in device_items:
                    items = self.core.get_proxy('/').get(
                        '/devices/{}/channel_terminations'.format(device_item.id))
                    for item in items:
                        if item.data.channelpair_ref == data.name:
                            return self.getDeviceId(item)
                return None
            elif(isinstance(data, channelpartition_config)):
                items = self.core.get_proxy('/').get('/channel_pairs')
                for item in items:
                    if item.data.channelpartition_ref == data.name:
                        return self.getDeviceId(item)
                return None
            elif(isinstance(data, channelgroup_config)):
                items = self.core.get_proxy('/').get('/channel_partitions')
                for item in items:
                    if item.data.channelgroup_ref == data.name:
                        return self.getDeviceId(item)
                return None
            # Take care of ont ani and v ont ani
            elif(isinstance(data, v_ontani_config)):
                channel_part_items = self.core.get_proxy('/').get('/channel_partitions')
                channel_pair_items = self.core.get_proxy('/').get('/channel_pairs')
                for channel_part_item in channel_part_items:
                    if channel_part_item.name == data.data.parent_ref:
                        return self.getDeviceId(channel_part_item)
                for channel_pair_item in channel_pair_items:
                    if channel_pair_item.name == data.data.preferred_chanpair or \
                        channel_pair_item.name == data.data.protection_chanpair:
                            return self.getDeviceId(channel_pair_item)
                return None
            elif(isinstance(data, ontani_config)):
                v_ont_ani_items = self.core.get_proxy('/').get('/v_ont_anis')
                for v_ont_ani_item in v_ont_ani_items:
                    if v_ont_ani_item.name == data.name:
                        return self.getDeviceId(v_ont_ani_item)
                return None
            elif(isinstance(data, v_enet_config)):
                v_ont_ani_items = self.core.get_proxy('/').get('/v_ont_anis')
                for v_ont_ani_item in v_ont_ani_items:
                    if v_ont_ani_item.name == data.data.v_ontani_ref:
                        return self.getDeviceId(v_ont_ani_item)
                return None
        return device_id
    
    def getParentData(self, data):
        if data is None:
            return None
        val = self.interface_stack[type(data)]
        if val['parent'] is None:
            return None 
        idVal = {}
        count = 0
        for key in val['parent_path_keys']:
            idVal[count] = self.rgetattr(data, key)
            count+=1
        parent_path = val['parent_path'].format(*idVal.values())
        try:
            parent_data = self.core.get_proxy('/').get(parent_path)
            return parent_data
        except ValueError:
            log.info('xpon_agent: Warning - interface cannot get parent', data=data)
            return None
    
    def rgetattr(self, obj, attr):
        def _getattr(obj, name):
            return getattr(obj, name)
        return functools.reduce(_getattr, [obj]+attr.split('.'))
    
    def isValidInterface(self, data):
        valid = False
        for key in self.interfaces.keys():
            valid |= isinstance(data, key)
        return valid

    def registerInterface(self, device_id, path, update=True):
        log.info('registerInterface:', device_id=device_id, path=path)
        try:
            interface_proxy = self.core.get_proxy(path)
            if update:
                interface_proxy.register_callback(CallbackType.POST_UPDATE, self.updateInterface, device_id)
            else:
                interface_proxy.register_callback(CallbackType.POST_ADD, self.createInterface, device_id)
                interface_proxy.register_callback(CallbackType.POST_REMOVE, self.removeInterface, device_id)
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def unregisterInterface(self, device_id, path, update=True):
        log.info('unregisterInterface:', device_id=device_id, path=path)
        try:
            interface_proxy = self.core.get_proxy(path)
            if update:
                interface_proxy.unregister_callback(CallbackType.POST_UPDATE, self.updateInterface, device_id)
            else:
                interface_proxy.unregister_callback(CallbackType.POST_ADD, self.createInterface, device_id)
                interface_proxy.unregister_callback(CallbackType.POST_REMOVE, self.removeInterface, device_id)
        except:
            print "Unexpected error:", sys.exc_info()[0]

    def createInterface(self, data, device_id=None):
        if device_id is None:
            device_id = self.getDeviceId(data)
        if not self.isValidInterface(data):
            log.info('createInterface: invalid interface type', type=type(data).__name__)
            return
        self.registerInterface(device_id=device_id, path=self.getInterfacePath(data))
        if device_id is not None:
            if(isinstance(data, channeltermination_config)):
                self.createChannelTermination(data, device_id)
            elif(isinstance(data, v_ontani_config)):
                self.createVOntAni(data, device_id)
            else:
                log.info('xpon_agent: createInterface:', device_id=device_id, data=data)
                device, adapter_agent = self.getDeviceAdapterAgent(device_id)
                adapter_agent.createInterface(device=device, data=data)
            
    
    def updateInterface(self, data, device_id):
        if not self.isValidInterface(data):
            log.info('updateInterface: invalid interface type', type=type(data).__name__)
            return
        if device_id is None:
            device_id = self.getDeviceId(data)
        if device_id is not None:
            # This can be any interface
            device, adapter_agent = self.getDeviceAdapterAgent(device_id)
            interfaces = []
            ont_interfaces = []
            parent_data = self.getParentData(data)
            pre_parent_data = self.getParentData(self.preData)
            if parent_data is not None and pre_parent_data is None:
                while parent_data is not None:
                    interfaces.insert(0, parent_data)
                    parent_data = self.getParentData(parent_data)
                
                for interface in interfaces:
                    log.info('xpon_agent: Creating interface', device_id=device_id, data=interface)
                    adapter_agent.createInterface(device=device, data=interface)
                
                venet_items = self.core.get_proxy('/').get('/v_enets')
                for venet in venet_items:
                    if device_id == self.getDeviceId(venet):
                        ont_interfaces.insert(0, venet)
                        parent_data = self.getParentData(venet)
                        while not isinstance(parent_data, channelpair_config):
                            ont_interfaces.insert(0, parent_data)
                            parent_data = self.getParentData(parent_data)
                        
                        for ont_interface in ont_interfaces:
                            log.info('xpon_agent: Creating ont interface', device_id=device_id, data=ont_interface)
                            adapter_agent.createInterface(device=device, data=ont_interface)
            
            log.info('xpon_agent: Updating interface', device_id=device_id, data=data)
            adapter_agent.updateInterface(device=device, data=data)

    def removeInterface(self, data, device_id=None):
        if device_id is None:
            device_id = self.getDeviceId(data)
        if not self.isValidInterface(data):
            log.info('removeInterface: invalid interface type', type=type(data).__name__)
            return
        log.info('removeInterface:', device_id=device_id, data=data)
        if device_id is not None:
            if(isinstance(data, channeltermination_config)):
                self.removeChannelTermination(data, device_id)
            else:
                device, adapter_agent = self.getDeviceAdapterAgent(device_id)
                adapter_agent.removeInterface(device=device, data=data)
                if isinstance(data, v_ontani_config):
                    self.deleteOnuDevice(device_id=device_id, vOntAni=data)
    
    def createChannelTermination(self, data, device_id):
        device, adapter_agent = self.getDeviceAdapterAgent(device_id)
        channel_pair = self.getParentData(data)
        channel_part = self.getParentData(channel_pair)
        channel_group = self.getParentData(channel_part)
        
        if channel_group:
            log.info('xpon_agent: Creating channel group', device_id=device_id, data=channel_group)
            adapter_agent.createInterface(device=device, data=channel_group)
        if channel_part:
            log.info('xpon_agent: Creating channel partition:', device_id=device_id, data=channel_part)
            adapter_agent.createInterface(device=device, data=channel_part)
        if channel_pair:
            log.info('xpon_agent: Creating channel pair:', device_id=device_id, data=channel_pair)
            adapter_agent.createInterface(device=device, data=channel_pair)
        log.info('xpon_agent: Creating channel termination:', device_id=device_id, data=data)
        adapter_agent.createInterface(device=device, data=data)
        # Take care of ont ani and v ont ani
        vont_items = self.core.get_proxy('/').get('/v_ont_anis')
        for vont in vont_items:
            vont_id = self.getDeviceId(vont)
            if device_id == vont_id:
                self.createVOntAni(vont, device_id)
    
    def createVOntAni(self, data, device_id):
        if not self.inReplay:
           self.createOnuDevice(device_id=device_id, vOntAni=data)
        device, adapter_agent = self.getDeviceAdapterAgent(device_id)
        venets = self.core.get_proxy('/').get('/v_enets')
        log.info('xpon_agent: Creating vont ani:', device_id=device_id, data=data)
        adapter_agent.createInterface(device=device, data=data)
        
        try:
            ont_ani = self.core.get_proxy('/').get('/ont_anis/{}'.format(data.name))
            log.info('xpon_agent <createVOntAni>: Creating ont ani:', device_id=device_id, data=ont_ani)
            adapter_agent.createInterface(device=device, data=ont_ani)
        except KeyError:
            log.info('xpon_agent <createVOntAni>: There is no ont ani to create')
        
        for venet in venets:
            if venet.data.v_ontani_ref == data.name:
                log.info('xpon_agent <createVOntAni>: Creating venet:', device_id=device_id, data=venet)
                adapter_agent.createInterface(device=device, data=venet)
    
    def removeChannelTermination(self, data, device_id):
        device, adapter_agent = self.getDeviceAdapterAgent(device_id)
        log.info('xpon_agent: Removing channel termination:', device_id=device_id, data=data)
        adapter_agent.removeInterface(device=device, data=data)
        
        if data.data.channelpair_ref:
            channel_pair = self.getParentData(data)
            log.info('xpon_agent: Removing channel pair:', device_id=device_id, data=channel_pair)
            adapter_agent.removeInterface(device=device, data=channel_pair)
            # Remove vontani and ontani if it has reference to cpair
            items = self.core.get_proxy('/').get('/v_ont_anis')
            for item in items:
                if (item.data.preferred_chanpair == channel_pair.name or \
                    item.data.protection_chanpair == channel_pair.name):
                    log.info('xpon_agent: Removing vont ani:', device_id=device_id, data=item)
                    adapter_agent.removeInterface(device=device, data=item)
                    self.deleteOnuDevice(device_id=device_id, vOntAni=item)
                    
                    venets_items = self.core.get_proxy('/').get('/v_enets')
                    for venet in venets_items:
                        if item.name == venet.data.v_ontani_ref:
                            log.info('xpon_agent: Removing venet:', device_id=device_id, data=venet)
                            adapter_agent.removeInterface(device=device, data=venet)
                    
                    ontani_items = self.core.get_proxy('/').get('/ont_anis')
                    for ontani_item in ontani_items:
                        if ontani_item.name == item.name:
                            log.info('xpon_agent: Removing ont ani:', device_id=device_id, data=ontani_item)
                            adapter_agent.removeInterface(device=device, data=ontani_item)
            # Remove cpart if exists
            if channel_pair.data.channelpartition_ref:
                channel_part = self.getParentData(channel_pair)
                log.info('xpon_agent: Removing channel partition:', device_id=device_id, data=channel_part)
                adapter_agent.removeInterface(device=device, data=channel_part)
                
                if channel_part.data.channelgroup_ref:
                    channel_group = self.getParentData(channel_part)
                    log.info('xpon_agent: Removing channel group:', device_id=device_id, data=channel_group)
                    adapter_agent.removeInterface(device=device, data=channel_group)
            
    def replayInterface(self, device_id):
        self.inReplay = True
        ct_items = self.core.get_proxy('/').get('/devices/{}/channel_terminations'.format(device_id))
        for ct in ct_items:
            self.createInterface(data=ct, device_id=device_id)
        self.inReplay = False

    def getPortNum(self, device_id, label):
        log.info('getPortNum:', label=label, device_id=device_id)
        ports = self.core.get_proxy('/').get('/devices/{}/ports'.format(device_id))
        log.info('getPortNum:', label=label, device_id=device_id, ports=ports)
        for port in ports:
            if port.label == label:
                return port.port_no
        return 0

    def createOnuDevice(self, device_id, vOntAni):
        log.info('create onu device', vOntAni=vOntAni, device=device_id)
        device, adapter_agent = self.getDeviceAdapterAgent(device_id)
        parentChnlPairId = self.getPortNum(device.id, vOntAni.data.preferred_chanpair)
        log.info('createOnuDevice:', parentChnlPairId=parentChnlPairId)
        onuType = vOntAni.data.expected_serial_number[:4]
        proxyAddress = Device.ProxyAddress(device_id=device.id, channel_id=parentChnlPairId,
                                           onu_id=vOntAni.data.onu_id, onu_session_id=vOntAni.data.onu_id)
        adapter_agent.child_device_detected(parent_device_id=device.id, parent_port_no=parentChnlPairId,
                                            child_device_type=onuType,
                                            proxy_address=proxyAddress,
                                            root=True, serial_number=vOntAni.data.expected_serial_number,
                                            admin_state=AdminState.ENABLED if vOntAni.interface.enabled else AdminState.DISABLED
                                            )
        return

    def deleteOnuDevice(self, device_id, vOntAni):
        log.info('delete onu device', vOntAni=vOntAni, device=device_id)
        device, adapter_agent = self.getDeviceAdapterAgent(device_id)
        onuDevice = adapter_agent.get_child_device(parent_device_id=device_id, serial_number=vOntAni.data.expected_serial_number)
        if onuDevice is not None:
            adapter_agent.delete_child_device(device_id, onuDevice.id)
        return
