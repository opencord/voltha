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
from Queue import Empty as QueueEmpty

import structlog
import re
from uuid import uuid4

from google.protobuf.empty_pb2 import Empty
from grpc import StatusCode

from voltha.protos.bbf_fiber_base_pb2 import \
    allchannelgroup_config, channelgroup_config, \
    allchannelpair_config, channelpair_config, \
    allchannelpartition_config, channelpartition_config, \
    allchanneltermination_config, channeltermination_config, \
    allontani_config, ontani_config, allvontani_config , v_ontani_config, \
    allvenet_config, v_enet_config

from voltha.protos.device_pb2 import Device
from voltha.protos.common_pb2 import AdminState

from requests.api import request

log = structlog.get_logger()


class XponHandler(object):
    def __init__(self, core):
        self.core = core
        self.root = None

    def start(self, root):
        log.debug('starting xpon_handler')
        self.root = root

    def getAllChannelGroupConfig (self, request, context): 
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_groups')
        return allchannelgroup_config(channelgroup_config=items)
    
    def createChannelGroup(self, request, context):
        log.info('grpc-request', request=request)
        
        try:
            assert isinstance(request, channelgroup_config)
            assert self.validateInterface(request, context)   
            log.debug('xpon_handler: Creating channel group - {}'.format(request.name))
            self.root.add('/channel_groups', request)
            
            return Empty()
        except AssertionError, e:
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel group \'{}\' cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def updateChannelGroup(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return channelgroup_config()
        
        try:
            assert isinstance(request, channelgroup_config)
            assert self.validateInterface(request, context)
            
            path = '/channel_groups/{}'.format(request.name)
            log.debug('xpon_handler: Updating channel group - {}'.format(request.name))
            self.root.update(path, request, strict=True)
            return Empty()
        
        except AssertionError, e:
            return Empty()
        
        except KeyError:
            context.set_details(
                    'channel group \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def deleteChannelGroup(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        try:
            assert isinstance(request, channelgroup_config)
            known_channel_group_ref = dict(
                (dt.data.channelgroup_ref, dt) for dt in self.root.get('/channel_partitions'))
            known_channel_group_ref_1 = dict(
                (dt.data.channelgroup_ref, dt) for dt in self.root.get('/channel_pairs'))
            reference = "channel partition"
            assert request.name not in known_channel_group_ref
            reference = "channel pair"
            assert request.name not in known_channel_group_ref_1
            path = '/channel_groups/{}'.format(request.name)
            log.debug('xpon_handler: Removing channel group - {}'.format(request.name))
            self.root.remove(path)
            
            return Empty()
        
        except AssertionError:
            context.set_details(
                'The channel group -- \'{}\' is referenced by {}'.format(request.name, reference))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        except KeyError:
            context.set_details(
                'channel group \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def getAllChannelPartitionConfig (self, request, context): 
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_partitions')
        return allchannelpartition_config(channelpartition_config=items)
    
    def createChannelPartition(self, request, context):
        log.info('grpc-request', request=request)
        
        try:
            assert isinstance(request, channelpartition_config)
            assert self.validateInterface(request, context)
            log.debug('xpon_handler: Creating channel partition - {}'.format(request.name))
            self.root.add('/channel_partitions', request)
            
            return Empty()
        except AssertionError, e:
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel partition \'{}\' cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def updateChannelPartition(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return channelpartition_config()
        
        try:
            assert isinstance(request, channelpartition_config)
            assert self.validateInterface(request, context)
            
            path = '/channel_partitions/{}'.format(request.name)
            log.debug('xpon_handler: Updating channel partition - {}'.format(request.name))
            self.root.update(path, request, strict=True)
            return Empty()
        
        except AssertionError, e:
            return Empty()
        
        except KeyError:
            context.set_details(
                    'channel partition \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def deleteChannelPartition(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        try:
            assert isinstance(request, channelpartition_config)
            known_channel_partition_ref = dict(
                (dt.data.channelpartition_ref, dt) for dt in self.root.get('/channel_pairs'))
            known_channel_partition_ref_1 = dict(
                (dt.data.parent_ref, dt) for dt in self.root.get('/v_ont_anis'))
            reference = "channel pair"
            assert request.name not in known_channel_partition_ref
            reference = "vontani"
            assert request.name not in known_channel_partition_ref_1
            path = '/channel_partitions/{}'.format(request.name)
            log.debug('xpon_handler: Removing channel partition - {}'.format(request.name))
            self.root.remove(path)
            
            return Empty()
        
        except AssertionError:
            context.set_details(
                'The channel partition -- \'{}\' is referenced by {}'.format(request.name, reference))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        except KeyError:
            context.set_details(
                'channel partition \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def getAllChannelPairConfig (self, request, context): 
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_pairs')
        return allchannelpair_config(channelpair_config=items)
    
    def createChannelPair(self, request, context):
        log.info('grpc-request', request=request)
        
        try:
            assert isinstance(request, channelpair_config)
            assert self.validateInterface(request, context)
            log.debug('xpon_handler: Creating channel pair - {}'.format(request.name))
            self.root.add('/channel_pairs', request)
            
            return Empty()
        except AssertionError, e:
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel pair \'{}\' cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def updateChannelPair(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return channelpair_config()
        
        try:
            assert isinstance(request, channelpair_config)
            assert self.validateInterface(request, context)
            
            path = '/channel_pairs/{}'.format(request.name)
            log.debug('xpon_handler: Updating channel pair - {}'.format(request.name))
            self.root.update(path, request, strict=True)
            return Empty()
        
        except AssertionError, e:
            return Empty()
        
        except KeyError:
            context.set_details(
                    'channel pair \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def deleteChannelPair(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        try:
            assert isinstance(request, channelpair_config)
            device_items = self.root.get('/devices')
            for device_item in device_items:
                known_channel_pair_ref = dict(
                    (dt.data.channelpair_ref, dt) for dt in self.root.get(
                        '/devices/{}/channel_terminations'.format(device_item.id)))
                assert request.name not in known_channel_pair_ref
            path = '/channel_pairs/{}'.format(request.name)
            log.debug('xpon_handler: Removing channel pair - {}'.format(request.name))
            self.root.remove(path)
            
            return Empty()
        
        except AssertionError:
            context.set_details(
                'The channel pair -- \'{}\' is referenced by channel termination'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        except KeyError:
            context.set_details(
                'channel pair \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def getAllChannelTerminationConfig (self, request, context): 
        log.info('grpc-request', request=request)
        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return allchanneltermination_config()

        try:
            items = self.root.get(
                '/devices/{}/channel_terminations'.format(request.id))
            return allchanneltermination_config(channeltermination_config=items)
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return allchanneltermination_config()
    
    def createChannelTermination(self, request, context):
        log.info('grpc-request', request=request)
        
        try:
            assert isinstance(request, channeltermination_config)
            assert self.validateInterface(request, context)
            #device = self.root.get('/devices/{}'.format(request.id))
        except AssertionError, e:
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        try:
            path = '/devices/{}/channel_terminations'.format(request.id)
            log.debug('xpon_handler: Creating channel termination - {}'.format(request.name))
            self.root.add(path, request)
            #if self.use_xpon_agent is False:
            #    self.createInterfaceBasedOnDevice(request)
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not activated'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel termination \'{}\' cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def updateChannelTermination(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return channeltermination_config()
        
        try:
            assert isinstance(request, channeltermination_config)
            assert self.validateInterface(request, context)
            
            #device = self.root.get('/devices/{}'.format(request.id))
        
        except AssertionError, e:
            return Empty()
        
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        
        try:
            path = '/devices/{}/channel_terminations/{}'.format(request.id, request.name)
            log.debug('xpon_handler: Updating channel termination - {}'.format(request.name))
            self.root.update(path, request, strict=True)
            return Empty()
        
        except KeyError:
            context.set_details(
                'channel termination \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def deleteChannelTermination(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        try:
            assert isinstance(request, channeltermination_config)
        except AssertionError:
            context.set_details(
                'Instance is not of channel termination')
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        try:
            path = '/devices/{}/channel_terminations/{}'.format(request.id, request.name)
            #ct = self.root.get(path)
        except KeyError:
            context.set_details(
                'channel termination \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        try:
            log.debug('xpon_handler: Removing channel termination - {}'.format(request.name))
            self.root.remove(path)
            return Empty()
        
        except KeyError:
            context.set_details(
                'Could not delete channel termination \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def getAllOntAniConfig (self, request, context): 
        log.info('grpc-request', request=request)
        items = self.root.get('/ont_anis')
        return allontani_config(ontani_config=items)
    
    def createOntAni(self, request, context):
        log.info('grpc-request', request=request)
        
        try:
            assert isinstance(request, ontani_config)
            assert self.validateInterface(request, context)   
            log.debug('xpon_handler: Creating ont ani - {}'.format(request.name))
            self.root.add('/ont_anis', request)
            return Empty()
        except AssertionError, e:
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create ontani \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated ontani \'{}\' cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def updateOntAni(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return ontani_config()
        
        try:
            assert isinstance(request, ontani_config)
            assert self.validateInterface(request, context)
            
            path = '/ont_anis/{}'.format(request.name)
            log.debug('xpon_handler: Updating ont ani - {}'.format(request.name))
            self.root.update(path, request, strict=True)
            return Empty()
        
        except AssertionError, e:
            return Empty()
        
        except KeyError:
            context.set_details(
                'ontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def deleteOntAni(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        try:
            assert isinstance(request, ontani_config)
            
            path = '/ont_anis/{}'.format(request.name)
            log.debug('xpon_handler: Removing ont ani - {}'.format(request.name))
            self.root.remove(path)
            
            return Empty()
        
        except AssertionError:
            context.set_details(
                'Instance is not of ont ani')
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        except KeyError:
            context.set_details(
                'ontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def getAllVOntAniConfig (self, request, context): 
        log.info('grpc-request', request=request)
        items = self.root.get('/v_ont_anis')
        return allvontani_config(v_ontani_config=items)
    
    def createVOntAni(self, request, context):
        log.info('grpc-request', request=request)
        
        try:
            assert isinstance(request, v_ontani_config)
            assert self.validateInterface(request, context)   
            log.debug('xpon_handler: Creating vont ani - {}'.format(request.name))
            self.root.add('/v_ont_anis', request)
            return Empty()
        except AssertionError, e:
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create vontani \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated vontani \'{}\' cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def updateVOntAni(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return v_ontani_config()
        
        try:
            assert isinstance(request, v_ontani_config)
            assert self.validateInterface(request, context)
            
            path = '/v_ont_anis/{}'.format(request.name)
            log.debug('xpon_handler: Updating vont ani - {}'.format(request.name))
            self.root.update(path, request, strict=True)
            return Empty()
        
        except AssertionError, e:
            return Empty()
        
        except KeyError:
            context.set_details(
                'vontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def deleteVOntAni(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        try:
            assert isinstance(request, v_ontani_config)
            known_v_ont_ani_ref = dict(
                (dt.data.v_ontani_ref, dt) for dt in self.root.get('/v_enets'))
            assert request.name not in known_v_ont_ani_ref
            
            path = '/v_ont_anis/{}'.format(request.name)
            log.debug('xpon_handler: Removing vont ani - {}'.format(request.name))
            self.root.remove(path)
            
            return Empty()
        
        except AssertionError:
            context.set_details(
                'The vont ani -- \'{}\' is referenced by venet'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        except KeyError:
            context.set_details(
                'vontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def getAllVEnetConfig (self, request, context): 
        log.info('grpc-request', request=request)
        items = self.root.get('/v_enets')
        return allvenet_config(v_enet_config=items)
    
    def createVEnet(self, request, context):
        log.info('grpc-request', request=request)
        
        try:
            assert isinstance(request, v_enet_config)
            assert self.validateInterface(request, context)   
            log.debug('xpon_handler: Creating venet - {}'.format(request.name))
            self.root.add('/v_enets', request)
            return Empty()
        except AssertionError, e:
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create venet \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated venet \'{}\' cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
    
    def updateVEnet(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return v_enet_config()
        
        try:
            assert isinstance(request, v_enet_config)
            assert self.validateInterface(request, context)
            
            path = '/v_enets/{}'.format(request.name)
            log.debug('xpon_handler: Updating venet - {}'.format(request.name))
            self.root.update(path, request, strict=True)
            return Empty()
        
        except AssertionError, e:
            return Empty()
        
        except KeyError:
            context.set_details(
                'venet \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def deleteVEnet(self, request, context):
        log.info('grpc-request', request=request)
        
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        try:
            assert isinstance(request, v_enet_config)
            #assert device.admin_state == AdminState.DISABLED, \
                #'Device to delete cannot be ' \
                #'in admin state \'{}\''.format(device.admin_state)
            path = '/v_enets/{}'.format(request.name)
            log.debug('xpon_handler: Removing venet - {}'.format(request.name))
            self.root.remove(path)
            return Empty()
        
        except AssertionError:
            context.set_details(
                'Instance is not of venet')
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        
        except KeyError:
            context.set_details(
                'venet \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
    
    def validateInterface(self, request, context):
        try:
            if(isinstance(request, channelgroup_config)):
                assert isinstance(request, channelgroup_config)
                channelgroup = request
                assert channelgroup.name != '', 'Channel Group name is mandatory'
                assert 0 <= channelgroup.data.polling_period <= 864000, \
                    'Channel Group polling period must be in range of [1, 864000]'
                return True
            elif(isinstance(request, channelpartition_config)):
                assert isinstance(request, channelpartition_config)
                channelpartition = request
                assert channelpartition.name != '', 'Channel Partition name is mandatory'
                
                assert channelpartition.data.channelgroup_ref != '', \
                    'Channel Partition must reference a channel group'
                assert self.getRefData(request, context, "channel_groups", request.data.channelgroup_ref), \
                    'Reference to channel group -- \'{}\' not found'.format(request.data.channelgroup_ref)
                
                assert 0 <= channelpartition.data.closest_ont_distance <= 40, \
                    'Channel Partition closest ont distance must be in range of [0, 40]'
                    
                assert channelpartition.data.differential_fiber_distance == 0 or \
                    channelpartition.data.differential_fiber_distance == 20 or \
                    channelpartition.data.differential_fiber_distance == 34 or \
                    channelpartition.data.differential_fiber_distance == 40, \
                    'Channel Partition differential fiber distance must be [20 | 34 | 40]'
                return True
            elif(isinstance(request, channelpair_config)):
                assert isinstance(request, channelpair_config)
                channelpair = request
                channelpair_type = ["channelpair", "channelpair_xgs"]
                channelpair_speed_type = ["unplanned_cp_speed", "down_10_up_10", "down_10_up_2_5", "down_2_5_up_2_5"]
                assert channelpair.name != '', 'Channel Pair name is mandatory'
                
                if channelpair.data.channelgroup_ref:
                    assert self.getRefData(request, context, "channel_groups", request.data.channelgroup_ref), \
                        'Reference to channel group -- \'{}\' not found'\
                        .format(request.data.channelgroup_ref)
                if channelpair.data.channelpartition_ref:
                    assert self.getRefData(request, context, "channel_partitions", request.data.channelpartition_ref), \
                        'Reference to channel partition -- \'{}\' not found'\
                        .format(request.data.channelpartition_ref)
                
                assert channelpair.data.channelpair_type != '', 'Channel Pair type is mandatory'
                assert channelpair.data.channelpair_type in channelpair_type, \
                    'Invalid value for Channel Pair type \'{}\''.format(channelpair.data.channelpair_type)
                assert channelpair.data.channelpair_linerate in channelpair_speed_type, \
                    'Invalid value for Channel Pair linerate \'{}\''.format(channelpair.data.channelpair_linerate)
                return True
            elif(isinstance(request, channeltermination_config)):
                assert isinstance(request, channeltermination_config)
                channeltermin = request
                assert '/' not in channeltermin.id, 'Malformed device id \'{}\''.format(request.id)
                assert channeltermin.id != '', 'Device ID is mandatory'
                assert channeltermin.name != '', 'Channel Termination name is mandatory'
                
                if channeltermin.data.channelpair_ref:
                    assert self.getRefData(request, context, "channel_pairs", request.data.channelpair_ref), \
                        'Reference to channel pair -- \'{}\' not found'.format(request.data.channelpair_ref)
                
                assert 0 <= channeltermin.data.ber_calc_period <= 864000, \
                    'Channel Termination ber calc period must be in range of [1, 864000]'
                return True
            elif(isinstance(request, ontani_config)):
                assert isinstance(request, ontani_config)
                ontani = request
                assert ontani.name != '', 'OntAni name is mandatory'
                return True
            elif(isinstance(request, v_ontani_config)):
                assert isinstance(request, v_ontani_config)
                vontani = request
                assert vontani.name != '', 'VOntAni name is mandatory'
                
                if vontani.data.parent_ref:
                    assert self.getRefData(request, context, "channel_partitions", request.data.parent_ref), \
                        'Reference to channel partition -- \'{}\' not found'.format(request.data.parent_ref)
                if vontani.data.preferred_chanpair:
                    assert self.getRefData(request, context, "channel_pairs", request.data.preferred_chanpair), \
                        'Preferred channel pair -- \'{}\' not found'.format(request.data.preferred_chanpair)
                if vontani.data.protection_chanpair:
                    assert self.getRefData(request, context, "channel_pairs", request.data.protection_chanpair), \
                        'Protection channel pair -- \'{}\' not found'.format(request.data.protection_chanpair)
                
                assert 0 <= len(vontani.data.expected_registration_id) <= 36, \
                    'VOnt Ani expected registration id string length must be in range of [0, 36]'
                assert 0 <= vontani.data.onu_id <= 1020, \
                    'VOnt Ani ONU id must be in range of [0, 1020]'
                
                items = self.root.get('/v_ont_anis')
                for item in items:
                    if item.data.parent_ref == vontani.data.parent_ref or \
                        item.data.preferred_chanpair == vontani.data.preferred_chanpair or \
                        item.data.protection_chanpair == vontani.data.protection_chanpair:
                        assert item.data.onu_id != vontani.data.onu_id, \
                            'VOnt Ani ONU id -- \'{}\' already exists, but must be unique within channel group'.format(vontani.data.onu_id)
                return True
            elif(isinstance(request, v_enet_config)):
                assert isinstance(request, v_enet_config)
                venet = request
                assert venet.name != '', 'VEnet name is mandatory'
                
                if venet.data.v_ontani_ref:
                    assert self.getRefData(request, context, "v_ont_anis", venet.data.v_ontani_ref), \
                        'Reference to ont ani -- \'{}\' not found'.format(venet.data.v_ontani_ref)
                return True
            else:
                return False
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return False
    
    def getRefData(self, request, context, interface, reference):
        depth = int(dict(context.invocation_metadata()).get('get-depth', 0))
        
        try:
            path = '/{}/'.format(interface)
            self.root.get(path + reference, depth=depth)
            log.info('Reference for {} is found \'{}\''.format(interface, reference))
            return True
        
        except KeyError:
            log.info('Reference for {} not found -- \'{}\''.format(interface, reference))
            return False
