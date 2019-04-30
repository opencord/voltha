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
    AllChannelgroupConfig, ChannelgroupConfig, \
    AllChannelpairConfig, ChannelpairConfig, \
    AllChannelpartitionConfig, ChannelpartitionConfig, \
    AllChannelterminationConfig, ChannelterminationConfig, \
    AllOntaniConfig, OntaniConfig, AllVOntaniConfig , VOntaniConfig, \
    AllVEnetConfig, VEnetConfig, AllTrafficDescriptorProfileData, \
    AllTcontsConfigData, AllGemportsConfigData
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData

from voltha.protos.device_pb2 import Device
from voltha.protos.common_pb2 import AdminState

from common.utils.indexpool import IndexPool

from requests.api import request

log = structlog.get_logger()


class XponHandler(object):
    def __init__(self, core):
        self.core = core
        self.root = None
        '''
        Pool for handling channel group indices
        @TODO: As per current persistency & HA design, each VOLTHA instance
            maintains a separate independent database. Since channel-groups are
            broadcast to all the VOLTHA instances in the cluster, the
            xpon_handler in each instance will independently try to allocate a
            unique index. This approach works OK for XGS-PON since CG<->CTerm
            relationship is 1:1 for XGS-PON(Since a device can only be served
            by one VOLTHA instance and thereby CTerm). This needs to be further
            investigated wrt persistency & HA design evolution, for a better
            approach in future.
        '''
        self.cg_pool = IndexPool(2**11-1, 1)
        self.cg_dict = {}

    def start(self, root):
        log.debug('starting xpon_handler')
        self.root = root
        self.reinitialize_cg_ids()
        self.reinitialize_tcont_and_gemport_ids()

    def reinitialize_cg_ids(self):
        cg_tup = ()
        channel_groups = self.root.get('/channel_groups')
        for cg in channel_groups:
            cg_tup += (cg.cg_index, )
            '''
            Pools for handling alloc-ids and gemport-ids
            @TODO: As per current persistency & HA design, each VOLTHA instance
                maintains a separate independent database. Since channel-groups
                broadcast to all the VOLTHA instances in the cluster, the
                xpon_handler in each instance will independently try to
                allocate a unique index. This approach works OK for XGS-PON
                since CG<->CTerm relationship is 1:1 for XGS-PON(Since a device
                can only be served by one VOLTHA instance and thereby CTerm).
                This needs to be further investigated wrt persistency & HA
                design evolution, for a better approach in future.
            '''
            self.cg_dict[cg.name] = {'alloc_id': IndexPool(16383, 1024)}
            self.cg_dict[cg.name].update({'gemport_id': IndexPool(64500, 1024)})
        self.cg_pool.pre_allocate(cg_tup)

    def reinitialize_tcont_and_gemport_ids(self):
        tconts = self.root.get('/tconts')
        for tc in tconts:
            cg_name = self.extract_channel_group_from_request(tc,
                        'v_ont_anis', tc.interface_reference)
            self.cg_dict[cg_name]['alloc_id'].pre_allocate((tc.alloc_id, ))
        gemports = self.root.get('/gemports')
        for gm in gemports:
            cg_name = self.extract_channel_group_from_request(gm,
                        'v_enets', gm.itf_ref)
            self.cg_dict[cg_name]['gemport_id'].pre_allocate((gm.gemport_id, ))

    def get_all_channel_group_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_groups')
        return AllChannelgroupConfig(channelgroup_config=items)

    def get_channel_group_config(self, request, context):
        log.info('grpc-request', request=request)
        item = self.root.get('/channel_groups/{}'.format(request.name))
        if(isinstance(item, ChannelgroupConfig)):
            return item
        return Empty()

    def create_channel_group(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, ChannelgroupConfig), \
                'Instance is not of Channel Group'
            assert self.validate_interface(request, context)
            log.debug('creating-channel-group', name=request.name)
            _id = self.cg_pool.get_next()
            assert _id != None, \
                'Fail to allocate id for Channel Group'
            request.cg_index = _id
            self.root.add('/channel_groups', request)
            self.cg_dict[request.name] = {'alloc_id': IndexPool(16383, 1024)}
            self.cg_dict[request.name].update({'gemport_id': IndexPool(64500, 1024)})

            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except ValueError:
            self.cg_pool.release(_id)
            context.set_details(
                'Duplicated channel group \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_channel_group(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return ChannelgroupConfig()

        try:
            assert isinstance(request, ChannelgroupConfig), \
                'Instance is not of Channel Group'
            assert self.validate_interface(request, context)
            channelgroup = self.get_channel_group_config(request, context)
            request.cg_index = channelgroup.cg_index
            path = '/channel_groups/{}'.format(request.name)
            log.debug('updating-channel-group', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                    'channel group \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_channel_group(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            assert isinstance(request, ChannelgroupConfig), \
                'Instance is not of Channel Group'
            channelgroup_ref_by_channelpartition = next(
                (cpart for cpart in self.root.get('/channel_partitions')
                 if cpart.data.channelgroup_ref == request.name), None)
            assert channelgroup_ref_by_channelpartition is None, \
                'Channel Group -- \'{}\' is referenced by Channel Partition'\
                .format(request.name)
            channelgroup_ref_by_channelpair = next(
                (cpair for cpair in self.root.get('/channel_pairs')
                 if cpair.data.channelgroup_ref == request.name), None)
            assert channelgroup_ref_by_channelpair is None, \
                'Channel Group -- \'{}\' is referenced by Channel Pair'\
                .format(request.name)
            channelgroup = self.get_channel_group_config(request, context)
            path = '/channel_groups/{}'.format(request.name)
            log.debug('removing-channel-group', name=request.name)
            self.root.remove(path)
            self.cg_pool.release(channelgroup.cg_index)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'channel group \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_channel_partition_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_partitions')
        return AllChannelpartitionConfig(channelpartition_config=items)

    def create_channel_partition(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, ChannelpartitionConfig), \
                'Instance is not of Channel Partition'
            assert self.validate_interface(request, context)
            log.debug('creating-channel-partition', name=request.name)
            self.root.add('/channel_partitions', request)

            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel partition \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_channel_partition(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return ChannelpartitionConfig()

        try:
            assert isinstance(request, ChannelpartitionConfig), \
                'Instance is not of Channel Partition'
            assert self.validate_interface(request, context)

            path = '/channel_partitions/{}'.format(request.name)
            log.debug('updating-channel-partition', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                    'channel partition \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_channel_partition(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            assert isinstance(request, ChannelpartitionConfig), \
                'Instance is not of Channel Partition'
            channelpartition_ref_by_channelpair = next(
                (cpair for cpair in self.root.get('/channel_pairs')
                 if cpair.data.channelpartition_ref == request.name), None)
            assert channelpartition_ref_by_channelpair is None, \
                'Channel Partition -- \'{}\' is referenced by Channel Pair'\
                .format(request.name)
            channelpartition_ref_by_vontani = next(
                (vont_ani for vont_ani in self.root.get('/v_ont_anis')
                 if vont_ani.data.parent_ref == request.name), None)
            assert channelpartition_ref_by_vontani is None, \
                'Channel Partition -- \'{}\' is referenced by VOntAni'\
                .format(request.name)
            path = '/channel_partitions/{}'.format(request.name)
            log.debug('removing-channel-partition', name=request.name)
            self.root.remove(path)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'channel partition \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_channel_pair_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_pairs')
        return AllChannelpairConfig(channelpair_config=items)

    def create_channel_pair(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, ChannelpairConfig), \
                'Instance is not of Channel Pair'
            assert self.validate_interface(request, context)
            log.debug('creating-channel-pair', name=request.name)
            self.root.add('/channel_pairs', request)

            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel pair \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_channel_pair(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return ChannelpairConfig()
        try:
            assert isinstance(request, ChannelpairConfig), \
                'Instance is not of Channel Pair'
            assert self.validate_interface(request, context)

            path = '/channel_pairs/{}'.format(request.name)
            log.debug('updating-channel-pair', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                    'channel pair \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_channel_pair(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            assert isinstance(request, ChannelpairConfig), \
                'Instance is not of Channel Pair'
            device_items = self.root.get('/devices')
            for device_item in device_items:
                channelpair_ref_by_channeltermination = next(
                    (cterm for cterm in self.root.get(
                        '/devices/{}/channel_terminations'.format(
                            device_item.id))
                     if cterm.data.channelpair_ref == request.name), None)
                assert channelpair_ref_by_channeltermination is None, \
                    'Channel Pair -- \'{}\' referenced by Channel Termination'\
                    .format(request.name)
            path = '/channel_pairs/{}'.format(request.name)
            log.debug('removing-channel-pair', name=request.name)
            self.root.remove(path)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'channel pair \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_channel_termination_config(self, request, context):
        log.info('grpc-request', request=request)
        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return AllChannelterminationConfig()

        try:
            items = self.root.get(
                '/devices/{}/channel_terminations'.format(request.id))
            return AllChannelterminationConfig(channeltermination_config=items)
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return AllChannelterminationConfig()

    def create_channel_termination(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, ChannelterminationConfig), \
                'Instance is not of Channel Termination'
            assert self.validate_interface(request, context)
            #device = self.root.get('/devices/{}'.format(request.id))
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        try:
            path = '/devices/{}/channel_terminations'.format(request.id)
            log.debug('creating-channel-termination', name=request.name)
            self.root.add(path, request)
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not activated'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel termination \'{}\' cannot be created'.
                format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_channel_termination(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return ChannelterminationConfig()

        try:
            assert isinstance(request, ChannelterminationConfig), \
                'Instance is not of Channel Termination'
            assert self.validate_interface(request, context)
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

        try:
            path = '/devices/{}/channel_terminations/{}'.format(
                request.id, request.name)
            log.debug('updating-channel-termination', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except KeyError:
            context.set_details(
                'channel termination \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_channel_termination(self, request, context):
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
            assert isinstance(request, ChannelterminationConfig)
        except AssertionError:
            context.set_details(
                'Instance is not of Channel Termination')
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        try:
            path = '/devices/{}/channel_terminations/{}'.format(
                request.id, request.name)
        except KeyError:
            context.set_details(
                'channel termination \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        try:
            log.debug('removing-channel-termination', name=request.name)
            self.root.remove(path)
            return Empty()

        except KeyError:
            context.set_details(
                'Could not delete channel termination \'{}\''.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def get_all_ont_ani_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/ont_anis')
        return AllOntaniConfig(ontani_config=items)

    def create_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, OntaniConfig), \
                'Instance is not of Ont Ani'
            assert self.validate_interface(request, context)
            log.debug('creating-ont-ani', name=request.name)
            self.root.add('/ont_anis', request)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create ontani \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated ontani \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return OntaniConfig()

        try:
            assert isinstance(request, OntaniConfig), \
                'Instance is not of Ont Ani'
            assert self.validate_interface(request, context)

            path = '/ont_anis/{}'.format(request.name)
            log.debug('updating-ont-ani', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'ontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            assert isinstance(request, OntaniConfig)

            path = '/ont_anis/{}'.format(request.name)
            log.debug('removing-ont-ani', name=request.name)
            self.root.remove(path)
            return Empty()

        except AssertionError:
            context.set_details(
                'Instance is not of Ont Ani')
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        except KeyError:
            context.set_details(
                'ontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_v_ont_ani_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/v_ont_anis')
        return AllVOntaniConfig(v_ontani_config=items)

    def create_v_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, VOntaniConfig), \
                'Instance is not of VOnt Ani'
            assert self.validate_interface(request, context)
            log.debug('creating-vont-ani', name=request.name)
            self.root.add('/v_ont_anis', request)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create vontani \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated vontani \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_v_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return VOntaniConfig()

        try:
            assert isinstance(request, VOntaniConfig), \
                'Instance is not of VOnt Ani'
            assert self.validate_interface(request, context)
            path = '/v_ont_anis/{}'.format(request.name)
            log.debug('updating-vont-ani', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'vontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_v_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        try:
            assert isinstance(request, VOntaniConfig), \
                'Instance is not of vont ani'
            vontani_ref_by_venet = next(
                (venet for venet in self.root.get('/v_enets')
                 if venet.data.v_ontani_ref == request.name), None)
            assert vontani_ref_by_venet is None, \
                'VOntAni -- \'{}\' is referenced by VEnet'.format(
                    request.name)
            vontani_ref_by_tcont = next(
                (tcont for tcont in self.root.get('/tconts')
                 if tcont.interface_reference == request.name), None)
            assert vontani_ref_by_tcont is None, \
                'VOntAni -- \'{}\' is referenced by TCont'.format(
                    request.name)
            path = '/v_ont_anis/{}'.format(request.name)
            log.debug('removing-vont-ani', name=request.name)
            self.root.remove(path)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'vontani \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_v_enet_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/v_enets')
        return AllVEnetConfig(v_enet_config=items)

    def create_v_enet(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, VEnetConfig), \
                'Instance is not of VEnet'
            assert self.validate_interface(request, context)
            log.debug('creating-venet', name=request.name)
            self.root.add('/v_enets', request)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create venet \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated venet \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_v_enet(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return VEnetConfig()

        try:
            assert isinstance(request, VEnetConfig), \
                'Instance is not of VEnet'
            assert self.validate_interface(request, context)
            path = '/v_enets/{}'.format(request.name)
            log.debug('updating-venet', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'venet \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_v_enet(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            assert isinstance(request, VEnetConfig), \
                'Instance is not of VEnet'
            #assert device.admin_state == AdminState.DISABLED, \
                #'Device to delete cannot be ' \
                #'in admin state \'{}\''.format(device.admin_state)
            v_enet_ref_by_gemport = next(
                (gemport for gemport in self.root.get('/gemports')
                 if gemport.itf_ref == request.name), None)
            assert v_enet_ref_by_gemport is None, \
                'The VEnet -- \'{}\' is referenced by Gemport'.format(
                    request.name)
            path = '/v_enets/{}'.format(request.name)
            log.debug('removing-venet', name=request.name)
            self.root.remove(path)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'venet \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_traffic_descriptor_profile_data(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/traffic_descriptor_profiles')
        return AllTrafficDescriptorProfileData(
            traffic_descriptor_profiles=items)

    def create_traffic_descriptor_profile(self, request, context):
        log.info('grpc-request', request=request)
        try:
            assert isinstance(request, TrafficDescriptorProfileData), \
                'Instance is not of Traffic Descriptor Profile'
            assert self.validate_interface(request, context)
            log.debug('creating-traffic-descriptor-profile', name=request.name)
            self.root.add('/traffic_descriptor_profiles', request)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create traffic descriptor profile \'{}\''.format(
                    request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated traffic descriptor profile \'{}\' \
                cannot be created'.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_traffic_descriptor_profile(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return TrafficDescriptorProfileData()

        try:
            assert isinstance(request, TrafficDescriptorProfileData), \
                'Instance is not of Traffic Descriptor Profile'
            assert self.validate_interface(request, context)
            path = '/traffic_descriptor_profiles/{}'.format(request.name)
            log.debug('updating-traffic-descriptor-profile',
                      name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'traffic descriptor profile \'{}\' not found'.format(
                    request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_traffic_descriptor_profile(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            assert isinstance(request, TrafficDescriptorProfileData), \
                'Instance is not of Traffic Descriptor Profile'
            tdp_ref_by_tcont = next(
                (tcont for tcont in self.root.get('/tconts') if
                 tcont.traffic_descriptor_profile_ref == request.name), None)
            assert tdp_ref_by_tcont is None, \
                'The Traffic Descriptor Profile -- \'{}\' is referenced \
                by TCont'.format(request.name)
            path = '/traffic_descriptor_profiles/{}'.format(request.name)
            log.debug('removing-traffic-descriptor-profile',
                      name=request.name)
            self.root.remove(path)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'traffic descriptor profile \'{}\' not found'.format(
                    request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_tconts_config_data(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/tconts')
        return AllTcontsConfigData(tconts_config=items)

    def create_tcont(self, request, context):
        log.info('grpc-request', request=request)
        try:
            assert isinstance(request, TcontsConfigData), \
                'Instance is not of TCont'
            assert self.validate_interface(request, context)
            cg_name = self.extract_channel_group_from_request(request,
                        'v_ont_anis', request.interface_reference)
            if request.alloc_id == 0:
                _id = self.cg_dict[cg_name]['alloc_id'].get_next()
                assert _id is not None, \
                    'Fail to allocate id for TCont'
                request.alloc_id = _id
            else:
                _id = self.cg_dict[cg_name]['alloc_id'].allocate(request.alloc_id)
                assert _id == request.alloc_id, \
                    'Fail to allocate id for TCont'

            log.debug('creating-tcont', name=request.name)
            self.root.add('/tconts', request)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create tcont \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            self.cg_dict[cg_name]['alloc_id'].release(_id)
            context.set_details(
                'Duplicated tcont \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_tcont(self, request, context):
        log.info('grpc-request', request=request)
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return TcontsConfigData()
        try:
            assert isinstance(request, TcontsConfigData), \
                'Instance is not of TCont'
            assert self.validate_interface(request, context)
            path = '/tconts/{}'.format(request.name)
            tcont = self.root.get(path)
            request.alloc_id = tcont.alloc_id
            log.debug('updating-tcont', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'tcont \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_tcont(self, request, context):
        log.info('grpc-request', request=request)
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        try:
            assert isinstance(request, TcontsConfigData), \
                'Instance is not of TCont'
            tcont_ref_by_gemport = next(
                (gemport for gemport in self.root.get('/gemports')
                 if gemport.tcont_ref == request.name), None)
            assert tcont_ref_by_gemport is None, \
                'The Tcont -- \'{}\' is referenced by GemPort'.format(
                    request.name)
            path = '/tconts/{}'.format(request.name)
            tcont = self.root.get(path)
            cg_name = self.extract_channel_group_from_request(tcont,
                        'v_ont_anis', tcont.interface_reference)
            log.debug('removing-tcont', name=request.name)
            self.root.remove(path)
            self.cg_dict[cg_name]['alloc_id'].release(tcont.alloc_id)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'tcont \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def get_all_gemports_config_data(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/gemports')
        return AllGemportsConfigData(gemports_config=items)

    def create_gem_port(self, request, context):
        log.info('grpc-request', request=request)
        try:
            assert isinstance(request, GemportsConfigData), \
                'Instance is not of GemPort'
            assert self.validate_interface(request, context)
            cg_name = self.extract_channel_group_from_request(request,
                        'v_enets', request.itf_ref)
            if request.gemport_id == 0:
                _id = self.cg_dict[cg_name]['gemport_id'].get_next()
                assert _id is not None, \
                    'Fail to allocate id for GemPort'
                request.gemport_id = _id
            else:
                _id = self.cg_dict[cg_name]['gemport_id'].allocate(request.gemport_id)
                assert _id == request.gemport_id, \
                    'Fail to allocate id for GemPort'

            log.debug('creating-gemport', name=request.name)
            self.root.add('/gemports', request)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'Cannot create gemport \'{}\''.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()
        except ValueError:
            self.cg_dict[cg_name]['gemport_id'].release(_id)
            context.set_details(
                'Duplicated gemport \'{}\' cannot be created'.format(
                    request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def update_gem_port(self, request, context):
        log.info('grpc-request', request=request)
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return GemportsConfigData()
        try:
            assert isinstance(request, GemportsConfigData), \
                'Instance is not of GemPort'
            assert self.validate_interface(request, context)
            path = '/gemports/{}'.format(request.name)
            gemport = self.root.get(path)
            request.gemport_id = gemport.gemport_id
            log.debug('updating-gemport', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'gemport \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def delete_gem_port(self, request, context):
        log.info('grpc-request', request=request)
        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        try:
            assert isinstance(request, GemportsConfigData)
            path = '/gemports/{}'.format(request.name)
            gemport = self.root.get(path)
            cg_name = self.extract_channel_group_from_request(gemport,
                        'v_enets', gemport.itf_ref)
            log.debug('removing-gemport', name=request.name)
            self.root.remove(path)
            self.cg_dict[cg_name]['gemport_id'].release(gemport.gemport_id)
            return Empty()
        except AssertionError:
            context.set_details('Instance is not of GemPort')
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()
        except KeyError:
            context.set_details(
                'gemport \'{}\' not found'.format(request.name))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    def validate_interface(self, request, context):
        try:
            if(isinstance(request, ChannelgroupConfig)):
                assert isinstance(request, ChannelgroupConfig)
                channelgroup = request
                assert channelgroup.name != '', \
                    'Channel Group name is mandatory'
                assert 0 <= channelgroup.data.polling_period <= 864000, \
                    'Channel Group polling period must be in range of \
                    [1, 864000]'
                return True
            elif(isinstance(request, ChannelpartitionConfig)):
                assert isinstance(request, ChannelpartitionConfig)
                channelpartition = request
                assert channelpartition.name != '', \
                    'Channel Partition name is mandatory'

                assert channelpartition.data.channelgroup_ref != '', \
                    'Channel Partition must reference a channel group'
                assert self.get_ref_data(
                    request, context, "channel_groups",
                    request.data.channelgroup_ref), \
                    'Reference to channel group -- \'{}\' not found'.format(
                        request.data.channelgroup_ref)

                assert 0 <= channelpartition.data.closest_ont_distance <= 40, \
                    'Channel Partition closest ont distance must be in range \
                    of [0, 40]'

                assert channelpartition.data.differential_fiber_distance \
                    == 0 or \
                    channelpartition.data.differential_fiber_distance == 20 \
                    or channelpartition.data.differential_fiber_distance \
                    == 34 or \
                    channelpartition.data.differential_fiber_distance == 40, \
                    'Channel Partition differential fiber distance must be \
                    [20 | 34 | 40]'
                return True
            elif(isinstance(request, ChannelpairConfig)):
                assert isinstance(request, ChannelpairConfig)
                channelpair = request
                channelpair_type = ["channelpair", "channelpair_xgs"]
                channelpair_speed_type = ["unplanned_cp_speed",
                                          "down_10_up_10", "down_10_up_2_5",
                                          "down_2_5_up_2_5"]
                assert channelpair.name != '', 'Channel Pair name is mandatory'

                if channelpair.data.channelgroup_ref:
                    assert self.get_ref_data(
                        request, context, "channel_groups",
                        request.data.channelgroup_ref), \
                        'Reference to channel group -- \'{}\' not found'\
                        .format(request.data.channelgroup_ref)
                '''
                @todo: For VOLTHA 1.0, make this reference mandatory until
                       VOL-314 & VOL-356 are implemented.
                '''
                assert channelpair.data.channelpartition_ref != '', \
                    'Channel Pair must reference an existing Channel Partition'
                assert self.get_ref_data(
                    request, context, "channel_partitions",
                    request.data.channelpartition_ref), \
                    'Reference to channel partition -- \'{}\' not found'\
                    .format(request.data.channelpartition_ref)

                assert channelpair.data.channelpair_type != '', \
                    'Channel Pair type is mandatory'
                assert channelpair.data.channelpair_type in channelpair_type, \
                    'Invalid value for Channel Pair type \'{}\''\
                    .format(channelpair.data.channelpair_type)
                assert channelpair.data.channelpair_linerate in \
                    channelpair_speed_type, \
                    'Invalid value for Channel Pair linerate \'{}\''\
                    .format(channelpair.data.channelpair_linerate)
                return True
            elif(isinstance(request, ChannelterminationConfig)):
                assert isinstance(request, ChannelterminationConfig)
                channeltermin = request
                assert '/' not in channeltermin.id, \
                    'Malformed device id \'{}\''.format(request.id)
                assert channeltermin.id != '', 'Device ID is mandatory'
                assert channeltermin.name != '', \
                    'Channel Termination name is mandatory'
                '''
                @todo: For VOLTHA 1.0, make this reference mandatory until
                       VOL-314 & VOL-356 are implemented.
                '''
                assert channeltermin.data.channelpair_ref != '', \
                    'Channel Termination must reference Channel Pair'
                assert self.get_ref_data(
                    request, context, "channel_pairs",
                    request.data.channelpair_ref), \
                    'Reference to channel pair -- \'{}\' not found'\
                    .format(request.data.channelpair_ref)

                assert 0 <= channeltermin.data.ber_calc_period <= 864000, \
                    'Channel Termination ber calc period must be in range of \
                    [1, 864000]'
                return True
            elif(isinstance(request, OntaniConfig)):
                assert isinstance(request, OntaniConfig)
                ontani = request
                assert ontani.name != '', 'OntAni name is mandatory'
                return True
            elif(isinstance(request, VOntaniConfig)):
                assert isinstance(request, VOntaniConfig)
                vontani = request
                assert vontani.name != '', 'VOntAni name is mandatory'
                assert vontani.data.parent_ref != '', \
                    'VOntAni must reference an existing Channel Partition'
                assert self.get_ref_data(
                    request, context, "channel_partitions",
                    request.data.parent_ref), \
                    'Reference to channel partition -- \'{}\' not found'\
                    .format(request.data.parent_ref)
                '''
                @todo: For VOLTHA 1.0, make this reference mandatory until
                       VOL-314 & VOL-356 are implemented.
                '''
                assert vontani.data.preferred_chanpair != '', \
                    'VOntAni must reference preferred Channel Pair'
                #if vontani.data.preferred_chanpair:
                assert self.get_ref_data(
                    request, context, "channel_pairs",
                    request.data.preferred_chanpair), \
                    'Preferred channel pair -- \'{}\' not found'\
                    .format(request.data.preferred_chanpair)
                if vontani.data.protection_chanpair:
                    assert self.get_ref_data(
                        request, context, "channel_pairs",
                        request.data.protection_chanpair), \
                        'Protection channel pair -- \'{}\' not found'\
                        .format(request.data.protection_chanpair)

                assert 0 <= len(vontani.data.expected_registration_id) <= 36, \
                    'VOnt Ani expected registration id string length must be \
                    in range of [0, 36]'
                assert 0 <= vontani.data.onu_id <= 1020, \
                    'VOnt Ani ONU id must be in range of [0, 1020]'

                items = self.root.get('/v_ont_anis')
                for item in items:
                    if item.data.parent_ref == vontani.data.parent_ref or \
                        item.data.preferred_chanpair == \
                        vontani.data.preferred_chanpair or \
                        item.data.protection_chanpair == \
                        vontani.data.protection_chanpair:
                        if item.name != vontani.name:
                            assert item.data.onu_id != vontani.data.onu_id, \
                                'VOnt Ani ONU id -- \'{}\' already exists, \
                                but must be unique within channel group'\
                                .format(vontani.data.onu_id)
                return True
            elif(isinstance(request, VEnetConfig)):
                assert isinstance(request, VEnetConfig)
                venet = request
                assert venet.name != '', 'VEnet name is mandatory'
                assert venet.data.v_ontani_ref != '', \
                    'VEnet must reference an existing VOntAni'
                assert self.get_ref_data(
                    request, context, "v_ont_anis", venet.data.v_ontani_ref), \
                    'Reference to VOntAni -- \'{}\' not found'\
                    .format(venet.data.v_ontani_ref)
                return True
            elif(isinstance(request, TrafficDescriptorProfileData)):
                assert isinstance(request, TrafficDescriptorProfileData)
                traffic_descriptor = request
                assert traffic_descriptor.name != '', \
                    'Traffic Descriptor Profile name is mandatory'
                assert traffic_descriptor.fixed_bandwidth != '', \
                    'Fixed bandwidth of Traffic Descriptor is mandatory'
                assert traffic_descriptor.assured_bandwidth != '', \
                    'Assured bandwidth of Traffic Descriptor is mandatory'
                assert traffic_descriptor.maximum_bandwidth != '', \
                    'Maximum bandwidth of Traffic Descriptor is mandatory'
                assert 0 <= traffic_descriptor.priority <= 8, \
                    'Traffic Descriptor Profile priority for or scheduling \
                    traffic on a TCont must be in range of [1, 8]'
                return True
            elif(isinstance(request, TcontsConfigData)):
                assert isinstance(request, TcontsConfigData)
                tcont = request
                assert tcont.name != '', 'TCont name is mandatory'
                assert tcont.interface_reference != '', \
                    'TCont must reference a vont ani interface'
                assert tcont.traffic_descriptor_profile_ref != '', \
                    'TCont must reference an existing traffic descriptor \
                    profile'
                assert self.get_ref_data(
                    request, context, "v_ont_anis",
                    tcont.interface_reference), \
                    'Reference to vont ani interface -- \'{}\' not found'\
                    .format(tcont.interface_reference)
                assert self.get_ref_data(
                    request, context, "traffic_descriptor_profiles",
                    tcont.traffic_descriptor_profile_ref), \
                    'Reference to traffic descriptor profile -- \'{}\' \
                    not found'.format(tcont.traffic_descriptor_profile_ref)
                return True
            elif(isinstance(request, GemportsConfigData)):
                assert isinstance(request, GemportsConfigData)
                gemport = request
                assert gemport.name != '', 'Gemport name is mandatory'
                assert gemport.itf_ref != '', \
                    'GemPort must reference an existing VEnet interface'
                assert self.get_ref_data(
                    request, context, "v_enets", gemport.itf_ref), \
                    'Reference to VEnet interface -- \'{}\' not found'\
                    .format(gemport.itf_ref)
                assert 0 <= gemport.traffic_class <= 7, \
                    'Traffic class value for Gemport \
                    must be in range of [0, 7]'
                '''
                @todo: For VOLTHA 1.0, make this reference mandatory until
                       VOL-314 & VOL-356 are implemented.
                '''
                assert gemport.tcont_ref != '', \
                    'GemPort must reference an existing TCont'
                assert self.get_ref_data(
                    request, context, "tconts", gemport.tcont_ref), \
                    'Reference to tcont -- \'{}\' not found'\
                    .format(gemport.tcont_ref)
                return True
            else:
                return False
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return False

    def get_ref_data(self, request, context, interface, reference):
        depth = int(dict(context.invocation_metadata()).get('get-depth', 0))

        try:
            path = '/{}/'.format(interface)
            self.root.get(path + reference, depth=depth)
            log.info('reference-for-{}-found-\'{}\''\
                     .format(interface, reference))
            return True

        except KeyError:
            log.info('reference-for-{}-not-found-\'{}\''\
                     .format(interface, reference))
            return False

    def extract_channel_group_from_request(self, request, interface,
                                     reference):
        try:
            path = '/{}/{}'.format(interface, reference)
            item = self.root.get(path)
            if isinstance(item, ChannelgroupConfig):
                return item.name
            elif isinstance(item, VEnetConfig):
                return self.extract_channel_group_from_request(Empty(),
                            'v_ont_anis', item.data.v_ontani_ref)
            elif isinstance(item, VOntaniConfig):
                return self.extract_channel_group_from_request(Empty(),
                            'channel_partitions', item.data.parent_ref)
            elif isinstance(item, ChannelpartitionConfig):
                return self.extract_channel_group_from_request(Empty(),
                            'channel_groups', item.data.channelgroup_ref)
        except KeyError:
            log.info('reference-for-{}-not found'.format(interface))
            return Empty()
