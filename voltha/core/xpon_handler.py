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
    AllVEnetConfig, VEnetConfig

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

    def get_all_channel_group_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_groups')
        return AllChannelgroupConfig(channelgroup_config=items)

    def create_channel_group(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, ChannelgroupConfig)
            assert self.validate_interface(request, context)
            log.debug('creating-channel-group', name=request.name)
            self.root.add('/channel_groups', request)

            return Empty()
        except AssertionError, e:
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel group \'{}\' cannot be created'.format(request.name))
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
            assert isinstance(request, ChannelgroupConfig)
            assert self.validate_interface(request, context)

            path = '/channel_groups/{}'.format(request.name)
            log.debug('updating-channel-group', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except AssertionError, e:
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
            assert isinstance(request, ChannelgroupConfig)
            known_channel_group_ref = dict(
                (dt.data.channelgroup_ref, dt) for dt in self.root.get('/channel_partitions'))
            known_channel_group_ref_1 = dict(
                (dt.data.channelgroup_ref, dt) for dt in self.root.get('/channel_pairs'))
            reference = "channel partition"
            assert request.name not in known_channel_group_ref
            reference = "channel pair"
            assert request.name not in known_channel_group_ref_1
            path = '/channel_groups/{}'.format(request.name)
            log.debug('removing-channel-group', name=request.name)
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

    def get_all_channel_partition_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_partitions')
        return AllChannelpartitionConfig(channelpartition_config=items)

    def create_channel_partition(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, ChannelpartitionConfig)
            assert self.validate_interface(request, context)
            log.debug('creating-channel-partition', name=request.name)
            self.root.add('/channel_partitions', request)

            return Empty()
        except AssertionError, e:
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel partition \'{}\' cannot be created'.format(request.name))
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
            assert isinstance(request, ChannelpartitionConfig)
            assert self.validate_interface(request, context)

            path = '/channel_partitions/{}'.format(request.name)
            log.debug('updating-channel-partition', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except AssertionError, e:
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
            assert isinstance(request, ChannelpartitionConfig)
            known_channel_partition_ref = dict(
                (dt.data.channelpartition_ref, dt) for dt in self.root.get('/channel_pairs'))
            known_channel_partition_ref_1 = dict(
                (dt.data.parent_ref, dt) for dt in self.root.get('/v_ont_anis'))
            reference = "channel pair"
            assert request.name not in known_channel_partition_ref
            reference = "vontani"
            assert request.name not in known_channel_partition_ref_1
            path = '/channel_partitions/{}'.format(request.name)
            log.debug('removing-channel-partition', name=request.name)
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

    def get_all_channel_pair_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/channel_pairs')
        return AllChannelpairConfig(channelpair_config=items)

    def create_channel_pair(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, ChannelpairConfig)
            assert self.validate_interface(request, context)
            log.debug('creating-channel-pair', name=request.name)
            self.root.add('/channel_pairs', request)

            return Empty()
        except AssertionError, e:
            return Empty()
        except ValueError:
            context.set_details(
                'Duplicated channel pair \'{}\' cannot be created'.format(request.name))
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
            assert isinstance(request, ChannelpairConfig)
            assert self.validate_interface(request, context)

            path = '/channel_pairs/{}'.format(request.name)
            log.debug('updating-channel-pair', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except AssertionError, e:
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
            assert isinstance(request, ChannelpairConfig)
            device_items = self.root.get('/devices')
            for device_item in device_items:
                known_channel_pair_ref = dict(
                    (dt.data.channelpair_ref, dt) for dt in self.root.get(
                        '/devices/{}/channel_terminations'.format(device_item.id)))
                assert request.name not in known_channel_pair_ref
            path = '/channel_pairs/{}'.format(request.name)
            log.debug('removing-channel-pair', name=request.name)
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
            assert isinstance(request, ChannelterminationConfig)
            assert self.validate_interface(request, context)
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
                'Duplicated channel termination \'{}\' cannot be created'.format(request.name))
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
            assert isinstance(request, ChannelterminationConfig)
            assert self.validate_interface(request, context)
        except AssertionError, e:
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

        try:
            path = '/devices/{}/channel_terminations/{}'.format(request.id, request.name)
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
                'Could not delete channel termination \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

    def get_all_ont_ani_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/ont_anis')
        return AllOntaniConfig(ontani_config=items)

    def create_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, OntaniConfig)
            assert self.validate_interface(request, context)
            log.debug('creating-ont-ani', name=request.name)
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

    def update_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return OntaniConfig()

        try:
            assert isinstance(request, OntaniConfig)
            assert self.validate_interface(request, context)

            path = '/ont_anis/{}'.format(request.name)
            log.debug('updating-ont-ani', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except AssertionError, e:
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
                'Instance is not of ont ani')
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
            assert isinstance(request, VOntaniConfig)
            assert self.validate_interface(request, context)
            log.debug('creating-vont-ani', name=request.name)
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

    def update_v_ont_ani(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return VOntaniConfig()

        try:
            assert isinstance(request, VOntaniConfig)
            assert self.validate_interface(request, context)

            path = '/v_ont_anis/{}'.format(request.name)
            log.debug('updating-vont-ani', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except AssertionError, e:
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
            assert isinstance(request, VOntaniConfig)
            known_v_ont_ani_ref = dict(
                (dt.data.v_ontani_ref, dt) for dt in self.root.get('/v_enets'))
            assert request.name not in known_v_ont_ani_ref

            path = '/v_ont_anis/{}'.format(request.name)
            log.debug('removing-vont-ani', name=request.name)
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

    def get_all_v_enet_config(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/v_enets')
        return AllVEnetConfig(v_enet_config=items)

    def create_v_enet(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, VEnetConfig)
            assert self.validate_interface(request, context)
            log.debug('creating-venet', name=request.name)
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

    def update_v_enet(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.name:
            context.set_details(
                'Malformed name \'{}\''.format(request.name))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return VEnetConfig()

        try:
            assert isinstance(request, VEnetConfig)
            assert self.validate_interface(request, context)

            path = '/v_enets/{}'.format(request.name)
            log.debug('updating-venet', name=request.name)
            self.root.update(path, request, strict=True)
            return Empty()

        except AssertionError, e:
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
            assert isinstance(request, VEnetConfig)
            #assert device.admin_state == AdminState.DISABLED, \
                #'Device to delete cannot be ' \
                #'in admin state \'{}\''.format(device.admin_state)
            path = '/v_enets/{}'.format(request.name)
            log.debug('removing-venet', name=request.name)
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

    def validate_interface(self, request, context):
        try:
            if(isinstance(request, ChannelgroupConfig)):
                assert isinstance(request, ChannelgroupConfig)
                channelgroup = request
                assert channelgroup.name != '', 'Channel Group name is mandatory'
                assert 0 <= channelgroup.data.polling_period <= 864000, \
                    'Channel Group polling period must be in range of [1, 864000]'
                return True
            elif(isinstance(request, ChannelpartitionConfig)):
                assert isinstance(request, ChannelpartitionConfig)
                channelpartition = request
                assert channelpartition.name != '', 'Channel Partition name is mandatory'

                assert channelpartition.data.channelgroup_ref != '', \
                    'Channel Partition must reference a channel group'
                assert self.get_ref_data(request, context, "channel_groups", request.data.channelgroup_ref), \
                    'Reference to channel group -- \'{}\' not found'.format(request.data.channelgroup_ref)

                assert 0 <= channelpartition.data.closest_ont_distance <= 40, \
                    'Channel Partition closest ont distance must be in range of [0, 40]'

                assert channelpartition.data.differential_fiber_distance == 0 or \
                    channelpartition.data.differential_fiber_distance == 20 or \
                    channelpartition.data.differential_fiber_distance == 34 or \
                    channelpartition.data.differential_fiber_distance == 40, \
                    'Channel Partition differential fiber distance must be [20 | 34 | 40]'
                return True
            elif(isinstance(request, ChannelpairConfig)):
                assert isinstance(request, ChannelpairConfig)
                channelpair = request
                channelpair_type = ["channelpair", "channelpair_xgs"]
                channelpair_speed_type = ["unplanned_cp_speed", "down_10_up_10", "down_10_up_2_5", "down_2_5_up_2_5"]
                assert channelpair.name != '', 'Channel Pair name is mandatory'

                if channelpair.data.channelgroup_ref:
                    assert self.get_ref_data(request, context, "channel_groups", request.data.channelgroup_ref), \
                        'Reference to channel group -- \'{}\' not found'\
                        .format(request.data.channelgroup_ref)
                if channelpair.data.channelpartition_ref:
                    assert self.get_ref_data(request, context, "channel_partitions", request.data.channelpartition_ref), \
                        'Reference to channel partition -- \'{}\' not found'\
                        .format(request.data.channelpartition_ref)

                assert channelpair.data.channelpair_type != '', 'Channel Pair type is mandatory'
                assert channelpair.data.channelpair_type in channelpair_type, \
                    'Invalid value for Channel Pair type \'{}\''.format(channelpair.data.channelpair_type)
                assert channelpair.data.channelpair_linerate in channelpair_speed_type, \
                    'Invalid value for Channel Pair linerate \'{}\''.format(channelpair.data.channelpair_linerate)
                return True
            elif(isinstance(request, ChannelterminationConfig)):
                assert isinstance(request, ChannelterminationConfig)
                channeltermin = request
                assert '/' not in channeltermin.id, 'Malformed device id \'{}\''.format(request.id)
                assert channeltermin.id != '', 'Device ID is mandatory'
                assert channeltermin.name != '', 'Channel Termination name is mandatory'

                if channeltermin.data.channelpair_ref:
                    assert self.get_ref_data(request, context, "channel_pairs", request.data.channelpair_ref), \
                        'Reference to channel pair -- \'{}\' not found'.format(request.data.channelpair_ref)

                assert 0 <= channeltermin.data.ber_calc_period <= 864000, \
                    'Channel Termination ber calc period must be in range of [1, 864000]'
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

                if vontani.data.parent_ref:
                    assert self.get_ref_data(request, context, "channel_partitions", request.data.parent_ref), \
                        'Reference to channel partition -- \'{}\' not found'.format(request.data.parent_ref)
                if vontani.data.preferred_chanpair:
                    assert self.get_ref_data(request, context, "channel_pairs", request.data.preferred_chanpair), \
                        'Preferred channel pair -- \'{}\' not found'.format(request.data.preferred_chanpair)
                if vontani.data.protection_chanpair:
                    assert self.get_ref_data(request, context, "channel_pairs", request.data.protection_chanpair), \
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
            elif(isinstance(request, VEnetConfig)):
                assert isinstance(request, VEnetConfig)
                venet = request
                assert venet.name != '', 'VEnet name is mandatory'

                if venet.data.v_ontani_ref:
                    assert self.get_ref_data(request, context, "v_ont_anis", venet.data.v_ontani_ref), \
                        'Reference to ont ani -- \'{}\' not found'.format(venet.data.v_ontani_ref)
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
            log.info('reference-for-{}-found-\'{}\''.format(interface, reference))
            return True

        except KeyError:
            log.info('reference-for-{}-not-found-\'{}\''.format(interface, reference))
            return False
