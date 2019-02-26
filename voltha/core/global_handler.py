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
import sys
import structlog
from grpc import StatusCode
from twisted.internet.defer import inlineCallbacks
from twisted.internet.defer import returnValue

from common.utils.grpc_utils import twisted_async
from common.utils.id_generation import \
    create_cluster_id, create_empty_broadcast_id
from voltha.core.config.config_root import ConfigRoot
from voltha.protos.device_pb2 import PmConfigs, Images, \
    ImageDownload, ImageDownloads
from voltha.protos.common_pb2 import OperationResp
from voltha.protos.voltha_pb2_grpc import \
    add_VolthaGlobalServiceServicer_to_server, VolthaLocalServiceStub, \
    VolthaGlobalServiceServicer, VolthaGlobalServiceStub
from voltha.protos.voltha_pb2 import \
    Voltha, VolthaInstances, VolthaInstance, \
    LogicalDevice, LogicalPort, Ports, Flows, FlowGroups, Device, SelfTestResponse, \
    Devices, DeviceType, DeviceTypes, DeviceGroup, \
    AlarmFilter, AlarmFilters
from voltha.registry import registry
from google.protobuf.empty_pb2 import Empty
from dispatcher import DispatchError
from voltha.protos import bbf_fiber_base_pb2 as fb
from voltha.protos.bbf_fiber_base_pb2 import ChannelgroupConfig, \
    ChannelpartitionConfig, ChannelpairConfig, ChannelterminationConfig, \
    OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_multicast_gemport_body_pb2 import \
    MulticastGemportsConfigData
from voltha.protos.bbf_fiber_multicast_distribution_set_body_pb2 import \
    MulticastDistributionSetData
from voltha.protos.omci_mib_db_pb2 import MibDeviceData
from voltha.protos.omci_alarm_db_pb2 import AlarmDeviceData

log = structlog.get_logger()


class GlobalHandler(VolthaGlobalServiceServicer):

    xpon_object_type = {
        'CreateChannelgroup': ChannelgroupConfig,
        'UpdateChannelgroup': ChannelgroupConfig,
        'DeleteChannelgroup': ChannelgroupConfig,
        'CreateChannelpartition': ChannelpartitionConfig,
        'UpdateChannelpartition': ChannelpartitionConfig,
        'DeleteChannelpartition': ChannelpartitionConfig,
        'CreateChannelpair': ChannelpairConfig,
        'UpdateChannelpair': ChannelpairConfig,
        'DeleteChannelpair': ChannelpairConfig,
        'CreateChanneltermination': ChannelterminationConfig,
        'UpdateChanneltermination': ChannelterminationConfig,
        'DeleteChanneltermination': ChannelterminationConfig,
        'CreateVOntani': VOntaniConfig,
        'UpdateVOntani': VOntaniConfig,
        'DeleteVOntani': VOntaniConfig,
        'CreateOntani': OntaniConfig,
        'UpdateOntani': OntaniConfig,
        'DeleteOntani': OntaniConfig,
        'CreateVEnet': VEnetConfig,
        'UpdateVEnet': VEnetConfig,
        'DeleteVEnet': VEnetConfig,
        'CreateTrafficDescriptorProfileData': TrafficDescriptorProfileData,
        'UpdateTrafficDescriptorProfileData': TrafficDescriptorProfileData,
        'DeleteTrafficDescriptorProfileData': TrafficDescriptorProfileData,
        'CreateTcontsConfigData': TcontsConfigData,
        'UpdateTcontsConfigData': TcontsConfigData,
        'DeleteTcontsConfigData': TcontsConfigData,
        'CreateGemportsConfigData': GemportsConfigData,
        'UpdateGemportsConfigData': GemportsConfigData,
        'DeleteGemportsConfigData': GemportsConfigData,
        'CreateMulticastGemportsConfigData': MulticastGemportsConfigData,
        'UpdateMulticastGemportsConfigData': MulticastGemportsConfigData,
        'DeleteMulticastGemportsConfigData': MulticastGemportsConfigData,
        'CreateMulticastDistributionSetData': MulticastDistributionSetData,
        'UpdateMulticastDistributionSetData': MulticastDistributionSetData,
        'DeleteMulticastDistributionSetData': MulticastDistributionSetData
                       }

    def __init__(self, dispatcher, instance_id, **init_kw):
        self.dispatcher = dispatcher
        self.instance_id = instance_id
        self.init_kw = init_kw
        self.root = None
        self.stopped = False

    def start(self):
        log.debug('starting')
        self.root = ConfigRoot(Voltha(**self.init_kw))
        log.info('started')
        return self

    def register_grpc_service(self):
        log.debug('registering')
        registry('grpc_server').register(
            add_VolthaGlobalServiceServicer_to_server, self)
        log.info('registered')

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    # gRPC service method implementations. BE CAREFUL; THESE ARE CALLED ON
    # the gRPC threadpool threads.

    @twisted_async
    def GetVoltha(self, request, context):
        log.debug('grpc-request', request=request)
        return self.root.get('/', depth=1)

    @twisted_async
    def ListVolthaInstances(self, request, context):
        log.debug('grpc-request', request=request)
        items = self.dispatcher.get_cluster_instances()
        return VolthaInstances(items=items)

    @twisted_async
    @inlineCallbacks
    def GetVolthaInstance(self, request, context):
        log.debug('grpc-request', request=request)
        core_id = self.dispatcher.get_core_id_from_instance_id(request.id)
        if not core_id:
            log.info('invalid-instance-id', instance=request.id)
            context.set_details('Voltha Instance error')
            context.set_code(StatusCode.NOT_FOUND)
            returnValue(VolthaInstance())

        response = yield self.dispatcher.dispatch('GetVolthaInstance',
                                                  Empty(),
                                                  context,
                                                  core_id=core_id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Voltha Instance error')
            context.set_code(response.error_code)
            returnValue(VolthaInstance())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDevices(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListLogicalDevices',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        # log.debug('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListReachableLogicalDevices(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
                'ListReachableLogicalDevices',
                Empty(),
                context,
                broadcast=True)
        # log.debug('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetLogicalDevice(self, request, context):
        log.debug('grpc-request', request=request)

        response = yield self.dispatcher.dispatch('GetLogicalDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        # log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(LogicalDevice())
        else:
            # log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDevicePorts(self, request, context):
        log.debug('grpc-request', request=request)

        response = yield self.dispatcher.dispatch('ListLogicalDevicePorts',
                                                  request,
                                                  context,
                                                  id=request.id)
        # log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device ports \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Ports())
        else:
            # log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetLogicalDevicePort(self, request, context):
        log.debug('grpc-request', request=request)

        response = yield self.dispatcher.dispatch('GetLogicalDevicePort',
                                                  request,
                                                  context,
                                                  id=request.id)
        # log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical port \'{}\' on device \'{}\' error'.format(request.port_id, request.id))
            context.set_code(response.error_code)
            returnValue(LogicalPort())
        else:
            # log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDeviceFlows(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListLogicalDeviceFlows',
                                                  request,
                                                  context,
                                                  id=request.id)
        # log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Flows())
        else:
            # log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def EnableLogicalDevicePort(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('EnableLogicalDevicePort',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DisableLogicalDevicePort(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('DisableLogicalDevicePort',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateLogicalDeviceMeterTable(self, request, context):
        log.info('meter-table-update-grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'UpdateLogicalDeviceMeterTable',
            request,
            context,
            id= request.id)
        log.info("meter-table-update-grpc-response", response=response)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetMeterStatsOfLogicalDevice(self, request, context):
        log.info('meter-stats-request-grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetMeterStatsOfLogicalDevice',
            request,
            context,
            id=request.id)
        log.info("meter-stats-request-grpc-response", response=response)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateLogicalDeviceFlowTable(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'UpdateLogicalDeviceFlowTable',
            request,
            context,
            id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDeviceFlowGroups(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'ListLogicalDeviceFlowGroups',
            request,
            context,
            id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(FlowGroups())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateLogicalDeviceFlowGroupTable(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'UpdateLogicalDeviceFlowGroupTable',
            request,
            context,
            id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDevices(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDevices',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        # log.debug('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListAdapters(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListAdapters',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        log.debug('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetDevice(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateDevice(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('CreateDevice',
                                                  request,
                                                  context)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Create device error')
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def EnableDevice(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('EnableDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DisableDevice(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('DisableDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def RebootDevice(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('RebootDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteDevice(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('DeleteDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(Empty())

    @twisted_async
    @inlineCallbacks
    def ListDevicePorts(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDevicePorts',
                                                  request,
                                                  context,
                                                  id=request.id)
        # log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Ports())
        else:
            # log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDevicePmConfigs(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDevicePmConfigs',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(PmConfigs())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateDevicePmConfigs(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('UpdateDevicePmConfigs',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceFlows(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDeviceFlows',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Flows())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceFlowGroups(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDeviceFlowGroups',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(FlowGroups())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceTypes(self, request, context):
        log.debug('grpc-request', request=request)
        # we always deflect this to the local instance, as we assume
        # they all loaded the same adapters, supporting the same device
        # types
        response = yield self.dispatcher.dispatch('ListDeviceTypes',
                                                  request,
                                                  context)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device types error')
            context.set_code(response.error_code)
            returnValue(DeviceTypes())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetDeviceType(self, request, context):
        log.debug('grpc-request', request=request)
        # we always deflect this to the local instance, as we assume
        # they all loaded the same adapters, supporting the same device
        # types
        response = yield self.dispatcher.dispatch('GetDeviceType',
                                                  request,
                                                  context)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device type \'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(DeviceType())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceGroups(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDeviceGroups',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        log.debug('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetDeviceGroup(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetDeviceGroup',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device group\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(DeviceGroup())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    # bbf_fiber rpcs start
    @twisted_async
    @inlineCallbacks
    def GetAllChannelgroupConfig(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetAllChannelgroupConfig',
            Empty(),
            context,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelgroup error')
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateChannelgroup(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def UpdateChannelgroup(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelgroupConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelgroupConfig())
        response = yield self.dispatcher.dispatch(
            'UpdateChannelgroup',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelgroup\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelgroupConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteChannelgroup(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelgroupConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelgroupConfig())
        response = yield self.dispatcher.dispatch(
            'DeleteChannelgroup',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelgroup\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelgroupConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAllChannelpartitionConfig(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetAllChannelpartitionConfig',
            Empty(),
            context,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpartition error')
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateChannelpartition(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelpartitionConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelpartitionConfig())
        response = yield self.dispatcher.dispatch(
            'CreateChannelpartition',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpartition\'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelpartitionConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateChannelpartition(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelpartitionConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelpartitionConfig())
        response = yield self.dispatcher.dispatch(
            'UpdateChannelpartition',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpartition\'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelpartitionConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteChannelpartition(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelpartitionConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelpartitionConfig())
        response = yield self.dispatcher.dispatch(
            'DeleteChannelpartition',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpartition\'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelpartitionConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAllChannelpairConfig(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetAllChannelpairConfig',
            Empty(),
            context,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpair error')
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateChannelpair(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelpairConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelpairConfig())
        response = yield self.dispatcher.dispatch(
            'CreateChannelpair',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpair\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelpairConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateChannelpair(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelpairConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelpairConfig())
        response = yield self.dispatcher.dispatch(
            'UpdateChannelpair',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpair\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelpairConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteChannelpair(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.ChannelpairConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.ChannelpairConfig())
        response = yield self.dispatcher.dispatch(
            'DeleteChannelpair',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channelpair\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelpairConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAllChannelterminationConfig(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetAllChannelterminationConfig',
            request,
            context,
            id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channeltermination \'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelterminationConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateChanneltermination(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'CreateChanneltermination',
            request,
            context,
            id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channeltermination \'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelterminationConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateChanneltermination(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'UpdateChanneltermination',
            request,
            context,
            id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channeltermination \'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelterminationConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteChanneltermination(self, request, context):
        log.debug('grpc-request', request=request)
        response =  yield self.dispatcher.dispatch(
            'DeleteChanneltermination',
            request,
            context,
            id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Channeltermination \'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(fb.ChannelterminationConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAllOntaniConfig(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetAllOntaniConfig',
            Empty(),
            context,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Ontani error')
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateOntani(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.OntaniConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.OntaniConfig())
        response = yield self.dispatcher.dispatch(
            'CreateOntani',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Ontani \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.OntaniConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateOntani(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.OntaniConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.OntaniConfig())
        response = yield self.dispatcher.dispatch(
            'UpdateOntani',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Ontani \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.OntaniConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteOntani(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.OntaniConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.OntaniConfig())
        response = yield self.dispatcher.dispatch(
            'DeleteOntani',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Ontani \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.OntaniConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAllVOntaniConfig(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetAllVOntaniConfig',
            Empty(),
            context,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VOntani error')
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateVOntani(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.VOntaniConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.VOntaniConfig())
        response = yield self.dispatcher.dispatch(
            'CreateVOntani',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VOntani \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.VOntaniConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateVOntani(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.VOntaniConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.VOntaniConfig())
        response = yield self.dispatcher.dispatch(
            'UpdateVOntani',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VOntani \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.VOntaniConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteVOntani(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.VOntaniConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.VOntaniConfig())
        response = yield self.dispatcher.dispatch(
            'DeleteVOntani',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VOntani \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.VOntaniConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAllVEnetConfig(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'GetAllVEnetConfig',
            request,
            context,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VEnet error')
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateVEnet(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.VEnetConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.VEnetConfig())
        response = yield self.dispatcher.dispatch(
            'CreateVEnet',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VEnet \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.VEnetConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateVEnet(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.VEnetConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.VEnetConfig())
        response = yield self.dispatcher.dispatch(
            'UpdateVEnet',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VEnet \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.VEnetConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteVEnet(self, request, context):
        log.debug('grpc-request', request=request)
        try:
            assert isinstance(request, fb.VEnetConfig)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(fb.VEnetConfig())
        response = yield self.dispatcher.dispatch(
            'DeleteVEnet',
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('VEnet \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(fb.VEnetConfig())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAllTrafficDescriptorProfileData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.get_all_global_xpon_object_data (request, context,
                                                     _method_name)

    @twisted_async
    @inlineCallbacks
    def CreateTrafficDescriptorProfileData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context,
                                               _method_name)

    @twisted_async
    @inlineCallbacks
    def UpdateTrafficDescriptorProfileData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context,
                                               _method_name)

    @twisted_async
    @inlineCallbacks
    def DeleteTrafficDescriptorProfileData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context,
                                               _method_name)

    @twisted_async
    @inlineCallbacks
    def GetAllTcontsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.get_all_global_xpon_object_data (request, context,
                                                     _method_name)

    @twisted_async
    @inlineCallbacks
    def CreateTcontsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def UpdateTcontsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def DeleteTcontsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def GetAllGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.get_all_global_xpon_object_data (request, context,
                                                     _method_name)

    @twisted_async
    @inlineCallbacks
    def CreateGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def UpdateGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def DeleteGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def GetAllMulticastGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.get_all_global_xpon_object_data (request, context,
                                                     _method_name)

    @twisted_async
    @inlineCallbacks
    def CreateMulticastGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def UpdateMulticastGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def DeleteMulticastGemportsConfigData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def GetAllMulticastDistributionSetData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.get_all_global_xpon_object_data (request, context,
                                                     _method_name)

    @twisted_async
    @inlineCallbacks
    def CreateMulticastDistributionSetData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def UpdateMulticastDistributionSetData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    @twisted_async
    @inlineCallbacks
    def DeleteMulticastDistributionSetData(self, request, context):
        _method_name = sys._getframe().f_code.co_name
        return self.manage_global_xpon_object (request, context, _method_name)

    def get_all_global_xpon_object_data(self, request, context, method_name):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            method_name,
            Empty(),
            context,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('{}\' error' .format(type(request).__name__))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    def manage_global_xpon_object(self, request, context, method_name):
        log.debug('grpc-request', request=request)
        _xpon_object_type = self.xpon_object_type[method_name]
        try:
            assert isinstance(request, _xpon_object_type)
            request.id = create_empty_broadcast_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(_xpon_object_type())
        response = yield self.dispatcher.dispatch(
            method_name,
            request,
            context,
            id=request.id,
            broadcast=True)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('{}\'{}\' error'.format(type(request).__name__,
                                                        request.id))
            context.set_code(response.error_code)
            returnValue(_xpon_object_type())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)
    # bbf_fiber rpcs end

    @twisted_async
    @inlineCallbacks
    def CreateAlarmFilter(self, request, context):
        log.debug('grpc-request', request=request)
        # Since AlarmFilter applies to the entire cluster, it will be assigned
        # a global id (using a global core_id).  Every Voltha instance will
        # have the same data.  Since the voltha instances are managed by
        # docker swarm mode then whenever an instance goes down it will be
        # brought up right away, hence reducing the chance of two instances
        # having different data.   In future phases, we should adopt the
        # strategy of having a unique persistence model for cluster data
        # compare to instance data
        try:
            assert isinstance(request, AlarmFilter)
            request.id = create_cluster_id()
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            returnValue(AlarmFilter())

        response = yield self.dispatcher.dispatch('CreateAlarmFilter',
                                                  request,
                                                  context,
                                                  id=request.id,
                                                  broadcast=True)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Create alarm error')
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAlarmFilter(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetAlarmFilter',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filter\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateAlarmFilter(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('UpdateAlarmFilter',
                                                  request,
                                                  context,
                                                  id=request.id,
                                                  broadcast=True)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filter\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteAlarmFilter(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('DeleteAlarmFilter',
                                                  request,
                                                  context,
                                                  id=request.id,
                                                  broadcast=True)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filter\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(Empty())

    @twisted_async
    @inlineCallbacks
    def ListAlarmFilters(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListAlarmFilters',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filters error')
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetImages(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetImages',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Images())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def SelfTest(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('SelfTest',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(SelfTestResponse())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DownloadImage(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('DownloadImage',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(OperationResp(code=OperationResp.OPERATION_FAILURE))
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetImageDownloadStatus(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('GetImageDownloadStatus',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(ImageDownloads())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetImageDownload(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('GetImageDownload',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(ImageDownload())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListImageDownloads(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('ListImageDownloads',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(ImageDownloads())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)


    @twisted_async
    @inlineCallbacks
    def CancelImageDownload(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('CancelImageDownload',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(OperationResp(code=OperationResp.OPERATION_FAILURE))
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ActivateImageUpdate(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('ActivateImageUpdate',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(OperationResp(code=OperationResp.OPERATION_FAILURE))
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def RevertImageUpdate(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('RevertImageUpdate',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(OperationResp(code=OperationResp.OPERATION_FAILURE))
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetMibDeviceData(self, request, context):
        log.debug('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetMibDeviceData',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(MibDeviceData())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAlarmDeviceData(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetAlarmDeviceData',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.debug('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(AlarmDeviceData())
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def SimulateAlarm(self, request, context):
        try:
            log.debug('grpc-request', request=request)
            response = yield self.dispatcher.dispatch('SimulateAlarm',
                                                      request,
                                                      context,
                                                      id=request.id)
            log.debug('grpc-response', response=response)
        except Exception as e:
            log.exception('grpc-exception', e=e)

        if isinstance(response, DispatchError):
            log.warn('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(OperationResp(code=OperationResp.OPERATION_FAILURE))
        else:
            log.debug('grpc-success-response', response=response)
            returnValue(response)
