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
from grpc import StatusCode
from twisted.internet.defer import inlineCallbacks
from twisted.internet.defer import returnValue

from common.utils.grpc_utils import twisted_async
from common.utils.id_generation import create_cluster_id
from voltha.core.config.config_root import ConfigRoot
from voltha.protos.device_pb2 import PmConfigs, Images
from voltha.protos.voltha_pb2 import \
    add_VolthaGlobalServiceServicer_to_server, VolthaLocalServiceStub, \
    VolthaGlobalServiceServicer, Voltha, VolthaInstances, VolthaInstance, \
    LogicalDevice, Ports, Flows, FlowGroups, Device, SelfTestResponse, \
    VolthaGlobalServiceStub, Devices, DeviceType, DeviceTypes, DeviceGroup, \
    AlarmFilter, AlarmFilters
from voltha.registry import registry
from google.protobuf.empty_pb2 import Empty
from dispatcher import DispatchError

log = structlog.get_logger()


class GlobalHandler(VolthaGlobalServiceServicer):
    def __init__(self, dispatcher, instance_id, **init_kw):
        self.dispatcher = dispatcher
        self.instance_id = instance_id
        self.init_kw = init_kw
        self.root = None
        self.stopped = False

    def start(self):
        log.debug('starting')
        self.root = ConfigRoot(Voltha(**self.init_kw))
        registry('grpc_server').register(
            add_VolthaGlobalServiceServicer_to_server, self)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    # gRPC service method implementations. BE CAREFUL; THESE ARE CALLED ON
    # the gRPC threadpool threads.

    @twisted_async
    def GetVoltha(self, request, context):
        log.info('grpc-request', request=request)
        return self.root.get('/', depth=1)

    @twisted_async
    def ListVolthaInstances(self, request, context):
        log.info('grpc-request', request=request)
        items = self.dispatcher.get_cluster_instances()
        return VolthaInstances(items=items)

    @twisted_async
    @inlineCallbacks
    def GetVolthaInstance(self, request, context):
        log.info('grpc-request', request=request)
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
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Voltha Instance error')
            context.set_code(response.error_code)
            returnValue(VolthaInstance())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDevices(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListLogicalDevices',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        log.info('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetLogicalDevice(self, request, context):
        log.info('grpc-request', request=request)

        response = yield self.dispatcher.dispatch('GetLogicalDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(LogicalDevice())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDevicePorts(self, request, context):
        log.info('grpc-request', request=request)

        response = yield self.dispatcher.dispatch('ListLogicalDevicePorts',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device ports \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Ports())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListLogicalDeviceFlows',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Flows())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateLogicalDeviceFlowTable(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'UpdateLogicalDeviceFlowTable',
            request,
            context,
            id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListLogicalDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'ListLogicalDeviceFlowGroups',
            request,
            context,
            id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(FlowGroups())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateLogicalDeviceFlowGroupTable(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch(
            'UpdateLogicalDeviceFlowGroupTable',
            request,
            context,
            id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details(
                'Logical device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDevices(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDevices',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        log.info('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetDevice(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def CreateDevice(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('CreateDevice',
                                                  request,
                                                  context)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Create device error')
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def EnableDevice(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('EnableDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DisableDevice(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('DisableDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def RebootDevice(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('RebootDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Device())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteDevice(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('DeleteDevice',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(Empty())

    @twisted_async
    @inlineCallbacks
    def ListDevicePorts(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDevicePorts',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Ports())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDevicePmConfigs(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDevicePmConfigs',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(PmConfigs())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateDevicePmConfigs(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('UpdateDevicePmConfigs',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDeviceFlows',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Flows())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDeviceFlowGroups',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(FlowGroups())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceTypes(self, request, context):
        log.info('grpc-request', request=request)
        # we always deflect this to the local instance, as we assume
        # they all loaded the same adapters, supporting the same device
        # types
        response = yield self.dispatcher.dispatch('ListDeviceTypes',
                                                  request,
                                                  context)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device types error')
            context.set_code(response.error_code)
            returnValue(DeviceTypes())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetDeviceType(self, request, context):
        log.info('grpc-request', request=request)
        # we always deflect this to the local instance, as we assume
        # they all loaded the same adapters, supporting the same device
        # types
        response = yield self.dispatcher.dispatch('GetDeviceType',
                                                  request,
                                                  context)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device type \'{}\' error'.format(
                request.id))
            context.set_code(response.error_code)
            returnValue(DeviceType())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def ListDeviceGroups(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListDeviceGroups',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        log.info('grpc-response', response=response)
        returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetDeviceGroup(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetDeviceGroup',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device group\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(DeviceGroup())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    # bbf_fiber rpcs start
    @twisted_async
    def GetAllChannelgroupConfig(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAllChannelgroupConfig',
            request,
            context)

    @twisted_async
    def CreateChannelgroup(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateChannelgroup',
            request,
            context)

    @twisted_async
    def UpdateChannelgroup(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateChannelgroup',
            request,
            context)

    @twisted_async
    def DeleteChannelgroup(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteChannelgroup',
            request,
            context)

    @twisted_async
    def GetAllChannelpartitionConfig(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAllChannelpartitionConfig',
            request,
            context)

    @twisted_async
    def CreateChannelpartition(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateChannelpartition',
            request,
            context)

    @twisted_async
    def UpdateChannelpartition(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateChannelpartition',
            request,
            context)

    @twisted_async
    def DeleteChannelpartition(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteChannelpartition',
            request,
            context)

    @twisted_async
    def GetAllChannelpairConfig(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAllChannelpairConfig',
            request,
            context)

    @twisted_async
    def CreateChannelpair(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateChannelpair',
            request,
            context)

    @twisted_async
    def UpdateChannelpair(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateChannelpair',
            request,
            context)

    @twisted_async
    def DeleteChannelpair(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteChannelpair',
            request,
            context)

    @twisted_async
    def GetAllChannelterminationConfig(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAllChannelterminationConfig',
            request,
            context)

    @twisted_async
    def CreateChanneltermination(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateChanneltermination',
            request,
            context)

    @twisted_async
    def UpdateChanneltermination(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateChanneltermination',
            request,
            context)

    @twisted_async
    def DeleteChanneltermination(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteChanneltermination',
            request,
            context)

    @twisted_async
    def GetAllOntaniConfig(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAllOntaniConfig',
            request,
            context)

    @twisted_async
    def CreateOntani(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateOntani',
            request,
            context)

    @twisted_async
    def UpdateOntani(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateOntani',
            request,
            context)

    @twisted_async
    def DeleteOntani(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteOntani',
            request,
            context)

    @twisted_async
    def GetAllVOntaniConfig(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAllVOntaniConfig',
            request,
            context)

    @twisted_async
    def CreateVOntani(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateVOntani',
            request,
            context)

    @twisted_async
    def UpdateVOntani(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateVOntani',
            request,
            context)

    @twisted_async
    def DeleteVOntani(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteVOntani',
            request,
            context)

    @twisted_async
    def GetAllVEnetConfig(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAllVEnetConfig',
            request,
            context)

    @twisted_async
    def CreateVEnet(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateVEnet',
            request,
            context)

    @twisted_async
    def UpdateVEnet(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateVEnet',
            request,
            context)

    @twisted_async
    def DeleteVEnet(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteVEnet',
            request,
            context)
    # bbf_fiber rpcs end

    @twisted_async
    @inlineCallbacks
    def CreateAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)
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
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Create alarm error')
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetAlarmFilter',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filter\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def UpdateAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('UpdateAlarmFilter',
                                                  request,
                                                  context,
                                                  id=request.id,
                                                  broadcast=True)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filter\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def DeleteAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('DeleteAlarmFilter',
                                                  request,
                                                  context,
                                                  id=request.id,
                                                  broadcast=True)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filter\'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Empty())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(Empty())

    @twisted_async
    @inlineCallbacks
    def ListAlarmFilters(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('ListAlarmFilters',
                                                  Empty(),
                                                  context,
                                                  broadcast=True)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Alarm filters error')
            context.set_code(response.error_code)
            returnValue(AlarmFilter())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def GetImages(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('GetImages',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(Images())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)

    @twisted_async
    @inlineCallbacks
    def SelfTest(self, request, context):
        log.info('grpc-request', request=request)
        response = yield self.dispatcher.dispatch('SelfTest',
                                                  request,
                                                  context,
                                                  id=request.id)
        log.info('grpc-response', response=response)
        if isinstance(response, DispatchError):
            log.info('grpc-error-response', error=response.error_code)
            context.set_details('Device \'{}\' error'.format(request.id))
            context.set_code(response.error_code)
            returnValue(SelfTestResponse())
        else:
            log.info('grpc-success-response', response=response)
            returnValue(response)
