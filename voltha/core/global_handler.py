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
from common.utils.id_generation import \
    create_cluster_id
from voltha.core.config.config_root import ConfigRoot
from voltha.protos.device_pb2 import PmConfigs, Images, \
    ImageDownload, ImageDownloads
from voltha.protos.common_pb2 import OperationResp
from voltha.protos.voltha_pb2_grpc import \
    add_VolthaGlobalServiceServicer_to_server, VolthaGlobalServiceServicer
from voltha.protos.voltha_pb2 import \
    Voltha, VolthaInstances, VolthaInstance, \
    LogicalDevice, LogicalPort, Ports, Flows, FlowGroups, Device, \
    SelfTestResponse, DeviceType, DeviceTypes, DeviceGroup, AlarmFilter
from voltha.registry import registry
from google.protobuf.empty_pb2 import Empty
from dispatcher import DispatchError
from voltha.protos.omci_mib_db_pb2 import MibDeviceData
from voltha.protos.omci_alarm_db_pb2 import AlarmDeviceData

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
                'Logical port \'{}\' on device \'{}\' error'.format(
                    request.port_id, request.id))
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
            id=request.id)
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
