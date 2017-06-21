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
from voltha.core.config.config_root import ConfigRoot
from voltha.protos.device_pb2 import PmConfigs, Images
from voltha.protos.voltha_pb2 import \
    add_VolthaGlobalServiceServicer_to_server, VolthaLocalServiceStub, \
    VolthaGlobalServiceServicer, Voltha, VolthaInstances, VolthaInstance, \
    LogicalDevice, Ports, Flows, FlowGroups, Device
from voltha.registry import registry
from google.protobuf.empty_pb2 import Empty

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
    @inlineCallbacks
    def ListVolthaInstances(self, request, context):
        log.info('grpc-request', request=request)
        items = yield registry('coordinator').get_members()
        returnValue(VolthaInstances(items=items))

    @twisted_async
    def GetVolthaInstance(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = request.id
        try:
            return self.dispatcher.dispatch(
                instance_id,
                VolthaLocalServiceStub,
                'GetVolthaInstance',
                Empty(),
                context)
        except KeyError:
            context.set_details(
                'Voltha instance \'{}\' not found'.format(instance_id))
            context.set_code(StatusCode.NOT_FOUND)
            return VolthaInstance()

    @twisted_async
    def ListLogicalDevices(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDevices',
            Empty(),
            context)

    @twisted_async
    def GetLogicalDevice(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_logical_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return LogicalDevice()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'GetLogicalDevice',
            request,
            context)

    @twisted_async
    def ListLogicalDevicePorts(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_logical_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Ports()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDevicePorts',
            request,
            context)

    @twisted_async
    def ListLogicalDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_logical_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Flows()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDeviceFlows',
            request,
            context)

    @twisted_async
    def UpdateLogicalDeviceFlowTable(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_logical_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'UpdateLogicalDeviceFlowTable',
            request,
            context)

    @twisted_async
    def ListLogicalDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_logical_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return FlowGroups()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDeviceFlowGroups',
            request,
            context)

    @twisted_async
    def UpdateLogicalDeviceFlowGroupTable(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_logical_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'UpdateLogicalDeviceFlowGroupTable',
            request,
            context)

    @twisted_async
    def ListDevices(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListDevices',
            request,
            context)

    @twisted_async
    def GetDevice(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Device()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'GetDevice',
            request,
            context)

    @twisted_async
    def CreateDevice(self, request, context):
        log.info('grpc-request', request=request)
        # TODO dispatching to local instead of passing it to leader
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateDevice',
            request,
            context)

    @twisted_async
    def EnableDevice(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Device()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'EnableDevice',
            request,
            context)


    @twisted_async
    def DisableDevice(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Device()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'DisableDevice',
            request,
            context)

    @twisted_async
    def RebootDevice(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Device()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'RebootDevice',
            request,
            context)

    @twisted_async
    def DeleteDevice(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Device()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'DeleteDevice',
            request,
            context)

    @twisted_async
    def ListDevicePorts(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Ports()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListDevicePorts',
            request,
            context)

    @twisted_async
    def ListDevicePmConfigs(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return PmConfigs()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListDevicePmConfigs',
            request,
            context)

    @twisted_async
    def UpdateDevicePmConfigs(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'UpdateDevicePmConfigs',
            request,
            context)

    @twisted_async
    def ListDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Flows()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListDeviceFlows',
            request,
            context)

    @twisted_async
    def ListDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(
                request.id
            )
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return FlowGroups()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListDeviceFlowGroups',
            request,
            context)

    @twisted_async
    def ListDeviceTypes(self, request, context):
        log.info('grpc-request', request=request)
        # we always deflect this to the local instance, as we assume
        # they all loaded the same adapters, supporting the same device
        # types
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListDeviceTypes',
            request,
            context)

    @twisted_async
    def GetDeviceType(self, request, context):
        log.info('grpc-request', request=request)
        # we always deflect this to the local instance, as we assume
        # they all loaded the same adapters, supporting the same device
        # types
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetDeviceType',
            request,
            context)

    @twisted_async
    def ListDeviceGroups(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListDeviceGroups',
            Empty(),
            context)

    @twisted_async
    def GetDeviceGroup(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetDeviceGroup',
            request,
            context)


    @twisted_async
    def CreateAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)
        # TODO dispatching to local instead of passing it to leader
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'CreateAlarmFilter',
            request,
            context)

    @twisted_async
    def GetAlarmFilter(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetAlarmFilter',
            request,
            context)

    @twisted_async
    def UpdateAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)
        # TODO dispatching to local instead of passing it to leader
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'UpdateAlarmFilter',
            request,
            context)

    @twisted_async
    def DeleteAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)
        # TODO dispatching to local instead of passing it to leader
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'DeleteAlarmFilter',
            request,
            context)

    @twisted_async
    def ListAlarmFilters(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListAlarmFilters',
            Empty(),
            context)

    @twisted_async
    def GetImages(self, request, context):
        log.info('grpc-request', request=request)

        try:
            instance_id = self.dispatcher.instance_id_by_device_id(request.id)
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Images()

        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'GetImages',
            request,
            context)
