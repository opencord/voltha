#
# Copyright 2016 the original author or authors.
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

"""
Voltha's CORE components.
"""
import structlog
from twisted.internet.defer import inlineCallbacks, returnValue
from zope.interface import implementer

from common.utils.grpc_utils import twisted_async
from voltha.core.config.config_root import ConfigRoot
from voltha.protos import third_party
from voltha.protos.voltha_pb2 import \
    add_VolthaGlobalServiceServicer_to_server, \
    add_VolthaLocalServiceServicer_to_server, \
    VolthaGlobalServiceServicer, VolthaLocalServiceStub, \
    VolthaLocalServiceServicer, Voltha, VolthaInstance, VolthaInstances, \
    Adapters, LogicalDevices, Ports, LogicalPorts, Flows, FlowGroups, Devices, \
    DeviceTypes, DeviceGroups
from voltha.registry import IComponent, registry
from google.protobuf.empty_pb2 import Empty

log = structlog.get_logger()


@implementer(IComponent)
class VolthaCore(object):

    def __init__(self, instance_id, version, log_level):
        self.instance_id = instance_id
        self.stopped = False
        self.global_service = VolthaGlobalServiceHandler(
            dispatcher=self,
            instance_id=instance_id,
            version=version,
            log_level=log_level)
        self.local_service = VolthaLocalServiceHandler(
            instance_id=instance_id,
            version=version,
            log_level=log_level)

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        yield self.global_service.start()
        yield self.local_service.start()
        log.info('started')
        returnValue(self)

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    def get_proxy(self, path, exclusive=False):
        return self.local_service.get_proxy(path, exclusive)

    # ~~~~~~~~~~~~~~~~~~~~~~~ DISPATCH LOGIC ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # TODO this shall be moved into its own module

    def dispatch(self, instance_id, stub, method_name, input):
        log.debug('dispatch', instance_id=instance_id, stub=stub,
                  _method_name=method_name, input=input)
        # special case if instance_id is us
        if instance_id == self.instance_id:
            # for now, we assume it is always the local stub
            assert stub == VolthaLocalServiceStub
            method = getattr(self.local_service, method_name)
            log.debug('dispatching', method=method)
            res = method(input, context=None)
            log.debug('dispatch-success', res=res)
            return res

        else:
            raise NotImplementedError('cannot handle real dispatch yet')

    def instance_id_by_logical_device_id(self, logical_device_id):
        log.warning('temp-mapping-logical-device-id')
        # TODO no true dispatchong uyet, we blindly map everything to self
        return self.instance_id

    def instance_id_by_device_id(self, device_id):
        log.warning('temp-mapping-logical-device-id')
        # TODO no true dispatchong uyet, we blindly map everything to self
        return self.instance_id


class VolthaGlobalServiceHandler(VolthaGlobalServiceServicer):

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
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'GetVolthaInstance',
            Empty())

    @twisted_async
    def ListLogicalDevices(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDevices',
            Empty())

    @twisted_async
    def GetLogicalDevice(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_logical_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'GetLogicalDevice',
            request
        )

    @twisted_async
    def ListLogicalDevicePorts(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_logical_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDevicePorts',
            request
        )

    @twisted_async
    def ListLogicalDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_logical_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDeviceFlows',
            request
        )

    @twisted_async
    def UpdateLogicalDeviceFlowTable(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_logical_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'UpdateLogicalDeviceFlowTable',
            request
        )

    @twisted_async
    def ListLogicalDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_logical_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListLogicalDeviceFlowGroups',
            request
        )

    @twisted_async
    def UpdateLogicalDeviceFlowGroupTable(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_logical_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'UpdateLogicalDeviceFlowGroupTable',
            request
        )

    @twisted_async
    def ListDevices(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListDevices',
            Empty())

    @twisted_async
    def GetDevice(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'GetDevice',
            request
        )

    @twisted_async
    def ListDevicePorts(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListDevicePorts',
            request
        )

    @twisted_async
    def ListDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListDeviceFlows',
            request
        )

    @twisted_async
    def ListDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)
        instance_id = self.dispatcher.instance_id_by_device_id(
            request.id
        )
        return self.dispatcher.dispatch(
            instance_id,
            VolthaLocalServiceStub,
            'ListDeviceFlowGroups',
            request
        )

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
            request
        )

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
            request
        )

    @twisted_async
    def ListDeviceGroups(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'ListDeviceGroups',
            Empty())

    @twisted_async
    def GetDeviceGroup(self, request, context):
        log.warning('temp-limited-implementation')
        # TODO dispatching to local instead of collecting all
        return self.dispatcher.dispatch(
            self.instance_id,
            VolthaLocalServiceStub,
            'GetDeviceGroup',
            request)


class VolthaLocalServiceHandler(VolthaLocalServiceServicer):

    def __init__(self, **init_kw):
        self.init_kw = init_kw
        self.root = None
        self.stopped = False

    def start(self):
        log.debug('starting')
        self.root = ConfigRoot(VolthaInstance(**self.init_kw))
        registry('grpc_server').register(
            add_VolthaLocalServiceServicer_to_server, self)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    def get_proxy(self, path, exclusive=False):
        return self.root.get_proxy(path, exclusive)

    # gRPC service method implementations. BE CAREFUL; THESE ARE CALLED ON
    # the gRPC threadpool threads.

    @twisted_async
    def GetVolthaInstance(self, request, context):
        log.info('grpc-request', request=request)
        return self.root.get('/', depth=1)

    @twisted_async
    def GetHealth(self, request, context):
        log.info('grpc-request', request=request)
        return self.root.get('/health')

    @twisted_async
    def ListAdapters(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/adapters')
        return Adapters(items=items)

    @twisted_async
    def ListLogicalDevices(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/logical_devices')
        return LogicalDevices(items=items)

    @twisted_async
    def GetLogicalDevice(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        return self.root.get('/logical_devices/' + request.id)

    @twisted_async
    def ListLogicalDevicePorts(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        items = self.root.get('/logical_devices/{}/ports'.format(request.id))
        return LogicalPorts(items=items)

    @twisted_async
    def ListLogicalDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        flows = self.root.get('/logical_devices/{}/flows'.format(request.id))
        return flows

    @twisted_async
    def UpdateLogicalDeviceFlowTable(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        raise NotImplementedError()

    @twisted_async
    def ListLogicalDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        groups = self.root.get(
            '/logical_devices/{}/flow_groups'.format(request.id))
        return groups

    @twisted_async
    def UpdateLogicalDeviceFlowGroupTable(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        raise NotImplementedError()

    @twisted_async
    def ListDevices(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/devices')
        return Devices(items=items)

    @twisted_async
    def GetDevice(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        return self.root.get('/devices/' + request.id)

    @twisted_async
    def ListDevicePorts(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        items = self.root.get('/devices/{}/ports'.format(request.id))
        return Ports(items=items)

    @twisted_async
    def ListDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        flows = self.root.get('/devices/{}/flows'.format(request.id))
        return flows

    @twisted_async
    def ListDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        groups = self.root.get('/devices/{}/flow_groups'.format(request.id))
        return groups

    @twisted_async
    def ListDeviceTypes(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/device_types')
        return DeviceTypes(items=items)

    @twisted_async
    def GetDeviceType(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        return self.root.get('/device_types/' + request.id)

    @twisted_async
    def ListDeviceGroups(self, request, context):
        log.info('grpc-request', request=request)
        # TODO is this mapped to tree or taken from coordinator?
        items = self.root.get('/device_groups')
        return DeviceGroups(items=items)

    @twisted_async
    def GetDeviceGroup(self, request, context):
        log.info('grpc-request', request=request)
        assert '/' not in request.id
        # TODO is this mapped to tree or taken from coordinator?
        return self.root.get('/device_groups/' + request.id)

    @twisted_async
    def StreamPacketsOut(self, request_iterator, context):
        raise NotImplementedError()

    @twisted_async
    def ReceivePacketsIn(self, request, context):
        raise NotImplementedError()
