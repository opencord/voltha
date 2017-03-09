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
from uuid import uuid4

import structlog
from google.protobuf.empty_pb2 import Empty
from grpc import StatusCode

from common.utils.grpc_utils import twisted_async
from voltha.core.config.config_root import ConfigRoot
from voltha.core.config.config_backend import ConsulStore
from voltha.protos.openflow_13_pb2 import PacketIn, Flows, FlowGroups, \
    ofp_port_status
from voltha.protos.voltha_pb2 import \
    add_VolthaLocalServiceServicer_to_server, VolthaLocalServiceServicer, \
    VolthaInstance, Adapters, LogicalDevices, LogicalDevice, Ports, \
    LogicalPorts, Devices, Device, DeviceType, \
    DeviceTypes, DeviceGroups, DeviceGroup, AdminState, OperStatus, ChangeEvent
from voltha.protos.device_pb2 import PmConfigs
from voltha.registry import registry

log = structlog.get_logger()


class LocalHandler(VolthaLocalServiceServicer):
    def __init__(self, core, **init_kw):
        self.core = core
        self.init_kw = init_kw
        self.root = None
        self.stopped = False

    def start(self, config_backend=None):
        log.debug('starting')
        if config_backend:
            if 'root' in config_backend:
                # This is going to block the entire reactor until loading is completed
                log.info('loading config from persisted backend')
                self.root = ConfigRoot.load(VolthaInstance,
                                            kv_store=config_backend)
            else:
                log.info('initializing new config')
                self.root = ConfigRoot(VolthaInstance(**self.init_kw),
                                       kv_store=config_backend)
        else:
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
        depth = int(dict(context.invocation_metadata()).get('get-depth', 0))
        res = self.root.get('/', depth=depth)
        return res

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

        depth = int(dict(context.invocation_metadata()).get('get-depth', 0))

        if '/' in request.id:
            context.set_details(
                'Malformed logical device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return LogicalDevice()

        try:
            return self.root.get('/logical_devices/' + request.id, depth=depth)
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return LogicalDevice()

    @twisted_async
    def ListLogicalDevicePorts(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed logical device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return LogicalPorts()

        try:
            items = self.root.get(
                '/logical_devices/{}/ports'.format(request.id))
            return LogicalPorts(items=items)
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return LogicalPorts()

    @twisted_async
    def ListLogicalDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed logical device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Flows()

        try:
            flows = self.root.get(
                '/logical_devices/{}/flows'.format(request.id))
            return flows
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Flows()

    @twisted_async
    def UpdateLogicalDeviceFlowTable(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed logical device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            agent = self.core.get_logical_device_agent(request.id)
            agent.update_flow_table(request.flow_mod)
            return Empty()
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    @twisted_async
    def ListLogicalDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed logical device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return FlowGroups()

        try:
            groups = self.root.get(
                '/logical_devices/{}/flow_groups'.format(request.id))
            return groups
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return FlowGroups()

    @twisted_async
    def UpdateLogicalDeviceFlowGroupTable(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed logical device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            agent = self.core.get_logical_device_agent(request.id)
            agent.update_group_table(request.group_mod)
            return Empty()
        except KeyError:
            context.set_details(
                'Logical device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

    @twisted_async
    def ListDevices(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/devices')
        return Devices(items=items)

    @twisted_async
    def GetDevice(self, request, context):
        log.info('grpc-request', request=request)

        depth = int(dict(context.invocation_metadata()).get('get-depth', 0))

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        try:
            return self.root.get('/devices/' + request.id, depth=depth)
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Device()

    @twisted_async
    def CreateDevice(self, request, context):
        log.info('grpc-request', request=request)

        known_device_types = dict(
            (dt.id, dt) for dt in self.root.get('/device_types'))

        try:
            assert isinstance(request, Device)
            device = request
            assert device.id == '', 'Device to be created cannot have id yet'
            assert device.type in known_device_types, \
                'Unknown device type \'{}\''.format(device.type)
            assert device.admin_state in (AdminState.UNKNOWN,
                                          AdminState.PREPROVISIONED), \
                'Newly created device cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)

        except AssertionError, e:
            context.set_details(e.msg)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        # fill additional data
        device.id = uuid4().hex[:12]
        device_type = known_device_types[device.type]
        device.adapter = device_type.adapter
        if device.admin_state != AdminState.PREPROVISIONED:
            device.admin_state = AdminState.PREPROVISIONED
            device.oper_status = OperStatus.UNKNOWN

        # add device to tree
        self.root.add('/devices', device)

        return request

    @twisted_async
    def EnableDevice(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state in (AdminState.PREPROVISIONED,
                                          AdminState.DISABLED), \
                'Device to enable cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            device.admin_state = AdminState.ENABLED
            self.root.update(path, device, strict=True)

        except AssertionError, e:
            context.set_details(e.msg)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)

        return Empty()

    @twisted_async
    def DisableDevice(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state == AdminState.ENABLED, \
                'Device to disable cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            device.admin_state = AdminState.DISABLED
            self.root.update(path, device, strict=True)

        except AssertionError, e:
            context.set_details(e.msg)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)

        return Empty()

    @twisted_async
    def RebootDevice(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)

            agent = self.core.get_device_agent(device.id)
            agent.reboot_device(device)

        except AssertionError, e:
            context.set_details(e.msg)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)

        return Empty()

    @twisted_async
    def DeleteDevice(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state == AdminState.DISABLED, \
                'Device to delete cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)

            self.root.remove(path)

        except AssertionError, e:
            context.set_details(e.msg)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)

        return Empty()

    @twisted_async
    def ListDevicePorts(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Ports()

        try:
            items = self.root.get('/devices/{}/ports'.format(request.id))
            return Ports(items=items)
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Ports()

    @twisted_async
    def ListDevicePmConfigs(self, request, context):
        #raise NotImplementedError('Method not implemented!')
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return PmConfigs()

        try:
            device = self.root.get('/devices/{}'.format(request.id))
            log.info('device-for-pms',device=device)
            return device.pm_configs
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return PmConfigs()

    #TODO: create the local PM config update function.
    @twisted_async
    def UpdateDevicePmConfigs(self, request, context):
        raise NotImplementedError('Method not implemented!')

    @twisted_async
    def ListDeviceFlows(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Flows()

        try:
            flows = self.root.get('/devices/{}/flows'.format(request.id))
            return flows
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Flows()

    @twisted_async
    def ListDeviceFlowGroups(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return FlowGroups()

        try:
            groups = self.root.get(
                '/devices/{}/flow_groups'.format(request.id))
            return groups
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return FlowGroups()

    @twisted_async
    def ListDeviceTypes(self, request, context):
        log.info('grpc-request', request=request)
        items = self.root.get('/device_types')
        return DeviceTypes(items=items)

    @twisted_async
    def GetDeviceType(self, request, context):
        log.info('grpc-request', request=request)

        depth = int(dict(context.invocation_metadata()).get('get-depth', 0))

        if '/' in request.id:
            context.set_details(
                'Malformed device type id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return DeviceType()

        try:
            return self.root.get('/device_types/' + request.id, depth=depth)
        except KeyError:
            context.set_details(
                'Device type \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return DeviceType()

    @twisted_async
    def ListDeviceGroups(self, request, context):
        log.info('grpc-request', request=request)
        # TODO is this mapped to tree or taken from coordinator?
        items = self.root.get('/device_groups')
        return DeviceGroups(items=items)

    @twisted_async
    def GetDeviceGroup(self, request, context):
        log.info('grpc-request', request=request)

        depth = int(dict(context.invocation_metadata()).get('get-depth', 0))

        if '/' in request.id:
            context.set_details(
                'Malformed device group id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return DeviceGroup()

        # TODO is this mapped to tree or taken from coordinator?
        try:
            return self.root.get('/device_groups/' + request.id, depth=depth)
        except KeyError:
            context.set_details(
                'Device group \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return DeviceGroup()

    def StreamPacketsOut(self, request_iterator, context):

        @twisted_async
        def forward_packet_out(packet_out):
            agent = self.core.get_logical_device_agent(packet_out.id)
            agent.packet_out(packet_out.packet_out)

        for request in request_iterator:
            forward_packet_out(packet_out=request)

        return Empty()

    def ReceivePacketsIn(self, request, context):
        while 1:
            try:
                packet_in = self.core.packet_in_queue.get(timeout=1)
                yield packet_in
            except QueueEmpty:
                if self.stopped:
                    break

    def send_packet_in(self, device_id, ofp_packet_in):
        """Must be called on the twisted thread"""
        packet_in = PacketIn(id=device_id, packet_in=ofp_packet_in)
        self.core.packet_in_queue.put(packet_in)

    def ReceiveChangeEvents(self, request, context):
        while 1:
            try:
                event = self.core.change_event_queue.get(timeout=1)
                yield event
            except QueueEmpty:
                if self.stopped:
                    break

    def send_port_change_event(self, device_id, port_status):
        """Must be called on the twisted thread"""
        assert isinstance(port_status, ofp_port_status)
        event = ChangeEvent(id=device_id, port_status=port_status)
        self.core.change_event_queue.put(event)
