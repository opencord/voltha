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
from common.utils.id_generation import create_cluster_device_id
from voltha.core.config.config_root import ConfigRoot
from voltha.protos.openflow_13_pb2 import PacketIn, Flows, FlowGroups, \
    ofp_port_status
from voltha.protos.voltha_pb2 import \
    add_VolthaLocalServiceServicer_to_server, VolthaLocalServiceServicer, \
    VolthaInstance, Adapters, LogicalDevices, LogicalDevice, Ports, \
    LogicalPorts, Devices, Device, DeviceType, \
    DeviceTypes, DeviceGroups, DeviceGroup, AdminState, OperStatus, ChangeEvent, \
    AlarmFilter, AlarmFilters, SelfTestResponse
from voltha.protos.device_pb2 import PmConfigs, Images, ImageDownload, ImageDownloads
from voltha.protos.common_pb2 import OperationResp
from voltha.registry import registry
from requests.api import request

log = structlog.get_logger()


class LocalHandler(VolthaLocalServiceServicer):
    def __init__(self, core, instance_id, core_store_id, **init_kw):
        self.core = core
        self.instance_id = instance_id
        self.core_store_id = core_store_id
        self.init_kw = init_kw
        self.root = None
        self.started_with_existing_data = False
        self.stopped = False

    def start(self, config_backend=None):
        log.debug('starting')
        if config_backend:
            if 'root' in config_backend:
                # This is going to block the entire reactor until loading is
                # completed
                log.info('loading-config-from-persisted-backend')
                try:
                    self.root = ConfigRoot.load(VolthaInstance,
                                                kv_store=config_backend)
                    self.started_with_existing_data = True
                except Exception, e:
                    log.exception('Failure-loading-from-backend', e=e)
            else:
                log.info('initializing-a-new-config')
                self.root = ConfigRoot(VolthaInstance(**self.init_kw),
                                       kv_store=config_backend)
        else:
            self.root = ConfigRoot(VolthaInstance(**self.init_kw))

        self.core.xpon_handler.start(self.root)

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

    def has_started_with_existing_data(self):
        return self.started_with_existing_data

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
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Device()

        # fill additional data
        device.id = create_cluster_device_id(self.core_store_id)
        log.debug('device-id-created', device_id=device.id)
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
            return Empty()

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
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)

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
            return Empty()
        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state == AdminState.ENABLED, \
                'Device to disable cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            device.admin_state = AdminState.DISABLED
            self.root.update(path, device, strict=True)

        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)

        except Exception, e:
            log.exception('disable-exception', e=e)

        return Empty()

    @twisted_async
    def RebootDevice(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state != AdminState.DOWNLOADING_IMAGE, \
                'Device to reboot cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            agent = self.core.get_device_agent(device.id)
            agent.reboot_device(device)

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)

        return Empty()

    @twisted_async
    def DownloadImage(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert isinstance(request, ImageDownload)
            self.root.add('/devices/{}/image_downloads'.\
                    format(request.id), request)
            assert device.admin_state == AdminState.ENABLED, \
                'Device to DOWNLOADING_IMAGE cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            device.admin_state = AdminState.DOWNLOADING_IMAGE
            self.root.update(path, device, strict=True)
            agent = self.core.get_device_agent(device.id)
            agent.register_image_download(request)
            return OperationResp(code=OperationResp.OPERATION_SUCCESS)

        except AssertionError as e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return OperationResp(code=OperationResp.OPERATION_UNSUPPORTED)

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

        except Exception as e:
            log.exception(e.message)
            context.set_code(StatusCode.NOT_FOUND)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

    @twisted_async
    def GetImageDownloadStatus(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            response = ImageDownload(state=ImageDownload.DOWNLOAD_UNKNOWN)
            return response

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            agent = self.core.get_device_agent(device.id)
            img_dnld = self.root.get('/devices/{}/image_downloads/{}'.\
                    format(request.id, request.name))
            agent.get_image_download_status(img_dnld)
            try:
                response = self.root.get('/devices/{}/image_downloads/{}'.\
                        format(request.id, request.name))
            except Exception as e:
                log.exception(e.message)
            return response

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            response = ImageDownload(state=ImageDownload.DOWNLOAD_UNKNOWN)
            return response
        except Exception as e:
            log.exception(e.message)
            response = ImageDownload(state=ImageDownload.DOWNLOAD_FAILED)
            return response

    @twisted_async
    def GetImageDownload(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            response = ImageDownload(state=ImageDownload.DOWNLOAD_UNKNOWN)
            return response

        try:
            response = self.root.get('/devices/{}/image_downloads/{}'.\
                    format(request.id, request.name))
            return response

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            response = ImageDownload(state=ImageDownload.DOWNLOAD_UNKNOWN)
            return response

    @twisted_async
    def ListImageDownloads(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            response = ImageDownload(state=ImageDownload.DOWNLOAD_UNKNOWN)
            return response

        try:
            response = self.root.get('/devices/{}/image_downloads'.\
                    format(request.id))
            return ImageDownloads(items=response)

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            response = ImageDownload(state=ImageDownload.DOWNLOAD_UNKNOWN)
            return response

    @twisted_async
    def CancelImageDownload(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

        try:
            assert isinstance(request, ImageDownload)
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state == AdminState.DOWNLOADING_IMAGE, \
                'Device to cancel DOWNLOADING_IMAGE cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            agent = self.core.get_device_agent(device.id)
            agent.cancel_image_download(request)
            return OperationResp(code=OperationResp.OPERATION_SUCCESS)

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

    @twisted_async
    def ActivateImageUpdate(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

        try:
            assert isinstance(request, ImageDownload)
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state == AdminState.ENABLED, \
                'Device to activate image cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            agent = self.core.get_device_agent(device.id)
            agent.activate_image_update(request)
            return OperationResp(code=OperationResp.OPERATION_SUCCESS)

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

    @twisted_async
    def RevertImageUpdate(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

        try:
            assert isinstance(request, ImageDownload)
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state == AdminState.ENABLED, \
                'Device to revert image cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)
            agent = self.core.get_device_agent(device.id)
            agent.revert_image_update(request)
            return OperationResp(code=OperationResp.OPERATION_SUCCESS)

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

    @twisted_async
    def DeleteDevice(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)
            assert device.admin_state == AdminState.DISABLED, \
                'Device to delete cannot be ' \
                'in admin state \'{}\''.format(device.admin_state)

            self.root.remove(path)

        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)

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
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return PmConfigs()

        try:
            pm_configs = self.root.get(
                '/devices/{}/pm_configs'.format(request.id))
            pm_configs.id = request.id
            log.info('device-for-pms', pm_configs=pm_configs)
            return pm_configs
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return PmConfigs()

    @twisted_async
    def UpdateDevicePmConfigs(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed logical device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            device = self.root.get('/devices/{}'.format(request.id))
            agent = self.core.get_device_agent(request.id)
            agent.update_device_pm_config(request)
            return Empty()
        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Empty()

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

    # bbf_fiber rpcs start
    @twisted_async
    def GetAllChannelgroupConfig(self, request, context):
        return self.core.xpon_handler.get_all_channel_group_config(
            request, context)

    @twisted_async
    def CreateChannelgroup(self, request, context):
        return self.core.xpon_handler.create_channel_group(request, context)

    @twisted_async
    def UpdateChannelgroup(self, request, context):
        return self.core.xpon_handler.update_channel_group(request, context)

    @twisted_async
    def DeleteChannelgroup(self, request, context):
        return self.core.xpon_handler.delete_channel_group(request, context)

    @twisted_async
    def GetAllChannelpartitionConfig(self, request, context):
        return self.core.xpon_handler.get_all_channel_partition_config(
            request, context)

    @twisted_async
    def CreateChannelpartition(self, request, context):
        return self.core.xpon_handler.create_channel_partition(
            request, context)

    @twisted_async
    def UpdateChannelpartition(self, request, context):
        return self.core.xpon_handler.update_channel_partition(
            request, context)

    @twisted_async
    def DeleteChannelpartition(self, request, context):
        return self.core.xpon_handler.delete_channel_partition(
            request, context)

    @twisted_async
    def GetAllChannelpairConfig(self, request, context):
        return self.core.xpon_handler.get_all_channel_pair_config(
            request, context)

    @twisted_async
    def CreateChannelpair(self, request, context):
        return self.core.xpon_handler.create_channel_pair(request, context)

    @twisted_async
    def UpdateChannelpair(self, request, context):
        return self.core.xpon_handler.update_channel_pair(request, context)

    @twisted_async
    def DeleteChannelpair(self, request, context):
        return self.core.xpon_handler.delete_channel_pair(request, context)

    @twisted_async
    def GetAllChannelterminationConfig(self, request, context):
        return self.core.xpon_handler.get_all_channel_termination_config(
            request, context)

    @twisted_async
    def CreateChanneltermination(self, request, context):
        return self.core.xpon_handler.create_channel_termination(
            request, context)

    @twisted_async
    def UpdateChanneltermination(self, request, context):
        return self.core.xpon_handler.update_channel_termination(
            request, context)

    @twisted_async
    def DeleteChanneltermination(self, request, context):
        return self.core.xpon_handler.delete_channel_termination(
            request, context)

    @twisted_async
    def GetAllOntaniConfig(self, request, context):
        return self.core.xpon_handler.get_all_ont_ani_config(request, context)

    @twisted_async
    def CreateOntani(self, request, context):
        return self.core.xpon_handler.create_ont_ani(request, context)

    @twisted_async
    def UpdateOntani(self, request, context):
        return self.core.xpon_handler.update_ont_ani(request, context)

    @twisted_async
    def DeleteOntani(self, request, context):
        return self.core.xpon_handler.delete_ont_ani(request, context)

    @twisted_async
    def GetAllVOntaniConfig(self, request, context):
        return self.core.xpon_handler.get_all_v_ont_ani_config(
            request, context)

    @twisted_async
    def CreateVOntani(self, request, context):
        return self.core.xpon_handler.create_v_ont_ani(request, context)

    @twisted_async
    def UpdateVOntani(self, request, context):
        return self.core.xpon_handler.update_v_ont_ani(request, context)

    @twisted_async
    def DeleteVOntani(self, request, context):
        return self.core.xpon_handler.delete_v_ont_ani(request, context)

    @twisted_async
    def GetAllVEnetConfig(self, request, context):
        return self.core.xpon_handler.get_all_v_enet_config(request, context)

    @twisted_async
    def CreateVEnet(self, request, context):
        return self.core.xpon_handler.create_v_enet(request, context)

    @twisted_async
    def UpdateVEnet(self, request, context):
        return self.core.xpon_handler.update_v_enet(request, context)

    @twisted_async
    def DeleteVEnet(self, request, context):
        return self.core.xpon_handler.delete_v_enet(request, context)

    @twisted_async
    def GetAllTrafficDescriptorProfileData(self, request, context):
        return AllTrafficDescriptorProfileData()

    @twisted_async
    def CreateTrafficDescriptorProfileData(self, request, context):
        return Empty()

    @twisted_async
    def UpdateTrafficDescriptorProfileData(self, request, context):
        return Empty()

    @twisted_async
    def DeleteTrafficDescriptorProfileData(self, request, context):
        return Empty()

    @twisted_async
    def GetAllTcontsConfigData(self, request, context):
        return AllTcontsConfigData()

    @twisted_async
    def CreateTcontsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def UpdateTcontsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def DeleteTcontsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def GetAllGemportsConfigData(self, request, context):
        return AllGemportsConfigData()

    @twisted_async
    def CreateGemportsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def UpdateGemportsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def DeleteGemportsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def GetAllMulticastGemportsConfigData(self, request, context):
        return AllMulticastGemportsConfigData()

    @twisted_async
    def CreateMulticastGemportsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def UpdateMulticastGemportsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def DeleteMulticastGemportsConfigData(self, request, context):
        return Empty()

    @twisted_async
    def GetAllMulticastDistributionSetData(self, request, context):
        return AllMulticastDistributionSetData()

    @twisted_async
    def CreateMulticastDistributionSetData(self, request, context):
        return Empty()

    @twisted_async
    def UpdateMulticastDistributionSetData(self, request, context):
        return Empty()

    @twisted_async
    def DeleteMulticastDistributionSetData(self, request, context):
        return Empty()
    # bbf_fiber rpcs end

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


    @twisted_async
    def ListAlarmFilters(self, request, context):
        try:
            filters = self.root.get('/alarm_filters')
            return AlarmFilters(filters=filters)
        except KeyError:
            context.set_code(StatusCode.NOT_FOUND)
            return AlarmFilters()

    @twisted_async
    def GetAlarmFilter(self, request, context):
        if '/' in request.id:
            context.set_details(
                'Malformed alarm filter id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return AlarmFilter()

        try:
            alarm_filter = self.root.get('/alarm_filters/{}'.format(request.id))

            return alarm_filter
        except KeyError:
            context.set_details(
                'Alarm filter \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return AlarmFilter()

    @twisted_async
    def DeleteAlarmFilter(self, request, context):
        if '/' in request.id:
            context.set_details(
                'Malformed alarm filter id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Empty()

        try:
            self.root.remove('/alarm_filters/{}'.format(request.id))
        except KeyError:
            context.set_code(StatusCode.NOT_FOUND)

        return Empty()

    @twisted_async
    def CreateAlarmFilter(self, request, context):
        log.info('grpc-request', request=request)

        try:
            assert isinstance(request, AlarmFilter)
            alarm_filter = request
            assert alarm_filter.id is not None, 'Local Alarm filter to be ' \
                                              'created must have id'
        except AssertionError, e:
            context.set_details(e.message)
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return AlarmFilter()

        # add device to tree
        self.root.add('/alarm_filters', alarm_filter)

        return request

    @twisted_async
    def UpdateAlarmFilter(self, request, context):
        if '/' in request.id:
            context.set_details(
                'Malformed alarm filter id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return AlarmFilter()

        try:
            assert isinstance(request, AlarmFilter)
            alarm_filter = self.root.get('/alarm_filters/{}'.format(request.id))
            self.root.update('/alarm_filters/{}'.format(request.id), request)

            return request
        except KeyError:
            context.set_details(
                'Alarm filter \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return AlarmFilter()

    @twisted_async
    def GetImages(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return Images()

        try:
            device = self.root.get('/devices/' + request.id)
            return device.images

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return Images()

    @twisted_async
    def SelfTest(self, request, context):
        log.info('grpc-request', request=request)

        if '/' in request.id:
            context.set_details(
                'Malformed device id \'{}\''.format(request.id))
            context.set_code(StatusCode.INVALID_ARGUMENT)
            return SelfTestResponse()

        try:
            path = '/devices/{}'.format(request.id)
            device = self.root.get(path)

            agent = self.core.get_device_agent(device.id)
            resp = agent.self_test(device)
            return resp.result

        except KeyError:
            context.set_details(
                'Device \'{}\' not found'.format(request.id))
            context.set_code(StatusCode.NOT_FOUND)
            return SelfTestResponse()
