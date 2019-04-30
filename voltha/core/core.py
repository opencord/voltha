#
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

"""
Voltha's CORE components.
"""

from Queue import Queue

import structlog
from twisted.internet.defer import inlineCallbacks, returnValue
from zope.interface import implementer

from voltha.core.alarm_filter_agent import AlarmFilterAgent
from voltha.core.config.config_proxy import CallbackType
from voltha.core.device_agent import DeviceAgent
from voltha.core.dispatcher import Dispatcher
from voltha.core.global_handler import GlobalHandler
from voltha.core.local_handler import LocalHandler
from voltha.core.logical_device_agent import LogicalDeviceAgent
from voltha.protos.voltha_pb2 import \
    Device, LogicalDevice, AlarmFilter
from voltha.registry import IComponent
from xpon_agent import XponAgent
from xpon_handler import XponHandler
from voltha.protos.bbf_fiber_base_pb2 import ChannelgroupConfig, \
    ChannelpartitionConfig, ChannelpairConfig, OntaniConfig, VOntaniConfig, \
    VEnetConfig
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData

log = structlog.get_logger()


@implementer(IComponent)
class VolthaCore(object):
    def __init__(self,
                 instance_id,
                 core_store_id,
                 grpc_port,
                 version,
                 log_level):
        self.instance_id = instance_id
        self.stopped = False
        self.dispatcher = Dispatcher(self,
                                     instance_id,
                                     core_store_id,
                                     grpc_port)
        self.core_store_id = core_store_id
        self.global_handler = GlobalHandler(
            dispatcher=self.dispatcher,
            instance_id=instance_id,
            version=version,
            log_level=log_level)
        self.xpon_handler = XponHandler(self)
        self.local_handler = LocalHandler(
            core=self,
            instance_id=instance_id,
            core_store_id=core_store_id,
            version=version,
            log_level=log_level)
        self.local_root_proxy = None
        self.device_agents = {}
        self.logical_device_agents = {}
        self.alarm_filter_agent = None
        self.packet_in_queue = Queue()
        self.change_event_queue = Queue()
        self.xpon_agent = XponAgent(self)

    @inlineCallbacks
    def start(self, config_backend=None):
        log.debug('starting')
        yield self.dispatcher.start()
        yield self.global_handler.start()
        yield self.local_handler.start(config_backend=config_backend)
        self.local_root_proxy = self.get_proxy('/')
        self.local_root_proxy.register_callback(
            CallbackType.POST_ADD, self._post_add_callback)
        self.local_root_proxy.register_callback(
            CallbackType.POST_REMOVE, self._post_remove_callback)

        log.info('started')
        returnValue(self)

    @inlineCallbacks
    def register_grpc_service(self):
        yield self.local_handler.register_grpc_service()
        yield self.global_handler.register_grpc_service()

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    def get_local_handler(self):
        return self.local_handler

    @inlineCallbacks
    def reconcile_data(self):
        # This method is used to trigger the necessary APIs when a voltha
        # instance is started using an existing config
        if self.local_handler.has_started_with_existing_data():
            log.info('reconciliation-started')

            # 1. Reconcile the logical device agents as they will be
            # referred by the device agents
            logical_devices = self.local_root_proxy.get('/logical_devices')
            for logical_device in logical_devices:
                self._handle_reconcile_logical_device(logical_device,
                                                      reconcile=True)

            # 2. Reconcile the device agents
            devices = self.local_root_proxy.get('/devices')

            # First create the device agents for the ONU without reconciling
            # them.  Reconciliation will be triggered by the OLT adapter after
            # it finishes reconciling the OLT.  Note that the device_agent
            # handling the ONU should be present before the ONU reconciliation
            # occurs
            for device in devices:
                if device.type.endswith("onu"):
                    yield self._handle_reconcile_existing_device(
                        device=device, reconcile=False)

            # Then reconcile the OLT devices
            for device in devices:
                if device.type.endswith("olt"):
                    yield self._handle_reconcile_existing_device(
                        device=device, reconcile=True)

            # 3. Reconcile the alarm filters
            alarm_filters = self.local_root_proxy.get('/alarm_filters')
            for alarm_filter in alarm_filters:
                yield self._handle_add_alarm_filter(alarm_filter)

            log.info('reconciliation-ends')
        else:
            log.info('no-existing-data-to-reconcile')

    def _get_devices(self):
        pass

    def _get_logical_devices(self):
        pass

    def get_proxy(self, path, exclusive=False):
        return self.local_handler.get_proxy(path, exclusive)

    def _post_add_callback(self, data, *args, **kw):
        log.debug('added', data=data, args=args, kw=kw)
        if isinstance(data, Device):
            self._handle_add_device(data)
        elif isinstance(data, LogicalDevice):
            self._handle_add_logical_device(data)
        elif isinstance(data, (ChannelgroupConfig, ChannelpartitionConfig,
                               ChannelpairConfig, OntaniConfig, VOntaniConfig,
                               VEnetConfig, TrafficDescriptorProfileData,
                               TcontsConfigData, GemportsConfigData)):
            self.xpon_agent.create_interface(data)
        elif isinstance(data, AlarmFilter):
            self._handle_add_alarm_filter(data)
        else:
            pass  # ignore others

    def _post_remove_callback(self, data, *args, **kw):
        log.debug('removed', data=data, args=args, kw=kw)
        if isinstance(data, Device):
            self._handle_remove_device(data)
        elif isinstance(data, LogicalDevice):
            self._handle_remove_logical_device(data)
        elif isinstance(data, (ChannelgroupConfig, ChannelpartitionConfig,
                               ChannelpairConfig, OntaniConfig, VOntaniConfig,
                               VEnetConfig, TrafficDescriptorProfileData,
                               TcontsConfigData, GemportsConfigData)):
            self.xpon_agent.remove_interface(data)
        elif isinstance(data, AlarmFilter):
            self._handle_remove_alarm_filter(data)
        else:
            pass  # ignore others

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~DeviceAgent Mgmt ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    @inlineCallbacks
    def _handle_add_device(self, device):
        # when a device is added, we attach an observer to it so that we can
        # guard it and propagate changes down to its owner adapter
        assert isinstance(device, Device)
        path = '/devices/{}'.format(device.id)
        assert device.id not in self.device_agents
        self.device_agents[device.id] = yield DeviceAgent(self, device).start()
        self.xpon_agent.register_interface(device.id, path, update=False)

    @inlineCallbacks
    def _handle_reconcile_existing_device(self, device, reconcile):
        assert isinstance(device, Device)
        assert device.id not in self.device_agents
        # We need to provide the existing device data to the start function
        self.device_agents[device.id] = \
            yield DeviceAgent(self, device).start(device=device,
                                                  reconcile=reconcile)
        path = '/devices/{}'.format(device.id)
        self.xpon_agent.register_interface(device.id, path, update=False)

        try:
            # Register for updates to '/tconts/{}'.
            # Otherwise TrafficDescriptorProfile updates after VOLTHA restart
            # are dropped at VOLTHA core.
            tconts = self.local_root_proxy.get('/tconts')
            for tcont in tconts:
                try:
                    olt_device = self.xpon_agent.get_device(tcont, 'olt')
                except Exception as e:
                    log.error("exception-getting-olt", e=e)
                    return
                if olt_device and olt_device.id == device.id:
                    tcont_path = '/tconts/{}'.format(tcont.name)
                    self.xpon_agent.register_interface(device.id, tcont_path)
        except Exception as e:
            log.exception("error-fetching-tcont--xpon-may-not-be-supported", e=e)


    @inlineCallbacks
    def _handle_remove_device(self, device):
        if device.id in self.device_agents:
            path = '/devices/{}'.format(device.id)
            self.xpon_agent.unregister_interface(device.id, path, update=False)
            if self.alarm_filter_agent is not None:
                self.alarm_filter_agent.remove_device_filters(device)

            log.debug('removed-device-filter', device=device)

            yield self.device_agents[device.id].stop(device)
            del self.device_agents[device.id]

    def get_device_agent(self, device_id):
        return self.device_agents[device_id]

    # ~~~~~~~~~~~~~~~~~~~~~~~ LogicalDeviceAgent Mgmt ~~~~~~~~~~~~~~~~~~~~~~~~~

    @inlineCallbacks
    def _handle_add_logical_device(self, logical_device):
        assert isinstance(logical_device, LogicalDevice)
        assert logical_device.id not in self.logical_device_agents
        agent = yield LogicalDeviceAgent(self, logical_device).start()
        self.logical_device_agents[logical_device.id] = agent

    @inlineCallbacks
    def _handle_reconcile_logical_device(self, logical_device, reconcile):
        assert isinstance(logical_device, LogicalDevice)
        assert logical_device.id not in self.logical_device_agents
        log.info('reconcile', reconcile=reconcile)
        agent = yield LogicalDeviceAgent(self,
                                         logical_device).start(
            reconcile=reconcile)
        self.logical_device_agents[logical_device.id] = agent

    @inlineCallbacks
    def _handle_remove_logical_device(self, logical_device):
        if logical_device.id in self.logical_device_agents:
            yield self.logical_device_agents[logical_device.id].stop()
            del self.logical_device_agents[logical_device.id]

    def get_logical_device_agent(self, logical_device_id):
        return self.logical_device_agents[logical_device_id]

    # ~~~~~~~~~~~~~~~~~~~~~~~ AlarmFilterAgent Mgmt ~~~~~~~~~~~~~~~~~~~~~~~~~

    @inlineCallbacks
    def _handle_add_alarm_filter(self, alarm_filter):
        assert isinstance(alarm_filter, AlarmFilter)
        # Create an agent if it does not yet exist
        if self.alarm_filter_agent is None:
            self.alarm_filter_agent = AlarmFilterAgent(self)

        yield self.alarm_filter_agent.add_filter(alarm_filter)

    @inlineCallbacks
    def _handle_remove_alarm_filter(self, alarm_filter):
        assert isinstance(alarm_filter, AlarmFilter)
        if self.alarm_filter_agent is not None:
            yield self.alarm_filter_agent.remove_filter(alarm_filter)
