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

from voltha.core.config.config_proxy import CallbackType
from voltha.core.device_agent import DeviceAgent
from voltha.core.dispatcher import Dispatcher
from voltha.core.global_handler import GlobalHandler
from voltha.core.local_handler import LocalHandler
from voltha.core.logical_device_agent import LogicalDeviceAgent
from voltha.protos.voltha_pb2 import \
    VolthaLocalServiceStub, \
    Device, LogicalDevice
from voltha.registry import IComponent

log = structlog.get_logger()


@implementer(IComponent)
class VolthaCore(object):

    def __init__(self, instance_id, version, log_level):
        self.instance_id = instance_id
        self.stopped = False
        self.dispatcher = Dispatcher(self, instance_id)
        self.global_handler = GlobalHandler(
            dispatcher=self.dispatcher,
            instance_id=instance_id,
            version=version,
            log_level=log_level)
        self.local_handler = LocalHandler(
            core=self,
            instance_id=instance_id,
            version=version,
            log_level=log_level)
        self.local_root_proxy = None
        self.device_agents = {}
        self.logical_device_agents = {}
        self.packet_in_queue = Queue()
        self.change_event_queue = Queue()

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        yield self.dispatcher.start()
        yield self.global_handler.start()
        yield self.local_handler.start()
        self.local_root_proxy = self.get_proxy('/')
        self.local_root_proxy.register_callback(
            CallbackType.POST_ADD, self._post_add_callback)
        self.local_root_proxy.register_callback(
            CallbackType.POST_REMOVE, self._post_remove_callback)
        log.info('started')
        returnValue(self)

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    def get_local_handler(self):
        return self.local_handler

    def get_proxy(self, path, exclusive=False):
        return self.local_handler.get_proxy(path, exclusive)

    def _post_add_callback(self, data, *args, **kw):
        log.debug('added', data=data, args=args, kw=kw)
        if isinstance(data, Device):
            self._handle_add_device(data)
        elif isinstance(data, LogicalDevice):
            self._handle_add_logical_device(data)
        else:
            pass  # ignore others

    def _post_remove_callback(self, data, *args, **kw):
        log.debug('added', data=data, args=args, kw=kw)
        if isinstance(data, Device):
            self._handle_remove_device(data)
        elif isinstance(data, LogicalDevice):
            self._handle_remove_logical_device(data)
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

    @inlineCallbacks
    def _handle_remove_device(self, device):
        if device.id in self.device_agents:
            yield self.device_agents[device.id].stop()
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
    def _handle_remove_logical_device(self, logical_device):
        if logical_device.id in self.logical_device_agents:
            yield self.logical_device_agents[logical_device.id].stop()
            del self.logical_device_agents[logical_device.id]

    def get_logical_device_agent(self, logical_device_id):
        return self.logical_device_agents[logical_device_id]
