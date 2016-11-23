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
Interface definition for Voltha Adapters
"""
import structlog
from twisted.internet.defer import inlineCallbacks, returnValue
from zope.interface import Interface
from zope.interface import implementer

from voltha.protos import third_party
from voltha.protos.device_pb2 import Device, Port
from voltha.protos.openflow_13_pb2 import ofp_port
from voltha.protos.voltha_pb2 import DeviceGroup, LogicalDevice
from voltha.registry import registry


log = structlog.get_logger()


class IAdapterInterface(Interface):
    """
    A Voltha adapter
    """

    def start():
        """
        Called once after adapter instance is laoded. Can be used to async
        initialization.
        :return: (None or Deferred)
        """

    def stop():
        """
        Called once before adapter is unloaded. It can be used to perform
        any cleanup after the adapter.
        :return: (None or Deferred)
        """

    def adapter_descriptor():
        """
        Return the adapter descriptor object for this adapter.
        :return: voltha.Adapter grpc object (see voltha/protos/adapter.proto),
        with adapter-specific information and config extensions.
        """

    def device_types():
        """
        Return list of device types supported by the adapter.
        :return: voltha.DeviceTypes protobuf object, with optional type
        specific extensions.
        """

    def health():
        """
        Return a 3-state health status using the voltha.HealthStatus message.
        :return: Deferred or direct return with voltha.HealthStatus message
        """

    def change_master_state(master):
        """
        Called to indicate if plugin shall assume or lose master role. The
        master role can be used to perform functions that must be performed
        from a single point in the cluster. In single-node deployments of
        Voltha, the plugins are always in master role.
        :param master: (bool) True to indicate the mastership needs to be
         assumed; False to indicate that mastership needs to be abandoned.
        :return: (Deferred) which is fired by the adapter when mastership is
         assumed/dropped, respectively.
        """

    def adopt_device(device):
        """
        Make sure the adapter looks after given device. Called when a device
        is provisioned top-down and needs to be activated by the adapter.
        :param device: A voltha.Device object, with possible device-type
        specific extensions. Such extensions shall be described as part of
        the device type specification returned by device_types().
        :return: (Deferred) Shall be fired to acknowledge device ownership.
        """

    def abandon_device(device):
        """
        Make sur ethe adapter no longer looks after device. This is called
        if device ownership is taken over by another Voltha instance.
        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge abandonment.
        """

    def deactivate_device(device):
        """
        Called if the device is to be deactivate based on a NBI call.
        :return: (Deferred) Shall be fired to acknowledge deactivation.
        """

    # TODO work in progress
    # ...


class IAdapterProxy(Interface):
    """
    This object is passed in to the __init__ function of each adapter,
    and can be used by the adapter implementation to initiate async calls
    toward Voltha's CORE via the APIs defined here.
    """

    def create_device(device):
        # TODO add doc
        """"""

    def add_port(device_id, port):
        # TODO add doc
        """"""

    def create_logical_device(logical_device):
        # TODO add doc
        """"""

    def add_logical_port(logical_device_id, port):
        # TODO add doc
        """"""

    # TODO work in progress
    pass


@implementer(IAdapterProxy)
class AdapterProxy(object):
    """
    Gate-keeper between CORE and device adapters.

    On one side it interacts with Core's internal model and update/dispatch
    mechanisms.

    On the other side, it interacts with the adapters standard interface as
    defined in
    """

    def __init__(self, adapter_name, adapter_cls):
        self.adapter_name = adapter_name
        self.adapter_cls = adapter_cls
        self.core = registry('core')
        self.adapter = None
        self.adapter_node_proxy = None

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        config = self._get_adapter_config()  # this may be None
        adapter = self.adapter_cls(self, config)
        yield adapter.start()
        self.adapter = adapter
        self.adapter_node_proxy = self._update_adapter_node()
        self._update_device_types()
        log.info('started')
        returnValue(self)

    @inlineCallbacks
    def stop(self):
        log.debug('stopping')
        if self.adapter is not None:
            yield self.adapter.stop()
            self.adapter = None
        log.info('stopped')

    def _get_adapter_config(self):
        """
        Opportunistically load persisted adapter configuration.
        Return None if no configuration exists yet.
        """
        proxy = self.core.get_proxy('/')
        try:
            config = proxy.get('/adapters/' + self.adapter_name)
            return config
        except KeyError:
            return None

    def _update_adapter_node(self):
        """
        Creates or updates the adapter node object based on self
        description from the adapter.
        """

        adapter_desc = self.adapter.adapter_descriptor()
        assert adapter_desc.id == self.adapter_name
        path = self._make_up_to_date(
            '/adapters', self.adapter_name, adapter_desc)
        return self.core.get_proxy(path)

    def _update_device_types(self):
        """
        Make sure device types are registered in Core
        """
        device_types = self.adapter.device_types()
        for device_type in device_types.items:
            key = device_type.id
            self._make_up_to_date('/device_types', key, device_type)

    def _make_up_to_date(self, container_path, key, data):
        full_path = container_path + '/' + str(key)
        root_proxy = self.core.get_proxy('/')
        try:
            root_proxy.get(full_path)
            root_proxy.update(full_path, data)
        except KeyError:
            root_proxy.add(container_path, data)
        return full_path

    # ~~~~~~~~~~~~~~~~~ Adapter-Facing Service ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def create_device(self, device):
        assert isinstance(device, Device)
        self._make_up_to_date('/devices', device.id, device)

        # TODO for now, just map everything into a single device group
        # which we create if it does not yet exist

        dg = DeviceGroup(id='1')
        self._make_up_to_date('/device_groups', dg.id, dg)

        # add device to device group
        # TODO how to do that?

    def create_logical_device(self, logical_device):
        assert isinstance(logical_device, LogicalDevice)
        self._make_up_to_date('/logical_devices',
                              logical_device.id, logical_device)

        # TODO link logical device to root device and back...

    def add_port(self, device_id, port):
        assert isinstance(port, Port)
        self._make_up_to_date('/devices/{}/ports'.format(device_id),
                              port.id, port)

    def add_logical_port(self, logical_device_id, port):
        assert isinstance(port, ofp_port)
        self._make_up_to_date(
            '/logical_devices/{}/ports'.format(logical_device_id),
            port.port_no, port)

