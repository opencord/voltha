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
Agent to play gateway between CORE and an individual adapter.
"""
from uuid import uuid4

import structlog
from twisted.internet.defer import inlineCallbacks, returnValue
from zope.interface import implementer

from voltha.adapters.interface import IAdapterAgent
from voltha.protos import third_party
from voltha.protos.device_pb2 import Device, Port
from voltha.protos.voltha_pb2 import DeviceGroup, LogicalDevice, \
    LogicalPort, AdminState
from voltha.registry import registry


log = structlog.get_logger()

@implementer(IAdapterAgent)
class AdapterAgent(object):
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
        self.root_proxy = self.core.get_proxy('/')

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

    # ~~~~~~~~~~~~~~~~~~~~~ Core-Facing Service ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def adopt_device(self, device):
        return self.adapter.adopt_device(device)

    def abandon_device(self, device):
        return self.adapter.abandon_device(device)

    def deactivate_device(self, device):
        return self.adapter.deactivate_device(device)

    # ~~~~~~~~~~~~~~~~~~~ Adapter-Facing Service ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def get_device(self, device_id):
        return self.root_proxy.get('/devices/{}'.format(device_id))

    def add_device(self, device):
        assert isinstance(device, Device)
        self._make_up_to_date('/devices', device.id, device)

        # TODO for now, just map everything into a single device group
        # which we create if it does not yet exist

        dg = DeviceGroup(id='1')
        self._make_up_to_date('/device_groups', dg.id, dg)

        # add device to device group
        # TODO how to do that?

    def update_device(self, device):
        assert isinstance(device, Device)

        # we run the update through the device_agent so that the change
        # does not loop back to the adapter unnecessarily
        device_agent = self.core.get_device_agent(device.id)
        device_agent.update_device(device)

    def remove_device(self, device_id):
        device_agent = self.core.get_device_agent(device_id)
        device_agent.remove_device(device_id)

    def add_port(self, device_id, port):
        assert isinstance(port, Port)

        # for referential integrity, add/augment references
        port.device_id = device_id
        me_as_peer = Port.PeerPort(device_id=device_id, port_no=port.port_no)
        for peer in port.peers:
            peer_port_path = '/devices/{}/ports/{}'.format(
                peer.device_id, peer.port_no)
            peer_port = self.root_proxy.get(peer_port_path)
            if me_as_peer not in peer_port.peers:
                new = peer_port.peers.add()
                new.CopyFrom(me_as_peer)
            self.root_proxy.update(peer_port_path, peer_port)

        self._make_up_to_date('/devices/{}/ports'.format(device_id),
                              port.port_no, port)

    def create_logical_device(self, logical_device):
        assert isinstance(logical_device, LogicalDevice)
        self._make_up_to_date('/logical_devices',
                              logical_device.id, logical_device)

    def add_logical_port(self, logical_device_id, port):
        assert isinstance(port, LogicalPort)
        self._make_up_to_date(
            '/logical_devices/{}/ports'.format(logical_device_id),
            port.id, port)

    def child_device_detected(self,
                              parent_device_id,
                              parent_port_no,
                              child_device_type,
                              child_device_address_kw):
        # we create new ONU device objects and insert them into the config
        # TODO should we auto-enable the freshly created device? Probably
        device = Device(
            id=uuid4().hex[:12],
            type=child_device_type,
            parent_id=parent_device_id,
            parent_port_no=parent_port_no,
            admin_state=AdminState.ENABLED,
            **child_device_address_kw
        )
        self._make_up_to_date(
            '/devices', device.id, device)
