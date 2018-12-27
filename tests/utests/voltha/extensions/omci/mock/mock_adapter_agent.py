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
import binascii
import structlog
from twisted.internet.defer import Deferred
from voltha.core.config.config_root import ConfigRoot
from voltha.protos.voltha_pb2 import VolthaInstance
from voltha.extensions.omci.omci_frame import OmciFrame

class MockProxyAddress(object):
    def __init__(self, device_id, pon_id, onu_id):
        self.device_id = device_id  # Device ID of proxy (OLT)
        self.onu_id = onu_id
        self.onu_session_id = onu_id

        self.channel_group_id = pon_id  # close enough for mock
        self.channel_id = pon_id
        self.channel_termination = pon_id


class MockDevice(object):
    def __init__(self, device_id, proxy_address=None, serial_number=None):
        from voltha.extensions.omci.omci_entities import entity_id_to_class_map
        self.id = device_id
        self.parent_id = None
        self.proxy_address = proxy_address
        self.serial_number = serial_number
        self.me_map = entity_id_to_class_map


class MockCore(object):
    def __init__(self):
        self.root = ConfigRoot(VolthaInstance())

    def get_proxy(self, path):
        return self.root.get_proxy(path)


class MockAdapterAgent(object):
    """
    Minimal class to handle adapter-agent needs in OpenOMCI. It can be
    used by a mock OLT or ONU.

    So that we do not have to duplicate the IAdapter functionality, just
    the handler, the OLT and ONU handlers are derived from a mock Device
    base class so that we can access the _devices map and get either a
    Device to play with (like the real thing) or the associated handler
    """
    def __init__(self, d=None):
        self.log = structlog.get_logger() 
        self._devices = dict()      # device-id -> mock device
        self.core = MockCore()
        self.deferred = d
        self.timeout_the_message = False

    @property
    def send_omci_defer(self):
        return self.deferred
        
    @send_omci_defer.setter
    def send_omci_defer(self, value):
        self.deferred = value

    @property
    def name(self):
        return "cig_mock_ont"
    
    def tearDown(self):
        """Test case cleanup"""
        for device in self._devices.itervalues():
            device.tearDown()
        self._devices.clear()

    def add_device(self, device):
        self._devices[device.id] = device

    def add_child_device(self, parent_device, child_device):
        # Set parent
        child_device.parent_id = parent_device.id

        # Add ONU serial number if PON and ONU enabled

        if (child_device.enabled and
                child_device.serial_number is not None and
                child_device.proxy_address.channel_id in parent_device.enabled_pons):
            parent_device.activated_onus.add(child_device.serial_number)

        self.add_device(child_device)

    def get_device(self, device_id):
        return self._devices[device_id]

    def get_child_device(self, parent_device_id, **kwargs):
        onu_id = kwargs.pop('onu_id', None)
        pon_id = kwargs.pop('pon_id', None)
        if onu_id is None and pon_id is None:
            return None

        # Get all child devices with the same parent ID
        children_ids = set(d.id for d in self._devices.itervalues()
                           if d.parent_id == parent_device_id)

        # Loop through all the child devices with this parent ID
        for child_id in children_ids:
            device = self.get_device(child_id)

            # Does this child device match the passed in ONU ID?
            found_onu_id = False
            if onu_id is not None:
                if device.proxy_address.onu_id == onu_id:
                    found_onu_id = True

            # Does this child device match the passed in SERIAL NUMBER?
            found_pon_id = False
            if pon_id is not None:
                if device.proxy_address.channel_id == pon_id:
                    found_pon_id = True
            # Match ONU ID and PON ID
            if onu_id is not None and pon_id is not None:
                found = found_onu_id & found_pon_id
            # Otherwise ONU ID or PON ID
            else:
                found = found_onu_id | found_pon_id

            # Return the matched child device
            if found:
                return device

        return None

    def send_proxied_message(self, proxy_address, msg):
        # Look up ONU handler and forward the message
        self.log.debug("--> send_proxied_message", message=msg)
        
        # if proxy_address is None:
        if self.deferred is not None and not self.timeout_the_message:
            self.deferred.callback(msg)
        #     return None

        # olt_handler = self.get_device(proxy_address.device_id)

        # if olt_handler is not None:
        #    olt_handler.send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        # Look up ONU handler and forward the message

        onu_handler = self.get_child_device(proxy_address.device_id,
                                            onu_id=proxy_address.onu_id,
                                            pon_id=proxy_address.channel_id)
        if onu_handler is not None:
            onu_handler.receive_proxied_message(proxy_address, msg)
