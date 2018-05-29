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

from mock_adapter_agent import MockProxyAddress, MockDevice
from voltha.extensions.omci.omci_cc import *
from voltha.extensions.omci.omci_entities import entity_id_to_class_map


class MockOnuHandler(MockDevice):
    """
    Minimal class to handle ONU needs in OpenOMCI testing

    So that we do not have to duplicate the IAdapter functionality, just
    the handler, the OLT and ONU handlers are derived from a mock Device
    base class so that we can access the _devices map and get either a
    Device to play with (like the real thing) or the associated handler
    """
    def __init__(self, adapter_agent, parent_id, device_id, pon_id, onu_id):

        self.proxy_address = MockProxyAddress(parent_id, pon_id, onu_id)
        super(MockOnuHandler, self).__init__(device_id, self.proxy_address)

        self.device_id = device_id
        self.device = self
        self._adapter_agent = adapter_agent

        self.onu_mock = None
        self.omci_cc = OMCI_CC(adapter_agent, device_id, me_map=entity_id_to_class_map)

        # Items that you can change to perform various test failures

        self._enabled = True

    def tearDown(self):
        """Test case cleanup"""
        if self.onu_mock is not None:
            self.onu_mock.tearDown()
        self.onu_mock = None

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._enabled != value:
            self._enabled = value
            olt = self._adapter_agent.get_device(self.proxy_address.device_id)
            if olt is not None and self.proxy_address.channel_id in olt.enabled_pons:
                if self._enabled:
                    olt.activated_onus.add(self.serial_number)
                else:
                    olt.activated_onus.discard(self.serial_number)

    # Begin minimal set of needed IAdapter interfaces

    # TODO: Implement minimal functionality

    def send_proxied_message(self, proxy_address, msg):
        assert False, 'OpenOMCI will implement this for the MOCK ONU'

    def receive_proxied_message(self, _, msg):
        # Rx of OMCI message from MOCK OLT

        if self.omci_cc is not None and self.enabled:
            self.omci_cc.receive_message(msg.decode('hex'))
