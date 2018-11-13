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

import sys
from mock_adapter_agent import MockDevice
from nose.twistedtools import reactor


class MockOltHandler(MockDevice):
    """
    VERY Minimal class to handle OLT needs in OpenOMCI testing

    So that we do not have to duplicate the IAdapter functionality, just
    the handler, the OLT and ONU handlers are derived from a mock Device
    base class so that we can access the _devices map and get either a
    Device to play with (like the real thing) or the associated handler
    """
    def __init__(self, adapter_agent, device_id):
        super(MockOltHandler, self).__init__(device_id)

        self.device_id = device_id
        self.device = self
        self._adapter_agent = adapter_agent
        self._num_tx = 0

        ####################################################################
        # NOTE: The following can be manipulated in your test case to modify the behaviour
        #       of this mock.
        #
        # Note that activated ONUs are added during adapter add_child_device
        # if the ONU handler associated is 'enabled'

        self.enabled = True                # OLT is enabled/active
        self.activated_onus = set()        # Activated ONU serial numbers
        self.enabled_pons = range(0, 16)   # Enabled PONs
        self.max_tx = sys.maxint           # Fail after this many tx requests
        self.latency = 0.0                 # OMCI response latency (keep small)

    # TODO: Implement minimal functionality

    # TODO: Implement minimal functionality

    def tearDown(self):
        """Test case cleanup"""
        pass

    # Begin minimal set of needed IAdapter interfaces

    def send_proxied_message(self, proxy_address, msg):
        """Check various enabled flags and status and send if okay"""

        if not self.enabled:
            return None

        pon_id = proxy_address.channel_id

        if pon_id not in self.enabled_pons:
            return None

        # Look up ONU device ID.
        onu_id = proxy_address.onu_id
        onu_handler = self._adapter_agent.get_child_device(proxy_address.device_id,
                                                           pon_id=pon_id,
                                                           onu_id=onu_id)

        if onu_handler is None or not onu_handler.enabled:
            return None

        onu_mock = onu_handler.onu_mock
        if onu_mock is None or onu_mock.serial_number not in self.activated_onus:
            return None

        # And Tx success (silent discard for OMCI timeout testing)
        if self._num_tx >= self.max_tx:
            return None
        self._num_tx += 1

        response = onu_mock.rx_omci_frame(msg)

        # Make async and add any requested latency. Bound it to less
        # than 5 seconds since this is a unit test that need to be
        # somewhat responsive

        assert 0.0 <= self.latency <= 5, 'Best practice is latency <= 5 seconds'
        if response is not None:
            reactor.callLater(self.latency, self._deliver_proxy_message, proxy_address, response)

    def _deliver_proxy_message(self, proxy_address, response):
        from common.frameio.frameio import hexify
        self._adapter_agent.receive_proxied_message(proxy_address,
                                                    hexify(str(response)))

    def receive_proxied_message(self, _, __):
        assert False, 'This is never called on the OLT side of proxy messaging'

