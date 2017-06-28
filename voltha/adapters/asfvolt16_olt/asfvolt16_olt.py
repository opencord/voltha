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
Asfvolt16 OLT adapter
"""

import structlog
from voltha.adapters.iadapter import OltAdapter
from voltha.adapters.asfvolt16.asfvolt16_device_handler import Asfvolt16Handler

log = structlog.get_logger()

class Asfvolt16Adapter(OltAdapter):
    def __init__(self, adapter_agent, config):
        super(Asfvolt16Adapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class = Asfvolt16Handler,
                                               name='asfvolt16_olt',
                                               vendor='Edgecore',
                                               version='0.1')
        # register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()
<<<<<<< 29dd1987b0e63d3ba500b8cb92aafd0b0a1b13c9
=======

class Asfvolt16Handler(object):
    def __init__(self, adapter, device_id):
        raise NotImplementedError()

    def __del__(self):
        raise NotImplementedError()

    def get_channel(self):
        raise NotImplementedError()

    def _get_nni_port(self):
        raise NotImplementedError()

    def activate(self, device):
        raise NotImplementedError()

    def reconcile(self, device):
        raise NotImplementedError()

    def rcv_io(self, port, frame):
        raise NotImplementedError()

    def update_flow_table(self, flows):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_config):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def packet_out(self, egress_port, msg):
        raise NotImplementedError()

    def self_test_req(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        log.info('self-test-req', device=device.id)
        raise NotImplementedError()

    def reboot(self):
        raise NotImplementedError()

    def disable(self):
        raise NotImplementedError()

    def reenable(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()

    def start_kpi_collection(self, device_id):
        raise NotImplementedError()
>>>>>>> Commit support Device Management- Self Test on Device
