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
from voltha.adapters.asfvolt16_olt.asfvolt16_device_handler import Asfvolt16Handler
from voltha.adapters.asfvolt16_olt.asfvolt16_rx_handler import Asfvolt16RxHandler

log = structlog.get_logger()

class Asfvolt16Adapter(OltAdapter):
    def __init__(self, adapter_agent, config):
        super(Asfvolt16Adapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class = Asfvolt16Handler,
                                               name='asfvolt16_olt',
                                               vendor='Edgecore',
                                               version='0.1',
                                               device_type='asfvolt16_olt')
        # register for adapter messages
        self.port = 60001
        self.rx_handler = Asfvolt16RxHandler(self, self.port, log)
        self.rx_handler.start()
        self.adapter_agent.register_for_inter_adapter_messages()

    def stop(self):
        self.rx_handler.stop()
