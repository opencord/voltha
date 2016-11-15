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
Mock device adapter for testing.
"""
import structlog
from zope.interface import implementer

from voltha.adapters.interface import IAdapterInterface
from voltha.protos.adapter_pb2 import Adapter, DeviceTypes, AdapterConfig
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.common_pb2 import INFO

log = structlog.get_logger()


@implementer(IAdapterInterface)
class SimulatedAdapter(object):

    def __init__(self, config):
        self.config = config
        self.descriptor = Adapter(
            id='simulated',
            vendor='Voltha project',
            version='0.1',
            config=AdapterConfig(log_level=INFO)
        )

    def start(self):
        log.debug('starting')
        # pass
        log.info('started')

    def stop(self):
        log.debug('stopping')
        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(
            items=[]  # TODO
        )

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        raise NotImplementedError(0
                                  )
    def deactivate_device(self, device):
        raise NotImplementedError()

