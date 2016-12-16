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
Microsemi/Celestica Ruby vOLTHA adapter.
"""
import structlog
from twisted.internet import reactor



from voltha.adapters.interface import IAdapterInterface
from voltha.adapters.microsemi.OltStateMachine import OltStateMachine
from voltha.adapters.microsemi.PAS5211_comm import PAS5211Communication
from voltha.protos import third_party
from voltha.protos.device_pb2 import DeviceTypes
from voltha.protos.health_pb2 import HealthStatus

from zope.interface import implementer

log = structlog.get_logger()
_ = third_party

# Move to configuration... eventually
olt_conf = { 'olts' : { 'id' : 0, 'mac' : '00:0c:d5:00:01:00'}, 'iface' : 'eth3'}

@implementer(IAdapterInterface)
class RubyAdapter(object):
    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.descriptor = None
        self.comm = comm = PAS5211Communication(dst_mac=olt_conf['olts']['mac'],
                                                iface=olt_conf['iface'])
        self.olt = OltStateMachine(iface=olt_conf['iface'],
                                   comm=comm,
                                   target=olt_conf['olts']['mac'])


    def start(self):
        log.info('starting')
        reactor.callLater(0, self.__init_olt)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.olt.stop()
        log.info('stopped')
        return self

    def adapter_descriptor(self):
        if self.descriptor is None:
            self.descriptor = self.__obtain_descriptor()
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
        raise NotImplementedError(0)

    def deactivate_device(self, device):
        raise NotImplementedError()

    ##
    # Private methods
    ##

    def __init_olt(self):
        self.olt.run()




