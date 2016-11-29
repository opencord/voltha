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
from voltha.adapters.microsemi.PAS5211 import PAS5211MsgGetOltVersion, PAS5211MsgGetOltVersionResponse
from voltha.adapters.microsemi.PAS5211_comm import PAS5211Communication
from voltha.adapters.microsemi.StateMachine import Disconnected, States

from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig, DeviceTypes
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
        self.olt = Disconnected(comm)

    def start(self):
        log.info('starting')
        reactor.callLater(0, self.__init_olt)
        reactor.callLater(2, self.adapter_descriptor)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.olt.disconnect()
        log.info('stopped')
        return self

    def adapter_descriptor(self):
        if self.descriptor is None:
            self.descriptor = self.__obtain_descriptor()
        print self.descriptor
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
        olt = self.olt
        while not olt.abandon():
            if olt.state() == States.DISCONNECTED or olt.state() == States.FETCH_VERSION:
                olt.run()
                olt = olt.transition()
            elif olt.state() == States.CONNECTED:
                olt.run()
                break
        if olt.abandon():
            #TODO Add more info here
            log.info('Disconnecting this OLT')
            self.stop()
        self.olt = olt


    def __obtain_descriptor(self):
        layer = PAS5211MsgGetOltVersionResponse.name
        pkt = self.olt.send_msg(PAS5211MsgGetOltVersion())
        return Adapter(
            id='ruby-{}'.format(olt_conf['olts']['id']),
            vendor='Celestica',
            version='{}.{}.{}'.format(pkt[layer].major_firmware_version,
                                      pkt[layer].minor_firmware_version,
                                      pkt[layer].build_firmware_version))

