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
Microsemi/Celestica Ruby vOLTHA adapter.
"""
import structlog
from twisted.internet import reactor

from voltha.adapters.interface import IAdapterInterface
from voltha.adapters.microsemi_olt.APIProxy import APIProxy
from voltha.adapters.microsemi_olt.ActivationWatcher import ActivationWatcher
from voltha.adapters.microsemi_olt.DeviceManager import DeviceManager
from voltha.adapters.microsemi_olt.OMCIProxy import OMCIProxy
from voltha.adapters.microsemi_olt.OltStateMachine import OltStateMachine
from voltha.adapters.microsemi_olt.PAS5211_comm import PAS5211Communication
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import OmciMessage
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.common_pb2 import LogLevel
from voltha.protos.device_pb2 import DeviceTypes, DeviceType
from voltha.protos.health_pb2 import HealthStatus
from voltha.registry import registry

from zope.interface import implementer

log = structlog.get_logger()
_ = third_party


@implementer(IAdapterInterface)
class RubyAdapter(object):

    name = "microsemi_olt"

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adaptor_agent, config):
        self.adaptor_agent = adaptor_agent
        self.config = config
        self.olts = {}
        self.descriptor = Adapter(
            id=self.name,
            vendor='Microsemi / Celestica',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )

        self.interface = registry('main').get_args().interface

    def start(self):
        log.info('starting')
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        for target in self.olts.keys():
            self._abandon(target)
        log.info('stopped')
        return self

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        device_manager = DeviceManager(device, self.adaptor_agent)
        target = device.mac_address
        comm = PAS5211Communication(dst_mac=target, iface=self.interface)
        olt = OltStateMachine(iface=self.interface, comm=comm,
                              target=target, device=device_manager)
        activation = ActivationWatcher(iface=self.interface, comm=comm,
                                       target=target, device=device_manager)
        reactor.callLater(0, self._init_olt, olt, activation)

        log.info('adopted-device', device=device)
        self.olts[target] = (olt, activation, comm)

    def abandon_device(self, device):
        self._abandon(device.mac_address)

    def disable_device(self, device):
        raise NotImplementedError()

    def reenable_device(self, device):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        raise NotImplementedError()

    def reboot_device(self, device):
        raise NotImplementedError()

    def delete_device(self, device):
        raise NotImplementedError()

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.debug('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

    def send_proxied_message(self, proxy_address, msg):
        device = self.adaptor_agent.get_device(proxy_address.device_id)
        _, _, comm = self.olts[device.mac_address]
        if isinstance(msg, OmciFrame):
            log.info('send-omci-proxied-message', proxy_address=proxy_address, device=device)
            # TODO make this more efficient
            omci_proxy = OMCIProxy(proxy_address=proxy_address,
                                   msg=msg,
                                   adapter_agent=self.adaptor_agent,
                                   target=device.mac_address,
                                   comm=comm,
                                   iface=self.interface)
            omci_proxy.runbg()


        else:
            log.info('send-proxied-message', proxy_address=proxy_address)
            api_proxy = APIProxy(proxy_address=proxy_address,
                                 msg=msg,
                                 adapter_agent=self.adaptor_agent,
                                 target=device.mac_address,
                                 comm=comm,
                                 iface=self.interface)
            api_proxy.runbg()

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    ##
    # Private methods
    ##
    def _init_olt(self, olt, activation_watch):
        olt.runbg()
        activation_watch.runbg()

    def _abandon(self, target):
        olt, activation, _ = self.olts[target]
        olt.stop()
        activation.stop()
        del self.olts[target]






