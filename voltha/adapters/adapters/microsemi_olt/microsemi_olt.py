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

import voltha.core.flow_decomposer as fd
from voltha.protos.openflow_13_pb2 import OFPPF_1GB_FD, OFPPF_FIBER, ofp_port, OFPPS_LIVE, OFPXMC_OPENFLOW_BASIC

from voltha.adapters.microsemi_olt.PAS5211_constants import PMC_UPSTREAM_PORT
from voltha.protos.openflow_13_pb2 import Flows, FlowGroups


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
        self.port_list = []

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

    def reconcile_device(self, device):
        raise NotImplementedError()

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

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def create_gemport(self, device, data):
        raise NotImplementedError()

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def update_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def remove_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def update_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def remove_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def download_image(self, device, request):
        raise NotImplementedError()

    def get_image_download_status(self, device, request):
        raise NotImplementedError()

    def cancel_image_download(self, device, request):
        raise NotImplementedError()

    def activate_image_update(self, device, request):
        raise NotImplementedError()

    def revert_image_update(self, device, request):
        raise NotImplementedError()

    def self_test_device(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        log.info('self-test-device', device=device.id)
        raise NotImplementedError()

    def delete_device(self, device):
        raise NotImplementedError()

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.debug('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)
        assert len(groups.items) == 0, "Cannot yet deal with groups"
        return self.update_flow_table(device, flows.items)

    def update_flow_table(self, device, flows):
        log.info('update-flow-table', device_id=device.id, flows=flows)

        def is_downstream(in_port):
            return in_port == PMC_UPSTREAM_PORT

        def is_upstream(in_port):
            return not is_downstream(in_port)

        try:
            for flow in flows:
                _table = None
                _port = None
                _vlan_vid = None
                _metadata = None
                _output = None
                _push_tpid = None
                _pop = None
                _field = None
                _set_vlan_vid = None
                _goto = None

                if not fd.get_in_port(flow):
                    continue

                for field in fd.get_ofb_fields(flow):

                    if field.type in (fd.IN_PORT, fd.METADATA):
                        _in_port = field.port
                        if _in_port not in (0, PMC_UPSTREAM_PORT):
                            if _in_port not in self.port_list:
                                self.port_list.append(_in_port)
                        log.info('field-type-in-port', in_port=_in_port)
            
                for port in self.port_list:
                    try:
                        self.forward_flows(port, device.parent_id, flows)
                    except Exception as e:
                        log.exception('failed-forward-flow', e=e, flow=flow)

        except Exception as e:
            log.exception('failed-update-flow-table', e=e, flow=flow)

    def forward_flows(self, logical_port, logical_device_id, flows):
        log.info('Forwarding flows to onu in port {} of {}'.format(logical_port,logical_device_id))
        onu_device_id= self.adaptor_agent.root_proxy.get('/logical_devices/{}/ports/{}'.format(logical_device_id, logical_port)).device_id
        self.adaptor_agent.root_proxy.update('/devices/{}/flows'.format(onu_device_id), Flows(items=flows))

    def get_channel_and_onu_id(self, port_no):
        channel_id = port_no / 32
        onu_id = (port_no % 32) - 1

        return channel_id, onu_id

    def create_interface(self, device, data):
        raise NotImplementedError()

    def update_interface(self, device, data):
        raise NotImplementedError()

    def remove_interface(self, device, data):
        raise NotImplementedError()

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        device = self.adaptor_agent.get_device(proxy_address.device_id)
        _, _, comm = self.olts[device.mac_address]
        if isinstance(msg, OmciFrame):
            log.info('send-omci-proxied-message', proxy_address=proxy_address,
                     device=device, adapter_agent=self.adaptor_agent.adapter_name)
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
        log.info("receive-proxied-message")
        #raise NotImplementedError()

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()



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


