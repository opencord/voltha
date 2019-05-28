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
Broadcom OpenOMCI OLT/ONU adapter.

This adapter does NOT support XPON
"""

from twisted.internet import reactor, task
from zope.interface import implementer

from voltha.adapters.brcm_openomci_onu.brcm_openomci_onu_handler import BrcmOpenomciOnuHandler
from voltha.adapters.interface import IAdapterInterface
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Image
from voltha.protos.health_pb2 import HealthStatus

from common.frameio.frameio import hexify
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent, OpenOmciAgentDefaults
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict
from omci.brcm_capabilities_task import BrcmCapabilitiesTask
from omci.brcm_get_mds_task import BrcmGetMdsTask
from omci.brcm_mib_sync import BrcmMibSynchronizer
from copy import deepcopy


_ = third_party
log = structlog.get_logger()


@implementer(IAdapterInterface)
class BrcmOpenomciOnuAdapter(object):

    name = 'brcm_openomci_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            vendor_ids=['OPEN', 'ALCL', 'BRCM', 'TWSH', 'ALPH', 'ISKT', 'SFAA', 'BBSM'],
            adapter=name,
            accepts_bulk_flow_update=True,
            accepts_add_remove_flow_updates=True
        )
    ]

    def __init__(self, adapter_agent, config):
        log.debug('function-entry', config=config)
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Voltha project',
            version='0.50',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.devices_handlers = dict()

        # Customize OpenOMCI for Broadcom ONUs
        self.broadcom_omci = deepcopy(OpenOmciAgentDefaults)

        self.broadcom_omci['mib-synchronizer']['state-machine'] = BrcmMibSynchronizer
        self.broadcom_omci['omci-capabilities']['tasks']['get-capabilities'] = BrcmCapabilitiesTask
        # Defer creation of omci agent to a lazy init that allows subclasses to override support classes
        # register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

    def custom_me_entities(self):
        return None

    @property
    def omci_agent(self):
        if not hasattr(self, '_omci_agent') or self._omci_agent is None:
            log.debug('creating-omci-agent')
            self._omci_agent = OpenOMCIAgent(self.adapter_agent.core,
                                             support_classes=self.broadcom_omci)
        return self._omci_agent

    def start(self):
        log.debug('starting')
        self.omci_agent.start()
        log.info('started')

    def stop(self):
        log.debug('stopping')

        omci, self._omci_agent = self._omci_agent, None
        if omci is not None:
            self._omci_agent.stop()

        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        log.info('adopt_device', device_id=device.id)
        self.devices_handlers[device.id] = BrcmOpenomciOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device

    def reconcile_device(self, device):
        log.info('reconcile-device', device_id=device.id)
        self.devices_handlers[device.id] = BrcmOpenomciOnuHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].reconcile, device)

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        log.info('disable-onu-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.disable(device)

    def reenable_device(self, device):
        log.info('reenable-onu-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.reenable(device)

    def reboot_device(self, device):
        log.info('reboot-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.reboot()

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
        log.info('self-test-device - Not implemented yet', device=device.id)
        raise NotImplementedError()

    def delete_device(self, device):
        log.info('delete-device', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.delete(device)
            del self.devices_handlers[device.id]
        return

    def get_device_details(self, device):
        raise NotImplementedError()

    # TODO(smbaker): When BrcmOpenomciOnuAdapter is updated to inherit from OnuAdapter, this function can be deleted
    def update_pm_config(self, device, pm_config):
        log.info("adapter-update-pm-config", device=device,
                 pm_config=pm_config)
        handler = self.devices_handlers[device.id]
        handler.update_pm_config(device, pm_config)

    def update_flows_bulk(self, device, flows, groups):
        '''
        log.info('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)
        '''
        assert len(groups.items) == 0
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(device, flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        log.info('incremental-flow-update', device_id=device.id,
                 flows=flow_changes, groups=group_changes)
        # For now, there is no support for group changes
        assert len(group_changes.to_add.items) == 0
        assert len(group_changes.to_remove.items) == 0

        handler = self.devices_handlers[device.id]
        # Remove flows
        if len(flow_changes.to_remove.items) != 0:
            handler.remove_onu_flows(device, flow_changes.to_remove.items)

        # Add flows
        if len(flow_changes.to_add.items) != 0:
            handler.add_onu_flows(device, flow_changes.to_add.items)

    def send_proxied_message(self, proxy_address, msg):
        log.debug('send-proxied-message', proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.debug('receive-proxied-message', proxy_address=proxy_address,
                 device_id=proxy_address.device_id, msg=hexify(msg))
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.receive_message(msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        log.debug('receive_inter_adapter_message', msg=msg)
        proxy_address = msg['proxy_address']
        assert proxy_address is not None
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.event_messages.put(msg)
        else:
            log.error("device-not-found")

    def create_interface(self, device, data):
        log.debug('create-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_interface(data)

    def update_interface(self, device, data):
        log.debug('update-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_interface(data)

    def remove_interface(self, device, data):
        log.debug('remove-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_interface(data)

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.debug('create-tcont', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_tcont(tcont_data, traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.debug('remove-tcont', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_tcont(tcont_data, traffic_descriptor_data)

    def create_gemport(self, device, data):
        log.debug('create-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_gemport(data)

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        log.debug('remove-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_gemport(data)

    def create_multicast_gemport(self, device, data):
        log.debug('create-multicast-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_multicast_gemport(data)

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

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

