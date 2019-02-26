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
Adapter abstract base class
"""

import structlog
from zope.interface import implementer
from twisted.internet import reactor

from voltha.protos.common_pb2 import AdminState
from voltha.protos.device_pb2 import DeviceType, DeviceTypes
from voltha.adapters.interface import IAdapterInterface
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel
from voltha.protos.health_pb2 import HealthStatus

log = structlog.get_logger()


@implementer(IAdapterInterface)
class IAdapter(object):
    def __init__(self, adapter_agent, config, device_handler_class, name,
                 vendor, version, device_type, vendor_id,
                 accepts_bulk_flow_update=True,
                 accepts_add_remove_flow_updates=False):
        log.debug('Initializing adapter: {} {} {}'.format(vendor, name, version))
        self.adapter_agent = adapter_agent
        self.config = config
        self.name = name
        self.supported_device_types = [
            DeviceType(
                id=device_type,
                vendor_id=vendor_id,
                adapter=name,
                accepts_bulk_flow_update=accepts_bulk_flow_update,
                accepts_add_remove_flow_updates=accepts_add_remove_flow_updates
            )
        ]
        self.descriptor = Adapter(
            id=self.name,
            vendor=vendor,
            version=version,
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.devices_handlers = dict()  # device_id -> Olt/OnuHandler()
        self.device_handler_class = device_handler_class

    def start(self):
        log.info('Starting adapter: {}'.format(self.name))

    def stop(self):
        log.info('Stopping adapter: {}'.format(self.name))

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        self.devices_handlers[device.id] = self.device_handler_class(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device

    def reconcile_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        log.info('disable-device', device_id=device.id)
        reactor.callLater(0, self.devices_handlers[device.id].disable)
        return device

    def reenable_device(self, device):
        log.info('reenable-device', device_id=device.id)
        reactor.callLater(0, self.devices_handlers[device.id].reenable)
        return device

    def reboot_device(self, device):
        log.info('reboot-device', device_id=device.id)
        reactor.callLater(0, self.devices_handlers[device.id].reboot)
        return device

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
        log.info('self-test-req', device_id=device.id)
        result = reactor.callLater(0, self.devices_handlers[device.id].self_test_device)
        return result

    def delete_device(self, device):
        log.info('delete-device', device_id=device.id)
        #  TODO: Update the logical device mapping
        reactor.callLater(0, self.devices_handlers[device.id].delete)
        return device

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id)
                    #flows=flows, groups=groups)
        assert len(groups.items) == 0
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        log.info('incremental-flow-update', device_id=device.id,
                 flows=flow_changes, groups=group_changes)
        # For now, there is no support for group changes
        assert len(group_changes.to_add.items) == 0
        assert len(group_changes.to_remove.items) == 0

        handler = self.devices_handlers[device.id]
        # Remove flows
        if len(flow_changes.to_remove.items) != 0:
            handler.remove_from_flow_table(flow_changes.to_remove.items)

        # Add flows
        if len(flow_changes.to_add.items) != 0:
            handler.add_to_flow_table(flow_changes.to_add.items)

    def update_pm_config(self, device, pm_config):
        log.info("adapter-update-pm-config", device=device,
                 pm_config=pm_config)
        handler = self.devices_handlers[device.id]
        handler.update_pm_config(device, pm_config)

    def send_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        raise NotImplementedError()

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

    def create_interface(self, device, data):
        log.info('create-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_interface(data)

    def update_interface(self, device, data):
        log.info('update-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_interface(data)

    def remove_interface(self, device, data):
        log.info('remove-interface', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_interface(data)

    def receive_onu_detect_state(self, proxy_address, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('remove-tcont', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_tcont(tcont_data, traffic_descriptor_data)

    def create_gemport(self, device, data):
        raise NotImplementedError()

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        log.info('remove-gemport', device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_gemport(data)

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

    def _get_handler(self, device):
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                return handler
            return None

"""
OLT Adapter base class
"""


class OltAdapter(IAdapter):
    def __init__(self, adapter_agent, config, device_handler_class, name,
                 vendor, version, device_type,
                 accepts_bulk_flow_update=True,
                 accepts_add_remove_flow_updates=False):
        super(OltAdapter, self).__init__(adapter_agent=adapter_agent,
                                         config=config,
                                         device_handler_class=device_handler_class,
                                         name=name,
                                         vendor=vendor,
                                         version=version,
                                         device_type=device_type,
                                         vendor_id=None,
                                         accepts_bulk_flow_update=accepts_bulk_flow_update,
                                         accepts_add_remove_flow_updates=accepts_add_remove_flow_updates)
        self.logical_device_id_to_root_device_id = dict()

    def reconcile_device(self, device):
        try:
            self.devices_handlers[device.id] = self.device_handler_class(self, device.id)
            # Work only required for devices that are in ENABLED state
            if device.admin_state == AdminState.ENABLED:
                reactor.callLater(0,
                                  self.devices_handlers[device.id].reconcile,
                                  device)
            else:
                # Invoke the children reconciliation which would setup the
                # basic children data structures
                self.adapter_agent.reconcile_child_devices(device.id)
            return device
        except Exception, e:
            log.exception('Exception', e=e)

    def send_proxied_message(self, proxy_address, msg):
        log.debug('send-proxied-message', proxy_address=proxy_address,
                  proxied_msg=msg)
        handler = self.devices_handlers[proxy_address.device_id]
        handler.send_proxied_message(proxy_address, msg)

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        def ldi_to_di(ldi):
            di = self.logical_device_id_to_root_device_id.get(ldi)
            if di is None:
                logical_device = self.adapter_agent.get_logical_device(ldi)
                di = logical_device.root_device_id
                self.logical_device_id_to_root_device_id[ldi] = di
            return di

        device_id = ldi_to_di(logical_device_id)
        handler = self.devices_handlers[device_id]
        handler.packet_out(egress_port_no, msg)


"""
ONU Adapter base class
"""


class OnuAdapter(IAdapter):
    def __init__(self, adapter_agent, config, device_handler_class, name,
                 vendor, version, device_type, vendor_id, accepts_bulk_flow_update=True,
                 accepts_add_remove_flow_updates=False):
        super(OnuAdapter, self).__init__(adapter_agent=adapter_agent,
                                         config=config,
                                         device_handler_class=device_handler_class,
                                         name=name,
                                         vendor=vendor,
                                         version=version,
                                         device_type=device_type,
                                         vendor_id=vendor_id,
                                         accepts_bulk_flow_update=accepts_bulk_flow_update,
                                         accepts_add_remove_flow_updates=accepts_add_remove_flow_updates
                                         )

    def reconcile_device(self, device):
        self.devices_handlers[device.id] = self.device_handler_class(self, device.id)
        # Reconcile only if state was ENABLED
        if device.admin_state == AdminState.ENABLED:
            reactor.callLater(0,
                              self.devices_handlers[device.id].reconcile,
                              device)
        return device

    def receive_proxied_message(self, proxy_address, msg):
        log.debug('receive-proxied-message', proxy_address=proxy_address,
                  device_id=proxy_address.device_id, proxied_msg=msg)
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent. \
            get_child_device_with_proxy_address(proxy_address)
        if device:
            handler = self.devices_handlers[device.id]
            handler.receive_message(msg)
