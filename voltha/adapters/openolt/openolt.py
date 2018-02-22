#
# Copyright 2018 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Openolt adapter.
"""
import structlog
from twisted.internet import reactor, defer
from zope.interface import implementer

from openolt_device import OpenoltDevice
from voltha.adapters.interface import IAdapterInterface
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel
from voltha.protos.device_pb2 import DeviceType, DeviceTypes
from voltha.protos.health_pb2 import HealthStatus
from voltha.registry import registry

_ = third_party
log = structlog.get_logger()

@implementer(IAdapterInterface)
class OpenoltAdapter(object):
    name = 'openolt'

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='OLT white box vendor',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        log.debug('openolt.__init__', adapter_agent=adapter_agent)
        self.devices = dict()  # device_id -> OpenoltDevice()
        self.interface = registry('main').get_args().interface
        self.logical_device_id_to_root_device_id = dict()

    def start(self):
        log.info('started', interface=self.interface)

    def stop(self):
        log.info('stopped', interface=self.interface)

    def adapter_descriptor(self):
        log.debug('get descriptor', interface=self.interface)
        return self.descriptor

    def device_types(self):
        log.debug('get device_types', interface=self.interface, items=self.supported_device_types)
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        log.debug('get health', interface=self.interface)
        raise NotImplementedError()

    def change_master_state(self, master):
        log.debug('change_master_state', interface=self.interface, master=master)
        raise NotImplementedError()

    def adopt_device(self, device):
        log.info('adopt-device', device=device)
        kwargs = {
            'adapter_agent': self.adapter_agent,
            'device': device
        }
        try:
            self.devices[device.id] = OpenoltDevice(**kwargs)
        except Exception as e:
            log.error('Failed to adopt OpenOLT device', error=e)
            del self.devices[device.id]
            raise

    def reconcile_device(self, device):
        log.info('reconcile-device', device=device)
        raise NotImplementedError()

    def abandon_device(self, device):
        log.info('abandon-device', device=device)
        raise NotImplementedError()

    def disable_device(self, device):
        log.info('disable-device', device=device)
        raise NotImplementedError()

    def reenable_device(self, device):
        log.info('reenable-device', device=device)
        raise NotImplementedError()

    def reboot_device(self, device):
        log.info('reboot_device', device=device)
        raise NotImplementedError()

    def download_image(self, device, request):
        log.info('image_download', device=device, request=request)
        raise NotImplementedError()

    def get_image_download_status(self, device, request):
        log.info('get_image_download', device=device, request=request)
        raise NotImplementedError()

    def cancel_image_download(self, device, request):
        log.info('cancel_image_download', device=device)
        raise NotImplementedError()

    def activate_image_update(self, device, request):
        log.info('activate_image_update', device=device, request=request)
        raise NotImplementedError()

    def revert_image_update(self, device, request):
        log.info('revert_image_update', device=device, request=request)
        raise NotImplementedError()

    def self_test_device(self, device):
        from voltha.protos.voltha_pb2 import SelfTestResponse
        raise NotImplementedError()

    def delete_device(self, device):
        log.info('delete-device', device=device)
        raise NotImplementedError()

    def get_device_details(self, device):
        log.debug('get_device_details', device=device)
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id,
                 flows=flows, groups=groups)
        assert len(groups.items) == 0, "Cannot yet deal with groups"
        handler = self.devices[device.id]
        return handler.update_flow_table(flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        log.debug('update_flows_incrementally', device=device, flow_changes=flow_changes,
                  group_changes=group_changes)
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        log.debug('update_pm_config', device=device, pm_configs=pm_configs)
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.debug('send-proxied-message', proxy_address=proxy_address, msg=msg)
        handler = self.devices[proxy_address.device_id]
        handler.send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.debug('receive_proxied_message', proxy_address=proxy_address, msg=msg)
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.debug('packet-out', logical_device_id=logical_device_id,
                  egress_port_no=egress_port_no, msg_len=len(msg))
        raise NotImplementedError()

    def receive_inter_adapter_message(self, msg):
        log.info('rx_inter_adapter_msg')
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        log.info('suppress_alarm', filter=filter)
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        log.info('unsuppress_alarm', filter=filter)
        raise NotImplementedError()

    # PON Mgnt APIs #
    def create_interface(self, device, data):
        log.debug('create-interface', data=data)
        raise NotImplementedError()

    def update_interface(self, device, data):
        log.debug('update-interface', data=data)
        raise NotImplementedError()

    def remove_interface(self, device, data):
        log.debug('remove-interface', data=data)
        raise NotImplementedError()

    def receive_onu_detect_state(self, proxy_address, state):
        log.debug('receive-onu-detect-state', data=data)
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('create-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('update-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('remove-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def create_gemport(self, device, data):
        log.info('create-gemport', data=data)
        raise NotImplementedError()

    def update_gemport(self, device, data):
        log.info('update-gemport', data=data)
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        log.info('remove-gemport', data=data)
        raise NotImplementedError()

    def create_multicast_gemport(self, device, data):
        log.info('create-mcast-gemport', data=data)
        raise NotImplementedError()

    def update_multicast_gemport(self, device, data):
        log.info('update-mcast-gemport', data=data)
        raise NotImplementedError()

    def remove_multicast_gemport(self, device, data):
        log.info('remove-mcast-gemport', data=data)
        raise NotImplementedError()

    def create_multicast_distribution_set(self, device, data):
        log.info('create-mcast-distribution-set', data=data)
        raise NotImplementedError()

    def update_multicast_distribution_set(self, device, data):
        log.info('update-mcast-distribution-set', data=data)
        raise NotImplementedError()

    def remove_multicast_distribution_set(self, device, data):
        log.info('remove-mcast-distribution-set', data=data)
        raise NotImplementedError()
