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
from zope.interface import implementer
import structlog

from openolt_device import OpenoltDevice
from voltha.adapters.interface import IAdapterInterface
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel
from voltha.protos.common_pb2 import OperationResp
from voltha.protos.device_pb2 import DeviceType, DeviceTypes
from voltha.registry import registry
from voltha.adapters.openolt.openolt_flow_mgr import OpenOltFlowMgr
from voltha.adapters.openolt.openolt_alarms import OpenOltAlarmMgr
from voltha.adapters.openolt.openolt_statistics import OpenOltStatisticsMgr
from voltha.adapters.openolt.openolt_platform import OpenOltPlatform
from voltha.adapters.openolt.openolt_resource_manager import OpenOltResourceMgr
from voltha.adapters.openolt.openolt_data_model import OpenOltDataModel

_ = third_party
log = structlog.get_logger()


OpenOltDefaults = {
    'support_classes': {
        'platform': OpenOltPlatform,
        'data_model': OpenOltDataModel,
        'resource_mgr': OpenOltResourceMgr,
        'flow_mgr': OpenOltFlowMgr,
        'alarm_mgr': OpenOltAlarmMgr,
        'stats_mgr': OpenOltStatisticsMgr,
    }
}


@implementer(IAdapterInterface)
class OpenoltAdapter(object):
    name = 'openolt'

    supported_device_types = [
        DeviceType(
            id=name,
            adapter=name,
            accepts_bulk_flow_update=True,
            accepts_direct_logical_flows_update=True
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
        self.num_devices = 0

    def start(self):
        log.info('started', interface=self.interface)

    def stop(self):
        log.info('stopped', interface=self.interface)

    def adapter_descriptor(self):
        log.debug('get descriptor', interface=self.interface)
        return self.descriptor

    def device_types(self):
        log.debug('get device_types', interface=self.interface,
                  items=self.supported_device_types)
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        log.debug('get health', interface=self.interface)
        raise NotImplementedError()

    def change_master_state(self, master):
        log.debug('change_master_state', interface=self.interface,
                  master=master)
        raise NotImplementedError()

    def adopt_device(self, device):
        log.info('adopt-device', device=device)

        kwargs = {
            'support_classes': OpenOltDefaults['support_classes'],
            'adapter_agent': self.adapter_agent,
            'device_id': device.id,
            'host_and_port': device.host_and_port,
            'extra_args': device.extra_args
        }
        try:
            self.devices[device.id] = OpenoltDevice(**kwargs)
        except Exception as e:
            log.error('Failed to adopt OpenOLT device', error=e)
            # TODO set status to ERROR so that is clear something went wrong
            del self.devices[device.id]
            raise
        else:
            self.num_devices += 1

    def reconcile_device(self, device):
        log.info('reconcile-device', device=device)
        kwargs = {
            'support_classes': OpenOltDefaults['support_classes'],
            'adapter_agent': self.adapter_agent,
            'device': device,
            'device_num': self.num_devices + 1,
            'reconciliation': True
        }
        try:
            reconciled_device = OpenoltDevice(**kwargs)
            log.debug('reconciled-device-recreated',
                      device_id=reconciled_device.device_id)
            self.devices[device.id] = reconciled_device
        except Exception as e:
            log.error('Failed to reconcile OpenOLT device', error=e,
                      exception_type=type(e).__name__)
            del self.devices[device.id]
            raise
        else:
            self.num_devices += 1
            # Invoke the children reconciliation which would setup the
            # basic children data structures
            self.adapter_agent.reconcile_child_devices(device.id)
            return device

    def abandon_device(self, device):
        log.info('abandon-device', device=device)
        raise NotImplementedError()

    def disable_device(self, device):
        log.info('disable-device', device=device)
        handler = self.devices[device.id]
        handler.disable()

    def reenable_device(self, device):
        log.info('reenable-device', device=device)
        handler = self.devices[device.id]
        handler.reenable()

    def reboot_device(self, device):
        log.info('reboot_device', device=device)
        handler = self.devices[device.id]
        handler.reboot()

    def download_image(self, device, request):
        log.info('image_download - Not implemented yet', device=device,
                 request=request)
        raise NotImplementedError()

    def get_image_download_status(self, device, request):
        log.info('get_image_download - Not implemented yet', device=device,
                 request=request)
        raise NotImplementedError()

    def cancel_image_download(self, device, request):
        log.info('cancel_image_download - Not implemented yet', device=device)
        raise NotImplementedError()

    def activate_image_update(self, device, request):
        log.info('activate_image_update - Not implemented yet',
                 device=device, request=request)
        raise NotImplementedError()

    def revert_image_update(self, device, request):
        log.info('revert_image_update - Not implemented yet',
                 device=device, request=request)
        raise NotImplementedError()

    def self_test_device(self, device):
        # from voltha.protos.voltha_pb2 import SelfTestResponse
        log.info('Not implemented yet')
        raise NotImplementedError()

    def delete_device(self, device):
        log.info('delete-device', device=device)
        handler = self.devices[device.id]
        handler.delete()
        del self.devices[device.id]
        del self.logical_device_id_to_root_device_id[device.parent_id]
        return device

    def get_device_details(self, device):
        log.debug('get_device_details', device=device)
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.info('bulk-flow-update', device_id=device.id,
                 number_of_flows=len(flows.items), number_of_groups=len(
                     groups.items))
        log.debug('flows and grousp details', flows=flows, groups=groups)
        assert len(groups.items) == 0, "Cannot yet deal with groups"
        handler = self.devices[device.id]
        return handler.update_flow_table(flows.items)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        log.debug('update_flows_incrementally', device=device,
                  flow_changes=flow_changes, group_changes=group_changes)
        log.info('This device does not allow this, therefore it is Not '
                 'implemented')
        raise NotImplementedError()

    def update_logical_flows(self, device_id, flows_to_add, flows_to_remove,
                             groups, device_rules_map):

        log.info('logical-flows-update', flows_to_add=len(flows_to_add),
                 flows_to_remove=len(flows_to_remove))
        log.debug('logical-flows-details', flows_to_add=flows_to_add,
                  flows_to_remove=flows_to_remove)
        assert len(groups) == 0, "Cannot yet deal with groups"
        handler = self.devices[device_id]
        handler.update_logical_flows(flows_to_add, flows_to_remove,
                                     device_rules_map)

    def update_pm_config(self, device, pm_configs):
        log.info('update_pm_config - Not implemented yet', device=device,
                 pm_configs=pm_configs)
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.debug('send-proxied-message',
                  proxy_address=proxy_address,
                  proxied_msg=msg)
        handler = self.devices[proxy_address.device_id]
        handler.send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        log.debug('receive_proxied_message - Not implemented',
                  proxy_address=proxy_address,
                  proxied_msg=msg)
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.debug('packet-out', logical_device_id=logical_device_id,
                  egress_port_no=egress_port_no, msg_len=len(msg))

        def ldi_to_di(ldi):
            di = self.logical_device_id_to_root_device_id.get(ldi)
            if di is None:
                logical_device = self.adapter_agent.get_logical_device(ldi)
                di = logical_device.root_device_id
                self.logical_device_id_to_root_device_id[ldi] = di
            return di

        try:
            device_id = ldi_to_di(logical_device_id)
            handler = self.devices[device_id]
            handler.packet_out(egress_port_no, msg)
        except Exception as e:
            log.error('packet-out:exception', e=e.message)

    def receive_inter_adapter_message(self, msg):
        log.info('rx_inter_adapter_msg - Not implemented')
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        log.info('suppress_alarm - Not implemented yet', filter=filter)
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        log.info('unsuppress_alarm - Not implemented yet', filter=filter)
        raise NotImplementedError()

    # PON Mgnt APIs #
    def create_interface(self, device, data):
        log.debug('create-interface - Not implemented - We do not use this',
                  data=data)
        raise NotImplementedError()

    def update_interface(self, device, data):
        log.debug('update-interface - Not implemented - We do not use this',
                  data=data)
        raise NotImplementedError()

    def remove_interface(self, device, data):
        log.debug('remove-interface - Not implemented - We do not use this',
                  data=data)
        raise NotImplementedError()

    def receive_onu_detect_state(self, proxy_address, state):
        log.debug('receive-onu-detect-state - Not implemented - We do not '
                  'use this', proxy_address=proxy_address,
                  state=state)
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('create-tcont - Not implemented - We do not use this',
                 tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('update-tcont - Not implemented - We do not use this',
                 tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        log.info('remove-tcont - Not implemented - We do not use this',
                 tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        raise NotImplementedError()

    def create_gemport(self, device, data):
        log.info('create-gemport - Not implemented - We do not use this',
                 data=data)
        raise NotImplementedError()

    def update_gemport(self, device, data):
        log.info('update-gemport - Not implemented - We do not use this',
                 data=data)
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        log.info('remove-gemport - Not implemented - We do not use this',
                 data=data)
        raise NotImplementedError()

    def create_multicast_gemport(self, device, data):
        log.info('create-mcast-gemport  - Not implemented - We do not use '
                 'this', data=data)
        raise NotImplementedError()

    def update_multicast_gemport(self, device, data):
        log.info('update-mcast-gemport - Not implemented - We do not use '
                 'this', data=data)
        raise NotImplementedError()

    def remove_multicast_gemport(self, device, data):
        log.info('remove-mcast-gemport - Not implemented - We do not use '
                 'this', data=data)
        raise NotImplementedError()

    def create_multicast_distribution_set(self, device, data):
        log.info('create-mcast-distribution-set - Not implemented - We do '
                 'not use this', data=data)
        raise NotImplementedError()

    def update_multicast_distribution_set(self, device, data):
        log.info('update-mcast-distribution-set - Not implemented - We do '
                 'not use this', data=data)
        raise NotImplementedError()

    def remove_multicast_distribution_set(self, device, data):
        log.info('remove-mcast-distribution-set - Not implemented - We do '
                 'not use this', data=data)
        raise NotImplementedError()

    def delete_child_device(self, parent_device_id, child_device):
        log.info('delete-child_device', parent_device_id=parent_device_id,
                 child_device=child_device)
        handler = self.devices[parent_device_id]
        if handler is not None:
            handler.delete_child_device(child_device)
        else:
            log.error('Could not find matching handler',
                      looking_for_device_id=parent_device_id,
                      available_handlers=self.devices.keys())

    # This is currently not part of the Iadapter interface
    def collect_stats(self, device_id):
        log.info('collect_stats', device_id=device_id)
        handler = self.devices[device_id]
        if handler is not None:
            handler.trigger_statistics_collection()
        else:
            log.error('Could not find matching handler',
                      looking_for_device_id=device_id,
                      available_handlers=self.devices.keys())

    def simulate_alarm(self, device, request):
        log.info('simulate_alarm', device=device, request=request)

        if device.id not in self.devices:
            log.error("Device does not exist", device_id=device.id)
            return OperationResp(code=OperationResp.OPERATION_FAILURE,
                                 additional_info="Device %s does not exist"
                                 % device.id)

        handler = self.devices[device.id]

        handler.simulate_alarm(request)

        return OperationResp(code=OperationResp.OPERATION_SUCCESS)
