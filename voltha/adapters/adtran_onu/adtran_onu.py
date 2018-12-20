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
Adtran ONU adapter.
"""
import structlog
import binascii
from voltha.adapters.iadapter import OnuAdapter
from voltha.protos import third_party
from adtran_onu_handler import AdtranOnuHandler
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent, OpenOmciAgentDefaults
from twisted.internet import reactor
from omci.adtn_capabilities_task import AdtnCapabilitiesTask
from omci.adtn_get_mds_task import AdtnGetMdsTask
from omci.adtn_mib_sync import AdtnMibSynchronizer
from omci.adtn_mib_resync_task import AdtnMibResyncTask
from omci.adtn_mib_reconcile_task import AdtnMibReconcileTask
from copy import deepcopy

_ = third_party


class AdtranOnuAdapter(OnuAdapter):
    def __init__(self, adapter_agent, config):
        self.log = structlog.get_logger()
        super(AdtranOnuAdapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class=AdtranOnuHandler,
                                               name='adtran_onu',
                                               vendor='ADTRAN, Inc.',
                                               version='1.25',
                                               device_type='adtran_onu',
                                               vendor_id='ADTN',
                                               accepts_add_remove_flow_updates=False),  # TODO: Support flow-mods
        # Customize OpenOMCI for Adtran ONUs
        self.adtran_omci = deepcopy(OpenOmciAgentDefaults)

        from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict
        self.adtran_omci['mib-synchronizer']['database'] = MibDbVolatileDict

        self.adtran_omci['mib-synchronizer']['state-machine'] = AdtnMibSynchronizer
        self.adtran_omci['mib-synchronizer']['tasks']['get-mds'] = AdtnGetMdsTask
        self.adtran_omci['mib-synchronizer']['tasks']['mib-audit'] = AdtnGetMdsTask
        self.adtran_omci['mib-synchronizer']['tasks']['mib-resync'] = AdtnMibResyncTask
        self.adtran_omci['mib-synchronizer']['tasks']['mib-reconcile'] = AdtnMibReconcileTask
        self.adtran_omci['omci-capabilities']['tasks']['get-capabilities'] = AdtnCapabilitiesTask
        # TODO: Continue to customize adtran_omci here as needed

        self._omci_agent = OpenOMCIAgent(self.adapter_agent.core,
                                         support_classes=self.adtran_omci)

    @property
    def omci_agent(self):
        return self._omci_agent

    def start(self):
        super(AdtranOnuAdapter, self).start()
        self._omci_agent.start()

    def stop(self):
        omci, self._omci_agent = self._omci_agent, None
        if omci is not None:
            omci.stop()

        super(AdtranOnuAdapter, self).stop()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

    def download_image(self, device, request):
        raise NotImplementedError()

    def activate_image_update(self, device, request):
        raise NotImplementedError()

    def cancel_image_download(self, device, request):
        raise NotImplementedError()

    def revert_image_update(self, device, request):
        raise NotImplementedError()

    def get_image_download_status(self, device, request):
        raise NotImplementedError()

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        raise NotImplementedError('Not an ONU method')

    def get_device_details(self, device):
        raise NotImplementedError('TODO: Not currently supported')

    def change_master_state(self, master):
        raise NotImplementedError('Not currently supported or required')

    def receive_inter_adapter_message(self, msg):
        # Currently the only OLT Device adapter that uses this is the EdgeCore

        self.log.info('receive_inter_adapter_message', msg=msg)
        proxy_address = msg['proxy_address']
        assert proxy_address is not None
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent.get_child_device_with_proxy_address(proxy_address)
        if device is not None:
            handler = self.devices_handlers[device.id]
            handler.event_messages.put(msg)
        else:
            self.log.error("device-not-found")

    def abandon_device(self, device):
        raise NotImplementedError('TODO: Not currently supported')

    def receive_onu_detect_state(self, proxy_address, state):
        raise NotImplementedError('TODO: Not currently supported')

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        raise NotImplementedError('Not an ONU method')

    def receive_proxied_message(self, proxy_address, msg):
        self.log.debug('receive-proxied-message', proxy_address=proxy_address,
                       device_id=proxy_address.device_id, msg=binascii.hexlify(msg))
        # Device_id from the proxy_address is the olt device id. We need to
        # get the onu device id using the port number in the proxy_address
        device = self.adapter_agent.get_child_device_with_proxy_address(proxy_address)

        if device is not None:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.receive_message(msg)

    ######################################################################
    # PON Mgnt APIs  (Eventually will be deprecated)

    def create_interface(self, device, data):
        """
        API to create various interfaces (only some PON interfaces as of now)
        in the devices
        """
        self.log.debug('create-interface', data=data)

        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            reactor.callLater(0, handler.xpon_create, data)

    def update_interface(self, device, data):
        """
        API to update various interfaces (only some PON interfaces as of now)
        in the devices
        """
        self.log.debug('update-interface', data=data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.xpon_update(data)

    def remove_interface(self, device, data):
        """
        API to delete various interfaces (only some PON interfaces as of now)
        in the devices
        """
        self.log.debug('remove-interface', data=data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.xpon_remove(data)

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to create tcont object in the devices
        :param device: device id
        :param tcont_data: tcont data object
        :param traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        self.log.info('create-tcont', tcont_data=tcont_data,
                      traffic_descriptor_data=traffic_descriptor_data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.create_tcont(tcont_data, traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to update tcont object in the devices
        :param device: device id
        :param tcont_data: tcont data object
        :param traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        self.log.info('update-tcont', tcont_data=tcont_data,
                      traffic_descriptor_data=traffic_descriptor_data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.update_tcont(tcont_data, traffic_descriptor_data)

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to delete tcont object in the devices
        :param device: device id
        :param tcont_data: tcont data object
        :param traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        self.log.info('remove-tcont', tcont_data=tcont_data,
                      traffic_descriptor_data=traffic_descriptor_data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.remove_tcont(tcont_data, traffic_descriptor_data)

    def create_gemport(self, device, data):
        """
        API to create gemport object in the devices
        :param device: device id
        :param data: gemport data object
        :return: None
        """
        self.log.info('create-gemport', data=data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.xpon_create(data)

    def update_gemport(self, device, data):
        """
        API to update gemport object in the devices
        :param device: device id
        :param data: gemport data object
        :return: None
        """
        self.log.info('update-gemport', data=data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.xpon_update(data)

    def remove_gemport(self, device, data):
        """
        API to delete gemport object in the devices
        :param device: device id
        :param data: gemport data object
        :return: None
        """
        self.log.info('remove-gemport', data=data)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            handler.xpon_remove(data)

    def create_multicast_gemport(self, device, data):
        raise NotImplemented('xPON has been deprecated')

    def update_multicast_gemport(self, device, data):
        raise NotImplemented('xPON has been deprecated')

    def remove_multicast_gemport(self, device, data):
        raise NotImplemented('xPON has been deprecated')

    def create_multicast_distribution_set(self, device, data):
        raise NotImplemented('xPON has been deprecated')

    def update_multicast_distribution_set(self, device, data):
        raise NotImplemented('xPON has been deprecated')

    def remove_multicast_distribution_set(self, device, data):
        raise NotImplemented('xPON has been deprecated')