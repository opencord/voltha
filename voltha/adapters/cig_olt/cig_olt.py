#
# Copyright 2017-present CIG, Inc.
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
Cig 1-U OLT adapter.
"""
import structlog
from twisted.internet import reactor,defer
from zope.interface import implementer
from voltha.adapters.iadapter import OltAdapter

from cig_olt_handler import CigOltHandler
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


#@implementer(IAdapterInterface)
class CigOltAdapter(OltAdapter):

    supported_device_types = [
        DeviceType(
            id='cig_olt',
            adapter='cig_olt',
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        super(CigOltAdapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class = CigOltHandler,
                                               name='cig_olt',
                                               vendor='CIG Tech',
                                               version='0.11',
                                               device_type='cig_olt')
    
        #self.adapter_agent = adapter_agent
        #self.config = config
        #self.descriptor = Adapter(
            #id='cig_olt',
            #vendor='Voltha project',
            #version='0.4',
            #config=AdapterConfig(log_level=LogLevel.INFO)
        #)
        self.devices_handlers = dict()  
        self.logical_device_id_to_root_device_id = dict()

        # register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()
        

    def start(self):
        """
        Called once after adapter instance is loaded. Can be used to async
        initialization.

        :return: (None or Deferred)
        """
        log.debug('cig starting')
        log.info('cig started')

    def stop(self):
        """
        Called once before adapter is unloaded. It can be used to perform
        any cleanup after the adapter.

        :return: (None or Deferred)
        """
        log.info('stopped')

    def adapter_descriptor(self):
        """
        Return the adapter descriptor object for this adapter.

        :return: voltha.Adapter grpc object (see voltha/protos/adapter.proto),
                 with adapter-specific information and config extensions.
        """
        log.debug('get descriptor')
        return self.descriptor

    def device_types(self):
        """
        Return list of device types supported by the adapter.

        :return: voltha.DeviceTypes protobuf object, with optional type
                 specific extensions.
        """
        log.debug('get device_types', items=self.supported_device_types)
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        """
        Return a 3-state health status using the voltha.HealthStatus message.

        :return: Deferred or direct return with voltha.HealthStatus message
        """
        log.debug('get health')
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        """
        Called to indicate if plugin shall assume or lose master role. The
        master role can be used to perform functions that must be performed
        from a single point in the cluster. In single-node deployments of
        Voltha, the plugins are always in master role.

        :param master: (bool) True to indicate the mastership needs to be
                assumed; False to indicate that mastership needs to be abandoned.
        :return: (Deferred) which is fired by the adapter when mastership is
                assumed/dropped, respectively.
        """
        log.debug('change_master_state', master=master)
        raise NotImplementedError()

    def adopt_device(self, device):
        """
        Make sure the adapter looks after given device. Called when a device
        is provisioned top-down and needs to be activated by the adapter.

        :param device: A voltha.Device object, with possible device-type
                specific extensions. Such extensions shall be described as part of
                the device type specification returned by device_types().
        :return: (Deferred) Shall be fired to acknowledge device ownership.
        """
        log.info('cig adopt-device', device=device)
        self.devices_handlers[device.id] = CigOltHandler(self, device.id)
        reactor.callLater(0, self.devices_handlers[device.id].activate, device)
        return device
        #raise NotImplementedError()

    def reconcile_device(self, device):
        """
        Make sure the adapter looks after given device. Called when this device has
        changed ownership from another Voltha instance to this one (typically, this
        occurs when the previous voltha instance went down).

        :param device: A voltha.Device object, with possible device-type specific
                       extensions. Such extensions shall be described as part of
                       the device type specification returned by device_types().
        :return: (Deferred) Shall be fired to acknowledge device ownership.
        """
        log.info('reconcile-device', device=device)
        #self.devices_handlers[device.id] = AdtranOltHandler(self, device.id)
        #reactor.callLater(0, self.devices_handlers[device.id].activate, device, reconciling=True)
        #return device
        raise NotImplementedError()

    def abandon_device(self, device):
        """
        Make sure the adapter no longer looks after device. This is called
        if device ownership is taken over by another Voltha instance.

        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge abandonment.
        """
        log.info('abandon-device', device=device)
        raise NotImplementedError()

    def disable_device(self, device):
        """
        This is called when a previously enabled device needs to be disabled
        based on a NBI call.

        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge disabling the device.
        """
        log.info('disable-device', device=device)
        #raise NotImplementedError()
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            reactor.callLater(0,handler.disable)
            return device

    def reenable_device(self, device):
        """
        This is called when a previously disabled device needs to be enabled
        based on a NBI call.

        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge re-enabling the device.
        """
        log.info('reenable_device', device=device)
        #raise NotImplementedError()
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            d = defer.Deferred()
            reactor.callLater(0,handler.reenable,done_deferred=d)
            return d

    def reboot_device(self, device):
        """
        This is called to reboot a device based on a NBI call.  The admin
        state of the device will not change after the reboot

        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge the reboot.
        """
        log.info('reboot_device', device=device)
        #raise NotImplementedError()
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            reactor.callLater(0,handler.reboot)
            return device

    def download_image(self, device, request):
        """
        This is called to request downloading a specified image into the standby partition
        of a device based on a NBI call.

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :return: (Deferred) Shall be fired to acknowledge the download.
        """
        log.info('image_download', device=device, request=request)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            return handler.start_download(device, request, defer.Deferred())

    def get_image_download_status(self, device, request):
        """
        This is called to inquire about a requested image download status based
        on a NBI call. The adapter is expected to update the DownloadImage DB object
        with the query result

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :return: (Deferred) Shall be fired to acknowledge
        """
        log.info('get_image_download', device=device, request=request)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            return handler.download_status(device, request, defer.Deferred())

    def cancel_image_download(self, device, request):
        """
        This is called to cancel a requested image download
        based on a NBI call.  The admin state of the device will not
        change after the download.
        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :return: (Deferred) Shall be fired to acknowledge
        """
        log.info('cancel_image_download', device=device)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            return handler.cancel_download(device, request, defer.Deferred())

    def activate_image_update(self, device, request):
        """
        This is called to activate a downloaded image from
        a standby partition into active partition.
        Depending on the device implementation, this call
        may or may not cause device reboot.
        If no reboot, then a reboot is required to make the
        activated image running on device
        This call is expected to be non-blocking.
        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :return: (Deferred) OperationResponse object.
        """
        log.info('activate_image_update', device=device, request=request)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            return handler.activate_image(device, request, defer.Deferred())

    def revert_image_update(self, device, request):
        """
        This is called to deactivate the specified image at
        active partition, and revert to previous image at
        standby partition.
        Depending on the device implementation, this call
        may or may not cause device reboot.
        If no reboot, then a reboot is required to make the
        previous image running on device
        This call is expected to be non-blocking.
        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :return: (Deferred) OperationResponse object.
        """
        log.info('revert_image_update', device=device, request=request)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            return handler.revert_image(device, request, defer.Deferred())

            

    def self_test_device(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        from  voltha.protos.voltha_pb2 import SelfTestResponse
        log.info('self-test-device', device=device.id)
        #raise NotImplementedError()
        return SelfTestResponse(result=SelfTestResponse.NOT_SUPPORTED)

    def delete_device(self, device):
        """
        This is called to delete a device from the PON based on a NBI call.
        If the device is an OLT then the whole PON will be deleted.

        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge the deletion.
        """
        log.info('delete-device', device=device)
        handler = self.devices_handlers.get(device.id)
        if handler is not None:
            reactor.callLater(0, handler.delete)
        return device

    def get_device_details(self, device):
        """
        This is called to get additional device details based on a NBI call.

        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge the retrieval of
                            additional details.
        """
        log.debug('get_device_details', device=device)
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        """
        Called after any flow table change, but only if the device supports
        bulk mode, which is expressed by the 'accepts_bulk_flow_update'
        capability attribute of the device type.

        :param device: A Voltha.Device object.
        :param flows: An openflow_v13.Flows object
        :param groups: An  openflow_v13.Flows object
        :return: (Deferred or None)
        """
        log.info('bulk-flow-update', device_id=device.id, flows=flows,
                 groups=groups)
        #assert len(groups.items) == 0, "Cannot yet deal with groups"
        handler = self.devices_handlers[device.id]
        return handler.update_flow_table(flows.items, device)
        #raise NotImplementedError()

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        """
        [This mode is not supported yet.]

        :param device: A Voltha.Device object.
        :param flow_changes:
        :param group_changes:
        :return:
        """
        log.debug('update_flows_incrementally', device=device, flow_changes=flow_changes,
                  group_changes=group_changes)
        raise NotImplementedError()

    def update_pm_config(self, device, pm_configs):
        """
        Called every time a request is made to change pm collection behavior
        :param device: A Voltha.Device object
        :param pm_configs: A Pms
        """
        log.debug('update_pm_config', device=device, pm_configs=pm_configs)
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        """
        Forward a msg to a child device of device, addressed by the given
        proxy_address=Device.ProxyAddress().

        :param proxy_address: Address info for the parent device
                to route the message to the child device. This was given to the
                child device by the parent device at the creation of the child
                device.
        :param msg: (str) The actual message to send.
        :return: (Deferred(None) or None) The return of this method should
                indicate that the message was successfully *sent*.
        """
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)
        handler = self.devices_handlers[proxy_address.device_id]
        handler.send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        """
        Pass an async message (arrived via a proxy) to this device.

        :param proxy_address: Address info for the parent device
                to route the message to the child device. This was given to the
                child device by the parent device at the creation of the child
                device. Note this is the proxy_address with which the adapter
                had to register prior to receiving proxied messages.
        :param msg: (str) The actual message received.
        :return: None
        """
        log.debug('receive_proxied_message', proxy_address=proxy_address, msg=msg)
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        """
        Pass a packet_out message content to adapter so that it can forward it
        out to the device. This is only called on root devices.

        :param logical_device_id:
        :param egress_port_no: egress logical port number
        :param msg: actual message
        :return: None
        """
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))
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

    def receive_inter_adapter_message(self, msg):
        """
        Called when the adapter recieves a message that was sent to it directly
        from another adapter. An adapter may register for these messages by calling
        the register_for_inter_adapter_messages() method in the adapter agent.
        Note that it is the responsibility of the sending and receiving
        adapters to properly encode and decode the message.
        :param msg: The message contents.
        :return: None
        """
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
        """
        API to create various interfaces (only some PON interfaces as of now)
        in the devices
        """
        log.info('create-interface', data=data)
        handler = self.devices_handlers[device.id]
        if handler is not None:
            handler.create_interface(data)

    def update_interface(self, device, data):
        """
        API to update various interfaces (only some PON interfaces as of now)
        in the devices
        """
        log.info('update-interface', data=data)
        handler = self.devices_handlers[device.id]
        if handler is not None:
            handler.update_interface(data)

    def remove_interface(self, device, data):
        """
        API to delete various interfaces (only some PON interfaces as of now)
        in the devices
        """
        log.info('remove-interface', data=data)
        handler = self.devices_handlers[device.id]
        if handler is not None:
            handler.remove_interface(data)


    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to create tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        log.info('create-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
                 
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_tcont(tcont_data, traffic_descriptor_data)
    
    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to update tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        log.info('update-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)
        
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_tcont(tcont_data, traffic_descriptor_data)
    
    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        """
        API to delete tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """
        log.info('remove-tcont', tcont_data=tcont_data,
                 traffic_descriptor_data=traffic_descriptor_data)

        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_tcont(tcont_data, traffic_descriptor_data)
    
    def create_gemport(self, device, data):
        """
        API to create gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        log.info('create-gemport', data=data)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.create_gemport(data)
    
    def update_gemport(self, device, data):
        """
        API to update gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        log.info('update-gemport', data=data)
        
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.update_gemport(data)
    
    def remove_gemport(self, device, data):
        """
        API to delete gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """
        log.info('remove-gemport', data=data)
        
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                handler.remove_gemport(data)
    
    def create_multicast_gemport(self, device, data):
        """
        API to create multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """
        log.info('create-mcast-gemport', data=data)
        
        raise NotImplementedError()
        #if device.id in self.devices_handlers:
            #handler = self.devices_handlers[device.id]
            #if handler is not None:
                #handler.create_multicast_gemport(data)
    
    def update_multicast_gemport(self, device, data):
        """
        API to update  multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """
        log.info('update-mcast-gemport', data=data)
        
        raise NotImplementedError()
        #if device.id in self.devices_handlers:
            #handler = self.devices_handlers[device.id]
            #if handler is not None:
                #handler.update_multicast_gemport(data)
    
    def remove_multicast_gemport(self, device, data):
        """
        API to delete multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """
        log.info('remove-mcast-gemport', data=data)
        
        raise NotImplementedError()
        #if device.id in self.devices_handlers:
            #handler = self.devices_handlers[device.id]
            #if handler is not None:
                #handler.remove_multicast_gemport(data)
    
    def create_multicast_distribution_set(self, device, data):
        """
        API to create multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """
        log.info('create-mcast-distribution-set', data=data)
        
        raise NotImplementedError()
        #if device.id in self.devices_handlers:
            #handler = self.devices_handlers[device.id]
            #if handler is not None:
                #handler.create_multicast_distribution_set(data)
    
    def update_multicast_distribution_set(self, device, data):
        """
        API to update multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """
        log.info('update-mcast-distribution-set', data=data)
        
        raise NotImplementedError()
        #if device.id in self.devices_handlers:
            #handler = self.devices_handlers[device.id]
            #if handler is not None:
                #handler.create_multicast_distribution_set(data)
    
    def remove_multicast_distribution_set(self, device, data):
        """
        API to delete multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """
        log.info('remove-mcast-distribution-set', data=data)
        
        raise NotImplementedError()
        #if device.id in self.devices_handlers:
            #handler = self.devices_handlers[device.id]
            #if handler is not None:
                #handler.create_multicast_distribution_set(data)


        
