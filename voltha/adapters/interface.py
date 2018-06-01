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
Interface definition for Voltha Adapters
"""
from zope.interface import Interface


class IAdapterInterface(Interface):
    """
    A Voltha adapter
    """

    def start():
        """
        Called once after adapter instance is laoded. Can be used to async
        initialization.
        :return: (None or Deferred)
        """

    def stop():
        """
        Called once before adapter is unloaded. It can be used to perform
        any cleanup after the adapter.
        :return: (None or Deferred)
        """

    def adapter_descriptor():
        """
        Return the adapter descriptor object for this adapter.
        :return: voltha.Adapter grpc object (see voltha/protos/adapter.proto),
        with adapter-specific information and config extensions.
        """

    def device_types():
        """
        Return list of device types supported by the adapter.
        :return: voltha.DeviceTypes protobuf object, with optional type
        specific extensions.
        """

    def health():
        """
        Return a 3-state health status using the voltha.HealthStatus message.
        :return: Deferred or direct return with voltha.HealthStatus message
        """

    def change_master_state(master):
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

    def adopt_device(device):
        """
        Make sure the adapter looks after given device. Called when a device
        is provisioned top-down and needs to be activated by the adapter.
        :param device: A voltha.Device object, with possible device-type
        specific extensions. Such extensions shall be described as part of
        the device type specification returned by device_types().
        :return: (Deferred) Shall be fired to acknowledge device ownership.
        """

    def reconcile_device(device):
        """
        Make sure the adapter looks after given device. Called when this 
        device has changed ownership from another Voltha instance to 
        this one (typically, this occurs when the previous voltha 
        instance went down). 
        :param device: A voltha.Device object, with possible device-type
        specific extensions. Such extensions shall be described as part of
        the device type specification returned by device_types().
        :return: (Deferred) Shall be fired to acknowledge device ownership.
        """


    def abandon_device(device):
        """
        Make sur ethe adapter no longer looks after device. This is called
        if device ownership is taken over by another Voltha instance.
        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge abandonment.
        """

    def disable_device(device):
        """
        This is called when a previously enabled device needs to be disabled
        based on a NBI call.
        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge disabling the device.
        """

    def reenable_device(device):
        """
        This is called when a previously disabled device needs to be enabled
        based on a NBI call.
        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge re-enabling the
        device.
        """

    def reboot_device(device):
        """
        This is called to reboot a device based on a NBI call.  The admin
        state of the device will not change after the reboot
        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge the reboot.
        """

    def download_image(device, request):
        """
        This is called to request downloading a specified image into
        the standby partition of a device based on a NBI call.
        This call is expected to be non-blocking.
        :param device: A Voltha.Device object.
                       A Voltha.ImageDownload object.
        :return: (Deferred) Shall be fired to acknowledge the download.
        """

    def get_image_download_status(device, request):
        """
        This is called to inquire about a requested image download
        status based on a NBI call.
        The adapter is expected to update the DownloadImage DB object
        with the query result
        :param device: A Voltha.Device object.
                       A Voltha.ImageDownload object.
        :return: (Deferred) Shall be fired to acknowledge
        """

    def cancel_image_download(device, request):
        """
        This is called to cancel a requested image download
        based on a NBI call.  The admin state of the device will not
        change after the download.
        :param device: A Voltha.Device object.
                       A Voltha.ImageDownload object.
        :return: (Deferred) Shall be fired to acknowledge
        """

    def activate_image_update(device, request):
        """
        This is called to activate a downloaded image from
        a standby partition into active partition.
        Depending on the device implementation, this call
        may or may not cause device reboot.
        If no reboot, then a reboot is required to make the
        activated image running on device
        This call is expected to be non-blocking.
        :param device: A Voltha.Device object.
                       A Voltha.ImageDownload object.
        :return: (Deferred) OperationResponse object.
        """

    def revert_image_update(device, request):
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
                       A Voltha.ImageDownload object.
        :return: (Deferred) OperationResponse object.
        """

    def self_test_device(device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """

    def delete_device(device):
        """
        This is called to delete a device from the PON based on a NBI call.
        If the device is an OLT then the whole PON will be deleted.
        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge the deletion.
        """

    def get_device_details(device):
        """
        This is called to get additional device details based on a NBI call.
        :param device: A Voltha.Device object.
        :return: (Deferred) Shall be fired to acknowledge the retrieval of
        additional details.
        """

    def update_flows_bulk(device, flows, groups):
        """
        Called after any flow table change, but only if the device supports
        bulk mode, which is expressed by the 'accepts_bulk_flow_update'
        capability attribute of the device type.
        :param device: A Voltha.Device object.
        :param flows: An openflow_v13.Flows object
        :param groups: An  openflow_v13.Flows object
        :return: (Deferred or None)
        """

    def update_flows_incrementally(device, flow_changes, group_changes):
        """
        Called after a flow table update, but only if the device supports
        non-bulk mode, which is expressed by the 'accepts_add_remove_flow_updates'
        capability attribute of the device type.
        :param device: A Voltha.Device object.
        :param flow_changes: An openflow_v13.FlowChanges object
        :param group_changes: An openflow_v13.FlowGroupChanges object
        :return: (Deferred or None)
        """

    def update_pm_config(device, pm_configs):
        """
        Called every time a request is made to change pm collection behavior
        :param device: A Voltha.Device object
        :param pm_collection_config: A Pms
        """

    def send_proxied_message(proxy_address, msg):
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

    def receive_proxied_message(proxy_address, msg):
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

    def receive_packet_out(logical_device_id, egress_port_no, msg):
        """
        Pass a packet_out message content to adapter so that it can forward it
        out to the device. This is only called on root devices.
        :param logical_device_id:
        :param egress_port: egress logical port number
        :param msg: actual message
        :return: None
        """

    def receive_inter_adapter_message(msg):
        """
        Called when the adapter recieves a message that was sent to it directly
        from another adapter. An adapter may register for these messages by calling
        the register_for_inter_adapter_messages() method in the adapter agent.
        Note that it is the responsibility of the sending and receiving
        adapters to properly encode and decode the message.
        :param msg: The message contents.
        :return: None
        """

    def suppress_alarm(filter):
        """
        Inform an adapter that all incoming alarms should be suppressed
        :param filter: A Voltha.AlarmFilter object.
        :return: (Deferred) Shall be fired to acknowledge the suppression.
        """

    def unsuppress_alarm(filter):
        """
        Inform an adapter that all incoming alarms should resume
        :param filter: A Voltha.AlarmFilter object.
        :return: (Deferred) Shall be fired to acknowledge the unsuppression.
        """

        # TODO work in progress
        # ...

    # PON Mgnt APIs #
    def create_interface(device, data):
        """
        API to create various interfaces (only some PON interfaces as of now)
        in the devices
        :param device: device id
        :data: interface data object
        :return: None
        """

    def update_interface(device, data):
        """
        API to update various interfaces (only some PON interfaces as of now)
        in the devices
        :param device: device id
        :data: interface data object
        :return: None
        """

    def remove_interface(device, data):
        """
        API to delete various interfaces (only some PON interfaces as of now)
        in the devices
        :param device: device id
        :data: interface data object
        :return: None
        """

    def receive_onu_detect_state(proxy_address, state):
        """
        Receive onu detect state in ONU adapter
        :param proxy_address: ONU device address
        :param state: ONU detect state (bool)
        :return: None
        """


    def create_tcont(device, tcont_data, traffic_descriptor_data):
        """
        API to create tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """

    def update_tcont(device, tcont_data, traffic_descriptor_data):
        """
        API to update tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """

    def remove_tcont(device, tcont_data, traffic_descriptor_data):
        """
        API to delete tcont object in the devices
        :param device: device id
        :tcont_data: tcont data object
        :traffic_descriptor_data: traffic descriptor data object
        :return: None
        """

    def create_gemport(device, data):
        """
        API to create gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """

    def update_gemport(device, data):
        """
        API to update gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """

    def remove_gemport(device, data):
        """
        API to delete gemport object in the devices
        :param device: device id
        :data: gemport data object
        :return: None
        """

    def create_multicast_gemport(device, data):
        """
        API to create multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """

    def update_multicast_gemport(device, data):
        """
        API to update  multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """

    def remove_multicast_gemport(device, data):
        """
        API to delete multicast gemport object in the devices
        :param device: device id
        :data: multicast gemport data object
        :return: None
        """

    def create_multicast_distribution_set(device, data):
        """
        API to create multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """

    def update_multicast_distribution_set(device, data):
        """
        API to update multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """

    def remove_multicast_distribution_set(device, data):
        """
        API to delete multicast distribution rule to specify
        the multicast VLANs that ride on the multicast gemport
        :param device: device id
        :data: multicast distribution data object
        :return: None
        """

class IAdapterAgent(Interface):
    """
    This object is passed in to the __init__ function of each adapter,
    and can be used by the adapter implementation to initiate async calls
    toward Voltha's CORE via the APIs defined here.
    """

    def get_device(device_id):
        # TODO add doc
        """"""

    def add_device(device):
        # TODO add doc
        """"""

    def update_device(device):
        # TODO add doc
        """"""

    def add_port(device_id, port):
        # TODO add doc
        """"""

    def create_logical_device(logical_device):
        # TODO add doc
        """"""

    def add_logical_port(logical_device_id, port):
        # TODO add doc
        """"""

    def child_device_detected(parent_device_id,
                              parent_port_no,
                              child_device_type,
                              proxy_address,
                              admin_state,
                              **kw):
        # TODO add doc
        """"""

    def send_proxied_message(proxy_address, msg):
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

    def receive_proxied_message(proxy_address, msg):
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

    def register_for_proxied_messages(proxy_address):
        """
        A child device adapter can use this to indicate its intent to
        receive async messages sent via a parent device. Example: an
        ONU adapter can use this to register for OMCI messages received
        via the OLT and the OLT adapter.
        :param child_device_address: Address info that was given to the
         child device by the parent device at the creation of the child
         device. Its uniqueness acts as a router information for the
         registration.
        :return: None
        """

    def unregister_for_proxied_messages(proxy_address):
        """
        Cancel a previous registration
        :return:
        """

    def send_packet_in(logical_device_id, logical_port_no, packet):
        """
        Forward given packet to the northbound toward an SDN controller.
        :param device_id: logical device identifier
        :param logical_port_no: logical port_no (as numbered in openflow)
        :param packet: the actual packet; can be a serialized string or a scapy
                       Packet.
        :return: None returned on success
        """

    def submit_kpis(kpi_event_msg):
        """
        Submit KPI metrics on behalf of the OLT and its adapter. This can
        include hardware related metrics, usage and utilization metrics, as
        well as optional adapter specific metrics.
        :param kpi_event_msg: A protobuf message of KpiEvent type.
        :return: None
        """

    def submit_alarm(device_id, alarm_event_msg):
        """
        Submit an alarm on behalf of the OLT and its adapter.
        :param alarm_event_msg: A protobuf message of AlarmEvent type.
        :return: None
        """

    def register_for_onu_detect_state(proxy_address):
        """

        :return: None
        """

    def unregister_for_onu_detect_state(proxy_address):
        """

        :return: None
        """

    def forward_onu_detect_state(proxy_address, state):
        """
        Forward onu detect state to ONU adapter
        :param proxy_address: ONU device address
        :param state: ONU detect state (bool)
        :return: None
        """
