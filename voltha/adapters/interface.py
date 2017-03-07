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
        [This mode is not supported yet.]
        :param device: A Voltha.Device object.
        :param flow_changes:
        :param group_changes:
        :return:
        """

    #def update_pm_collection(device, pm_collection_config):
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

        # TODO work in progress
        # ...


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

    def submit_alarm(alarm_event_msg):
        """
        Submit an alarm on behalf of the OLT and its adapter.
        :param alarm_event_msg: A protobuf message of AlarmEvent type.
        :return: None
        """
