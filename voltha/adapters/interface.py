#
# Copyright 2016 the original author or authors.
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

    def deactivate_device(device):
        """
        Called if the device is to be deactivate based on a NBI call.
        :return: (Deferred) Shall be fired to acknowledge deactivation.
        """

    # TODO work in progress
    # ...


class IAdapterAgent(Interface):
    """
    This object is passed in to the __init__ function of each adapter,
    and can be used by the adapter implementation to initiate async calls
    toward Voltha's CORE via the APIs defined here.
    """

    def get_device(selfdevice_id):
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
                              child_device_type,
                              child_device_address_kw):
        # TODO add doc
        """"""

    # TODO work in progress
    pass


