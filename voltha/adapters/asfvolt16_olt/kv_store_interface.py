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
Interface definition for KV Store interface for ASFvOLT16 adapter
"""
from zope.interface import Interface


class KvStoreInterface(Interface):
    """
    KV Store Interface for ASFvOLT16 adapter
    """
     
    def get_flows_to_remove_info(device_id, flows):
        """
        Use this API to get the list of info of flows to be removed 
        This is used for incremental flow update
        We extract the bal flow info from kv store for the received flows
        :param device_id: A OLT device id
        :param flows : Incremntal flows to be removed received at the adapter 
                       from higher layer as part of incremental flow update
        :return: list of info of flows to be removed
        """
    
    def get_flows_to_remove(device_id, flows):
        """
        Use this API to get the list of info of flows to be deleted by comparing
        with current flow in kv and received bulk flow
        This is used for bulk flow update
        :param device_id: A OLT device id
        :param flows : Flows received at the adapter from higher layer
                       as part of bulk flow update
        :return: list of info of flows to be deleted (bal_flow_id, direction etc)
        """

    def get_flows_to_add(device_id, flows):
        """
        Use this API to get the list of cookies of the new OpenFlow rules
        that need to be installed on the device
        :param device_id: A OLT device id
        :param flows : Flows received at the adapter from higher layers as
                       part of bulks flow/incremantal flow update 
        :return: list of OpenFlow cookies
        """

    def add_to_kv_store(device_id, new_flow_mapping_list, flows):
        """
        Use this API to add new bal flow id mapping info to the KV store
        Used for incremental flow update 
        :param device_id: A OLT device id
        :param new_flow_mapping_list: It contains the flows and its mapping to bal flows
                                      to be added newly to KV store and bal
        :param flows : Flows received at the adapter from higher layers as
                       part of incremental flow to add update
        :return: None
        """

    def remove_from_kv_store(device_id, flows):
        """
        Use this API to remove bal flow id mapping info from the KV store
        Used for incremental flow update 
        :param device_id: A OLT device id
        :param flows : Flows received at the adapter from higher layers as
                       part of incremental flow to remove update
        :return: None
        """

    def update_kv_store(device_id, new_flow_mapping_list, flows):
        """
        Use this API to update(add and remove) the bal flow id mapping info to the KV store
        :param device_id: A OLT device id
        :param new_flow_mapping_list: It contains the flows and its mapping to bal flows
                                      to be added newly to KV store and bal
        :param flows : Flows received at the adapter from higher layers as
                       part of update_flows_bulk
        :return: None
        """

    def clear_kv_store(device_id):
        """
        Use this API to clear all the bal flow id mapping info from the KV store
        :param device_id: A OLT device id
        :return: None
        """
