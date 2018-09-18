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
Resource Manager will be unique for each OLT device.

It exposes APIs to create/free alloc_ids/onu_ids/gemport_ids. Resource Manager
uses a KV store in backend to ensure resiliency of the data.
"""
import json
import structlog
from bitstring import BitArray
from twisted.internet.defer import returnValue, inlineCallbacks

from common.kvstore.kvstore import create_kv_client
from common.utils.asleep import asleep


class PONResourceManager(object):
    """Implements APIs to initialize/allocate/release alloc/gemport/onu IDs."""

    # Constants to identify resource pool
    ONU_ID = 'ONU_ID'
    ALLOC_ID = 'ALLOC_ID'
    GEMPORT_ID = 'GEMPORT_ID'

    # The resource ranges for a given device vendor_type should be placed
    # at 'resource_manager/<technology>/resource_ranges/<olt_vendor_type>'
    # path on the KV store.
    # If Resource Range parameters are to be read from the external KV store,
    # they are expected to be stored in the following format.
    # Note: All parameters are MANDATORY for now.
    '''
        {
           "onu_start_idx": 1,
           "onu_end_idx": 127,
           "alloc_id_start_idx": 1024,
           "alloc_id_end_idx": 65534,
           "gem_port_id_start_idx": 1024,
           "gem_port_id_end_idx": 16383,
           "num_of_pon_port": 16
        }
    '''
    # constants used as keys to reference the resource range parameters from
    # and external KV store.
    ONU_START_IDX = "onu_start_idx"
    ONU_END_IDX = "onu_end_idx"
    ALLOC_ID_START_IDX = "alloc_id_start_idx"
    ALLOC_ID_END_IDX = "alloc_id_end_idx"
    GEM_PORT_ID_START_IDX = "gem_port_id_start_idx"
    GEM_PORT_ID_END_IDX = "gem_port_id_end_idx"
    NUM_OF_PON_PORT = "num_of_pon_port"

    # PON Resource range configuration on the KV store.
    # Format: 'resource_manager/<technology>/resource_ranges/<olt_vendor_type>'
    PON_RESOURCE_RANGE_CONFIG_PATH = 'resource_manager/{}/resource_ranges/{}'

    # resource path in kv store
    ALLOC_ID_POOL_PATH = 'resource_manager/{}/{}/alloc_id_pool/{}'
    GEMPORT_ID_POOL_PATH = 'resource_manager/{}/{}/gemport_id_pool/{}'
    ONU_ID_POOL_PATH = 'resource_manager/{}/{}/onu_id_pool/{}'

    # Constants for internal usage.
    PON_INTF_ID = 'pon_intf_id'
    START_IDX = 'start_idx'
    END_IDX = 'end_idx'
    POOL = 'pool'

    def __init__(self, technology, olt_vendor_type, device_id,
                 backend, host, port):
        """
        Create PONResourceManager object.

        :param technology: PON technology
        :param: olt_vendor_type: This string defines the OLT vendor type
        and is used as a Key to load the resource range configuration from
        KV store location.
        :param device_id: OLT device id
        :param backend: backend store
        :param host: ip of backend store
        :param port: port on which backend store listens
        :raises exception when invalid backend store passed as an argument
        """
        # logger
        self._log = structlog.get_logger()

        try:
            self._kv_store = create_kv_client(backend, host, port)
            self.technology = technology
            self.olt_vendor_type = olt_vendor_type
            self.device_id = device_id
            # Below attribute, pon_resource_ranges, should be initialized
            # by reading from KV store.
            self.pon_resource_ranges = dict()
        except Exception as e:
            self._log.exception("exception-in-init")
            raise Exception(e)

    @inlineCallbacks
    def init_pon_resource_ranges(self):
        # Try to initialize the PON Resource Ranges from KV store if available
        status = yield self.init_resource_ranges_from_kv_store()
        # If reading from KV store fails, initialize to default values.
        if not status:
            self._log.error("failed-to-read-resource-ranges-from-kv-store")
            self.init_default_pon_resource_ranges()

    @inlineCallbacks
    def init_resource_ranges_from_kv_store(self):
        path = self.PON_RESOURCE_RANGE_CONFIG_PATH.format(
            self.technology, self.olt_vendor_type)
        # get resource from kv store
        result = yield self._kv_store.get(path)
        resource_range_config = result[0]

        if resource_range_config is not None:
            self.pon_resource_ranges = eval(resource_range_config.value)
            self._log.debug("Init-resource-ranges-from-kvstore-success",
                            pon_resource_ranges=self.pon_resource_ranges,
                            path=path)
            returnValue(True)

        returnValue(False)

    def init_default_pon_resource_ranges(self, onu_start_idx=1,
                                         onu_end_idx=127,
                                         alloc_id_start_idx=1024,
                                         alloc_id_end_idx=65534,
                                         gem_port_id_start_idx=1024,
                                         gem_port_id_end_idx=16383,
                                         num_of_pon_ports=16):
        self._log.info("initialize-default-resource-range-values")
        self.pon_resource_ranges[PONResourceManager.ONU_START_IDX] = onu_start_idx
        self.pon_resource_ranges[PONResourceManager.ONU_END_IDX] = onu_end_idx
        self.pon_resource_ranges[PONResourceManager.ALLOC_ID_START_IDX] = alloc_id_start_idx
        self.pon_resource_ranges[PONResourceManager.ALLOC_ID_END_IDX] = alloc_id_end_idx
        self.pon_resource_ranges[
            PONResourceManager.GEM_PORT_ID_START_IDX] = gem_port_id_start_idx
        self.pon_resource_ranges[
            PONResourceManager.GEM_PORT_ID_END_IDX] = gem_port_id_end_idx
        self.pon_resource_ranges[PONResourceManager.NUM_OF_PON_PORT] = num_of_pon_ports

    def init_device_resource_pool(self):
        i = 0
        while i < self.pon_resource_ranges[PONResourceManager.NUM_OF_PON_PORT]:
            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ONU_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.ONU_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.ONU_END_IDX])

            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ALLOC_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.ALLOC_ID_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.ALLOC_ID_END_IDX])

            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.GEMPORT_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.GEM_PORT_ID_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.GEM_PORT_ID_END_IDX])
            i += 1

    def clear_device_resource_pool(self):
        i = 0
        while i < self.pon_resource_ranges[PONResourceManager.NUM_OF_PON_PORT]:
            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ONU_ID,
            )

            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ALLOC_ID,
            )

            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.GEMPORT_ID,
            )
            i += 1

    @inlineCallbacks
    def init_resource_id_pool(self, pon_intf_id, resource_type, start_idx,
                              end_idx):
        """
        Initialize Resource ID pool for a given Resource Type on a given PON Port

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param start_idx: start index for onu id pool
        :param end_idx: end index for onu id pool
        :return boolean: True if resource id pool initialized else false
        """
        status = False
        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            returnValue(status)

        # In case of adapter reboot and reconciliation resource in kv store
        # checked for its presence if not kv store update happens
        resource = yield self._get_resource(path)

        if resource is not None:
            self._log.info("Resource-already-present-in-store", path=path)
            status = True
        else:
            resource = self._format_resource(pon_intf_id, start_idx, end_idx)
            self._log.info("Resource-initialized", path=path)

            # Add resource as json in kv store.
            result = yield self._kv_store.put(path, resource)
            if result is None:
                status = True
        returnValue(status)

    @inlineCallbacks
    def get_resource_id(self, pon_intf_id, resource_type, num_of_id=1):
        """
        Create alloc/gemport/onu id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param num_of_id: required number of ids
        :return list/int/None: list, int or None if resource type is
                               alloc_id/gemport_id, onu_id or invalid type
                               respectively
        """
        result = None
        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            returnValue(result)

        resource = yield self._get_resource(path)
        try:
            if resource is not None and resource_type == \
                    PONResourceManager.ONU_ID:
                result = self._generate_next_id(resource)
            elif resource is not None and (
                    resource_type == PONResourceManager.GEMPORT_ID or
                    resource_type == PONResourceManager.ALLOC_ID):
                result = list()
                while num_of_id > 0:
                    result.append(self._generate_next_id(resource))
                    num_of_id -= 1

            # Update resource in kv store
            self._update_resource(path, resource)

        except BaseException:
            self._log.exception("Get-" + resource_type + "-id-failed",
                                path=path)
        self._log.debug("Get-" + resource_type + "-success", result=result,
                        path=path)
        returnValue(result)

    @inlineCallbacks
    def free_resource_id(self, pon_intf_id, resource_type, release_content):
        """
        Release alloc/gemport/onu id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param release_content: required number of ids
        :return boolean: True if all IDs in given release_content released
                         else False
        """
        status = False
        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            returnValue(status)

        resource = yield self._get_resource(path)
        try:
            if resource is not None and resource_type == \
                    PONResourceManager.ONU_ID:
                self._release_id(resource, release_content)
            elif resource is not None and (
                    resource_type == PONResourceManager.ALLOC_ID or
                    resource_type == PONResourceManager.GEMPORT_ID):
                for content in release_content:
                    self._release_id(resource, content)
            self._log.debug("Free-" + resource_type + "-success", path=path)

            # Update resource in kv store
            status = yield self._update_resource(path, resource)

        except BaseException:
            self._log.exception("Free-" + resource_type + "-failed", path=path)
        returnValue(status)

    @inlineCallbacks
    def clear_resource_id_pool(self, pon_intf_id, resource_type):
        """
        Clear Resource Pool for a given Resource Type on a given PON Port.

        :return boolean: True if removed else False
        """
        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            returnValue(False)

        result = yield self._kv_store.delete(path)
        if result is None:
            self._log.debug("Resource-pool-cleared", device_id=self.device_id,
                            path=path)
            returnValue(True)
        self._log.error("Clear-resource-pool-failed", device_id=self.device_id,
                        path=path)
        returnValue(False)

    def _generate_next_id(self, resource):
        """
        Generate unique id having OFFSET as start index.

        :param resource: resource used to generate ID
        :return int: generated id
        """
        pos = resource[PONResourceManager.POOL].find('0b0')
        resource[PONResourceManager.POOL].set(1, pos)
        return pos[0] + resource[PONResourceManager.START_IDX]

    def _release_id(self, resource, unique_id):
        """
        Release unique id having OFFSET as start index.

        :param resource: resource used to release ID
        :param unique_id: id need to be released
        """
        pos = ((int(unique_id)) - resource[PONResourceManager.START_IDX])
        resource[PONResourceManager.POOL].set(0, pos)

    def _get_path(self, pon_intf_id, resource_type):
        """
        Get path for given resource type.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :return: path for given resource type
        """
        path = None
        if resource_type == PONResourceManager.ONU_ID:
            path = self._get_onu_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.ALLOC_ID:
            path = self._get_alloc_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.GEMPORT_ID:
            path = self._get_gemport_id_resource_path(pon_intf_id)
        else:
            self._log.error("invalid-resource-pool-identifier")
        return path

    def _get_alloc_id_resource_path(self, pon_intf_id):
        """
        Get alloc id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: alloc id resource path
        """
        return PONResourceManager.ALLOC_ID_POOL_PATH.format(
            self.technology, self.device_id, pon_intf_id)

    def _get_gemport_id_resource_path(self, pon_intf_id):
        """
        Get gemport id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: gemport id resource path
        """
        return PONResourceManager.GEMPORT_ID_POOL_PATH.format(
            self.technology, self.device_id, pon_intf_id)

    def _get_onu_id_resource_path(self, pon_intf_id):
        """
        Get onu id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: onu id resource path
        """
        return PONResourceManager.ONU_ID_POOL_PATH.format(
            self.technology, self.device_id, pon_intf_id)

    @inlineCallbacks
    def _update_resource(self, path, resource):
        """
        Update resource in resource kv store.

        :param path: path to update resource
        :param resource: resource need to be updated
        :return boolean: True if resource updated in kv store else False
        """
        resource[PONResourceManager.POOL] = \
            resource[PONResourceManager.POOL].bin
        result = yield self._kv_store.put(path, json.dumps(resource))
        if result is None:
            returnValue(True)
        returnValue(False)

    @inlineCallbacks
    def _get_resource(self, path):
        """
        Get resource from kv store.

        :param path: path to get resource
        :return: resource if resource present in kv store else None
        """
        # get resource from kv store
        result = yield self._kv_store.get(path)
        resource = result[0]

        if resource is not None:
            # decode resource fetched from backend store to dictionary
            resource = eval(resource.value)

            # resource pool in backend store stored as binary string whereas to
            # access the pool to generate/release IDs it need to be converted
            # as BitArray
            resource[PONResourceManager.POOL] = \
                BitArray('0b' + resource[PONResourceManager.POOL])

        returnValue(resource)

    def _format_resource(self, pon_intf_id, start_idx, end_idx):
        """
        Format resource as json.

        :param pon_intf_id: OLT PON interface id
        :param start_idx: start index for id pool
        :param end_idx: end index for id pool
        :return dictionary: resource formatted as dictionary
        """
        # Format resource as json to be stored in backend store
        resource = dict()
        resource[PONResourceManager.PON_INTF_ID] = pon_intf_id
        resource[PONResourceManager.START_IDX] = start_idx
        resource[PONResourceManager.END_IDX] = end_idx

        # resource pool stored in backend store as binary string
        resource[PONResourceManager.POOL] = BitArray(end_idx).bin

        return json.dumps(resource)
