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
import ast
import structlog
from bitstring import BitArray

from common.pon_resource_manager.resource_kv_store import ResourceKvStore


class PONResourceManager(object):
    """Implements apis to initialize/allocate/release alloc/gemport/onu IDs."""

    # Constants to identify resource pool
    ONU_ID = 'ONU_ID'
    ALLOC_ID = 'ALLOC_ID'
    GEMPORT_ID = 'GEMPORT_ID'

    # constants used as key in resource json
    PON_INTF_ID = 'pon_intf_id'
    START_IDX = 'start_idx'
    END_IDX = 'end_idx'
    POOL = 'pool'

    # resource path in kv store
    ALLOC_ID_POOL_PATH = '/alloc_id_pool/{}'
    GEMPORT_ID_POOL_PATH = '/gemport_id_pool/{}'
    ONU_ID_POOL_PATH = '/onu_id_pool/{}'

    def __init__(self, technology, device_id, backend, host, port):
        """
        Create PONResourceManager object.

        :param technology: PON technology
        :param device_id: OLT device id
        :param backend: backend store
        :param host: ip of backend store
        :param port: port on which backend store listens
        :raises exception when invalid backend store passed as an argument
        """
        # logger
        self._log = structlog.get_logger()

        try:
            self._kv_store = ResourceKvStore(technology, device_id, backend,
                                             host, port)
        except Exception as e:
            self._log.exception("exception-in-init")
            raise Exception(e)

    def init_resource_id_pool(self, pon_intf_id, resource_type, start_idx,
                              end_idx):
        """
        Initialize onu id pool.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param start_idx: start index for onu id pool
        :param end_idx: end index for onu id pool
        :return boolean: True if resource id pool initialized else false
        """
        status = False
        if resource_type == PONResourceManager.ONU_ID:
            path = self._get_onu_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.ALLOC_ID:
            path = self._get_alloc_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.GEMPORT_ID:
            path = self._get_gemport_id_resource_path(pon_intf_id)
        else:
            self._log.error("invalid-resource-pool-identifier")
            return status

        # In case of adapter reboot and reconciliation resource in kv store
        # checked for its presence if not kv store update happens
        resource = self._get_resource(path)

        if resource is not None:
            self._log.info("Resource-already-present-in-store", path=path,
                           resource=resource)
            status = True
        else:
            resource = self._format_resource(pon_intf_id, start_idx, end_idx)
            self._log.info("Resource-initialized", path=path,
                           resource=resource)

            # Add resource as json in kv store.
            status = self._kv_store.update_to_kv_store(path, resource)
        return status

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
        if resource_type == PONResourceManager.ONU_ID:
            path = self._get_onu_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.ALLOC_ID:
            path = self._get_alloc_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.GEMPORT_ID:
            path = self._get_gemport_id_resource_path(pon_intf_id)
        else:
            self._log.error("invalid-resource-pool-identifier")
            return result

        resource = self._get_resource(path)
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
        return result

    def free_resource_id(self, pon_intf_id, resource_type, release_content):
        """
        Release alloc/gemport/onu id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param release_content: required number of ids
        :return boolean: True if all IDs in given release_content released
                         else False
        """
        if resource_type == PONResourceManager.ONU_ID:
            path = self._get_onu_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.ALLOC_ID:
            path = self._get_alloc_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.GEMPORT_ID:
            path = self._get_gemport_id_resource_path(pon_intf_id)
        else:
            self._log.error("invalid-resource-pool-identifier")
            return False

        resource = self._get_resource(path)
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
            return self._update_resource(path, resource)

        except BaseException:
            self._log.exception("Free-" + resource_type + "-failed", path=path)
        return False

    def clear_device_resource_pool(self):
        """
        Remove resource pools.

        :return boolean: True if all resource pools removed else False
        """
        return self._kv_store.remove_from_kv_store('')

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

    def _update_resource(self, path, resource):
        """
        Update resource in resource kv store.

        :param path: path to update resource
        :param resource: resource need to be updated
        """
        resource[PONResourceManager.POOL] = \
            resource[PONResourceManager.POOL].bin
        return self._kv_store.update_to_kv_store(path, resource)

    def _get_alloc_id_resource_path(self, pon_intf_id):
        """
        Get alloc id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: alloc id resource path
        """
        return PONResourceManager.ALLOC_ID_POOL_PATH.format(pon_intf_id)

    def _get_gemport_id_resource_path(self, pon_intf_id):
        """
        Get gemport id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: gemport id resource path
        """
        return PONResourceManager.GEMPORT_ID_POOL_PATH.format(pon_intf_id)

    def _get_onu_id_resource_path(self, pon_intf_id):
        """
        Get onu id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: onu id resource path
        """
        return PONResourceManager.ONU_ID_POOL_PATH.format(pon_intf_id)

    def _get_resource(self, path):
        """
        Get resource from kv store.

        :param path: path to get resource
        :return: resource if resource present in kv store else None
        """
        # get resource from kv store
        resource = self._kv_store.get_from_kv_store(path)

        if resource is not None:
            # decode resource fetched from backend store to dictionary
            resource = ast.literal_eval(resource)

            # resource pool in backend store stored as binary string whereas to
            # access the pool to generate/release IDs it need to be converted
            # as BitArray
            resource[PONResourceManager.POOL] = \
                BitArray('0b' + resource[PONResourceManager.POOL])

            return resource
        return resource

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

        return resource
