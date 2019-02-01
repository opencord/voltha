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
from bitstring import BitArray
import json
from common.pon_resource_manager.resource_manager import PONResourceManager
import adtranolt_platform as platform


class AdtranPONResourceManager(PONResourceManager):
    """Implements APIs to initialize/allocate/release alloc/gemport/onu IDs."""

    # Constants for internal usage.
    ONU_MAP = 'onu_map'

    def init_device_resource_pool(self):
        """
        Initialize resource pool for all PON ports.
        """
        for pon_id in self.intf_ids:
            self.init_resource_id_pool(
                pon_intf_id=pon_id,
                resource_type=PONResourceManager.ONU_ID,
                start_idx=self.pon_resource_ranges[PONResourceManager.ONU_ID_START_IDX],
                end_idx=self.pon_resource_ranges[PONResourceManager.ONU_ID_END_IDX])

            alloc_id_map = dict()
            for onu_id in range(platform.MAX_ONUS_PER_PON):
                alloc_id_map[onu_id] = [platform.mk_alloc_id(pon_id, onu_id, idx)
                                        for idx in xrange(platform.MAX_TCONTS_PER_ONU)]

            self.init_resource_id_pool(pon_intf_id=pon_id,
                                       resource_type=PONResourceManager.ALLOC_ID,
                                       resource_map=alloc_id_map)

            self.init_resource_id_pool(
                pon_intf_id=pon_id,
                resource_type=PONResourceManager.GEMPORT_ID,
                start_idx=self.pon_resource_ranges[PONResourceManager.GEMPORT_ID_START_IDX],
                end_idx=self.pon_resource_ranges[PONResourceManager.GEMPORT_ID_END_IDX])

    def clear_device_resource_pool(self):
        """
        Clear resource pool of all PON ports.
        """
        for pon_id in self.intf_ids:
            self.clear_resource_id_pool(pon_intf_id=pon_id,
                                        resource_type=PONResourceManager.ONU_ID)

            self.clear_resource_id_pool(
                pon_intf_id=pon_id,
                resource_type=PONResourceManager.ALLOC_ID,
            )

            self.clear_resource_id_pool(
                pon_intf_id=pon_id,
                resource_type=PONResourceManager.GEMPORT_ID,
            )
            self.clear_resource_id_pool(
                pon_intf_id=pon_id,
                resource_type=PONResourceManager.FLOW_ID,
            )

    def init_resource_id_pool(self, pon_intf_id, resource_type, start_idx=None,
                              end_idx=None, resource_map=None):
        """
        Initialize Resource ID pool for a given Resource Type on a given PON Port

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param start_idx: start index for onu id pool
        :param end_idx: end index for onu id pool
        :param resource_map: (dict) Resource map if per-ONU specific
        :return boolean: True if resource id pool initialized else false
        """
        status = False
        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            return status

        try:
            # In case of adapter reboot and reconciliation resource in kv store
            # checked for its presence if not kv store update happens
            resource = self._get_resource(path)

            if resource is not None:
                self._log.info("Resource-already-present-in-store", path=path)
                status = True

            else:
                if resource_map is None:
                    resource = self._format_resource(pon_intf_id, start_idx, end_idx)
                    self._log.info("Resource-initialized", path=path)

                else:
                    resource = self._format_map_resource(pon_intf_id, resource_map)

                # Add resource as json in kv store.
                status = self._kv_store.update_to_kv_store(path, resource)

        except Exception as e:
            self._log.exception("error-initializing-resource-pool", e=e)

        return status

    def _generate_next_id(self, resource, onu_id=None):
        """
        Generate unique id having OFFSET as start index.

        :param resource: resource used to generate ID
        :return int: generated id
        """
        if onu_id is not None:
            resource = resource[AdtranPONResourceManager.ONU_MAP][str(onu_id)]

        pos = resource[PONResourceManager.POOL].find('0b0')
        resource[PONResourceManager.POOL].set(1, pos)
        return pos[0] + resource[PONResourceManager.START_IDX]

    def _release_id(self, resource, unique_id, onu_id=None):
        """
        Release unique id having OFFSET as start index.

        :param resource: resource used to release ID
        :param unique_id: id need to be released
        :param onu_id: ONU ID if unique per ONU
        """
        if onu_id is not None:
            resource = resource[AdtranPONResourceManager.ONU_MAP][str(onu_id)]

        pos = ((int(unique_id)) - resource[PONResourceManager.START_IDX])
        resource[PONResourceManager.POOL].set(0, pos)

    def get_resource_id(self, pon_intf_id, resource_type, onu_id=None, num_of_id=1):
        """
        Create alloc/gemport/onu id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param num_of_id: required number of ids
        :param onu_id: ONU ID if unique per ONU  (Used for Alloc IDs)
        :return list/int/None: list, int or None if resource type is
                               alloc_id/gemport_id, onu_id or invalid type
                               respectively
        """
        result = None

        if num_of_id < 1:
            self._log.error("invalid-num-of-resources-requested")
            return result

        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            return result

        try:
            resource = self._get_resource(path, onu_id)
            if resource is not None and \
                    (resource_type == PONResourceManager.ONU_ID or
                     resource_type == PONResourceManager.FLOW_ID):
                result = self._generate_next_id(resource)

            elif resource is not None and \
                    resource_type == PONResourceManager.GEMPORT_ID:
                if num_of_id == 1:
                    result = self._generate_next_id(resource)
                else:
                    result = [self._generate_next_id(resource) for _ in range(num_of_id)]

            elif resource is not None and \
                    resource_type == PONResourceManager.ALLOC_ID:
                if num_of_id == 1:
                    result = self._generate_next_id(resource, onu_id)
                else:
                    result = [self._generate_next_id(resource, onu_id) for _ in range(num_of_id)]
            else:
                raise Exception("get-resource-failed")

            self._log.debug("Get-" + resource_type + "-success", result=result,
                            path=path)
            # Update resource in kv store
            self._update_resource(path, resource, onu_id=onu_id)

        except Exception as e:
            self._log.exception("Get-" + resource_type + "-id-failed",
                                path=path, e=e)
        return result

    def free_resource_id(self, pon_intf_id, resource_type, release_content, onu_id=None):
        """
        Release alloc/gemport/onu id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param release_content: required number of ids
        :param onu_id: ONU ID if unique per ONU
        :return boolean: True if all IDs in given release_content released
                         else False
        """
        status = False
        try:
	    path = self._get_path(pon_intf_id, resource_type)
        except KeyError:
            path = None
        
        if path is None:
            return status

        try:
            resource = self._get_resource(path, onu_id=onu_id)
            if resource is None:
                raise Exception("get-resource-for-free-failed")

            if resource_type == PONResourceManager.ONU_ID:
                self._release_id(resource, release_content)

            elif resource_type == PONResourceManager.ALLOC_ID:
                for content in release_content:
                    self._release_id(resource, content)

            elif resource_type == PONResourceManager.GEMPORT_ID:
                for content in release_content:
                    self._release_id(resource, content, onu_id)
            else:
                raise Exception("get-resource-for-free-failed")

            self._log.debug("Free-" + resource_type + "-success", path=path)

            # Update resource in kv store
            status = self._update_resource(path, resource, onu_id=onu_id)

        except Exception as e:
            self._log.exception("Free-" + resource_type + "-failed",
                                path=path, e=e)
        return status

    def _update_resource(self, path, resource, onu_id=None):
        """
        Update resource in resource kv store.

        :param path: path to update resource
        :param resource: resource need to be updated
        :return boolean: True if resource updated in kv store else False
        """
        if 'alloc_id' in path.lower():
            assert onu_id is not None
            poolResource = resource[AdtranPONResourceManager.ONU_MAP][str(onu_id)]
            poolResource[PONResourceManager.POOL] = \
                poolResource[PONResourceManager.POOL].bin
        else:
            resource[PONResourceManager.POOL] = \
                resource[PONResourceManager.POOL].bin

        return self._kv_store.update_to_kv_store(path, json.dumps(resource))

    def _get_resource(self, path, onu_id=None):
        """
        Get resource from kv store.

        :param path: path to get resource
        :return: resource if resource present in kv store else None
        """
        # get resource from kv store
        result = self._kv_store.get_from_kv_store(path)
        if result is None:
            return result

        self._log.info("dumping-resource", result=result)
        resource = result

        if resource is not None:
            # decode resource fetched from backend store to dictionary
            resource = json.loads(resource)

            if 'alloc_id' in path.lower():
                assert onu_id is not None
                poolResource = resource[AdtranPONResourceManager.ONU_MAP][str(onu_id)]
                poolResource[PONResourceManager.POOL] = \
                    BitArray('0b' + poolResource[PONResourceManager.POOL])
            else:
                # resource pool in backend store stored as binary string whereas to
                # access the pool to generate/release IDs it need to be converted
                # as BitArray
                resource[PONResourceManager.POOL] = \
                    BitArray('0b' + resource[PONResourceManager.POOL])

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
        resource[PONResourceManager.POOL] = BitArray(end_idx-start_idx).bin

        return json.dumps(resource)

    def _format_map_resource(self, pon_intf_id, resource_map):
        """
        Format resource as json.
        # TODO: Refactor the resource BitArray to be just a list of the resources.
        #       This is used to store available alloc-id's on a per-onu/pon basis
        #       which in BitArray string form, is a 768 byte string for just 4 possible
        #       alloc-IDs.  This equates to 1.57 MB of storage when you take into
        #       account 128 ONUs and 16 PONs pre-provisioneed
        :param pon_intf_id: OLT PON interface id
        :param resource_map: (dict) ONU ID -> Scattered list of IDs
        :return dictionary: resource formatted as dictionary
        """
        # Format resource as json to be stored in backend store
        resource = dict()
        resource[PONResourceManager.PON_INTF_ID] = pon_intf_id

        onu_dict = dict()
        for onu_id, resources in resource_map.items():
            start_idx = min(resources)
            end_idx = max(resources) + 1

            onu_dict[onu_id] = {
                PONResourceManager.START_IDX: start_idx,
                PONResourceManager.END_IDX: end_idx,
            }
            # Set non-allowed values as taken
            resource_map = BitArray(end_idx - start_idx)
            not_available = {pos for pos in xrange(end_idx-start_idx)
                             if pos + start_idx not in resources}
            resource_map.set(True, not_available)
            onu_dict[onu_id][PONResourceManager.POOL] = resource_map.bin

        resource[AdtranPONResourceManager.ONU_MAP] = onu_dict
        return json.dumps(resource)
