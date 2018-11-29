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
import ast
import structlog
from bitstring import BitArray
import shlex
from argparse import ArgumentParser, ArgumentError

from common.pon_resource_manager.resource_kv_store import ResourceKvStore
from common.tech_profile.tech_profile import TechProfile


# Used to parse extra arguments to OpenOlt adapter from the NBI
class OltVendorArgumentParser(ArgumentParser):
    # Must override the exit command to prevent it from
    # calling sys.exit().  Return exception instead.
    def exit(self, status=0, message=None):
        raise Exception(message)


class PONResourceManager(object):
    """Implements APIs to initialize/allocate/release alloc/gemport/onu IDs."""

    # Constants to identify resource pool
    UNI_ID = 'UNI_ID'
    ONU_ID = 'ONU_ID'
    ALLOC_ID = 'ALLOC_ID'
    GEMPORT_ID = 'GEMPORT_ID'
    FLOW_ID = 'FLOW_ID'

    # Constants for passing command line arugments
    OLT_MODEL_ARG = '--olt_model'

    # The resource ranges for a given device model should be placed
    # at 'resource_manager/<technology>/resource_ranges/<olt_model_type>'
    # path on the KV store.
    # If Resource Range parameters are to be read from the external KV store,
    # they are expected to be stored in the following format.
    # Note: All parameters are MANDATORY for now.
    '''
    {
        "onu_id_start": 1,
        "onu_id_end": 127,
        "alloc_id_start": 1024,
        "alloc_id_end": 2816,
        "gemport_id_start": 1024,
        "gemport_id_end": 8960,
        "flow_id_start": 1,
        "flow_id_end": 16383,
        "uni_id_start": 0,
        "uni_id_end": 0,
        "pon_ports": 16
    }

    '''
    # constants used as keys to reference the resource range parameters from
    # and external KV store.
    UNI_ID_START_IDX = "uni_id_start"
    UNI_ID_END_IDX = "uni_id_end"
    ONU_ID_START_IDX = "onu_id_start"
    ONU_ID_END_IDX = "onu_id_end"
    ONU_ID_SHARED_IDX = "onu_id_shared"
    ALLOC_ID_START_IDX = "alloc_id_start"
    ALLOC_ID_END_IDX = "alloc_id_end"
    ALLOC_ID_SHARED_IDX = "alloc_id_shared"
    GEMPORT_ID_START_IDX = "gemport_id_start"
    GEMPORT_ID_END_IDX = "gemport_id_end"
    GEMPORT_ID_SHARED_IDX = "gemport_id_shared"
    FLOW_ID_START_IDX = "flow_id_start"
    FLOW_ID_END_IDX = "flow_id_end"
    FLOW_ID_SHARED_IDX = "flow_id_shared"
    NUM_OF_PON_PORT = "pon_ports"

    # PON Resource range configuration on the KV store.
    # Format: 'resource_manager/<technology>/resource_ranges/<olt_model_type>'
    # The KV store backend is initialized with a path prefix and we need to
    # provide only the suffix.
    PON_RESOURCE_RANGE_CONFIG_PATH = 'resource_ranges/{}'

    # resource path suffix
    ALLOC_ID_POOL_PATH = '{}/alloc_id_pool/{}'
    GEMPORT_ID_POOL_PATH = '{}/gemport_id_pool/{}'
    ONU_ID_POOL_PATH = '{}/onu_id_pool/{}'
    FLOW_ID_POOL_PATH = '{}/flow_id_pool/{}'

    # Path on the KV store for storing list of alloc IDs for a given ONU
    # Format: <device_id>/<(pon_intf_id, onu_id)>/alloc_ids
    ALLOC_ID_RESOURCE_MAP_PATH = '{}/{}/alloc_ids'

    # Path on the KV store for storing list of gemport IDs for a given ONU
    # Format: <device_id>/<(pon_intf_id, onu_id)>/gemport_ids
    GEMPORT_ID_RESOURCE_MAP_PATH = '{}/{}/gemport_ids'

    # Path on the KV store for storing list of Flow IDs for a given ONU
    # Format: <device_id>/<(pon_intf_id, onu_id)>/flow_ids
    FLOW_ID_RESOURCE_MAP_PATH = '{}/{}/flow_ids'

    # Flow Id info: Use to store more metadata associated with the flow_id
    # Format: <device_id>/<(pon_intf_id, onu_id)>/flow_id_info/<flow_id>
    FLOW_ID_INFO_PATH = '{}/{}/flow_id_info/{}'

    # Constants for internal usage.
    PON_INTF_ID = 'pon_intf_id'
    START_IDX = 'start_idx'
    END_IDX = 'end_idx'
    POOL = 'pool'

    def __init__(self, technology, extra_args, device_id,
                 backend, host, port):
        """
        Create PONResourceManager object.

        :param technology: PON technology
        :param: extra_args: This string contains extra arguments passed during
        pre-provisioning of OLT and specifies the OLT Vendor type
        :param device_id: OLT device id
        :param backend: backend store
        :param host: ip of backend store
        :param port: port on which backend store listens
        :raises exception when invalid backend store passed as an argument
        """
        # logger
        self._log = structlog.get_logger()

        try:
            self.technology = technology
            self.extra_args = extra_args 
            self.device_id = device_id
            self.backend = backend
            self.host = host
            self.port = port
            self.olt_model = None

            self._kv_store = ResourceKvStore(technology, device_id, backend,
                                             host, port)
            self.tech_profile = TechProfile(self)

            # Below attribute, pon_resource_ranges, should be initialized
            # by reading from KV store.
            self.pon_resource_ranges = dict()
            self.pon_resource_ranges[PONResourceManager.ONU_ID_SHARED_IDX] = None
            self.pon_resource_ranges[PONResourceManager.ALLOC_ID_SHARED_IDX] = None
            self.pon_resource_ranges[PONResourceManager.GEMPORT_ID_SHARED_IDX] = None
            self.pon_resource_ranges[PONResourceManager.FLOW_ID_SHARED_IDX] = None

            self.shared_resource_mgrs = dict()
            self.shared_resource_mgrs[PONResourceManager.ONU_ID_SHARED_IDX] = None
            self.shared_resource_mgrs[PONResourceManager.ALLOC_ID_SHARED_IDX] = None
            self.shared_resource_mgrs[PONResourceManager.GEMPORT_ID_SHARED_IDX] = None
            self.shared_resource_mgrs[PONResourceManager.FLOW_ID_SHARED_IDX] = None

            self.shared_idx_by_type = dict()
            self.shared_idx_by_type[PONResourceManager.ONU_ID] = PONResourceManager.ONU_ID_SHARED_IDX
            self.shared_idx_by_type[PONResourceManager.ALLOC_ID] = PONResourceManager.ALLOC_ID_SHARED_IDX
            self.shared_idx_by_type[PONResourceManager.GEMPORT_ID] = PONResourceManager.GEMPORT_ID_SHARED_IDX
            self.shared_idx_by_type[PONResourceManager.FLOW_ID] = PONResourceManager.FLOW_ID_SHARED_IDX

            self.intf_ids = None

        except Exception as e:
            self._log.exception("exception-in-init")
            raise Exception(e)

    def init_resource_ranges_from_kv_store(self):
        """
        Initialize PON resource ranges with config fetched from kv store.

        :return boolean: True if PON resource ranges initialized else false
        """
        self.olt_model = self._get_olt_model()
        # Try to initialize the PON Resource Ranges from KV store based on the
        # OLT model key, if available
        if self.olt_model is None:
            self._log.info("device-model-unavailable--not-reading-from-kv-store")
            return False

        path = self.PON_RESOURCE_RANGE_CONFIG_PATH.format(self.olt_model)
        try:
            # get resource from kv store
            result = self._kv_store.get_from_kv_store(path)

            if result is None:
                self._log.debug("resource-range-config-unavailable-on-kvstore")
                return False

            resource_range_config = result

            if resource_range_config is not None:
                # update internal ranges from kv ranges. If there are missing
                # values in the KV profile, continue to use the defaults
                for key,value in json.loads(resource_range_config): self.pon_resource_ranges[key] = value

                # initialize optional elements that may not be in the profile
                if self.pon_resource_ranges[PONResourceManager.UNI_ID_START_IDX] is None:
                    self.pon_resource_ranges[PONResourceManager.UNI_ID_START_IDX] = 0
                if self.pon_resource_ranges[PONResourceManager.UNI_ID_END_IDX] is None:
                    self.pon_resource_ranges[PONResourceManager.UNI_ID_END_IDX] = 0

                self._log.debug("Init-resource-ranges-from-kvstore-success",
                                pon_resource_ranges=self.pon_resource_ranges,
                                path=path)
                return True

        except Exception as e:
            self._log.exception("error-initializing-resource-range-from-kv-store",
                                e=e)
        return False

    def update_range_(self, start_idx, start, end_idx, end, shared_idx = None, shared_pool_id = None,
                      shared_resource_mgr = None):
        if (start is not None) and \
                (start_idx not in self.pon_resource_ranges or self.pon_resource_ranges[start_idx] < start):
            self.pon_resource_ranges[start_idx] = start
        if (end is not None) and \
                (end_idx not in self.pon_resource_ranges or self.pon_resource_ranges[end_idx] > end):
            self.pon_resource_ranges[end_idx] = end
        if (shared_pool_id is not None) and \
                (shared_idx not in self.pon_resource_ranges or self.pon_resource_ranges[shared_idx] is None):
            self.pon_resource_ranges[shared_idx] = shared_pool_id
        if (shared_resource_mgr is not None) and \
                (shared_idx not in self.shared_resource_mgrs or self.shared_resource_mgrs[shared_idx] is None):
            self.shared_resource_mgrs[shared_idx] = shared_resource_mgr

    def update_ranges(self,
                      onu_id_start_idx=None,
                      onu_id_end_idx=None,
                      onu_id_shared_pool_id=None,
                      onu_id_shared_resource_mgr=None,
                      alloc_id_start_idx=None,
                      alloc_id_end_idx=None,
                      alloc_id_shared_pool_id=None,
                      alloc_id_shared_resource_mgr=None,
                      gemport_id_start_idx=None,
                      gemport_id_end_idx=None,
                      gemport_id_shared_pool_id=None,
                      gemport_id_shared_resource_mgr=None,
                      flow_id_start_idx=None,
                      flow_id_end_idx=None,
                      flow_id_shared_pool_id=None,
                      flow_id_shared_resource_mgr=None,
                      uni_id_start_idx=None,
                      uni_id_end_idx=None):

        self.update_range_(PONResourceManager.ONU_ID_START_IDX, onu_id_start_idx,
                           PONResourceManager.ONU_ID_END_IDX, onu_id_end_idx,
                           PONResourceManager.ONU_ID_SHARED_IDX, onu_id_shared_pool_id,
                           onu_id_shared_resource_mgr)

        self.update_range_(PONResourceManager.ALLOC_ID_START_IDX, alloc_id_start_idx,
                           PONResourceManager.ALLOC_ID_END_IDX, alloc_id_end_idx,
                           PONResourceManager.ALLOC_ID_SHARED_IDX, alloc_id_shared_pool_id,
                           alloc_id_shared_resource_mgr)

        self.update_range_(PONResourceManager.GEMPORT_ID_START_IDX, gemport_id_start_idx,
                           PONResourceManager.GEMPORT_ID_END_IDX, gemport_id_end_idx,
                           PONResourceManager.GEMPORT_ID_SHARED_IDX, gemport_id_shared_pool_id,
                           gemport_id_shared_resource_mgr)

        self.update_range_(PONResourceManager.FLOW_ID_START_IDX, flow_id_start_idx,
                           PONResourceManager.FLOW_ID_END_IDX, flow_id_end_idx,
                           PONResourceManager.FLOW_ID_SHARED_IDX, flow_id_shared_pool_id,
                           flow_id_shared_resource_mgr)

        self.update_range_(PONResourceManager.UNI_ID_START_IDX, uni_id_start_idx,
                           PONResourceManager.UNI_ID_END_IDX, uni_id_end_idx)

    def init_default_pon_resource_ranges(self,
                                         onu_id_start_idx=1,
                                         onu_id_end_idx=127,
                                         onu_id_shared_pool_id=None,
                                         alloc_id_start_idx=1024,
                                         alloc_id_end_idx=2816,
                                         alloc_id_shared_pool_id=None,
                                         gemport_id_start_idx=1024,
                                         gemport_id_end_idx=8960,
                                         gemport_id_shared_pool_id=None,
                                         flow_id_start_idx=1,
                                         flow_id_end_idx=16383,
                                         flow_id_shared_pool_id=None,
                                         uni_id_start_idx=0,
                                         uni_id_end_idx=0,
                                         num_of_pon_ports=16,
                                         intf_ids=None):
        """
        Initialize default PON resource ranges

        :param onu_id_start_idx: onu id start index
        :param onu_id_end_idx: onu id end index
        :param onu_id_shared_pool_id: pool idx for id shared by all intfs or None for no sharing
        :param alloc_id_start_idx: alloc id start index
        :param alloc_id_end_idx: alloc id end index
        :param alloc_id_shared_pool_id: pool idx for alloc id shared by all intfs or None for no sharing
        :param gemport_id_start_idx: gemport id start index
        :param gemport_id_end_idx: gemport id end index
        :param gemport_id_shared_pool_id: pool idx for gemport id shared by all intfs or None for no sharing
        :param flow_id_start_idx: flow id start index
        :param flow_id_end_idx: flow id end index
        :param flow_id_shared_pool_id: pool idx for flow id shared by all intfs or None for no sharing
        :param num_of_pon_ports: number of PON ports
        :param intf_ids: interfaces serviced by this manager
        """
        self._log.info("initialize-default-resource-range-values")

        self.update_ranges(onu_id_start_idx, onu_id_end_idx, onu_id_shared_pool_id, None,
                           alloc_id_start_idx, alloc_id_end_idx, alloc_id_shared_pool_id, None,
                           gemport_id_start_idx, gemport_id_end_idx, gemport_id_shared_pool_id, None,
                           flow_id_start_idx, flow_id_end_idx, flow_id_shared_pool_id, None,
                           uni_id_start_idx, uni_id_end_idx)

        if intf_ids is None:
            intf_ids = range(0, num_of_pon_ports)

        self.intf_ids = intf_ids

    def init_device_resource_pool(self):
        """
        Initialize resource pool for all PON ports.
        """

        self._log.info("init-device-resource-pool", technology=self.technology,
                       pon_resource_ranges=self.pon_resource_ranges)

        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.ONU_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ONU_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.ONU_ID_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.ONU_ID_END_IDX])
            if shared_pool_id is not None:
                break

        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.ALLOC_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ALLOC_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.ALLOC_ID_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.ALLOC_ID_END_IDX])
            if shared_pool_id is not None:
                break

        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.GEMPORT_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.GEMPORT_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.GEMPORT_ID_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.GEMPORT_ID_END_IDX])
            if shared_pool_id is not None:
                break

        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.FLOW_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.FLOW_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.FLOW_ID_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.FLOW_ID_END_IDX])
            if shared_pool_id is not None:
                break

    def clear_device_resource_pool(self):
        """
        Clear resource pool of all PON ports.
        """
        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.ONU_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ONU_ID,
            )
            if shared_pool_id is not None:
                break

        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.ALLOC_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ALLOC_ID,
            )
            if shared_pool_id is not None:
                break

        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.GEMPORT_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.GEMPORT_ID,
            )
            if shared_pool_id is not None:
                break

        for i in self.intf_ids:
            shared_pool_id = self.pon_resource_ranges[PONResourceManager.FLOW_ID_SHARED_IDX]
            if shared_pool_id is not None:
                i = shared_pool_id
            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.FLOW_ID,
            )
            if shared_pool_id is not None:
                break

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

        # delegate to the master instance if sharing enabled across instances
        shared_resource_mgr = self.shared_resource_mgrs[self.shared_idx_by_type[resource_type]]
        if shared_resource_mgr is not None and shared_resource_mgr is not self:
            return shared_resource_mgr.init_resource_id_pool(pon_intf_id, resource_type,
                                                             start_idx, end_idx)

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
                resource = self._format_resource(pon_intf_id, start_idx,
                                                 end_idx)
                self._log.info("Resource-initialized", path=path)

                # Add resource as json in kv store.
                result = self._kv_store.update_to_kv_store(path, resource)
                if result is True:
                    status = True

        except Exception as e:
            self._log.exception("error-initializing-resource-pool", e=e)

        return status

    def assert_resource_limits(self, id, resource_type):
        """
        Assert the specified id value is in the limit bounds of he requested resource type.

        :param id: The value to assert is in limits
        :param resource_type: String to identify type of resource
        """
        start_idx = PONResourceManager.ONU_ID_START_IDX if resource_type == PONResourceManager.ONU_ID \
            else PONResourceManager.ALLOC_ID_START_IDX if resource_type == PONResourceManager.ALLOC_ID \
            else PONResourceManager.GEMPORT_ID_START_IDX if resource_type == PONResourceManager.GEMPORT_ID \
            else PONResourceManager.FLOW_ID_START_IDX if resource_type == PONResourceManager.FLOW_ID \
            else PONResourceManager.UNI_ID_START_IDX if resource_type == PONResourceManager.UNI_ID \
            else None
        end_idx = PONResourceManager.ONU_ID_END_IDX if resource_type == PONResourceManager.ONU_ID \
            else PONResourceManager.ALLOC_ID_END_IDX if resource_type == PONResourceManager.ALLOC_ID \
            else PONResourceManager.GEMPORT_ID_END_IDX if resource_type == PONResourceManager.GEMPORT_ID \
            else PONResourceManager.FLOW_ID_END_IDX if resource_type == PONResourceManager.FLOW_ID \
            else PONResourceManager.UNI_ID_END_IDX if resource_type == PONResourceManager.UNI_ID \
            else None
        assert id >= self.pon_resource_ranges[start_idx] and id <= self.pon_resource_ranges[end_idx]

    def get_resource_id(self, pon_intf_id, resource_type, num_of_id=1):
        """
        Create alloc/gemport/onu/flow id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param num_of_id: required number of ids
        :return list/int/None: list, int or None if resource type is
                               alloc_id/gemport_id, onu_id or invalid type
                               respectively
        """
        result = None

        if num_of_id < 1:
            self._log.error("invalid-num-of-resources-requested")
            return result

        # delegate to the master instance if sharing enabled across instances
        shared_resource_mgr = self.shared_resource_mgrs[self.shared_idx_by_type[resource_type]]
        if shared_resource_mgr is not None and shared_resource_mgr is not self:
            return shared_resource_mgr.get_resource_id(pon_intf_id, resource_type, num_of_id)

        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            return result

        try:
            resource = self._get_resource(path)
            if resource is not None and \
                    (resource_type == PONResourceManager.ONU_ID or
                     resource_type == PONResourceManager.FLOW_ID):
                result = self._generate_next_id(resource)
            elif resource is not None and (
                    resource_type == PONResourceManager.GEMPORT_ID or
                    resource_type == PONResourceManager.ALLOC_ID):
                if num_of_id == 1:
                    result = self._generate_next_id(resource)
                else:
                    result = list()
                    while num_of_id > 0:
                        result.append(self._generate_next_id(resource))
                        num_of_id -= 1
            else:
                raise Exception("get-resource-failed")

            self._log.debug("Get-" + resource_type + "-success", result=result,
                            path=path)
            # Update resource in kv store
            self._update_resource(path, resource)

        except Exception as e:
            self._log.exception("Get-" + resource_type + "-id-failed",
                                path=path, e=e)
        return result

    def free_resource_id(self, pon_intf_id, resource_type, release_content):
        """
        Release alloc/gemport/onu/flow id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param release_content: required number of ids
        :return boolean: True if all IDs in given release_content released
                         else False
        """
        status = False
        known_resource_types = [PONResourceManager.ONU_ID,
                                PONResourceManager.ALLOC_ID,
                                PONResourceManager.GEMPORT_ID,
                                PONResourceManager.FLOW_ID]
        if resource_type not in known_resource_types:
            self._log.error("unknown-resource-type",
                            resource_type=resource_type)
            return status
        if release_content is None:
            self._log.debug("nothing-to-release")
            return status
        # delegate to the master instance if sharing enabled across instances
        shared_resource_mgr = self.shared_resource_mgrs[self.shared_idx_by_type[resource_type]]
        if shared_resource_mgr is not None and shared_resource_mgr is not self:
            return shared_resource_mgr.free_resource_id(pon_intf_id, resource_type)

        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            return status

        try:
            resource = self._get_resource(path)
            if resource is None:
                raise Exception("get-resource-failed")
            if isinstance(release_content, list):
                for content in release_content:
                    self._release_id(resource, content)
            else:
                self._release_id(resource, release_content)

            self._log.debug("Free-" + resource_type + "-success", path=path)

            # Update resource in kv store
            status = self._update_resource(path, resource)

        except Exception as e:
            self._log.exception("Free-" + resource_type + "-failed",
                                path=path, e=e)
        return status

    def clear_resource_id_pool(self, pon_intf_id, resource_type):
        """
        Clear Resource Pool for a given Resource Type on a given PON Port.

        :return boolean: True if removed else False
        """

        # delegate to the master instance if sharing enabled across instances
        shared_resource_mgr = self.shared_resource_mgrs[self.shared_idx_by_type[resource_type]]
        if shared_resource_mgr is not None and shared_resource_mgr is not self:
            return shared_resource_mgr.clear_resource_id_pool(pon_intf_id, resource_type)

        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            return False

        try:
            result = self._kv_store.remove_from_kv_store(path)
            if result is True:
                self._log.debug("Resource-pool-cleared",
                                device_id=self.device_id,
                                path=path)
                return True
        except Exception as e:
            self._log.exception("error-clearing-resource-pool", e=e)

        self._log.error("Clear-resource-pool-failed", device_id=self.device_id,
                        path=path)
        return False

    def init_resource_map(self, pon_intf_onu_id):
        """
        Initialize resource map

        :param pon_intf_onu_id: reference of PON interface id and onu id
        """
        # initialize pon_intf_onu_id tuple to alloc_ids map
        alloc_id_path = PONResourceManager.ALLOC_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        alloc_ids = list()
        self._kv_store.update_to_kv_store(
            alloc_id_path, json.dumps(alloc_ids)
        )

        # initialize pon_intf_onu_id tuple to gemport_ids map
        gemport_id_path = PONResourceManager.GEMPORT_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        gemport_ids = list()
        self._kv_store.update_to_kv_store(
            gemport_id_path, json.dumps(gemport_ids)
        )

    def remove_resource_map(self, pon_intf_onu_id):
        """
        Remove resource map

        :param pon_intf_onu_id: reference of PON interface id and onu id
        """
        # remove pon_intf_onu_id tuple to alloc_ids map
        try:
            alloc_id_path = PONResourceManager.ALLOC_ID_RESOURCE_MAP_PATH.format(
                self.device_id, str(pon_intf_onu_id)
            )
            self._kv_store.remove_from_kv_store(alloc_id_path)
        except Exception as e:
            self._log.error("error-removing-alloc-id", e=e)

        try:
            # remove pon_intf_onu_id tuple to gemport_ids map
            gemport_id_path = PONResourceManager.GEMPORT_ID_RESOURCE_MAP_PATH.format(
                self.device_id, str(pon_intf_onu_id)
            )
            self._kv_store.remove_from_kv_store(gemport_id_path)
        except Exception as e:
            self._log.error("error-removing-gem-ports", e=e)

        flow_id_path = PONResourceManager.FLOW_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id))
        flow_ids = self._kv_store.get_from_kv_store(flow_id_path)

        if flow_ids and isinstance(flow_ids, list):
            for flow_id in flow_ids:
                try:
                    flow_id_info_path = PONResourceManager.FLOW_ID_INFO_PATH.format(
                                        self.device_id, str(pon_intf_onu_id), flow_id)
                    self._kv_store.remove_from_kv_store(flow_id_info_path)
                except Exception as e:
                    self._log.error("error-removing-flow-info", flow_id=flow_id, e=e)
                    continue
        try:
            self._kv_store.remove_from_kv_store(flow_id_path)
        except Exception as e:
            self._log.error("error-removing-flow-ids", e=e)

    def get_current_alloc_ids_for_onu(self, pon_intf_onu_id):
        """
        Get currently configured alloc ids for given pon_intf_onu_id

        :param pon_intf_onu_id: reference of PON interface id and onu id

        :return list: List of alloc_ids if available, else None
        """
        path = PONResourceManager.ALLOC_ID_RESOURCE_MAP_PATH.format(
            self.device_id,
            str(pon_intf_onu_id))
        value = self._kv_store.get_from_kv_store(path)
        if value is not None:
            alloc_id_list = json.loads(value)
            if len(alloc_id_list) > 0:
                return alloc_id_list

        return None

    def get_current_gemport_ids_for_onu(self, pon_intf_onu_id):
        """
        Get currently configured gemport ids for given pon_intf_onu_id

        :param pon_intf_onu_id: reference of PON interface id and onu id

        :return list: List of gemport IDs if available, else None
        """

        path = PONResourceManager.GEMPORT_ID_RESOURCE_MAP_PATH.format(
            self.device_id,
            str(pon_intf_onu_id))
        value = self._kv_store.get_from_kv_store(path)
        if value is not None:
            gemport_id_list = json.loads(value)
            if len(gemport_id_list) > 0:
                return gemport_id_list

        return None

    def get_current_flow_ids_for_onu(self, pon_intf_onu_id):
        """
        Get currently configured flow ids for given pon_intf_onu_id

        :param pon_intf_onu_id: reference of PON interface id and onu id

        :return list: List of Flow IDs if available, else None
        """

        path = PONResourceManager.FLOW_ID_RESOURCE_MAP_PATH.format(
            self.device_id,
            str(pon_intf_onu_id))
        value = self._kv_store.get_from_kv_store(path)
        if value is not None:
            flow_id_list = json.loads(value)
            assert(isinstance(flow_id_list, list))
            if len(flow_id_list) > 0:
                return flow_id_list

        return None

    def get_flow_id_info(self, pon_intf_onu_id, flow_id):
        """
        Get flow_id details configured for the ONU.

        :param pon_intf_onu_id: reference of PON interface id and onu id
        :param flow_id: Flow Id reference

        :return blob: Flow data blob if available, else None
        """

        path = PONResourceManager.FLOW_ID_INFO_PATH.format(
            self.device_id,
            str(pon_intf_onu_id),
            flow_id)
        value = self._kv_store.get_from_kv_store(path)
        if value is not None:
            return ast.literal_eval(value)

        return None

    def remove_flow_id_info(self, pon_intf_onu_id, flow_id):
        """
        Get flow_id details configured for the ONU.

        :param pon_intf_onu_id: reference of PON interface id and onu id
        :param flow_id: Flow Id reference

        """

        path = PONResourceManager.FLOW_ID_INFO_PATH.format(
            self.device_id,
            str(pon_intf_onu_id),
            flow_id)
        self._kv_store.remove_from_kv_store(path)

    def update_alloc_ids_for_onu(self, pon_intf_onu_id, alloc_ids):
        """
        Update currently configured alloc ids for given pon_intf_onu_id

        :param pon_intf_onu_id: reference of PON interface id and onu id
        :param alloc_ids: list of alloc ids
        """
        path = PONResourceManager.ALLOC_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        self._kv_store.update_to_kv_store(
            path, json.dumps(alloc_ids)
        )

    def update_gemport_ids_for_onu(self, pon_intf_onu_id, gemport_ids):
        """
        Update currently configured gemport ids for given pon_intf_onu_id

        :param pon_intf_onu_id: reference of PON interface id and onu id
        :param gemport_ids: list of gem port ids
        """
        path = PONResourceManager.GEMPORT_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        self._kv_store.update_to_kv_store(
            path, json.dumps(gemport_ids)
        )

    def update_flow_id_for_onu(self, pon_intf_onu_id, flow_id, add=True):
        """
        Update the flow_id list of the ONU (add or remove flow_id from the list)

        :param pon_intf_onu_id: reference of PON interface id and onu id
        :param flow_id: flow ID
        :param add: Boolean flag to indicate whether the flow_id should be
                    added or removed from the list. Defaults to adding the flow.
        """
        path = PONResourceManager.FLOW_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        current_flow_ids = self.get_current_flow_ids_for_onu(pon_intf_onu_id)
        if not isinstance(current_flow_ids, list):
            # When the first flow_id is being added, the current_flow_ids is None
            current_flow_ids = list()

        if add:
            if flow_id not in current_flow_ids:
                current_flow_ids.append(flow_id)
        else:
            if flow_id in current_flow_ids:
                current_flow_ids.remove(flow_id)

        self._kv_store.update_to_kv_store(path, current_flow_ids)

    def update_flow_id_info_for_onu(self, pon_intf_onu_id, flow_id, flow_data):
        """
        Update any metadata associated with the flow_id. The flow_data could be json
        or any of other data structure. The resource manager doesnt care

        :param pon_intf_onu_id: reference of PON interface id and onu id
        :param flow_id: Flow ID
        :param flow_data: Flow data blob
        """
        path = PONResourceManager.FLOW_ID_INFO_PATH.format(
            self.device_id, str(pon_intf_onu_id), flow_id
        )

        if not self._kv_store.update_to_kv_store(path, flow_data):
            self._log.error("flow-info-update-failed", path=path, flow_id=flow_id)

    def _get_olt_model(self):
        """
        Get olt model variant

        :return: type of olt model 
        """
        olt_model = None
        if self.extra_args and len(self.extra_args) > 0:
            parser = OltVendorArgumentParser(add_help=False)
            parser.add_argument(PONResourceManager.OLT_MODEL_ARG, '-m', action='store', default='default')
            try:
                args = parser.parse_args(shlex.split(self.extra_args))
                self._log.debug('parsing-extra-arguments', args=args)
                olt_model = args.olt_model
            except ArgumentError as e:
                self._log.exception('invalid-arguments: {}', e=e)
            except Exception as e:
                self._log.exception('option-parsing-error: {}', e=e)

        self._log.debug('olt-model', olt_model=olt_model)
        return olt_model

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

        shared_pool_id = self.pon_resource_ranges[self.shared_idx_by_type[resource_type]]
        if shared_pool_id is not None:
            pon_intf_id = shared_pool_id

        path = None
        if resource_type == PONResourceManager.ONU_ID:
            path = self._get_onu_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.ALLOC_ID:
            path = self._get_alloc_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.GEMPORT_ID:
            path = self._get_gemport_id_resource_path(pon_intf_id)
        elif resource_type == PONResourceManager.FLOW_ID:
            path = self._get_flow_id_resource_path(pon_intf_id)
        else:
            self._log.error("invalid-resource-pool-identifier")
        return path

    def _get_flow_id_resource_path(self, pon_intf_id):
        """
        Get flow id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: flow id resource path
        """
        return PONResourceManager.FLOW_ID_POOL_PATH.format(
            self.device_id, pon_intf_id)

    def _get_alloc_id_resource_path(self, pon_intf_id):
        """
        Get alloc id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: alloc id resource path
        """
        return PONResourceManager.ALLOC_ID_POOL_PATH.format(
            self.device_id, pon_intf_id)

    def _get_gemport_id_resource_path(self, pon_intf_id):
        """
        Get gemport id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: gemport id resource path
        """
        return PONResourceManager.GEMPORT_ID_POOL_PATH.format(
            self.device_id, pon_intf_id)

    def _get_onu_id_resource_path(self, pon_intf_id):
        """
        Get onu id resource path.

        :param pon_intf_id: OLT PON interface id
        :return: onu id resource path
        """
        return PONResourceManager.ONU_ID_POOL_PATH.format(
            self.device_id, pon_intf_id)

    def _update_resource(self, path, resource):
        """
        Update resource in resource kv store.

        :param path: path to update resource
        :param resource: resource need to be updated
        :return boolean: True if resource updated in kv store else False
        """
        resource[PONResourceManager.POOL] = \
            resource[PONResourceManager.POOL].bin
        result = self._kv_store.update_to_kv_store(path, json.dumps(resource))
        if result is True:
            return True
        return False

    def _get_resource(self, path):
        """
        Get resource from kv store.

        :param path: path to get resource
        :return: resource if resource present in kv store else None
        """
        # get resource from kv store
        result = self._kv_store.get_from_kv_store(path)
        if result is None:
            return result
        self._log.info("dumping resource", result=result)
        resource = result

        if resource is not None:
            # decode resource fetched from backend store to dictionary
            resource = json.loads(resource)

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
        resource[PONResourceManager.POOL] = BitArray(end_idx).bin

        return json.dumps(resource)
