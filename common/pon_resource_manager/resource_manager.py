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
from ast import literal_eval
import shlex
from argparse import ArgumentParser, ArgumentError

from common.pon_resource_manager.resource_kv_store import ResourceKvStore


# Used to parse extra arguments to OpenOlt adapter from the NBI
class OltVendorArgumentParser(ArgumentParser):
    # Must override the exit command to prevent it from
    # calling sys.exit().  Return exception instead.
    def exit(self, status=0, message=None):
        raise Exception(message)


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
        "onu_id_start": 1,
        "onu_id_end": 127,
        "alloc_id_start": 1024,
        "alloc_id_end": 2816,
        "gemport_id_start": 1024,
        "gemport_id_end": 8960,
        "pon_ports": 16
    }

    '''
    # constants used as keys to reference the resource range parameters from
    # and external KV store.
    ONU_START_IDX = "onu_id_start"
    ONU_END_IDX = "onu_id_end"
    ALLOC_ID_START_IDX = "alloc_id_start"
    ALLOC_ID_END_IDX = "alloc_id_end"
    GEM_PORT_ID_START_IDX = "gemport_id_start"
    GEM_PORT_ID_END_IDX = "gemport_id_end"
    NUM_OF_PON_PORT = "pon_ports"

    # PON Resource range configuration on the KV store.
    # Format: 'resource_manager/<technology>/resource_ranges/<olt_vendor_type>'
    # The KV store backend is initialized with a path prefix and we need to
    # provide only the suffix.
    PON_RESOURCE_RANGE_CONFIG_PATH = 'resource_ranges/{}'

    # resource path suffix
    ALLOC_ID_POOL_PATH = '{}/alloc_id_pool/{}'
    GEMPORT_ID_POOL_PATH = '{}/gemport_id_pool/{}'
    ONU_ID_POOL_PATH = '{}/onu_id_pool/{}'

    # Path on the KV store for storing list of alloc IDs for a given ONU
    # Format: <device_id>/<(pon_intf_id, onu_id)>/alloc_ids
    ALLOC_ID_RESOURCE_MAP_PATH = '{}/{}/alloc_ids'

    # Path on the KV store for storing list of gemport IDs for a given ONU
    # Format: <device_id>/<(pon_intf_id, onu_id)>/gemport_ids
    GEMPORT_ID_RESOURCE_MAP_PATH = '{}/{}/gemport_ids'

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
            self.olt_vendor = None
            self._kv_store = ResourceKvStore(technology, device_id, backend,
                                             host, port)
            # Below attribute, pon_resource_ranges, should be initialized
            # by reading from KV store.
            self.pon_resource_ranges = dict()
        except Exception as e:
            self._log.exception("exception-in-init")
            raise Exception(e)

    def init_resource_ranges_from_kv_store(self):
        """
        Initialize PON resource ranges with config fetched from kv store.

        :return boolean: True if PON resource ranges initialized else false
        """
        self.olt_vendor = self._get_olt_vendor()
        # Try to initialize the PON Resource Ranges from KV store based on the
        # OLT vendor key, if available
        if self.olt_vendor is None:
            self._log.info("olt-vendor-unavailable--not-reading-from-kv-store")
            return False

        path = self.PON_RESOURCE_RANGE_CONFIG_PATH.format(self.olt_vendor)
        try:
            # get resource from kv store
            result = self._kv_store.get_from_kv_store(path)

            if result is None:
                self._log.debug("resource-range-config-unavailable-on-kvstore")
                return False

            resource_range_config = result

            if resource_range_config is not None:
                self.pon_resource_ranges = json.loads(resource_range_config)
                self._log.debug("Init-resource-ranges-from-kvstore-success",
                                pon_resource_ranges=self.pon_resource_ranges,
                                path=path)
                return True

        except Exception as e:
            self._log.exception("error-initializing-resource-range-from-kv-store",
                                e=e)
        return False

    def init_default_pon_resource_ranges(self, onu_start_idx=1,
                                         onu_end_idx=127,
                                         alloc_id_start_idx=1024,
                                         alloc_id_end_idx=2816,
                                         gem_port_id_start_idx=1024,
                                         gem_port_id_end_idx=8960,
                                         num_of_pon_ports=16):
        """
        Initialize default PON resource ranges

        :param onu_start_idx: onu id start index
        :param onu_end_idx: onu id end index
        :param alloc_id_start_idx: alloc id start index
        :param alloc_id_end_idx: alloc id end index
        :param gem_port_id_start_idx: gemport id start index
        :param gem_port_id_end_idx: gemport id end index
        :param num_of_pon_ports: number of PON ports
        """
        self._log.info("initialize-default-resource-range-values")
        self.pon_resource_ranges[
            PONResourceManager.ONU_START_IDX] = onu_start_idx
        self.pon_resource_ranges[PONResourceManager.ONU_END_IDX] = onu_end_idx
        self.pon_resource_ranges[
            PONResourceManager.ALLOC_ID_START_IDX] = alloc_id_start_idx
        self.pon_resource_ranges[
            PONResourceManager.ALLOC_ID_END_IDX] = alloc_id_end_idx
        self.pon_resource_ranges[
            PONResourceManager.GEM_PORT_ID_START_IDX] = gem_port_id_start_idx
        self.pon_resource_ranges[
            PONResourceManager.GEM_PORT_ID_END_IDX] = gem_port_id_end_idx
        self.pon_resource_ranges[
            PONResourceManager.NUM_OF_PON_PORT] = num_of_pon_ports

    def init_device_resource_pool(self):
        """
        Initialize resource pool for all PON ports.
        """
        i = 0
        while i < self.pon_resource_ranges[PONResourceManager.NUM_OF_PON_PORT]:
            self.init_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ONU_ID,
                start_idx=self.pon_resource_ranges[
                    PONResourceManager.ONU_START_IDX],
                end_idx=self.pon_resource_ranges[
                    PONResourceManager.ONU_END_IDX])

            i += 1

        # TODO: ASFvOLT16 platform requires alloc and gemport ID to be unique
        # across OLT. To keep it simple, a single pool (POOL 0) is maintained
        # for both the resource types. This may need to change later.
        self.init_resource_id_pool(
            pon_intf_id=0,
            resource_type=PONResourceManager.ALLOC_ID,
            start_idx=self.pon_resource_ranges[
                PONResourceManager.ALLOC_ID_START_IDX],
            end_idx=self.pon_resource_ranges[
                PONResourceManager.ALLOC_ID_END_IDX])

        self.init_resource_id_pool(
            pon_intf_id=0,
            resource_type=PONResourceManager.GEMPORT_ID,
            start_idx=self.pon_resource_ranges[
                PONResourceManager.GEM_PORT_ID_START_IDX],
            end_idx=self.pon_resource_ranges[
                PONResourceManager.GEM_PORT_ID_END_IDX])

    def clear_device_resource_pool(self):
        """
        Clear resource pool of all PON ports.
        """
        i = 0
        while i < self.pon_resource_ranges[PONResourceManager.NUM_OF_PON_PORT]:
            self.clear_resource_id_pool(
                pon_intf_id=i,
                resource_type=PONResourceManager.ONU_ID,
            )
            i += 1

        self.clear_resource_id_pool(
            pon_intf_id=0,
            resource_type=PONResourceManager.ALLOC_ID,
        )

        self.clear_resource_id_pool(
            pon_intf_id=0,
            resource_type=PONResourceManager.GEMPORT_ID,
        )

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

        # TODO: ASFvOLT16 platform requires alloc and gemport ID to be unique
        # across OLT. To keep it simple, a single pool (POOL 0) is maintained
        # for both the resource types. This may need to change later.
        # Override the incoming pon_intf_id to PON0
        if resource_type == PONResourceManager.GEMPORT_ID or \
                resource_type == PONResourceManager.ALLOC_ID:
            pon_intf_id = 0

        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            return result

        try:
            resource = self._get_resource(path)
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
        Release alloc/gemport/onu id for given OLT PON interface.

        :param pon_intf_id: OLT PON interface id
        :param resource_type: String to identify type of resource
        :param release_content: required number of ids
        :return boolean: True if all IDs in given release_content released
                         else False
        """
        status = False

        # TODO: ASFvOLT16 platform requires alloc and gemport ID to be unique
        # across OLT. To keep it simple, a single pool (POOL 0) is maintained
        # for both the resource types. This may need to change later.
        # Override the incoming pon_intf_id to PON0
        if resource_type == PONResourceManager.GEMPORT_ID or \
                resource_type == PONResourceManager.ALLOC_ID:
            pon_intf_id = 0

        path = self._get_path(pon_intf_id, resource_type)
        if path is None:
            return status

        try:
            resource = self._get_resource(path)
            if resource is not None and resource_type == \
                    PONResourceManager.ONU_ID:
                self._release_id(resource, release_content)
            elif resource is not None and (
                    resource_type == PONResourceManager.ALLOC_ID or
                    resource_type == PONResourceManager.GEMPORT_ID):
                for content in release_content:
                    self._release_id(resource, content)
            else:
                raise Exception("get-resource-failed")

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
        alloc_id_path = PONResourceManager.ALLOC_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        self._kv_store.remove_from_kv_store(alloc_id_path)

        # remove pon_intf_onu_id tuple to gemport_ids map
        gemport_id_path = PONResourceManager.GEMPORT_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        self._kv_store.remove_from_kv_store(gemport_id_path)

    def get_current_alloc_ids_for_onu(self, pon_intf_onu_id):
        """
        Get currently configured alloc ids for given pon_intf_onu_id

        :param pon_intf_onu_id: reference of PON interface id and onu id
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

    def update_alloc_ids_for_onu(self, pon_intf_onu_id, alloc_ids):
        """
        Update currently configured alloc ids for given pon_intf_onu_id

        :param pon_intf_onu_id: reference of PON interface id and onu id
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
        """
        path = PONResourceManager.GEMPORT_ID_RESOURCE_MAP_PATH.format(
            self.device_id, str(pon_intf_onu_id)
        )
        self._kv_store.update_to_kv_store(
            path, json.dumps(gemport_ids)
        )

    def _get_olt_vendor(self):
        """
        Get olt vendor variant

        :return: type of olt vendor
        """
        olt_vendor = None
        if self.extra_args and len(self.extra_args) > 0:
            parser = OltVendorArgumentParser(add_help=False)
            parser.add_argument('--olt_vendor', '-o', action='store',
                                choices=['default', 'asfvolt16', 'cigolt24'],
                                default='default')
            try:
                args = parser.parse_args(shlex.split(self.extra_args))
                self._log.debug('parsing-extra-arguments', args=args)
                olt_vendor = args.olt_vendor
            except ArgumentError as e:
                self._log.exception('invalid-arguments: {}', e=e)
            except Exception as e:
                self._log.exception('option-parsing-error: {}', e=e)

        return olt_vendor

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
