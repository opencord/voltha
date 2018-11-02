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

import structlog

from common.pon_resource_manager.resource_manager import PONResourceManager
from voltha.registry import registry
from voltha.core.config.config_backend import ConsulStore
from voltha.core.config.config_backend import EtcdStore
from voltha.adapters.openolt.protos import openolt_pb2

class OpenOltResourceMgr(object):
    GEMPORT_IDS = "gemport_ids"
    ALLOC_IDS = "alloc_ids"
    BASE_PATH_KV_STORE = "openolt/{}" # openolt/<device_id>

    def __init__(self, device_id, host_and_port, extra_args, device_info):
        self.log = structlog.get_logger(id=device_id,
                                        ip=host_and_port)
        self.device_id = device_id
        self.host_and_port = host_and_port
        self.extra_args = extra_args
        self.device_info = device_info
        self.args = registry('main').get_args()

        # KV store's IP Address and PORT
        host, port = '127.0.0.1', 8500
        if self.args.backend == 'etcd':
            host, port = self.args.etcd.split(':', 1)
            self.kv_store = EtcdStore(host, port,
                                      OpenOltResourceMgr.BASE_PATH_KV_STORE.format(device_id))
        elif self.args.backend == 'consul':
            host, port = self.args.consul.split(':', 1)
            self.kv_store = ConsulStore(host, port,
                                        OpenOltResourceMgr.BASE_PATH_KV_STORE.format(device_id))
        else:
            self.log.error('Invalid-backend')
            raise Exception("Invalid-backend-for-kv-store")

        ranges = dict()
        resource_mgrs_by_tech = dict()
        self.resource_mgrs = dict()

        # If a legacy driver returns protobuf without any ranges,s synthesize one from
        # the legacy global per-device informaiton. This, in theory, is temporary until
        # the legacy drivers are upgrade to support pool ranges.
        if len(self.device_info.ranges) == 0:
            arange = self.device_info.ranges.add()
            arange.technology = self.device_info.technology
            arange.intf_ids.extend(range(0, device_info.pon_ports))

            pool = arange.pools.add()
            pool.type = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.ONU_ID
            pool.start = self.device_info.onu_id_start
            pool.end = self.device_info.onu_id_end
            pool.sharing = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.DEDICATED_PER_INTF

            pool = arange.pools.add()
            pool.type = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.ALLOC_ID
            pool.start = self.device_info.alloc_id_start
            pool.end = self.device_info.alloc_id_end
            pool.sharing = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH

            pool = arange.pools.add()
            pool.type = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.GEMPORT_ID
            pool.start = self.device_info.gemport_id_start
            pool.end = self.device_info.gemport_id_end
            pool.sharing = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH

        # Create a separate Resource Manager instance for each range. This assumes that
        # each technology is represented by only a single range
        global_resource_mgr = None
        for arange in self.device_info.ranges:
            technology = arange.technology
            self.log.info("device-info", technology=technology)
            ranges[technology] = arange
            extra_args = self.extra_args + ' ' + PONResourceManager.OLT_MODEL_ARG +  ' {}'.format(self.device_info.model)
            resource_mgr = PONResourceManager(technology,
                extra_args, self.device_id, self.args.backend, host, port)
            resource_mgrs_by_tech[technology] = resource_mgr
            if global_resource_mgr is None: global_resource_mgr = resource_mgr
            for intf_id in arange.intf_ids:
                self.resource_mgrs[intf_id] = resource_mgrs_by_tech[technology]
            self.initialize_device_resource_range_and_pool(resource_mgr, global_resource_mgr, arange)

        # After we have initialized resource ranges, initialize the
        # resource pools accordingly.
        for technology, resource_mgr in resource_mgrs_by_tech.iteritems():
            resource_mgr.init_device_resource_pool()

    def __del__(self):
        self.log.info("clearing-device-resource-pool")
        for key, resource_mgr in self.resource_mgrs.iteritems(): 
            resource_mgr.clear_device_resource_pool()

    def get_onu_id(self, pon_intf_id):
        onu_id = self.resource_mgrs[pon_intf_id].get_resource_id(
            pon_intf_id, PONResourceManager.ONU_ID, 1)

        if onu_id is not None:
            pon_intf_onu_id = (pon_intf_id, onu_id)
            self.resource_mgrs[pon_intf_id].init_resource_map(
                pon_intf_onu_id)

        return onu_id

    def get_alloc_id(self, pon_intf_onu_id):
        # Derive the pon_intf from the pon_intf_onu_id tuple
        pon_intf = pon_intf_onu_id[0]
        alloc_id_list = self.resource_mgrs[pon_intf].get_current_alloc_ids_for_onu(
            pon_intf_onu_id)

        if alloc_id_list and len(alloc_id_list) > 0:
            # Since we support only one alloc_id for the ONU at the moment,
            # return the first alloc_id in the list, if available, for that
            # ONU.
            return alloc_id_list[0]

        alloc_id_list = self.resource_mgrs[pon_intf].get_resource_id(
            pon_intf_id=pon_intf,
            resource_type=PONResourceManager.ALLOC_ID,
            num_of_id=1
        )
        if alloc_id_list and len(alloc_id_list) == 0:
            self.log.error("no-alloc-id-available")
            return None

        # update the resource map on KV store with the list of alloc_id
        # allocated for the pon_intf_onu_id tuple
        self.resource_mgrs[pon_intf].update_alloc_ids_for_onu(pon_intf_onu_id,
                                                   alloc_id_list)

        # Since we request only one alloc id, we refer the 0th
        # index
        alloc_id = alloc_id_list[0]

        return alloc_id

    def get_gemport_id(self, pon_intf_onu_id):
        # Derive the pon_intf and onu_id from the pon_intf_onu_id tuple
        pon_intf = pon_intf_onu_id[0]
        onu_id = pon_intf_onu_id[1]

        gemport_id_list = self.resource_mgrs[pon_intf].get_current_gemport_ids_for_onu(
            pon_intf_onu_id)
        if gemport_id_list and len(gemport_id_list) > 0:
            # Since we support only one gemport_id for the ONU at the moment,
            # return the first gemport_id in the list, if available, for that
            # ONU.
            return gemport_id_list[0]

        gemport_id_list = self.resource_mgrs[pon_intf].get_resource_id(
            pon_intf_id=pon_intf,
            resource_type=PONResourceManager.GEMPORT_ID,
            num_of_id=1
        )

        if gemport_id_list and len(gemport_id_list) == 0:
            self.log.error("no-gemport-id-available")
            return None

        # update the resource map on KV store with the list of gemport_id
        # allocated for the pon_intf_onu_id tuple
        self.resource_mgrs[pon_intf].update_gemport_ids_for_onu(pon_intf_onu_id,
                                                     gemport_id_list)

        # We currently use only one gemport
        gemport = gemport_id_list[0]

        pon_intf_gemport = (pon_intf, gemport)
        # This information is used when packet_indication is received and
        # we need to derive the ONU Id for which the packet arrived based
        # on the pon_intf and gemport available in the packet_indication
        self.kv_store[str(pon_intf_gemport)] = str(onu_id)

        return gemport

    def free_onu_id(self, pon_intf_id, onu_id):
        result = self.resource_mgrs[pon_intf_id].free_resource_id(
            pon_intf_id, PONResourceManager.ONU_ID, onu_id)

        pon_intf_onu_id = (pon_intf_id, onu_id)
        self.resource_mgrs[pon_intf_id].remove_resource_map(
            pon_intf_onu_id)

    def free_pon_resources_for_onu(self, pon_intf_id_onu_id):

        pon_intf_id = pon_intf_id_onu_id[0]
        onu_id = pon_intf_id_onu_id[1]
        alloc_ids = \
            self.resource_mgrs[pon_intf_id].get_current_alloc_ids_for_onu(pon_intf_id_onu_id)
        self.resource_mgrs[pon_intf_id].free_resource_id(pon_intf_id,
                                           PONResourceManager.ALLOC_ID,
                                           alloc_ids)

        gemport_ids = \
            self.resource_mgrs[pon_intf_id].get_current_gemport_ids_for_onu(pon_intf_id_onu_id)
        self.resource_mgrs[pon_intf_id].free_resource_id(pon_intf_id,
                                           PONResourceManager.GEMPORT_ID,
                                           gemport_ids)

        self.resource_mgrs[pon_intf_id].free_resource_id(pon_intf_id,
                                           PONResourceManager.ONU_ID,
                                           onu_id)

        # Clear resource map associated with (pon_intf_id, gemport_id) tuple.
        self.resource_mgrs[pon_intf_id].remove_resource_map(pon_intf_id_onu_id)

        # Clear the ONU Id associated with the (pon_intf_id, gemport_id) tuple.
        for gemport_id in gemport_ids:
            del self.kv_store[str((pon_intf_id, gemport_id))]

    def initialize_device_resource_range_and_pool(self, resource_mgr, global_resource_mgr, arange):
        self.log.info("resource-range-pool-init", technology=resource_mgr.technology)

        # first load from KV profiles
        status = resource_mgr.init_resource_ranges_from_kv_store()
        if not status:
            self.log.info("failed-to-load-resource-range-from-kv-store", technology=resource_mgr.technology)

        # Then apply device specific information. If KV doesn't exist
        # or is broader than the device, the device's informationw ill
        # dictate the range limits
        self.log.info("using-device-info-to-init-pon-resource-ranges", technology=resource_mgr.technology)

        onu_id_start = self.device_info.onu_id_start
        onu_id_end = self.device_info.onu_id_end
        onu_id_shared = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.DEDICATED_PER_INTF
        onu_id_shared_pool_id = None
        alloc_id_start = self.device_info.alloc_id_start
        alloc_id_end = self.device_info.alloc_id_end
        alloc_id_shared = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH # TODO EdgeCore/BAL limitation
        alloc_id_shared_pool_id = None
        gemport_id_start = self.device_info.gemport_id_start
        gemport_id_end = self.device_info.gemport_id_end
        gemport_id_shared = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH # TODO EdgeCore/BAL limitation
        gemport_id_shared_pool_id = None

        global_pool_id = 0
        for first_intf_pool_id in arange.intf_ids: break;

        for pool in arange.pools:
            shared_pool_id = global_pool_id if pool.sharing == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH else \
                   first_intf_pool_id if  pool.sharing == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_SAME_TECH else \
                   None

            if pool.type == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.ONU_ID:
                onu_id_start = pool.start
                onu_id_end = pool.end
                onu_id_shared = pool.sharing
                onu_id_shared_pool_id = shared_pool_id
            elif pool.type == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.ALLOC_ID:
                alloc_id_start = pool.start
                alloc_id_end = pool.end
                alloc_id_shared = pool.sharing
                alloc_id_shared_pool_id = shared_pool_id
            elif pool.type == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.GEMPORT_ID:
                gemport_id_start = pool.start
                gemport_id_end = pool.end
                gemport_id_shared = pool.sharing
                gemport_id_shared_pool_id = shared_pool_id

        self.log.info("device-info-init", technology=arange.technology,
                onu_id_start=onu_id_start, onu_id_end=onu_id_end, onu_id_shared_pool_id=onu_id_shared_pool_id,
                alloc_id_start=alloc_id_start, alloc_id_end=alloc_id_end, alloc_id_shared_pool_id=alloc_id_shared_pool_id,
                gemport_id_start=gemport_id_start, gemport_id_end=gemport_id_end, gemport_id_shared_pool_id=gemport_id_shared_pool_id,
                intf_ids=arange.intf_ids)

        resource_mgr.init_default_pon_resource_ranges(
                onu_id_start_idx=onu_id_start,
                onu_id_end_idx=onu_id_end,
                onu_id_shared_pool_id=onu_id_shared_pool_id,
                alloc_id_start_idx=alloc_id_start,
                alloc_id_end_idx=alloc_id_end,
                alloc_id_shared_pool_id=alloc_id_shared_pool_id,
                gemport_id_start_idx=gemport_id_start,
                gemport_id_end_idx=gemport_id_end,
                gemport_id_shared_pool_id=gemport_id_shared_pool_id,
                num_of_pon_ports=self.device_info.pon_ports,
                intf_ids=arange.intf_ids
            )

        # For global sharing, make sure to refresh both local and global resource manager instances' range
        if global_resource_mgr is not self:
            if onu_id_shared == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH:
                global_resource_mgr.update_ranges(onu_id_start_idx=onu_id_start, onu_id_end_idx=onu_id_end)
                resource_mgr.update_ranges(onu_id_start_idx=onu_id_start, onu_id_end_idx=onu_id_end,
                    onu_id_shared_resource_mgr=global_resource_mgr)

            if alloc_id_shared == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH:
                global_resource_mgr.update_ranges(alloc_id_start_idx=alloc_id_start, alloc_id_end_idx=alloc_id_end)
                resource_mgr.update_ranges(alloc_id_start_idx=alloc_id_start, alloc_id_end_idx=alloc_id_end,
                    alloc_id_shared_resource_mgr=global_resource_mgr)

            if gemport_id_shared == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH:
                global_resource_mgr.update_ranges(gemport_id_start_idx=gemport_id_start, gemport_id_end_idx=gemport_id_end)
                resource_mgr.update_ranges(gemport_id_start_idx=gemport_id_start, gemport_id_end_idx=gemport_id_end,
                    gemport_id_shared_resource_mgr=global_resource_mgr)
