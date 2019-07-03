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
from voltha.adapters.openolt.openolt_flow_mgr import *

from voltha.adapters.openolt.protos import openolt_pb2
from voltha.adapters.openolt.openolt_platform import OpenOltPlatform


class OpenOltResourceMgr(object):
    BASE_PATH_KV_STORE = "service/voltha/openolt/{}"  # service/voltha/openolt/<device_id>
    TP_ID_PATH_SUFFIX = 'tp_id/{}'  # tp_id/<(pon_id, onu_id, uni_id)>
    METER_ID_PATH_SUFFIX = 'meter_id/{}/{}'  # meter_id/<(pon_id, onu_id, uni_id)>/<direction>

    def __init__(self, device_id, host_and_port, extra_args, device_info):
        self.log = structlog.get_logger(id=device_id,
                                        ip=host_and_port)
        self.device_id = device_id
        self.host_and_port = host_and_port
        self.extra_args = extra_args
        self.device_info = device_info
        self.args = registry('main').get_args()

        # KV store's IP Address and PORT
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

            pool = arange.pools.add()
            pool.type = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.FLOW_ID
            pool.start = self.device_info.flow_id_start
            pool.end = self.device_info.flow_id_end
            pool.sharing = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH

        # Create a separate Resource Manager instance for each range. This assumes that
        # each technology is represented by only a single range
        global_resource_mgr = None
        for arange in self.device_info.ranges:
            technology = arange.technology
            self.log.info("device-info", technology=technology)
            ranges[technology] = arange
            extra_args = self.extra_args + ' ' + PONResourceManager.OLT_MODEL_ARG + ' {}'.format(self.device_info.model)
            resource_mgr = PONResourceManager(technology,
                                              extra_args, self.device_id, self.args.backend, host, port)
            resource_mgrs_by_tech[technology] = resource_mgr
            if global_resource_mgr is None:
                global_resource_mgr = resource_mgr
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

    def assert_pon_id_limit(self, pon_intf_id):
        assert pon_intf_id in self.resource_mgrs

    def assert_onu_id_limit(self, pon_intf_id, onu_id):
        self.assert_pon_id_limit(pon_intf_id)
        self.resource_mgrs[pon_intf_id].assert_resource_limits(onu_id, PONResourceManager.ONU_ID)

    @property
    def max_uni_id_per_onu(self):
        return 0  # OpenOltPlatform.MAX_UNIS_PER_ONU-1, zero-based indexing Uncomment or override to make default multi-uni

    def assert_uni_id_limit(self, pon_intf_id, onu_id, uni_id):
        self.assert_onu_id_limit(pon_intf_id, onu_id)
        self.resource_mgrs[pon_intf_id].assert_resource_limits(uni_id, PONResourceManager.UNI_ID)

    def get_onu_id(self, pon_intf_id):
        onu_id = self.resource_mgrs[pon_intf_id].get_resource_id(
            pon_intf_id, PONResourceManager.ONU_ID, 1)

        return onu_id

    def get_flow_id(self, pon_intf_id, onu_id, uni_id, **kwargs):
        pon_intf_onu_id = (pon_intf_id, onu_id, uni_id)
        flow_store_cookie = kwargs.pop('flow_cookie', None)
        flow_category = kwargs.pop('flow_category', None)
        flow_pcp = kwargs.pop('flow_pcp', None)
        try:
            flow_ids = self.resource_mgrs[pon_intf_id]. \
                get_current_flow_ids_for_onu(pon_intf_onu_id)
            if flow_ids is not None:
                for flow_id in flow_ids:
                    try:
                        flows = self.get_flow_id_info(
                            pon_intf_id, onu_id, uni_id, flow_id
                        )
                        assert (isinstance(flows, list))
                        for flow in flows:
                            # If a flow_cookie is provided, we need no other match
                            # criteria to find the relevant flow_id.
                            # Return the first matched flow for the given flow_store_cookie
                            if flow_store_cookie is not None and \
                                    flow_store_cookie == flow['flow_store_cookie']:
                                return flow_id
                            # If flow_category is specified as match criteria, we need the
                            # the vlan pcp for the flow as well. This is because the given
                            # flow_category (for ex: HSIA) could cater to more than one vlan pcp.
                            # Each, flow matches uniquely matches one vlan pcp.
                            # So, to find the exact flow_id we need the vlan pcp too.
                            if flow_category is not None:
                                assert flow_pcp is not None
                                if 'flow_category' in flow and \
                                    flow['flow_category'] == flow_category:
                                    if 'o_pbits' in flow['classifier'] and \
                                        flow['classifier']['o_pbits'] == flow_pcp:
                                        return flow_id
                                    elif flow_pcp == 0 and \
                                        'o_pbits' not in flow['classifier']:
                                        return flow_id
                    except KeyError as e:
                        self.log.error("key-error-retrieving-flow-info",
                                       e=e, flow_id=flow_id)
        except Exception as e:
            self.log.error("error-retrieving-flow-info", e=e)

        # We could not find any existing flow_id for the given match criteria.
        # Generate a new flow id.
        flow_id = self.resource_mgrs[pon_intf_id].get_resource_id(
            pon_intf_onu_id[0], PONResourceManager.FLOW_ID)
        if flow_id is not None:
            self.resource_mgrs[pon_intf_id].update_flow_id_for_onu(
                pon_intf_onu_id, flow_id
            )
        return flow_id

    def get_flow_id_info(self, intf_id, onu_id, uni_id, flow_id):
        '''
        Note: For flows which trap from the NNI and not really associated with any particular
        ONU (like LLDP), the onu_id and uni_id is set as -1. The intf_id is the NNI intf_id.
        '''
        intf_onu_id = (intf_id, onu_id, uni_id)
        return self.resource_mgrs[intf_id].get_flow_id_info(intf_onu_id, flow_id)

    def get_current_flow_ids(self, intf_id, onu_id, uni_id):
        '''
        Note: For flows which trap from the NNI and not really associated with any particular
        ONU (like LLDP), the onu_id and uni_id is set as -1. The intf_id is the NNI intf_id.
        '''
        intf_onu_id = (intf_id, onu_id, uni_id)
        return self.resource_mgrs[intf_id].get_current_flow_ids_for_onu(intf_onu_id)

    def update_flow_id_info(self, intf_id, onu_id, uni_id, flow_id, flow_data):
        '''
        Note: For flows which trap from the NNI and not really associated with any particular
        ONU (like LLDP), the onu_id and uni_id is set as -1. The intf_id is the NNI intf_id.
        '''
        intf_onu_id = (intf_id, onu_id, uni_id)
        return self.resource_mgrs[intf_id].update_flow_id_info_for_onu(
            intf_onu_id, flow_id, flow_data)

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

        alloc_id = self.resource_mgrs[pon_intf].get_resource_id(
            pon_intf_id=pon_intf,
            resource_type=PONResourceManager.ALLOC_ID,
            num_of_id=1
        )
        if alloc_id is None:
            self.log.error("no-alloc-id-available")
            return None

        # update the resource map on KV store with the list of alloc_id
        # allocated for the pon_intf_onu_id tuple
        self.resource_mgrs[pon_intf].update_alloc_ids_for_onu(pon_intf_onu_id,
                                                              list(alloc_id))

        return alloc_id

    def get_current_gemport_ids_for_onu(self, pon_intf_onu_id):
        pon_intf_id = pon_intf_onu_id[0]
        return self.resource_mgrs[pon_intf_id].get_current_gemport_ids_for_onu(pon_intf_onu_id)

    def get_current_alloc_ids_for_onu(self, pon_intf_onu_id):
        pon_intf_id = pon_intf_onu_id[0]
        alloc_ids = self.resource_mgrs[pon_intf_id].get_current_alloc_ids_for_onu(pon_intf_onu_id)
        if alloc_ids is None:
            return None
        # We support only one tcont at the moment
        return alloc_ids[0]

    def update_gemports_ponport_to_onu_map_on_kv_store(self, gemport_list, pon_port, onu_id, uni_id):
        for gemport in gemport_list:
            pon_intf_gemport = (pon_port, gemport)
            # This information is used when packet_indication is received and
            # we need to derive the ONU Id for which the packet arrived based
            # on the pon_intf and gemport available in the packet_indication
            self.kv_store[str(pon_intf_gemport)] = ' '.join(map(str, (onu_id, uni_id)))

    def get_onu_uni_from_ponport_gemport(self, pon_port, gemport):
        pon_intf_gemport = (pon_port, gemport)
        return tuple(map(int, self.kv_store[str(pon_intf_gemport)].split(' ')))

    def get_gemport_id(self, pon_intf_onu_id, num_of_id=1):
        # Derive the pon_intf and onu_id from the pon_intf_onu_id tuple
        pon_intf = pon_intf_onu_id[0]
        onu_id = pon_intf_onu_id[1]
        uni_id = pon_intf_onu_id[2]
        assert False, 'unused function'

        gemport_id_list = self.resource_mgrs[pon_intf].get_current_gemport_ids_for_onu(
            pon_intf_onu_id)
        if gemport_id_list and len(gemport_id_list) > 0:
            return gemport_id_list

        gemport_id_list = self.resource_mgrs[pon_intf].get_resource_id(
            pon_intf_id=pon_intf,
            resource_type=PONResourceManager.GEMPORT_ID,
            num_of_id=num_of_id
        )

        if gemport_id_list and len(gemport_id_list) == 0:
            self.log.error("no-gemport-id-available")
            return None

        # update the resource map on KV store with the list of gemport_id
        # allocated for the pon_intf_onu_id tuple
        self.resource_mgrs[pon_intf].update_gemport_ids_for_onu(pon_intf_onu_id,
                                                                gemport_id_list)

        self.update_gemports_ponport_to_onu_map_on_kv_store(gemport_id_list,
                                                            pon_intf, onu_id, uni_id)
        return gemport_id_list

    def free_onu_id(self, pon_intf_id, onu_id):
        _ = self.resource_mgrs[pon_intf_id].free_resource_id(
            pon_intf_id, PONResourceManager.ONU_ID, onu_id)

        pon_intf_onu_id = (pon_intf_id, onu_id)
        self.resource_mgrs[pon_intf_id].remove_resource_map(
            pon_intf_onu_id)

    def free_flow_id(self, intf_id, onu_id, uni_id, flow_id):
        self.resource_mgrs[intf_id].free_resource_id(
            intf_id, PONResourceManager.FLOW_ID, flow_id)
        intf_onu_id = (intf_id, onu_id, uni_id)
        self.resource_mgrs[intf_id].update_flow_id_for_onu(intf_onu_id,
                                                           flow_id, False)
        self.resource_mgrs[intf_id].remove_flow_id_info(intf_onu_id,
                                                        flow_id)

    def free_pon_resources_for_onu(self, pon_intf_id_onu_id, reset_onu_id_pool=True):

        pon_intf_id = pon_intf_id_onu_id[0]
        onu_id = pon_intf_id_onu_id[1]
        uni_id = pon_intf_id_onu_id[2]
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

        flow_ids = \
            self.resource_mgrs[pon_intf_id].get_current_flow_ids_for_onu(pon_intf_id_onu_id)
        self.resource_mgrs[pon_intf_id].free_resource_id(pon_intf_id,
                                                         PONResourceManager.FLOW_ID,
                                                         flow_ids)
        if flow_ids:
            for flow_id in flow_ids:
                self.free_flow_id(pon_intf_id, onu_id, uni_id, flow_id)

        if reset_onu_id_pool:
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
        alloc_id_shared = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH  # TODO EdgeCore/BAL limitation
        alloc_id_shared_pool_id = None
        gemport_id_start = self.device_info.gemport_id_start
        gemport_id_end = self.device_info.gemport_id_end
        gemport_id_shared = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH  # TODO EdgeCore/BAL limitation
        gemport_id_shared_pool_id = None
        flow_id_start = self.device_info.flow_id_start
        flow_id_end = self.device_info.flow_id_end
        flow_id_shared = openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH  # TODO EdgeCore/BAL limitation
        flow_id_shared_pool_id = None

        global_pool_id = 0
        for first_intf_pool_id in arange.intf_ids:
            break

        for pool in arange.pools:
            shared_pool_id = global_pool_id if pool.sharing == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH else \
                first_intf_pool_id if pool.sharing == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_SAME_TECH else \
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
            elif pool.type == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.FLOW_ID:
                flow_id_start = pool.start
                flow_id_end = pool.end
                flow_id_shared = pool.sharing
                flow_id_shared_pool_id = shared_pool_id

        self.log.info("device-info-init", technology=arange.technology,
                      onu_id_start=onu_id_start, onu_id_end=onu_id_end, onu_id_shared_pool_id=onu_id_shared_pool_id,
                      alloc_id_start=alloc_id_start, alloc_id_end=alloc_id_end,
                      alloc_id_shared_pool_id=alloc_id_shared_pool_id,
                      gemport_id_start=gemport_id_start, gemport_id_end=gemport_id_end,
                      gemport_id_shared_pool_id=gemport_id_shared_pool_id,
                      flow_id_start_idx=flow_id_start,
                      flow_id_end_idx=flow_id_end,
                      flow_id_shared_pool_id=flow_id_shared_pool_id,
                      intf_ids=arange.intf_ids,
                      uni_id_start_idx=0,
                      uni_id_end_idx=self.max_uni_id_per_onu)

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
            flow_id_start_idx=flow_id_start,
            flow_id_end_idx=flow_id_end,
            flow_id_shared_pool_id=flow_id_shared_pool_id,
            uni_id_start_idx=0, uni_id_end_idx=self.max_uni_id_per_onu,
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
                global_resource_mgr.update_ranges(gemport_id_start_idx=gemport_id_start,
                                                  gemport_id_end_idx=gemport_id_end)
                resource_mgr.update_ranges(gemport_id_start_idx=gemport_id_start, gemport_id_end_idx=gemport_id_end,
                                           gemport_id_shared_resource_mgr=global_resource_mgr)

            if flow_id_shared == openolt_pb2.DeviceInfo.DeviceResourceRanges.Pool.SHARED_BY_ALL_INTF_ALL_TECH:
                global_resource_mgr.update_ranges(flow_id_start_idx=flow_id_start,
                                                  flow_id_end_idx=flow_id_end)
                resource_mgr.update_ranges(flow_id_start_idx=flow_id_start, flow_id_end_idx=flow_id_end,
                                           flow_id_shared_resource_mgr=global_resource_mgr)

        # Make sure loaded range fits the platform bit encoding ranges
        resource_mgr.update_ranges(uni_id_start_idx=0, uni_id_end_idx=OpenOltPlatform.MAX_UNIS_PER_ONU - 1)

    def is_flow_cookie_on_kv_store(self, intf_id, onu_id, uni_id, flow_store_cookie):
        '''
        Note: For flows which trap from the NNI and not really associated with any particular
        ONU (like LLDP), the onu_id and uni_id is set as -1. The intf_id is the NNI intf_id.
        '''
        intf_onu_id = (intf_id, onu_id, uni_id)
        try:
            flow_ids = self.resource_mgrs[intf_id]. \
                get_current_flow_ids_for_onu(intf_onu_id)
            if flow_ids is not None:
                for flow_id in flow_ids:
                    flows = self.get_flow_id_info(intf_id, onu_id, uni_id, flow_id)
                    assert (isinstance(flows, list))
                    for flow in flows:
                        if flow['flow_store_cookie'] == flow_store_cookie:
                            return True
        except Exception as e:
            self.log.error("error-retrieving-flow-info", e=e)

        return False

    def update_tech_profile_id_for_onu(self, intf_id, onu_id, uni_id, tp_id):
        intf_id_onu_id_uni_id = (intf_id, onu_id, uni_id)
        kv_path = OpenOltResourceMgr.TP_ID_PATH_SUFFIX.format(str(intf_id_onu_id_uni_id))
        self.kv_store[kv_path] = str(tp_id)

    def get_tech_profile_id_for_onu(self, intf_id, onu_id, uni_id):
        intf_id_onu_id_uni_id = (intf_id, onu_id, uni_id)
        try:
            kv_path = OpenOltResourceMgr.TP_ID_PATH_SUFFIX.format(str(intf_id_onu_id_uni_id))
            return int(self.kv_store[kv_path])
        except Exception as e:
            self.log.warn("tp-id-not-found-on-kv-store", e=e)
            return None

    def remove_tech_profile_id_for_onu(self, intf_id, onu_id, uni_id):
        intf_id_onu_id_uni_id = (intf_id, onu_id, uni_id)
        kv_path = OpenOltResourceMgr.TP_ID_PATH_SUFFIX.format(str(intf_id_onu_id_uni_id))
        try:
            del self.kv_store[kv_path]
        except Exception as e:
            self.log.error("error-deleting-tech-profile-id", e=e)

    def update_meter_id_for_onu(self, direction, intf_id, onu_id, uni_id, meter_id):
        intf_id_onu_id_uni_id = (intf_id, onu_id, uni_id)
        kv_path = OpenOltResourceMgr.METER_ID_PATH_SUFFIX.format(str(intf_id_onu_id_uni_id),
                                                                 direction)
        self.kv_store[kv_path] = str(meter_id)
        self.log.debug("updated-meter-id-for-onu", path=kv_path, meter_id=meter_id)

    def get_meter_id_for_onu(self, direction, intf_id, onu_id, uni_id):
        intf_id_onu_id_uni_id = (intf_id, onu_id, uni_id)
        try:
            kv_path = OpenOltResourceMgr.METER_ID_PATH_SUFFIX.format(str(intf_id_onu_id_uni_id),
                                                                     direction)
            return int(self.kv_store[kv_path])
        except Exception as e:
            self.log.debug("meter-id-not-found-on-kv-store", e=e)
            return None

    def remove_meter_id_for_onu(self, direction, intf_id, onu_id, uni_id):
        intf_id_onu_id_uni_id = (intf_id, onu_id, uni_id)
        try:
            kv_path = OpenOltResourceMgr.METER_ID_PATH_SUFFIX.format(str(intf_id_onu_id_uni_id),
                                                                     direction)
            del self.kv_store[kv_path]
            self.log.debug("removed-meter-id-for-onu", path=kv_path)
        except Exception as e:
            self.log.debug("error-removing-meter", e=e)
