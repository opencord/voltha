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
from adtran_resource_manager import AdtranPONResourceManager


class AdtranOltResourceMgr(object):

    GEMPORT_IDS = "gemport_ids"
    ALLOC_IDS = "alloc_ids"
    BASE_PATH_KV_STORE = "adtran_olt/{}"       # adtran_olt/<device_id>

    def __init__(self, device_id, host_and_port, extra_args, device_info):
        self.log = structlog.get_logger(id=device_id,
                                        ip=host_and_port)
        self.device_id = device_id
        self.host_and_port = host_and_port
        self.extra_args = extra_args
        self.device_info = device_info
        self.args = registry('main').get_args()

        # KV store's IP Address and PORT
        # host, port = '127.0.0.1', 8500
        if self.args.backend == 'etcd':
            host, port = self.args.etcd.split(':', 1)
            self.kv_store = EtcdStore(host, port,
                                      AdtranOltResourceMgr.BASE_PATH_KV_STORE.format(device_id))
        elif self.args.backend == 'consul':
            host, port = self.args.consul.split(':', 1)
            self.kv_store = ConsulStore(host, port,
                                        AdtranOltResourceMgr.BASE_PATH_KV_STORE.format(device_id))
        else:
            self.log.error('Invalid-backend')
            raise Exception("Invalid-backend-for-kv-store")

        self.resource_mgr = AdtranPONResourceManager(
            self.device_info.technology,
            self.extra_args,
            self.device_id, self.args.backend,
            host, port
        )
        # Flag to indicate whether information fetched from device should
        # be used to initialize PON Resource Ranges
        self.use_device_info = False

        self.initialize_device_resource_range_and_pool()

    def __del__(self):
        self.log.info("clearing-device-resource-pool")
        self.resource_mgr.clear_device_resource_pool()

    def get_onu_id(self, pon_intf_id):
        onu_id = self.resource_mgr.get_resource_id(pon_intf_id,
                                                   PONResourceManager.ONU_ID,
                                                   1)
        if onu_id is not None:
            pon_intf_onu_id = (pon_intf_id, onu_id)
            self.resource_mgr.init_resource_map(pon_intf_onu_id)

        return onu_id

    def free_onu_id(self, pon_intf_id, onu_id):
        self.resource_mgr.free_resource_id(pon_intf_id,
                                           PONResourceManager.ONU_ID,
                                           onu_id)
        pon_intf_onu_id = (pon_intf_id, onu_id)
        self.resource_mgr.remove_resource_map(pon_intf_onu_id)

    def get_alloc_id(self, pon_intf_onu_id):
        # Derive the pon_intf from the pon_intf_onu_id tuple
        pon_intf = pon_intf_onu_id[0]
        onu_id = pon_intf_onu_id[1]
        alloc_id_list = self.resource_mgr.get_current_alloc_ids_for_onu(pon_intf_onu_id)

        if alloc_id_list and len(alloc_id_list) > 0:
            # Since we support only one alloc_id for the ONU at the moment,
            # return the first alloc_id in the list, if available, for that
            # ONU.
            return alloc_id_list[0]

        alloc_id_list = self.resource_mgr.get_resource_id(
            pon_intf_id=pon_intf,
            onu_id=onu_id,
            resource_type=PONResourceManager.ALLOC_ID,
            num_of_id=1
        )
        if alloc_id_list and len(alloc_id_list) == 0:
            self.log.error("no-alloc-id-available")
            return None

        # update the resource map on KV store with the list of alloc_id
        # allocated for the pon_intf_onu_id tuple
        self.resource_mgr.update_alloc_ids_for_onu(pon_intf_onu_id,
                                                   alloc_id_list)

        # Since we request only one alloc id, we refer the 0th
        # index
        alloc_id = alloc_id_list[0]

        return alloc_id

    def get_gemport_id(self, pon_intf_onu_id):
        # Derive the pon_intf and onu_id from the pon_intf_onu_id tuple
        pon_intf = pon_intf_onu_id[0]
        onu_id = pon_intf_onu_id[1]

        gemport_id_list = self.resource_mgr.get_current_gemport_ids_for_onu(
            pon_intf_onu_id)

        if gemport_id_list and len(gemport_id_list) > 0:
            # Since we support only one gemport_id for the ONU at the moment,
            # return the first gemport_id in the list, if available, for that
            # ONU.
            return gemport_id_list[0]

        gemport_id_list = self.resource_mgr.get_resource_id(
            pon_intf_id=pon_intf,
            resource_type=PONResourceManager.GEMPORT_ID,
            num_of_id=1
        )
        if gemport_id_list is None or len(gemport_id_list) == 0:
            self.log.error("no-gemport-id-available")
            return None

        # update the resource map on KV store with the list of gemport_id
        # allocated for the pon_intf_onu_id tuple
        self.resource_mgr.update_gemport_ids_for_onu(pon_intf_onu_id,
                                                     gemport_id_list)
        # We currently use only one gemport
        gemport = gemport_id_list[0]

        pon_intf_gemport = (pon_intf, gemport)

        # This information is used when packet_indication is received and
        # we need to derive the ONU Id for which the packet arrived based
        # on the pon_intf and gemport available in the packet_indication
        self.kv_store[str(pon_intf_gemport)] = str(onu_id)
        return gemport

    def free_pon_resources_for_onu(self, pon_intf_id_onu_id):
        """ Typically called on ONU delete """

        pon_intf_id = pon_intf_id_onu_id[0]
        onu_id = pon_intf_id_onu_id[1]
        try:
            alloc_ids = self.resource_mgr.get_current_alloc_ids_for_onu(pon_intf_id_onu_id)
            if alloc_ids is not None:
                self.resource_mgr.free_resource_id(pon_intf_id,
                                                   PONResourceManager.ALLOC_ID,
                                                   alloc_ids, onu_id=onu_id)
        except:
            pass

        try:
            gemport_ids = self.resource_mgr.get_current_gemport_ids_for_onu(pon_intf_id_onu_id)
            if gemport_ids is not None:
                self.resource_mgr.free_resource_id(pon_intf_id,
                                                   PONResourceManager.GEMPORT_ID,
                                                   gemport_ids)
        except:
            pass

        try:
            self.resource_mgr.free_resource_id(pon_intf_id,
                                               PONResourceManager.ONU_ID,
                                               onu_id)
        except:
            pass

        # Clear resource map associated with (pon_intf_id, gemport_id) tuple.
        self.resource_mgr.remove_resource_map(pon_intf_id_onu_id)

        # Clear the ONU Id associated with the (pon_intf_id, gemport_id) tuple.
        if gemport_ids is not None:
            for gemport_id in gemport_ids:
                try:
                    del self.kv_store[str((pon_intf_id, gemport_id))]
                except:
                    pass

    def initialize_device_resource_range_and_pool(self):
        if not self.use_device_info:
            status = self.resource_mgr.init_resource_ranges_from_kv_store()
            if not status:
                self.log.error("failed-to-load-resource-range-from-kv-store")
                # When we have failed to read the PON Resource ranges from KV
                # store, use the information selected as the default.
                self.use_device_info = True

        if self.use_device_info:
            self.log.info("using-device-info-to-init-pon-resource-ranges")
            self.resource_mgr.init_default_pon_resource_ranges(
                onu_id_start_idx=self.device_info.onu_id_start,
                onu_id_end_idx=self.device_info.onu_id_end,
                alloc_id_start_idx=self.device_info.alloc_id_start,
                alloc_id_end_idx=self.device_info.alloc_id_end,
                gemport_id_start_idx=self.device_info.gemport_id_start,
                gemport_id_end_idx=self.device_info.gemport_id_end,
                num_of_pon_ports=self.device_info.pon_ports,
                intf_ids=self.device_info.intf_ids
            )

        # After we have initialized resource ranges, initialize the
        # resource pools accordingly.
        self.resource_mgr.init_device_resource_pool()
