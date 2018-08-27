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

from common.pon_resource_manager.resource_manager import PONResourceManager


# Class defines ASFvOLT16 device specific resource ranges.
class Asfvolt16ResourceManager(PONResourceManager):

    ONU_ID_START_IDX = 1
    ONU_ID_END_IDX = 127

    GEMPORT_START_IDX = 1024
    GEMPORT_END_IDX = 65534

    ALLOCID_START_IDX = 1024
    ALLOCID_END_IDX = 16383

    def __init__(self, technology, device_id, backend, ip_addr, port):
        super(Asfvolt16ResourceManager, self).__init__(
            technology, device_id, backend, ip_addr, port
        )

    def init_pon_resource_pool(self, pon_intf_id, resource_type):
        status = False
        if resource_type == PONResourceManager.ONU_ID:
            super(Asfvolt16ResourceManager, self).init_resource_id_pool(
                pon_intf_id=pon_intf_id,
                resource_type=resource_type,
                start_idx=Asfvolt16ResourceManager.ONU_ID_START_IDX,
                end_idx=Asfvolt16ResourceManager.ONU_ID_END_IDX
            )
        elif resource_type == PONResourceManager.ALLOC_ID:
            super(Asfvolt16ResourceManager, self).init_resource_id_pool(
                pon_intf_id=pon_intf_id,
                resource_type=resource_type,
                start_idx=Asfvolt16ResourceManager.ALLOCID_START_IDX,
                end_idx=Asfvolt16ResourceManager.ALLOCID_END_IDX
            )
        elif resource_type == PONResourceManager.GEMPORT_ID:
            super(Asfvolt16ResourceManager, self).init_resource_id_pool(
                pon_intf_id=pon_intf_id,
                resource_type=resource_type,
                start_idx=Asfvolt16ResourceManager.GEMPORT_START_IDX,
                end_idx=Asfvolt16ResourceManager.GEMPORT_END_IDX
            )
        else:
            self._log.error("invalid-resource-pool-identifier")
            return status
