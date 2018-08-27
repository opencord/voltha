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

from common.pon_resource_manager.resource_manager import DefaultPONResourceRanges


# Class defines ASFvOLT16 device specific resource ranges.
class Asfvolt16PONResourceRanges(DefaultPONResourceRanges):
    def __init__(self):
        super(Asfvolt16PONResourceRanges, self).__init__()
        self.onu_start_idx = 1
        self.onu_end_idx = 127

        self.alloc_id_start_idx = 1024
        self.alloc_id_end_idx = 65534

        self.gem_port_id_start_idx = 1024
        self.gem_port_end_idx = 16383

        self.num_of_pon_port = 16
