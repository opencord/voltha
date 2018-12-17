# Copyright 2018-present Tellabs, Inc.
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

from voltha.adapters.openolt.openolt import OpenOltResourceMgr, OpenOltPlatform

class TellabsResourceManager(OpenOltResourceMgr):

    def __init__(self, device_id, host_and_port, extra_args, device_info):
        super(TellabsResourceManager, self).__init__(device_id, host_and_port, extra_args, device_info)

    @property
    def max_uni_id_per_onu(self):
        return 3 # OpenOltPlatform.MAX_UNIS_PER_ONU-1