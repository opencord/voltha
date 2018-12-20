# Copyright 2017-present Adtran, Inc.
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


class TCont(object):
    """
    Class to wrap TCont capabilities
    """
    def __init__(self, alloc_id, tech_profile_id, traffic_descriptor, uni_id, is_mock=False):
        self.alloc_id = alloc_id
        self.traffic_descriptor = traffic_descriptor
        self._is_mock = is_mock
        self.tech_profile_id = tech_profile_id
        self.uni_id = uni_id

    def __str__(self):
        return "TCont: alloc-id: {}, uni-id: {}".format(self.alloc_id,
                                                        self.uni_id)
