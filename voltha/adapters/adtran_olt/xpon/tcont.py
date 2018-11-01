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
    def __init__(self, alloc_id, traffic_descriptor, name=None):
        self.alloc_id = alloc_id
        self.traffic_descriptor = traffic_descriptor
        self.name = name

        # TODO: Make this a base class and derive OLT and ONU specific classes from it
        #       The primary thing difference is the add/remove from hardware methods

    def __str__(self):
        return "TCont: {}, alloc-id: {}".format(self.name, self.alloc_id)
