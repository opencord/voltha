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


class GemPort(object):
    """
    Class to wrap TCont capabilities
    """
    def __init__(self, gem_id, alloc_id, uni_id, tech_profile_id,
                 encryption=False,
                 multicast=False,
                 traffic_class=None,
                 handler=None,
                 is_mock=False):

        self.gem_id = gem_id
        self._alloc_id = alloc_id
        self.uni_id = uni_id
        self.tech_profile_id = tech_profile_id
        self.traffic_class = traffic_class
        self._encryption = encryption
        self.multicast = multicast
        self._handler = handler
        self._is_mock = is_mock
        self.tech_profile_id = None     # TODO: Make property and clean up object once tech profiles fully supported

        # Statistics
        self.rx_packets = 0
        self.rx_bytes = 0
        self.tx_packets = 0
        self.tx_bytes = 0

    def __str__(self):
        return "GemPort: alloc-id: {}, gem-id: {}, uni-id: {}".format(self.alloc_id,
                                                                      self.gem_id,
                                                                      self.uni_id)

    @property
    def alloc_id(self):
        return self._alloc_id

    @property
    def encryption(self):
        return self._encryption

    def to_dict(self):
        return {
            'port-id': self.gem_id,
            'alloc-id': self.alloc_id,
            'encryption': self._encryption,
            'omci-transport': False
        }
