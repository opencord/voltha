# Copyright 2017-present Open Networking Foundation
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

import structlog

log = structlog.get_logger()


class GemPort(object):
    """
    Class to wrap TCont capabilities
    """
    def __init__(self, gem_id, alloc_id,
                 encryption=False,
                 omci_transport=False,
                 multicast=False,
                 exception=False,        # TODO: Debug only, remove in production
                 name=None):
        self.name = name
        self.gem_id = gem_id
        self.alloc_id = alloc_id
        self.encryption = encryption
        self.omci_transport = omci_transport
        self.multicast = multicast
        self.exception = exception

    def __str__(self):
        return "GemPort: {}, alloc-id: {}, gem-id: {}".format(self.name,
                                                              self.alloc_id,
                                                              self.gem_id)

    def to_dict(self):
        return {
            'port-id': self.gem_id,
            'alloc-id': self.alloc_id,
            'encryption': self.encryption,
            'omci-transport': self.omci_transport
        }
