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
    def __init__(self, gem_id, alloc_id,
                 encryption=False,
                 omci_transport=False,
                 multicast=False,
                 tcont_ref=None,
                 traffic_class=None,
                 name=None,
                 handler=None):
        self.name = name
        self.gem_id = gem_id
        self._alloc_id = alloc_id
        self.tcont_ref = tcont_ref
        self.traffic_class = traffic_class
        self._encryption = encryption
        self._omci_transport = omci_transport
        self.multicast = multicast
        self._handler = handler

        # TODO: Make this a base class and derive OLT and ONU specific classes from it
        #       The primary thing to change is the PON ID is OLT specific and the add/remove
        #       from hardware methods
        self._pon_id = None
        self._onu_id = None
        self._intf_id = None

        # Statistics
        self.rx_packets = 0
        self.rx_bytes = 0
        self.tx_packets = 0
        self.tx_bytes = 0

    def __str__(self):
        return "GemPort: {}, alloc-id: {}, gem-id: {}".format(self.name,
                                                              self.alloc_id,
                                                              self.gem_id)

    @property
    def pon_id(self):
        return self._pon_id

    @pon_id.setter
    def pon_id(self, pon_id):
        assert self._pon_id is None or self._pon_id == pon_id, 'PON-ID can only be set once'
        self._pon_id = pon_id

    @property
    def onu_id(self):
        return self._onu_id

    @onu_id.setter
    def onu_id(self, onu_id):
        assert self._onu_id is None or self._onu_id == onu_id, 'ONU-ID can only be set once'
        self._onu_id = onu_id

    @property
    def intf_id(self):
        return self._intf_id

    @intf_id.setter
    def intf_id(self, intf_id):
        assert self._intf_id is None or self._intf_id == intf_id, 'Port Number can only be set once'
        self._intf_id = intf_id

    @property
    def alloc_id(self):
        if self._alloc_id is None and self._handler is not None:
            try:
                self._alloc_id = self._handler.tconts.get(self.tcont_ref).get('alloc-id')

            except Exception:
                pass

        return self._alloc_id

    @property
    def tcont(self):
        tcont_item = self._handler.tconts.get(self.tcont_ref)
        return tcont_item.get('object') if tcont_item is not None else None

    @property
    def omci_transport(self):
        return self._omci_transport

    def to_dict(self):
        return {
            'port-id': self.gem_id,
            'alloc-id': self.alloc_id,
            'encryption': self._encryption,
            'omci-transport': self.omci_transport
        }
