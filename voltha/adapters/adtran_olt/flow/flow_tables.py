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
#
from flow_entry import FlowEntry
from collections import MutableMapping
from evc import EVC
import six


class _Storage(MutableMapping):
    def __init__(self, *args, **kwargs):
        self._store = dict()   # Key = (str)Flow ID, Value = FlowEntry
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def _keytransform(self, key):
        raise NotImplementedError

    def __getitem__(self, key):
        return self._store[self._keytransform(key)]

    def __setitem__(self, key, flow):
        self._store[self._keytransform(key)] = flow

    def __delitem__(self, key):
        del self._store[self._keytransform(key)]

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)


class DeviceFlows(_Storage):
    """ Tracks existing flows on the device """
    def _keytransform(self, key):
        key = key.flow_id if isinstance(key, FlowEntry) else key
        assert isinstance(key, six.integer_types), "Flow key should be int"
        return key

    def __setitem__(self, key, flow):
        assert isinstance(flow, FlowEntry)
        assert key == flow.flow_id
        return super(DeviceFlows, self).__setitem__(key, flow)

    def add(self, flow):
        """
        Non-standard dict function that adds and returns the added element
        If the element with this key already exists, no state is modified
        :param FlowEntry flow: element to add
        :return: returns the added element
        :rtype: FlowEntry
        """
        assert isinstance(flow, FlowEntry)
        if flow.flow_id not in self:
            self[flow.flow_id] = flow
        return flow

    def remove(self, item):
        """
        Non-standard dict function that removes and returns an element
        :param Union[int, FlowEntry] item: identifier for which element to remove
        :return: flow entry or None
        :rtype: Optional[FlowEntry]
        """
        return self.pop(item, None)


class DownstreamFlows(_Storage):
    """
    Tracks existing flows that are downstream (NNI as source port)

    The downstream table is slightly different than the base DeviceFlows
    table as it is used to track flows that will become EVCs.  The base
    table tracks flows that will be EVC-maps (or related to them).

    The downstream table is also indexed by a downstream signature that
    is composed as follows:

        <dev-id>.<ingress-port-number>.<s-tag>.*

    In comparison, the upstream flows is similar, but instead of '*' it has the
    c-tag (if any).

    TODO: Drop device ID from signatures once flow tables are unique to a device handler
    """
    # Key = (str)Downstream signature
    #  |
    #  +-> downstream-signature
    #      |
    #      +-> 'evc' -> EVC
    #      |
    #      +-> flow-ids -> flow-entries...

    def _keytransform(self, key):
        key = key.signature if isinstance(key, DownstreamFlows.SignatureTableEntry) else key
        assert isinstance(key, six.string_types)
        return key

    def __setitem__(self, key, item):
        assert isinstance(item, DownstreamFlows.SignatureTableEntry)
        assert key == item.signature
        return super(DownstreamFlows, self).__setitem__(key, item)

    def add(self, signature):
        """
        Can be called by upstream flow to reserve a slot
        """
        if signature not in self:
            self[signature] = DownstreamFlows.SignatureTableEntry(signature)
        return self[signature]

    def remove(self, signature):
        """
        Non-standard dict function that removes and returns an element
        :param Union[str] signature: identifier for which element to remove
        :return: Signature Table or None
        :rtype: Optional[DownstreamFlows.SignatureTableEntry]
        """
        return self.pop(signature, None)

    class SignatureTableEntry(object):
        def __init__(self, signature):
            self._signature = signature
            self._evc = None
            self._flow_table = DeviceFlows()

        @property
        def signature(self):
            return self._signature

        @property
        def evc(self):
            return self._evc

        @evc.setter
        def evc(self, evc):
            assert isinstance(evc, EVC) or evc is None
            self._evc = evc

        @property
        def flows(self):
            return self._flow_table
