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
from evc import EVC


class DeviceFlows(object):
    """ Tracks existing flows on the device """

    def __init__(self):
        self._flow_table = dict()   # Key = (str)Flow ID, Value = FlowEntry

    def __getitem__(self, item):
        flow_id = item.flow_id if isinstance(item, FlowEntry) else item
        return self._flow_table[flow_id]

    def __iter__(self):
        for _flow_id, _flow in self._flow_table.items():
            yield _flow_id, _flow

    def itervalues(self):
        for _flow in self._flow_table.values():
            yield _flow

    def iterkeys(self):
        for _id in self._flow_table.keys():
            yield _id

    def items(self):
        return self._flow_table.items()

    def values(self):
        return self._flow_table.values()

    def keys(self):
        return self._flow_table.keys()

    def __len__(self):
        return len(self._flow_table)

    def add(self, flow):
        assert isinstance(flow, FlowEntry)
        if flow.flow_id not in self._flow_table:
            self._flow_table[flow.flow_id] = flow
        return flow

    def get(self, item):
        flow_id = item.flow_id if isinstance(item, FlowEntry) else item
        return self._flow_table.get(flow_id)

    def remove(self, item):
        flow_id = item.flow_id if isinstance(item, FlowEntry) else item
        return self._flow_table.pop(flow_id, default=None)

    def clear_all(self):
        self._flow_table = dict()


class DownstreamFlows(object):
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
    def __init__(self):
        self._signature_table = dict()  # Key = (str)Downstream signature
                                        #  |
                                        #  +-> downstream-signature
                                        #      |
                                        #      +-> 'evc' -> EVC
                                        #      |
                                        #      +-> flow-ids -> flow-entries...

    def __getitem__(self, signature):
        assert isinstance(signature, str)
        return self._signature_table[signature]

    def __iter__(self):
        for _flow_id, _flow in self._signature_table.items():
            yield _flow_id, _flow

    def itervalues(self):
        for _flow in self._signature_table.values():
            yield _flow

    def iterkeys(self):
        for _id in self._signature_table.keys():
            yield _id

    def items(self):
        return self._signature_table.items()

    def values(self):
        return self._signature_table.values()

    def keys(self):
        return self._signature_table.keys()

    def __len__(self):
        return len(self._signature_table)

    def get(self, signature):
        assert isinstance(signature, str)
        return self._signature_table.get(signature)

    def add(self, signature):
        assert isinstance(signature, str)
        """
        Can be called by upstream flow to reserve a slot
        """
        if signature not in self._signature_table:
            self._signature_table[signature] = DownstreamFlows.SignatureTableEntry(signature)
        return self._signature_table[signature]

    def remove(self, signature):
        assert isinstance(signature, str)
        return self._signature_table.pop(signature)

    def clear_all(self):
        self._signature_table = dict()

    class SignatureTableEntry(object):
        def __init__(self, signature):
            self._signature = signature
            self._evc = None
            self._flow_table = DeviceFlows()

        @property
        def evc(self):
            return self._evc

        @evc.setter
        def evc(self, evc):
            assert isinstance(evc, (EVC, type(None)))
            self._evc = evc

        @property
        def flows(self):
            return self._flow_table
