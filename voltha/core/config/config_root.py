#
# Copyright 2016 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from uuid import uuid4

import structlog

from voltha.core.config.config_node import ConfigNode, MergeConflictException

log = structlog.get_logger()


class ConfigRoot(ConfigNode):

    __slots__ = (
        '_dirty_nodes',  # holds set of modified nodes per transaction branch
    )

    def __init__(self, initial_data):
        super(ConfigRoot, self).__init__(initial_data, False)
        self._dirty_nodes = {}

    def mk_txbranch(self):
        txid = uuid4().hex[:12]
        self._dirty_nodes[txid] = {self}
        self._mk_txbranch(txid)
        return txid

    def del_txbranch(self, txid):
        for dirty_node in self._dirty_nodes[txid]:
            dirty_node._del_txbranch(txid)
        del self._dirty_nodes[txid]

    def fold_txbranch(self, txid):
        try:
            self._merge_txbranch(txid, dry_run=1)
        except MergeConflictException:
            self.del_txbranch(txid)
            raise

        self._merge_txbranch(txid)

    # ~~~~~~ Overridden, root-level CRUD methods to handle transactions ~~~~~~~

    def update(self, path, data, strict=None, txid=None, mk_branch=None):
        assert mk_branch is None
        if txid is not None:
            dirtied = self._dirty_nodes[txid]

            def track_dirty(node):
                dirtied.add(node)
                return node._mk_txbranch(txid)

            return super(ConfigRoot, self).update(path, data, strict,
                                                      txid, track_dirty)
        else:
            return super(ConfigRoot, self).update(path, data, strict)

    def add(self, path, data, txid=None, mk_branch=None):
        assert mk_branch is None
        if txid is not None:
            dirtied = self._dirty_nodes[txid]

            def track_dirty(node):
                dirtied.add(node)
                return node._mk_txbranch(txid)

            return super(ConfigRoot, self).add(path, data, txid, track_dirty)
        else:
            return super(ConfigRoot, self).add(path, data)

    def remove(self, path, txid=None, mk_branch=None):
        assert mk_branch is None
        if txid is not None:
            dirtied = self._dirty_nodes[txid]

            def track_dirty(node):
                dirtied.add(node)
                return node._mk_txbranch(txid)

            return super(ConfigRoot, self).remove(path, txid, track_dirty)
        else:
            return super(ConfigRoot, self).remove(path)

