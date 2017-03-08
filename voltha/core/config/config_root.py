#
# Copyright 2017 the original author or authors.
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
from simplejson import dumps, loads

from voltha.core.config.config_node import ConfigNode
from voltha.core.config.config_rev import ConfigRevision
from voltha.core.config.config_rev_persisted import PersistedConfigRevision
from voltha.core.config.merge_3way import MergeConflictException

log = structlog.get_logger()


class ConfigRoot(ConfigNode):

    __slots__ = (
        '_dirty_nodes',  # holds set of modified nodes per transaction branch
        '_kv_store',
        '_loading',
        '_rev_cls',
        '_deferred_callback_queue',
        '_notification_deferred_callback_queue'
    )

    def __init__(self, initial_data, kv_store=None, rev_cls=ConfigRevision):
        self._kv_store = kv_store
        self._dirty_nodes = {}
        self._loading = False
        if kv_store is not None and \
                not issubclass(rev_cls, PersistedConfigRevision):
            rev_cls = PersistedConfigRevision
        self._rev_cls = rev_cls
        self._deferred_callback_queue = []
        self._notification_deferred_callback_queue = []
        super(ConfigRoot, self).__init__(self, initial_data, False)

    @property
    def kv_store(self):
        if self._loading:
            # provide fake store for storing things
            # TODO this shall be a fake_dict providing noop for all relevant
            # operations
            return dict()
        else:
            return self._kv_store

    def mkrev(self, *args, **kw):
        return self._rev_cls(*args, **kw)

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

        try:
            self._merge_txbranch(txid)
        finally:
            self.execute_deferred_callbacks()

    # ~~~~~~ Overridden, root-level CRUD methods to handle transactions ~~~~~~~

    def update(self, path, data, strict=None, txid=None, mk_branch=None):
        assert mk_branch is None
        self.check_callback_queue()
        try:
            if txid is not None:
                dirtied = self._dirty_nodes[txid]

                def track_dirty(node):
                    dirtied.add(node)
                    return node._mk_txbranch(txid)

                res = super(ConfigRoot, self).update(path, data, strict,
                                                          txid, track_dirty)
            else:
                res = super(ConfigRoot, self).update(path, data, strict)
        finally:
            self.execute_deferred_callbacks()
        return res

    def add(self, path, data, txid=None, mk_branch=None):
        assert mk_branch is None
        self.check_callback_queue()
        try:
            if txid is not None:
                dirtied = self._dirty_nodes[txid]

                def track_dirty(node):
                    dirtied.add(node)
                    return node._mk_txbranch(txid)

                res = super(ConfigRoot, self).add(path, data, txid, track_dirty)
            else:
                res = super(ConfigRoot, self).add(path, data)
        finally:
            self.execute_deferred_callbacks()
        return res

    def remove(self, path, txid=None, mk_branch=None):
        assert mk_branch is None
        self.check_callback_queue()
        try:
            if txid is not None:
                dirtied = self._dirty_nodes[txid]

                def track_dirty(node):
                    dirtied.add(node)
                    return node._mk_txbranch(txid)

                res = super(ConfigRoot, self).remove(path, txid, track_dirty)
            else:
                res = super(ConfigRoot, self).remove(path)
        finally:
            self.execute_deferred_callbacks()
        return res

    def check_callback_queue(self):
        assert len(self._deferred_callback_queue) == 0

    def enqueue_callback(self, func, *args, **kw):
        self._deferred_callback_queue.append((func, args, kw))

    def enqueue_notification_callback(self, func, *args, **kw):
        """
        A separate queue is required for notification.  Previously, when the
        notifications were added to the self._deferred_callback_queue there
        was a deadlock condition where two callbacks were added (one
        related to the model change and one for the notification related to
        that model change).  Since the model change requires the
        self._deferred_callback_queue to be empty then there was a deadlock
        in that scenario.   The simple approach to avoid this problem is to
        have separate queues for model and notification.
        TODO: Investigate whether there is a need for the
        self._deferred_callback_queue to handle multiple model events at the same time
        :param func: callback function
        :param args: args
        :param kw: key-value args
        :return: None
        """
        self._notification_deferred_callback_queue.append((func, args, kw))

    def execute_deferred_callbacks(self):
        # First process the model-triggered related callbacks
        while self._deferred_callback_queue:
            func, args, kw = self._deferred_callback_queue.pop(0)
            func(*args, **kw)

        # Execute the notification callbacks
        while self._notification_deferred_callback_queue:
            func, args, kw = self._notification_deferred_callback_queue.pop(0)
            func(*args, **kw)


    # ~~~~~~~~~~~~~~~~ Persistence related ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    @classmethod
    def load(cls, root_msg_cls, kv_store):
        # need to use fake kv store during initial load for not to override
        # our real k vstore
        fake_kv_store = dict()  # shall use more efficient mock dict
        root = cls(root_msg_cls(), kv_store=fake_kv_store,
                   rev_cls=PersistedConfigRevision)
        # we can install the real store now
        root._kv_store = kv_store
        root.load_from_persistence(root_msg_cls)
        return root

    def _make_latest(self, branch, *args, **kw):
        super(ConfigRoot, self)._make_latest(branch, *args, **kw)
        # only persist the committed branch
        if self._kv_store is not None and branch._txid is None:
            root_data = dict(
                latest=branch._latest._hash,
                tags=dict((k, v._hash) for k, v in self._tags.iteritems())
            )
            blob = dumps(root_data)
            self._kv_store['root'] = blob

    def persist_tags(self):
        if self._kv_store is not None:
            root_data = loads(self.kv_store['root'])
            root_data = dict(
                latest=root_data['latest'],
                tags=dict((k, v._hash) for k, v in self._tags.iteritems())
            )
            blob = dumps(root_data)
            self._kv_store['root'] = blob

    def load_from_persistence(self, root_msg_cls):
        self._loading = True
        blob = self._kv_store['root']
        root_data = loads(blob)

        for tag, hash in root_data['tags'].iteritems():
            self.load_latest(hash)
            self._tags[tag] = self.latest

        self.load_latest(root_data['latest'])

        self._loading = False

