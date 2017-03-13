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
import structlog
from enum import Enum

from voltha.core.config.config_txn import ConfigTransaction

log = structlog.get_logger()


class OperationContext(object):
    def __init__(self, path=None, data=None, field_name=None, child_key=None):
        self.path = path
        self._data = data
        self.field_name = field_name
        self.child_key = child_key
    @property
    def data(self):
        return self._data
    def update(self, data):
        self._data = data
        return self
    def __repr__(self):
        return 'OperationContext({})'.format(self.__dict__)


class CallbackType(Enum):

    # GET hooks are called after the data is retrieved and can be used to
    # augment the data (they should only augment fields marked as REAL_TIME
    GET = 1

    # PRE_UPDATE hooks are called before the change is made and are supposed
    # to be used to reject the data by raising an exception. If they don't,
    # the change will be applied.
    PRE_UPDATE = 2

    # POST_UPDATE hooks are called after the update has occurred and can
    # be used to deal with the change. For instance, an adapter can use the
    # callback to trigger the south-bound configuration
    POST_UPDATE = 3

    # These behave similarly to the update callbacks as described above.
    PRE_ADD = 4
    POST_ADD = 5
    PRE_REMOVE = 6
    POST_REMOVE = 7

    # Bulk list change due to transaction commit that changed items in
    # non-keyed container fields
    POST_LISTCHANGE = 8


class ConfigProxy(object):
    """
    Allows an entity to look at a sub-tree and see it as it was the whole tree
    """
    __slots__ = (
        '_root',
        '_node',
        '_path',
        '_exclusive',
        '_callbacks'
    )

    def __init__(self, root, node, path, exclusive):
        self._root = root
        self._node = node
        self._exclusive = exclusive
        self._path = path  # full path to proxied node
        self._callbacks = {}  # call back type -> list of callbacks

    @property
    def exclusive(self):
        return self._exclusive

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~ CRUD handlers ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def get(self, path='/', depth=None, deep=None, txid=None):
        return self._node.get(path, depth=depth, deep=deep, txid=txid)

    def update(self, path, data, strict=False, txid=None):
        assert path.startswith('/')
        full_path = self._path if path == '/' else self._path + path
        return self._root.update(full_path, data, strict, txid=txid)

    def add(self, path, data, txid=None):
        assert path.startswith('/')
        full_path = self._path if path == '/' else self._path + path
        return self._root.add(full_path, data, txid=txid)

    def remove(self, path, txid=None):
        assert path.startswith('/')
        full_path = self._path if path == '/' else self._path + path
        return self._root.remove(full_path, txid=txid)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~ Transaction support ~~~~~~~~~~~~~~~~~~~~~~~~~~

    def open_transaction(self):
        """Open a new transaction"""
        txid = self._root.mk_txbranch()
        return ConfigTransaction(self, txid)

    def commit_transaction(self, txid):
        """
        If having an open transaction, commit it now. Will raise exception
        if conflict is detected. Either way, transaction will be deleted.
        """
        self._root.fold_txbranch(txid)

    def cancel_transaction(self, txid):
        """
        Cancel current transaction if we are in a transaction. Always succeeds.
        """
        self._root.del_txbranch(txid)

    # ~~~~~~~~~~~~~~~~~~~~~~ Callbacks registrations ~~~~~~~~~~~~~~~~~~~~~~~~~~

    def register_callback(self, callback_type, callback, *args, **kw):
        lst = self._callbacks.setdefault(callback_type, [])
        lst.append((callback, args, kw))

    def unregister_callback(self, callback_type, callback, *args, **kw):
        lst = self._callbacks.setdefault(callback_type, [])
        if (callback, args, kw) in lst:
            lst.remove((callback, args, kw))

    # ~~~~~~~~~~~~~~~~~~~~~ Callback dispatch ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def invoke_callbacks(self, callback_type, context, proceed_on_errors=False):
        lst = self._callbacks.get(callback_type, [])
        for callback, args, kw in lst:
            try:
                context = callback(context, *args, **kw)
            except Exception, e:
                if proceed_on_errors:
                    log.exception(
                        'call-back-error', callback_type=callback_type,
                        context=context, e=e)
                else:
                    raise
        return context
