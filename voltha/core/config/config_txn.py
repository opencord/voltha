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

class ClosedTransactionError(Exception):
    pass


class ConfigTransaction(object):

    __slots__ = (
        '_proxy',
        '_txid'
    )

    def __init__(self, proxy, txid):
        self._proxy = proxy
        self._txid = txid

    def __del__(self):
        if self._txid:
            try:
                self.cancel()
            except:
                raise

    # ~~~~~~~~~~~~~~~~~~~~ CRUD ops within the transaction ~~~~~~~~~~~~~~~~~~~~

    def get(self, path='/', depth=None, deep=None):
        if self._txid is None:
            raise ClosedTransactionError()
        return self._proxy.get(path, depth=depth, deep=deep, txid=self._txid)

    def update(self, path, data, strict=False):
        if self._txid is None:
            raise ClosedTransactionError()
        return self._proxy.update(path, data, strict, self._txid)

    def add(self, path, data):
        if self._txid is None:
            raise ClosedTransactionError()
        return self._proxy.add(path, data, self._txid)

    def remove(self, path):
        if self._txid is None:
            raise ClosedTransactionError()
        return self._proxy.remove(path, self._txid)

    # ~~~~~~~~~~~~~~~~~~~~ transaction finalization ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def cancel(self):
        """Explicitly cancel the transaction"""
        self._proxy.cancel_transaction(self._txid)
        self._txid = None

    def commit(self):
        """Commit all transaction changes"""
        try:
            self._proxy.commit_transaction(self._txid)
        finally:
            self._txid = None
