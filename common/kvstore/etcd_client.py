# Copyright 2018-present Open Networking Foundation
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

################################################################################
#
# Most of the txaioetcd methods provide a timeout parameter. This parameter
# is likely intended to limit the amount of time spent by any one method
# waiting for a response from the etcd server. However, if the server is
# down, the method immediately throws a ConnectionRefusedError exception;
# it does not perform any retries. The timeout parameter provided by the
# methods in EtcdClient cover this contingency.
#
################################################################################

from common.kvstore.kv_client import DEFAULT_TIMEOUT, Event, KVClient, KVPair
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.error import ConnectionRefusedError
from txaioetcd import Client, CompVersion, Failed, KeySet, OpGet, OpSet, Transaction

log = get_logger()

class EtcdClient(KVClient):

    def __init__(self, kv_host, kv_port):
        KVClient.__init__(self, kv_host, kv_port)
        self.url = u'http://' + kv_host + u':' + str(kv_port)
        self.client = Client(reactor, self.url)

    @inlineCallbacks
    def watch(self, key, key_change_callback, timeout=DEFAULT_TIMEOUT):
        self.key_watches[key] = key_change_callback
        result = yield self._op_with_retry('WATCH', key, None, timeout, callback=self.key_changed)
        returnValue(result)

    def key_changed(self, kv):
        key = kv.key
        value = kv.value
        log.debug('key-changed', key=key, value=value)
        # Notify client of key change event
        if value is not None:
            evt = Event(Event.PUT, key, value)
        else:
            evt = Event(Event.DELETE, key, None)
        if key in self.key_watches:
            self.key_watches[key](evt)

    def close_watch(self, key, timeout=DEFAULT_TIMEOUT):
        log.debug('close-watch', key=key)
        if key in self.key_watches:
            self.key_watches.pop(key)

    @inlineCallbacks
    def _op_with_retry(self, operation, key, value, timeout, *args, **kw):
        log.debug('kv-op', operation=operation, key=key, timeout=timeout, args=args, kw=kw)
        err = None
        result = None
        if type(key) == str:
            key = bytes(key)
        if value is not None:
           value = bytes(value)
        while True:
            try:
                if operation == 'GET':
                    result = yield self._get(key)
                elif operation == 'LIST':
                    result, err = yield self._list(key)
                elif operation == 'PUT':
                    # Put returns an object of type Revision
                    result = yield self.client.set(key, value, **kw)
                elif operation == 'DELETE':
                    # Delete returns an object of type Deleted
                    result = yield self.client.delete(key)
                elif operation == 'RESERVE':
                    result, err = yield self._reserve(key, value, **kw)
                elif operation == 'RENEW':
                    result, err = yield self._renew_reservation(key)
                elif operation == 'RELEASE':
                    result, err = yield self._release_reservation(key)
                elif operation == 'RELEASE-ALL':
                    err = yield self._release_all_reservations()
                elif operation == 'WATCH':
                    for name, val in kw.items():
                        if name == 'callback':
                            callback = val
                            break
                    result = self.client.watch([KeySet(key, prefix=True)], callback)
                self._clear_backoff()
                break
            except ConnectionRefusedError as ex:
                log.error('comms-exception', ex=ex)
                yield self._backoff('etcd-not-up')
            except Exception as ex:
                log.error('etcd-exception', ex=ex)
                err = ex

            if timeout > 0 and self.retry_time > timeout:
                err = 'operation-timed-out'
            if err is not None:
                self._clear_backoff()
                break

        returnValue((result, err))

    @inlineCallbacks
    def _get(self, key):
        kvp = None
        resp = yield self.client.get(key)
        if resp.kvs is not None and len(resp.kvs) == 1:
            kv = resp.kvs[0]
            kvp = KVPair(kv.key, kv.value, kv.mod_revision)
        returnValue(kvp)

    @inlineCallbacks
    def _list(self, key):
        err = None
        list = []
        resp = yield self.client.get(KeySet(key, prefix=True))
        if resp.kvs is not None and len(resp.kvs) > 0:
            for kv in resp.kvs:
                list.append(KVPair(kv.key, kv.value, kv.mod_revision))
        returnValue((list, err))

    @inlineCallbacks
    def _reserve(self, key, value, **kw):
        for name, val in kw.items():
            if name == 'ttl':
                ttl = val
                break
        reserved = False
        err = 'reservation-failed'
        owner = None

        # Create a lease
        lease = yield self.client.lease(ttl)

        # Create a transaction
        txn = Transaction(
            compare=[ CompVersion(key, '==', 0) ],
            success=[ OpSet(key, bytes(value), lease=lease) ],
            failure=[ OpGet(key) ]
        )
        newly_acquired = False
        try:
            result = yield self.client.submit(txn)
        except Failed as failed:
            log.debug('key-already-present', key=key)
            if len(failed.responses) > 0:
                response = failed.responses[0]
                if response.kvs is not None and len(response.kvs) > 0:
                    kv = response.kvs[0]
                    log.debug('key-already-present', value=kv.value)
                    if kv.value == value:
                        reserved = True
                        log.debug('key-already-reserved', key = kv.key, value=kv.value)
        else:
            newly_acquired = True
            log.debug('key-was-absent', key=key, result=result)

        # Check if reservation succeeded
        resp = yield self.client.get(key)
        if resp.kvs is not None and len(resp.kvs) == 1:
            owner = resp.kvs[0].value
            if owner == value:
                if newly_acquired:
                    log.debug('key-reserved', key=key, value=value, ttl=ttl,
                             lease_id=lease.lease_id)
                    reserved = True
                    # Add key to reservation list
                    self.key_reservations[key] = lease
                else:
                    log.debug("reservation-still-held")
            else:
                log.debug('reservation-held-by-another', value=owner)

        if reserved:
            err = None
        returnValue((owner, err))

    @inlineCallbacks
    def _renew_reservation(self, key):
        result = None
        err = None
        if key not in self.key_reservations:
            err = 'key-not-reserved'
        else:
            lease = self.key_reservations[key]
            # A successfully refreshed lease returns an object of type Header
            result = yield lease.refresh()
        if result is None:
            err = 'lease-refresh-failed'
        returnValue((result, err))

    @inlineCallbacks
    def _release_reservation(self, key):
        err = None
        if key not in self.key_reservations:
            err = 'key-not-reserved'
        else:
            lease = self.key_reservations[key]
            time_left = yield lease.remaining()
            # A successfully revoked lease returns an object of type Header
            log.debug('release-reservation', key=key, lease_id=lease.lease_id,
                      time_left_in_secs=time_left)
            result = yield lease.revoke()
            if result is None:
                err = 'lease-revoke-failed'
            self.key_reservations.pop(key)
        returnValue((result, err))

    @inlineCallbacks
    def _release_all_reservations(self):
        err = None
        keys_to_delete = []
        for key in self.key_reservations:
            lease = self.key_reservations[key]
            time_left = yield lease.remaining()
            # A successfully revoked lease returns an object of type Header
            log.debug('release-reservation', key=key, lease_id=lease.lease_id,
                      time_left_in_secs=time_left)
            result = yield lease.revoke()
            if result is None:
                err = 'lease-revoke-failed'
                log.debug('lease-revoke', result=result)
            keys_to_delete.append(key)
        for key in keys_to_delete:
            self.key_reservations.pop(key)
        returnValue(err)
