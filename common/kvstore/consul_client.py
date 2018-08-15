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

from common.kvstore.kv_client import DEFAULT_TIMEOUT, Event, KVClient, KVPair, RETRY_BACKOFF
from common.utils.asleep import asleep
from common.utils.deferred_utils import DeferredWithTimeout, TimeOutError
from consul import ConsulException
from consul.twisted import Consul
from structlog import get_logger
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred

log = get_logger()

class ConsulClient(KVClient):

    def __init__(self, kv_host, kv_port):
        KVClient.__init__(self, kv_host, kv_port)
        self.session_id = None
        self.client = Consul(kv_host, kv_port)

    def watch(self, key, key_change_callback, timeout=DEFAULT_TIMEOUT):
        self._retriggering_watch(key, key_change_callback, timeout)

    @inlineCallbacks
    def _retriggering_watch(self, key, key_change_callback, timeout):
        self.key_watches[key] = ConsulWatch(self.client, key, key_change_callback, timeout)
        yield self.key_watches[key].start()

    def close_watch(self, key, timeout=DEFAULT_TIMEOUT):
        if key in self.key_watches:
            self.key_watches[key].stop()

    @inlineCallbacks
    def _op_with_retry(self, operation, key, value, timeout, *args, **kw):
        log.debug('kv-op', operation=operation, key=key, timeout=timeout, args=args, kw=kw)
        err = None
        result = None
        while True:
            try:
                if operation == 'GET':
                    result = yield self._get(key, **kw)
                elif operation == 'LIST':
                    result, err = yield self._list(key)
                elif operation == 'PUT':
                    # Put returns a boolean response
                    result = yield self.client.kv.put(key, value)
                    if not result:
                        err = 'put-failed'
                elif operation == 'DELETE':
                    # Delete returns a boolean response
                    result = yield self.client.kv.delete(key)
                    if not result:
                        err = 'delete-failed'
                elif operation == 'RESERVE':
                    result, err = yield self._reserve(key, value, **kw)
                elif operation == 'RENEW':
                    result, err = yield self._renew_reservation(key)
                elif operation == 'RELEASE':
                    result, err = yield self._release_reservation(key)
                elif operation == 'RELEASE-ALL':
                    err = yield self._release_all_reservations()
                self._clear_backoff()
                break
            except ConsulException as ex:
                if 'ConnectionRefusedError' in ex.message:
                    log.exception('comms-exception', ex=ex)
                    yield self._backoff('consul-not-up')
                else:
                    log.error('consul-specific-exception', ex=ex)
                    err = ex
            except Exception as ex:
                log.error('consul-exception', ex=ex)
                err = ex

            if timeout > 0 and self.retry_time > timeout:
                err = 'operation-timed-out'
            if err is not None:
                self._clear_backoff()
                break

        returnValue((result,err))

    @inlineCallbacks
    def _get(self, key, **kw):
        kvp = None
        index, rec = yield self.client.kv.get(key, **kw)
        if rec is not None:
            kvp = KVPair(rec['Key'], rec['Value'], index)
        returnValue(kvp)

    @inlineCallbacks
    def _list(self, key):
        err = None
        list = []
        index, recs = yield self.client.kv.get(key, recurse=True)
        for rec in recs:
            list.append(KVPair(rec['Key'], rec['Value'], rec['ModifyIndex']))
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

        # Create a session
        self.session_id = yield self.client.session.create(behavior='delete',
                                                           ttl=ttl) # lock_delay=1)
        log.debug('create-session', id=self.session_id)
        # Try to acquire the key
        result = yield self.client.kv.put(key, value, acquire=self.session_id)
        log.debug('key-acquire', key=key, value=value, sess=self.session_id, result=result)

        # Check if reservation succeeded
        index, record = yield self.client.kv.get(key)
        if record is not None and 'Value' in record:
            owner = record['Value']
            log.debug('get-key', session=record['Session'], owner=owner)
            if record['Session'] == self.session_id and owner == value:
                reserved = True
                log.debug('key-reserved', key=key, value=value, ttl=ttl)
                # Add key to reservation list
                self.key_reservations[key] = self.session_id
            else:
                log.debug('reservation-held-by-another', owner=owner)

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
            session_id = self.key_reservations[key]
            # A successfully renewed session returns an object with fields:
            # Node, CreateIndex, Name, ModifyIndex, ID, Behavior, TTL,
            # LockDelay, and Checks
            result = yield self.client.session.renew(session_id=session_id)
            log.debug('session-renew', result=result)
        if result is None:
            err = 'session-renewal-failed'
        returnValue((result, err))

    @inlineCallbacks
    def _release_reservation(self, key):
        err = None
        if key not in self.key_reservations:
            err = 'key-not-reserved'
        else:
            session_id = self.key_reservations[key]
            # A successfully destroyed session returns a boolean result
            success = yield self.client.session.destroy(session_id)
            log.debug('session-destroy', result=success)
            if not success:
                err = 'session-destroy-failed'
            self.session_id = None
            self.key_reservations.pop(key)
        returnValue((success, err))

    @inlineCallbacks
    def _release_all_reservations(self):
        err = None
        keys_to_delete = []
        for key in self.key_reservations:
            session_id = self.key_reservations[key]
            # A successfully destroyed session returns a boolean result
            success = yield self.client.session.destroy(session_id)
            if not success:
                err = 'session-destroy-failed'
                log.debug('session-destroy', id=session_id, result=success)
            self.session_id = None
            keys_to_delete.append(key)
        for key in keys_to_delete:
            self.key_reservations.pop(key)
        returnValue(err)


class ConsulWatch():

    def __init__(self, consul, key, callback, timeout):
        self.client = consul
        self.key = key
        self.index = None
        self.callback = callback
        self.timeout = timeout
        self.period = 60
        self.running = True
        self.retries = 0
        self.retry_time = 0

    @inlineCallbacks
    def start(self):
        self.running = True
        index, rec = yield self._get_with_retry(self.key, None,
                                              timeout=self.timeout)
        self.index = str(index)

        @inlineCallbacks
        def _get(key, deferred):
            try:
                index, rec = yield self._get_with_retry(key, None,
                                                     timeout=self.timeout,
                                                     index=self.index)
                self.index = str(index)
                if not deferred.called:
                    log.debug('got-result-cancelling-deferred')
                    deferred.callback((self.index, rec))
            except Exception as e:
                log.exception('got-exception', e=e)

        while self.running:
            try:
                rcvd = DeferredWithTimeout(timeout=self.period)
                _get(self.key, rcvd)
                try:
                    # Update index for next watch iteration
                    index, rec = yield rcvd
                    log.debug('event-received', index=index, rec=rec)
                    # Notify client of key change event
                    if rec is None:
                        # Key has been deleted
                        self._send_event(Event(Event.DELETE, self.key, None))
                    else:
                        self._send_event(Event(Event.PUT, rec['Key'], rec['Value']))
                except TimeOutError as e:
                    log.debug('no-events-over-watch-period', key=self.key)
                except Exception as e:
                    log.exception('exception', e=e)
            except Exception as e:
                log.exception('exception', e=e)

        log.debug('close-watch', key=self.key)

    def stop(self):
        self.running = False
        self.callback = None

    @inlineCallbacks
    def _get_with_retry(self, key, value, timeout, *args, **kw):
        log.debug('watch-period', key=key, period=self.period, timeout=timeout, args=args, kw=kw)
        err = None
        result = None
        while True:
            try:
                result = yield self.client.kv.get(key, **kw)
                self._clear_backoff()
                break
            except ConsulException as ex:
                err = ex
                if 'ConnectionRefusedError' in ex.message:
                    self._send_event(Event(Event.CONNECTION_DOWN, self.key, None))
                    log.exception('comms-exception', ex=ex)
                    yield self._backoff('consul-not-up')
                else:
                    log.error('consul-specific-exception', ex=ex)
            except Exception as ex:
                err = ex
                log.error('consul-exception', ex=ex)

            if timeout > 0 and self.retry_time > timeout:
                err = 'operation-timed-out'
            if err is not None:
                self._clear_backoff()
                break

        returnValue(result)

    def _send_event(self, event):
        if self.callback is not None:
            self.callback(event)

    def _backoff(self, msg):
        wait_time = RETRY_BACKOFF[min(self.retries, len(RETRY_BACKOFF) - 1)]
        self.retry_time += wait_time
        self.retries += 1
        log.error(msg, next_retry_in_secs=wait_time,
                  total_delay_in_secs = self.retry_time,
                  retries=self.retries)
        return asleep(wait_time)

    def _clear_backoff(self):
        if self.retries:
            log.debug('reconnected-to-kv', after_retries=self.retries)
            self.retries = 0
            self.retry_time = 0
