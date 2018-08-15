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

from common.utils.asleep import asleep
from structlog import get_logger
from twisted.internet.defer import inlineCallbacks, returnValue

log = get_logger()

class KVPair():
    def __init__(self, key, value, index):
        self.key = key
        self.value = value
        self.index = index

class Event():
    PUT = 0
    DELETE = 1
    CONNECTION_DOWN = 2

    def __init__(self, event_type, key, value):
        self.event_type = event_type
        self.key = key
        self.value = value

RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]
DEFAULT_TIMEOUT = 0.0
for i in range(len(RETRY_BACKOFF)):
    DEFAULT_TIMEOUT += RETRY_BACKOFF[i]

class KVClient():

    def __init__(self, kv_host, kv_port):
        self.host = kv_host
        self.port = kv_port
        self.key_reservations = {}
        self.key_watches = {}
        self.retries = 0
        self.retry_time = 0

    @inlineCallbacks
    def get(self, key, timeout=DEFAULT_TIMEOUT):
        '''
        This method returns the value of the given key in KV store.

        :param key: The key whose value is requested
        :param timeout: The length of time in seconds the method will wait for a response
        :return: (KVPair, error) where KVPair is None if an error occurred
        '''
        result = yield self._op_with_retry('GET', key, None, timeout)
        returnValue(result)

    @inlineCallbacks
    def list(self, key, timeout=DEFAULT_TIMEOUT):
        '''
        The list method returns an array of key-value pairs all of which
        share the same key prefix.

        :param key: The key prefix
        :param timeout: The length of time in seconds the method will wait for a response
        :return: ([]KVPair, error) where []KVPair is a list of KVPair objects
        '''
        result = yield self._op_with_retry('LIST', key, None, timeout)
        returnValue(result)

    @inlineCallbacks
    def put(self, key, value, timeout=DEFAULT_TIMEOUT):
        '''
        The put method writes a value to the given key in KV store.
        Do NOT modify a reserved key in an etcd store; doing so seems
        to nullify the TTL of the key. In other words, the key lasts
        forever.

        :param key: The key to be written to
        :param value: The value of the key
        :param timeout: The length of time in seconds the method will wait for a response
        :return: error, which is set to None for a successful write
        '''
        _, err = yield self._op_with_retry('PUT', key, value, timeout)
        returnValue(err)

    @inlineCallbacks
    def delete(self, key, timeout=DEFAULT_TIMEOUT):
        '''
        The delete method removes a key from the KV store.

        :param key: The key to be deleted
        :param timeout: The length of time in seconds the method will wait for a response
        :return: error, which is set to None for a successful deletion
        '''
        _, err = yield self._op_with_retry('DELETE', key, None, timeout)
        returnValue(err)

    @inlineCallbacks
    def reserve(self, key, value, ttl, timeout=DEFAULT_TIMEOUT):
        '''
        This method acts essentially like a semaphore. The underlying mechanism
        differs depending on the KV store: etcd uses a test-and-set transaction;
        consul uses an acquire lock. If using etcd, do NOT write to the key
        subsequent to the initial reservation; the TTL functionality may become
        impaired (i.e. the reservation never expires).

        :param key: The key under reservation
        :param value: The reservation owner
        :param ttl: The time-to-live (TTL) for the reservation. The key is unreserved
        by the KV store when the TTL expires.
        :param timeout: The length of time in seconds the method will wait for a response
        :return: (key_value, error) If the key is acquired, then the value returned will
        be the value passed in.  If the key is already acquired, then the value assigned
        to that key will be returned.
        '''
        result = yield self._op_with_retry('RESERVE', key, value, timeout, ttl=ttl)
        returnValue(result)

    @inlineCallbacks
    def renew_reservation(self, key, timeout=DEFAULT_TIMEOUT):
        '''
        This method renews the reservation for a given key. A reservation expires
        after the TTL (Time To Live) period specified when reserving the key.

        :param key: The reserved key
        :param timeout: The length of time in seconds the method will wait for a response
        :return: error, which is set to None for a successful renewal
        '''
        result, err = yield self._op_with_retry('RENEW', key, None, timeout)
        returnValue(err)

    @inlineCallbacks
    def release_reservation(self, key, timeout=DEFAULT_TIMEOUT):
        '''
        The release_reservation method cancels the reservation for a given key.

        :param key: The reserved key
        :param timeout: The length of time in seconds the method will wait for a response
        :return: error, which is set to None for a successful cancellation
        '''
        result, err = yield self._op_with_retry('RELEASE', key, None, timeout)
        returnValue(err)

    @inlineCallbacks
    def release_all_reservations(self, timeout=DEFAULT_TIMEOUT):
        '''
        This method cancels all key reservations made previously
        using the reserve API.

        :param timeout: The length of time in seconds the method will wait for a response
        :return: error, which is set to None for a successful cancellation
        '''
        result, err = yield self._op_with_retry('RELEASE-ALL', None, None, timeout)
        returnValue(err)

    @inlineCallbacks
    def watch(self, key, key_change_callback, timeout=DEFAULT_TIMEOUT):
        '''
        This method provides a watch capability for the given key. If the value of the key
        changes or the key is deleted, then an event indicating the change is passed to
        the given callback function.

        :param key: The key to be watched
        :param key_change_callback: The function invoked whenever the key changes
        :param timeout: The length of time in seconds the method will wait for a response
        :return: There is no return; key change events are passed to the callback function
        '''
        raise NotImplementedError('Method not implemented')

    @inlineCallbacks
    def close_watch(self, key, timeout=DEFAULT_TIMEOUT):
        '''
        This method closes the watch on the given key. Once the watch is closed, key
        change events are no longer passed to the key change callback function.

        :param key: The key under watch
        :param timeout: The length of time in seconds the method will wait for a response
        :return: There is no return
        '''
        raise NotImplementedError('Method not implemented')

    @inlineCallbacks
    def _op_with_retry(self, operation, key, value, timeout, *args, **kw):
        raise NotImplementedError('Method not implemented')

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
            log.debug('reset-backoff', after_retries=self.retries)
            self.retries = 0
            self.retry_time = 0