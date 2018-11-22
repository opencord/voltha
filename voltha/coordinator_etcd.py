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

""" Etcd-based coordinator services """

from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from txaioetcd import Client, KeySet, Transaction, CompVersion, OpGet, OpSet, Failed
from zope.interface import implementer

from leader import Leader
from common.utils.asleep import asleep
from common.utils.message_queue import MessageQueue
from voltha.registry import IComponent
from worker import Worker
from simplejson import dumps
from common.utils.deferred_utils import DeferredWithTimeout, TimeOutError

log = get_logger()


class StaleMembershipEntryException(Exception):
    pass


@implementer(IComponent)
class CoordinatorEtcd(object):
    """
    An app shall instantiate only one Coordinator (singleton).
    A single instance of this object shall take care of all external
    with etcd, and via etcd, all coordination activities with its
    clustered peers. Roles include:
    - registering an ephemeral membership entry (k/v record) in etcd
    - participating in a symmetric leader election, and potentially assuming
      the leader's role. What leadership entails is not a concern for the
      coordination, it simply instantiates (and shuts down) a leader class
      when it gains (or looses) leadership.
    """

    CONNECT_RETRY_INTERVAL_SEC = 1
    RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]

    # Public methods:

    def __init__(self,
                 internal_host_address,
                 external_host_address,
                 instance_id,
                 rest_port,
                 config,
                 etcd='localhost:2379',
                 container_name_regex='^.*\.([0-9]+)\..*$'):

        log.info('initializing-coordinator')
        self.config = config['coordinator']
        self.worker_config = config['worker']
        self.leader_config = config['leader']
        self.membership_watch_relatch_delay = config.get(
            'membership_watch_relatch_delay', 0.1)
        self.tracking_loop_delay = self.config.get(
            'tracking_loop_delay', 1)
        self.session_renewal_timeout = self.config.get(
            'session_renewal_timeout', 5)
        self.session_renewal_loop_delay = self.config.get(
            'session_renewal_loop_delay', 3)
        self.membership_maintenance_loop_delay = self.config.get(
            'membership_maintenance_loop_delay', 5)
        self.session_time_to_live = self.config.get(
            'session_time_to_live', 10)
        self.prefix = self.config.get('voltha_kv_prefix', 'service/voltha')
        self.leader_prefix = '/'.join((self.prefix, self.config.get(
            self.config['leader_key'], 'leader')))
        self.membership_prefix = '/'.join((self.prefix, self.config.get(
            self.config['membership_key'], 'members'), ''))
        self.assignment_prefix = '/'.join((self.prefix, self.config.get(
            self.config['assignment_key'], 'assignments'), ''))
        self.workload_prefix = '/'.join((self.prefix, self.config.get(
            self.config['workload_key'], 'work'), ''))
        self.core_store_prefix = '/'.join((self.prefix, self.config.get(
            self.config['core_store_key'], 'data/core')))
        self.core_store_assignment_key = self.core_store_prefix + \
                                         '/assignment'
        self.core_storage_suffix = 'core_store'

        self.retries = 0
        self.instance_id = instance_id
        self.internal_host_address = internal_host_address
        self.external_host_address = external_host_address
        self.rest_port = rest_port
        self.membership_record_key = self.membership_prefix + self.instance_id

        self.lease = None
        # session_id refers to either a Consul session ID or an Etcd lease object
        self.session_id = None
        self.i_am_leader = False
        self.leader_id = None  # will be the instance id of the current leader
        self.shutting_down = False
        self.leader = None
        self.membership_callback = None

        self.worker = Worker(self.instance_id, self)

        # Create etcd client
        kv_host = etcd.split(':')[0].strip()
        kv_port = etcd.split(':')[1].strip()
        self.etcd_url = u'http://' + kv_host + u':' + kv_port
        self.etcd = Client(reactor, self.etcd_url)

        self.container_name_regex = container_name_regex

        self.wait_for_leader_deferreds = []

        self.peers_mapping_queue = MessageQueue()

    def start(self):
        log.debug('starting')
        reactor.callLater(0, self._async_init)
        log.info('started')
        return self

    @inlineCallbacks
    def stop(self):
        log.debug('stopping')
        self.shutting_down = True
        yield self._delete_session()  # this will delete the leader lock too
        yield self.worker.stop()
        if self.leader is not None:
            yield self.leader.stop()
            self.leader = None
        log.info('stopped')

    def wait_for_a_leader(self):
        """
        Async wait till a leader is detected/elected. The deferred will be
        called with the leader's instance_id
        :return: Deferred.
        """
        d = Deferred()
        if self.leader_id is not None:
            d.callback(self.leader_id)
            return d
        else:
            self.wait_for_leader_deferreds.append(d)
            return d

    # Wait for a core data id to be assigned to this voltha instance
    @inlineCallbacks
    def get_core_store_id_and_prefix(self):
        core_store_id = yield self.worker.get_core_store_id()
        returnValue((core_store_id, self.core_store_prefix))

    def recv_peers_map(self):
        return self.peers_mapping_queue.get()

    def publish_peers_map_change(self, msg):
        self.peers_mapping_queue.put(msg)

    # Proxy methods for etcd with retry support

    def kv_get(self, *args, **kw):
        # Intercept 'index' argument
        for name, value in kw.items():
            if name == 'index':
                kw.pop('index')
                break
        return self._retry('GET', *args, **kw)

    def kv_put(self, *args, **kw):
        return self._retry('PUT', *args, **kw)

    def kv_delete(self, *args, **kw):
        return self._retry('DELETE', *args, **kw)

    # Methods exposing key membership information

    @inlineCallbacks
    def get_members(self):
        """Return list of all members"""
        _, members = yield self.kv_get(self.membership_prefix, recurse=True)
        returnValue([member['Key'][len(self.membership_prefix):]
                     for member in members])

    # Private (internal) methods:

    @inlineCallbacks
    def _async_init(self):
        yield self._create_session()
        yield self._create_membership_record()
        yield self._start_leader_tracking()
        yield self.worker.start()

    def _backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries,
                                           len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        log.error(msg, retry_in=wait_time)
        return asleep(wait_time)

    def _clear_backoff(self):
        if self.retries:
            log.info('reconnected-to-etcd', after_retries=self.retries)
            self.retries = 0

    @inlineCallbacks
    def _create_session(self):

        @inlineCallbacks
        def _create_session():
            etcd = yield self.get_kv_client()
            # Create etcd lease
            self.lease = yield etcd.lease(self.session_time_to_live)
            self.session_id = self.lease
            log.info('created-etcd-lease', lease=self.session_id)
            self._start_session_tracking()

        yield self._retry(_create_session)

    @inlineCallbacks
    def _delete_session(self):
        try:
            yield self.lease.revoke()
        except Exception as e:
            log.exception('failed-to-delete-session %s' % e,
                          session_id=self.session_id)

    @inlineCallbacks
    def _create_membership_record(self):
        yield self._do_create_membership_record_with_retries()
        reactor.callLater(0, self._maintain_membership_record)

    @inlineCallbacks
    def _maintain_membership_record(self):
        try:
            while 1:
                valid_membership = yield self._assert_membership_record_valid()
                if not valid_membership:
                    log.info('recreating-membership-before',
                             session=self.session_id)
                    yield self._do_create_membership_record_with_retries()
                    log.info('recreating-membership-after',
                             session=self.session_id)
                else:
                    log.debug('valid-membership', session=self.session_id)
                # Async sleep before checking the membership record again
                yield asleep(self.membership_maintenance_loop_delay)

        except Exception, e:
            log.exception('unexpected-error-leader-trackin', e=e)
        finally:
            # except in shutdown, the loop must continue (after a short delay)
            if not self.shutting_down:
                reactor.callLater(self.membership_watch_relatch_delay,
                                  self._maintain_membership_record)

    def _create_membership_record_data(self):
        member_record = dict()
        member_record['status'] = 'alive'
        member_record['host_address'] = self.external_host_address
        return member_record

    @inlineCallbacks
    def _assert_membership_record_valid(self):
        try:
            log.debug('membership-record-before')
            is_timeout, (_, record) = yield \
                                        self.coordinator_get_with_timeout(
                                                key=self.membership_record_key,
                                                index=0,
                                                timeout=5)
            if is_timeout:
                log.debug('timeout creating membership record in etcd, key: %s' %
                          self.membership_record_key)
                returnValue(False)

            log.debug('membership-record-after', record=record)
            if record is None or \
                            'Session' not in record:
                log.info('membership-record-change-detected',
                         old_session=self.session_id,
                         record=record)
                returnValue(False)
            else:
                returnValue(True)
        except Exception as e:
            log.exception('membership-validation-exception', e=e)
            returnValue(False)

    @inlineCallbacks
    def _do_create_membership_record_with_retries(self):
        while 1:
            log.info('recreating-membership', session=self.session_id)
            result = yield self._retry(
                'PUT',
                self.membership_record_key,
                dumps(self._create_membership_record_data()),
                acquire=self.session_id)
            if result:
                log.info('new-membership-record-created',
                         session=self.session_id)
                break
            else:
                log.warn('cannot-create-membership-record')
                yield self._backoff('stale-membership-record')

    def _start_session_tracking(self):
        reactor.callLater(0, self._session_tracking_loop)

    @inlineCallbacks
    def _session_tracking_loop(self):

        @inlineCallbacks
        def _redo_session():
            log.info('_redo_session-before')
            yield self._delete_session()

            # Create a new etcd connection/session with a new lease
            try:
                self.etcd = Client(reactor, self.etcd_url)
                self.lease = yield self.etcd.lease(self.session_time_to_live)
                self.session_id = self.lease
                log.info('new-etcd-session', session=self.session_id)

            except Exception as e:
                log.exception('could-not-create-an-etcd-lease', e=e)

        @inlineCallbacks
        def _renew_session(m_callback):
            try:
                time_left = yield self.lease.remaining()
                log.debug('_renew_session', time_left=time_left)
                result = yield self.lease.refresh()
                log.debug('just-renewed-session', result=result)
                if not m_callback.called:
                    # Triggering callback will cancel the timeout timer
                    log.debug('trigger-callback-to-cancel-timeout-timer')
                    m_callback.callback(result)
                else:
                    # Timeout event has already been called.  Just ignore
                    # this event
                    log.info('renew-called-after-timeout, etcd ref changed?')
            except Exception, e:
                # Let the invoking method receive a timeout
                log.exception('could-not-renew-session', e=e)

        try:
            while 1:
                log.debug('session-tracking-start')
                rcvd = DeferredWithTimeout(
                    timeout=self.session_renewal_timeout)
                _renew_session(rcvd)
                try:
                    _ = yield rcvd
                except TimeOutError as e:
                    log.info('session-renew-timeout', e=e)
                    # Redo the session
                    yield _redo_session()
                except Exception as e:
                    log.exception('session-renew-exception', e=e)
                else:
                    log.debug('successfully-renewed-session')

                # Async sleep before the next session tracking
                yield asleep(self.session_renewal_loop_delay)

        except Exception as e:
            log.exception('renew-exception', e=e)
        finally:
            reactor.callLater(self.session_renewal_loop_delay,
                              self._session_tracking_loop)

    def _start_leader_tracking(self):
        reactor.callLater(0, self._leadership_tracking_loop)

    @inlineCallbacks
    def _leadership_tracking_loop(self):
        try:
            # Try to seize leadership via test-and-set operation.
            # Success means the leader key was previously absent
            # and was just re-created by this instance.

            leader_prefix = bytes(self.leader_prefix)
            txn = Transaction(
                compare=[
                    CompVersion(leader_prefix, '==', 0)
                ],
                success=[
                    OpSet(leader_prefix, bytes(self.instance_id), lease=self.lease),
                    OpGet(leader_prefix)
                ],
                failure=[]
            )
            newly_asserted = False
            try:
                result = yield self.etcd.submit(txn)
            except Failed as failed:
                # Leader key already present
                pass
            else:
                newly_asserted = True
                log.info('leader-key-absent')

            # Confirm that the assertion succeeded by reading back
            # the value of the leader key.
            leader = None
            result = yield self.etcd.get(leader_prefix)
            if result.kvs:
                kv = result.kvs[0]
                leader = kv.value
                log.debug('get-leader-key', leader=leader, instance=self.instance_id)

            if leader is None:
                log.error('get-leader-failed')
            elif leader == self.instance_id:
                if newly_asserted:
                    log.info('leadership-seized')
                    yield self._assert_leadership()
                else:
                    log.debug('already-leader')
            else:
                log.debug('leader-is-another', leader=leader)
                yield self._assert_nonleadership(leader)

        except Exception as e:
            log.exception('unexpected-error-leader-tracking', e=e)

        finally:
            # Except in shutdown, the loop must continue (after a short delay)
            if not self.shutting_down:
                reactor.callLater(self.tracking_loop_delay,
                                  self._leadership_tracking_loop)

    @inlineCallbacks
    def _assert_leadership(self):
        """(Re-)assert leadership"""
        if not self.i_am_leader:
            self.i_am_leader = True
            self._set_leader_id(self.instance_id)
            yield self._just_gained_leadership()

    @inlineCallbacks
    def _assert_nonleadership(self, leader_id):
        """(Re-)assert non-leader role"""

        # update leader_id anyway
        self._set_leader_id(leader_id)

        if self.i_am_leader:
            self.i_am_leader = False
            yield self._just_lost_leadership()

    def _set_leader_id(self, leader_id):
        self.leader_id = leader_id
        deferreds, self.wait_for_leader_deferreds = \
            self.wait_for_leader_deferreds, []
        for d in deferreds:
            d.callback(leader_id)

    def _just_gained_leadership(self):
        log.info('became-leader')
        self.leader = Leader(self)
        return self.leader.start()

    def _just_lost_leadership(self):
        log.info('lost-leadership')
        return self._halt_leader()

    def _halt_leader(self):
        if self.leader:
            d = self.leader.stop()
            self.leader = None
        return d

    def get_kv_client(self):
        return self.etcd

    @inlineCallbacks
    def _retry(self, operation, *args, **kw):
        prefix = False
        keys_only = False
        for name, value in kw.items():
            if name == 'acquire':
                lease = value
                kw['lease'] = lease
                kw.pop('acquire')
            elif name == 'keys':
                keys_only = True
                prefix = True
                keyset = KeySet(bytes(args[0]), prefix=True)
                kw['keys_only'] = True
                kw.pop('keys')
            elif name=='recurse':
                prefix = True
                keyset = KeySet(bytes(args[0]), prefix=True)
                kw.pop('recurse')
        log.debug('start-op', operation=operation, args=args, kw=kw)

        while 1:
            try:
                etcd = yield self.get_kv_client()
                if operation == 'GET':
                    key = bytes(args[0])
                    # If multiple keys requested, return a list
                    # else return a single record
                    if not prefix:
                        index = 0
                        record = dict()
                        res = yield etcd.get(key, **kw)
                        if res.kvs:
                            if len(res.kvs) == 1:
                                kv = res.kvs[0]
                                index = kv.mod_revision
                                record['Key'] = kv.key
                                record['Value'] = kv.value
                                record['ModifyIndex'] = index
                                record['Session'] = self.lease.lease_id if self.lease else ''
                                result = (index, record)
                    else:
                        # Get values for all keys that match the prefix
                        # If keys_only requested, get only the keys
                        index = 0
                        records = []
                        keys = []
                        res = yield etcd.get(keyset, **kw)
                        if args[0] == 'service/voltha/assignments/':
                            log.info('assignments', result=res)
                        if res.kvs and len(res.kvs) > 0:
                            for kv in res.kvs:
                                # Which index should be returned? The max over all keys?
                                if kv.mod_revision > index:
                                    index = kv.mod_revision
                                if keys_only:
                                    keys.append(kv.key)
                                else:
                                    rec = dict()
                                    rec['Key'] = kv.key
                                    rec['Value'] = kv.value
                                    rec['ModifyIndex'] = kv.mod_revision
                                    rec['Session'] = self.lease.lease_id if self.lease else ''
                                    records.append(rec)
                        result = (index, keys) if keys_only else (index, records)
                elif operation == 'PUT':
                    key = bytes(args[0])
                    result = yield etcd.set(key, args[1], **kw)
                elif operation == 'DELETE':
                    key = bytes(args[0])
                    result = yield etcd.delete(keyset)
                else:
                    # Default case - consider operation as a function call
                    result = yield operation(*args, **kw)
                self._clear_backoff()
                break
            except Exception as e:
                if not self.shutting_down:
                    log.exception(e)
                yield self._backoff('etcd-unknown-error: %s' % e)

        log.debug('end-op', operation=operation, args=args, kw=kw)
        returnValue(result)

    @inlineCallbacks
    def coordinator_get_with_timeout(self, key, timeout, **kw):
        """
        Query etcd with a timeout
        :param key: Key to query
        :param timeout: timeout value
        :param kw: additional key-value params
        :return: (is_timeout, (index, result)).

        The Consul version of this method performed a 'wait-type' get operation
        that returned a result when the key's value had a ModifyIndex greater
        than the 'index' argument. Not sure etcd supports this functionality.
        """

        # Intercept 'index' argument
        for name, value in kw.items():
            if name == 'index':
                mod_revision = value
                log.debug('coordinator-get-with-timeout-etcd',
                          index=mod_revision)
                kw.pop('index')
                break

        @inlineCallbacks
        def _get(key, m_callback):
            try:
                (index, result) = yield self._retry('GET', key, **kw)
                if index > mod_revision and not m_callback.called:
                    log.debug('got-result-cancelling-timer')
                    m_callback.callback((index, result))
            except Exception as e:
                log.exception('got-exception', e=e)

        try:
            rcvd = DeferredWithTimeout(timeout=timeout)
            _get(key, rcvd)
            try:
                result = yield rcvd
                log.debug('result-received', result=result)
                returnValue((False, result))
            except TimeOutError as e:
                log.debug('timeout-or-no-data-change', etcd_key=key)
            except Exception as e:
                log.exception('exception', e=e)
        except Exception as e:
            log.exception('exception', e=e)

        returnValue((True, (None, None)))
