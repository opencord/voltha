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

""" Consul-based coordinator services """

from consul import ConsulException
from consul.twisted import Consul
from requests import ConnectionError
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.error import DNSLookupError
from zope.interface import implementer

from leader import Leader
from common.utils.asleep import asleep
from common.utils.message_queue import MessageQueue
from voltha.registry import IComponent
from worker import Worker
from simplejson import dumps, loads
from common.utils.deferred_utils import DeferredWithTimeout, TimeOutError

log = get_logger()


class StaleMembershipEntryException(Exception):
    pass


@implementer(IComponent)
class Coordinator(object):
    """
    An app shall instantiate only one Coordinator (singleton).
    A single instance of this object shall take care of all external
    with consul, and via consul, all coordination activities with its
    clustered peers. Roles include:
    - registering an ephemeral membership entry (k/v record) in consul
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
                 consul='localhost:8500',
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

        self.session_id = None
        self.i_am_leader = False
        self.leader_id = None  # will be the instance id of the current leader
        self.shutting_down = False
        self.leader = None
        self.membership_callback = None

        self.worker = Worker(self.instance_id, self)

        self.host = consul.split(':')[0].strip()
        self.port = int(consul.split(':')[1].strip())

        # TODO need to handle reconnect events properly
        self.consul = Consul(host=self.host, port=self.port)

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

    # Proxy methods for consul with retry support

    def kv_get(self, *args, **kw):
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
        log.info(msg, retry_in=wait_time)
        return asleep(wait_time)

    def _clear_backoff(self):
        if self.retries:
            log.info('reconnected-to-consul', after_retries=self.retries)
            self.retries = 0

    @inlineCallbacks
    def _create_session(self):

        @inlineCallbacks
        def _create_session():
            consul = yield self.get_consul()
            # create consul session
            self.session_id = yield consul.session.create(
                behavior='release', ttl=self.session_time_to_live,
                lock_delay=1)
            log.info('created-consul-session', session_id=self.session_id)
            self._start_session_tracking()

        yield self._retry(_create_session)

    @inlineCallbacks
    def _delete_session(self):
        try:
            yield self.consul.session.destroy(self.session_id)
        except Exception as e:
            log.exception('failed-to-delete-session',
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
            log.info('membership-record-before')
            is_timeout, (_, record) = yield \
                                        self.coordinator_get_with_timeout(
                                                key=self.membership_record_key,
                                                index=0,
                                                timeout=5)
            if is_timeout:
                returnValue(False)

            log.info('membership-record-after', record=record)
            if record is None or \
                            'Session' not in record or \
                            record['Session'] != self.session_id:
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

            # Create a new consul connection/session with a TTL of 25 secs
            try:
                self.consul = Consul(host=self.host, port=self.port)
                self.session_id = yield self.consul.session.create(
                    behavior='release',
                    ttl=self.session_time_to_live,
                    lock_delay=1)
                log.info('new-consul-session', session=self.session_id)

            except Exception as e:
                log.exception('could-not-create-a-consul-session', e=e)

        @inlineCallbacks
        def _renew_session(m_callback):
            try:
                log.debug('_renew_session-before')
                consul_ref = self.consul
                result = yield consul_ref.session.renew(
                    session_id=self.session_id)
                log.info('just-renewed-session', result=result)
                if not m_callback.called:
                    # Triggering callback will cancel the timeout timer
                    log.info('trigger-callback-to-cancel-timout-timer')
                    m_callback.callback(result)
                else:
                    # Timeout event has already been called.  Just ignore
                    # this event
                    log.info('renew-called-after-timout',
                             new_consul_ref=self.consul,
                             old_consul_ref=consul_ref)
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
            # Attempt to acquire leadership lock. True indicates success;
            # False indicates there is already a leader. It's instance id
            # is then the value under the leader key service/voltha/leader.

            # attempt acquire leader lock
            log.info('leadership-attempt-before')
            result = yield self._retry('PUT',
                                       self.leader_prefix,
                                       self.instance_id,
                                       acquire=self.session_id)
            log.info('leadership-attempt-after')

            # read it back before being too happy; seeing our session id is a
            # proof and now we have the change id that we can use to reliably
            # track any changes. In an unlikely scenario where the leadership
            # key gets wiped out administratively since the previous line,
            # the returned record can be None. Handle it.
            (index, record) = yield self._retry('GET',
                                                self.leader_prefix)
            log.info('leader-prefix',
                     i_am_leader=result, index=index, record=record)

            if record is not None:
                if result is True:
                    if record['Session'] == self.session_id:
                        yield self._assert_leadership()
                    else:
                        pass  # confusion; need to retry leadership
                else:
                    leader_id = record['Value']
                    yield self._assert_nonleadership(leader_id)

            # if record was none, we shall try leadership again
            last = record
            while last is not None:
                # this shall return only when update is made to leader key
                # or expires after 5 seconds wait
                is_timeout, (tmp_index, updated) = yield \
                    self.coordinator_get_with_timeout(
                        key=self.leader_prefix,
                        index=index,
                        timeout=5)
                # Timeout means either there is a lost connectivity to
                # consul or there are no change to that key.  Do nothing.
                if is_timeout:
                    continue

                # After timeout event the index returned from
                # coordinator_get_with_timeout is None.  If we are here it's
                # not a timeout, therefore the index is a valid one.
                index=tmp_index

                if updated is None or updated != last:
                    log.info('leader-key-change',
                             index=index, updated=updated, last=last)
                    # leadership has changed or vacated (or forcefully
                    # removed), apply now
                    # If I was previoulsy the leader then assert a non
                    # leadership role before going for election
                    if self.i_am_leader:
                        log.info('leaving-leaderdhip',
                                 leader=self.instance_id)
                        yield self._assert_nonleadership(self.instance_id)

                    break
                last = updated

        except Exception, e:
            log.exception('unexpected-error-leader-trackin', e=e)

        finally:
            # except in shutdown, the loop must continue (after a short delay)
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

    def get_consul(self):
        return self.consul

    @inlineCallbacks
    def _retry(self, operation, *args, **kw):
        while 1:
            try:
                consul = yield self.get_consul()
                log.info('start', operation=operation, args=args)
                if operation == 'GET':
                    result = yield consul.kv.get(*args, **kw)
                elif operation == 'PUT':
                    for name, value in kw.items():
                        if name == 'acquire':
                            if value != self.session_id:
                                log.info('updating-session-in-put-operation',
                                         old_session=value,
                                         new_session=self.session_id)
                                kw['acquire'] = self.session_id
                            break
                    result = yield consul.kv.put(*args, **kw)
                elif operation == 'DELETE':
                    result = yield consul.kv.delete(*args, **kw)
                else:
                    # Default case - consider operation as a function call
                    result = yield operation(*args, **kw)
                self._clear_backoff()
                break
            except ConsulException, e:
                log.exception('consul-not-up',
                              operation=operation,
                              args=args,
                              session=self.consul.Session,
                              e=e)
                yield self._backoff('consul-not-up')
            except ConnectionError, e:
                log.exception('cannot-connect-to-consul',
                              operation=operation,
                              args=args,
                              session=self.consul.Session,
                              e=e)
                yield self._backoff('cannot-connect-to-consul')
            except DNSLookupError, e:
                log.info('dns-lookup-failed', operation=operation, args=args,
                            host=self.host)
                yield self._backoff('dns-lookup-failed')
            except StaleMembershipEntryException, e:
                log.exception('stale-membership-record-in-the-way',
                              operation=operation,
                              args=args,
                              session=self.consul.Session,
                              e=e)
                yield self._backoff('stale-membership-record-in-the-way')
            except Exception, e:
                if not self.shutting_down:
                    log.exception(e)
                yield self._backoff('unknown-error')

        log.info('end', operation=operation, args=args)
        returnValue(result)

    @inlineCallbacks
    def coordinator_get_with_timeout(self, key, timeout, **kw):
        """
        Query consul with a timeout
        :param key: Key to query
        :param timeout: timeout value
        :param kw: additional key-value params
        :return: (is_timeout, (index, result)).
        """

        @inlineCallbacks
        def _get(key, m_callback):
            try:
                (index, result) = yield self._retry('GET', key, **kw)
                if not m_callback.called:
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
                log.debug('timeout-or-no-data-change', consul_key=key)
            except Exception as e:
                log.exception('exception', e=e)
        except Exception as e:
            log.exception('exception', e=e)

        returnValue((True, (None, None)))
