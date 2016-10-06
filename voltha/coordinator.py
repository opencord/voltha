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

""" Consul-based coordinator services """

from consul import ConsulException
from consul.twisted import Consul
from requests import ConnectionError
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.task import LoopingCall

from asleep import asleep
from leader import Leader
from worker import Worker


class StaleMembershipEntryException(Exception):
    pass


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
    LEADER_KEY = 'service/voltha/leader'

    MEMBERSHIP_PREFIX = 'service/voltha/members/'
    ASSIGNMENT_PREFIX = 'service/voltha/assignments/'
    WORKLOAD_PREFIX = 'service/voltha/work/'

    # Public methods:

    def __init__(self,
                 internal_host_address,
                 external_host_address,
                 instance_id,
                 rest_port,
                 consul='localhost:8500',
                 leader_class=Leader):

        self.retries = 0
        self.instance_id = instance_id
        self.internal_host_address = internal_host_address
        self.external_host_address = external_host_address
        self.rest_port = rest_port
        self.membership_record_key = self.MEMBERSHIP_PREFIX + self.instance_id

        self.session_id = None
        self.i_am_leader = False
        self.leader_id = None  # will be the instance id of the current leader
        self.shutting_down = False
        self.leader = None

        self.worker = Worker(self.instance_id, self)

        self.log = get_logger()
        self.log.info('initializing-coordinator')

        host = consul.split(':')[0].strip()
        port = int(consul.split(':')[1].strip())

        # TODO need to handle reconnect events properly
        self.consul = Consul(host=host, port=port)

        reactor.callLater(0, self._async_init)
        self.log.info('initialized-coordinator')

        self.wait_for_leader_deferreds = []

    @inlineCallbacks
    def shutdown(self):
        self.shutting_down = True
        yield self._delete_session()  # this will delete the leader lock too
        yield self.worker.halt()
        if self.leader is not None:
            yield self.leader.halt()
            self.leader = None

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

    # Proxy methods for consul with retry support

    def kv_get(self, *args, **kw):
        return self._retry(self.consul.kv.get, *args, **kw)

    def kv_put(self, *args, **kw):
        return self._retry(self.consul.kv.put, *args, **kw)

    def kv_delete(self, *args, **kw):
        return self._retry(self.consul.kv.delete, *args, **kw)

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
        self.log.error(msg, retry_in=wait_time)
        return asleep(wait_time)

    def _clear_backoff(self):
        if self.retries:
            self.log.info('reconnected-to-consul', after_retries=self.retries)
            self.retries = 0

    @inlineCallbacks
    def _create_session(self):

        @inlineCallbacks
        def _renew_session():
            try:
                result = yield self.consul.session.renew(
                    session_id=self.session_id)
                self.log.debug('just renewed session', result=result)
            except Exception, e:
                self.log.exception('could-not-renew-session', e=e)

        @inlineCallbacks
        def _create_session():

            # create consul session
            self.session_id = yield self.consul.session.create(
                behavior='delete', ttl=10, lock_delay=1)
            self.log.info('created-consul-session', session_id=self.session_id)

            # start renewing session it 3 times within the ttl
            lc = LoopingCall(_renew_session)
            lc.start(3)

        yield self._retry(_create_session)

    @inlineCallbacks
    def _delete_session(self):
        yield self.consul.session.destroy(self.session_id)

    @inlineCallbacks
    def _create_membership_record(self):
        yield self._retry(self._do_create_membership_record)
        reactor.callLater(0, self._maintain_membership_record)

    @inlineCallbacks
    def _do_create_membership_record(self):
        result = yield self.consul.kv.put(
            self.membership_record_key, 'alive',
            acquire=self.session_id)
        if not result:
            raise StaleMembershipEntryException(self.instance_id)

    @inlineCallbacks
    def _maintain_membership_record(self):
        index = None
        try:
            while 1:
                (index, record) = yield self._retry(self.consul.kv.get,
                                                    self.membership_record_key,
                                                    index=index)
                self.log.debug('membership-record-change-detected',
                               index=index, record=record)
                if record is None or record['Session'] != self.session_id:
                    self.log.debug('remaking-membership-record')
                    yield self._retry(self._do_create_membership_record)

        except Exception, e:
            self.log.exception('unexpected-error-leader-trackin', e=e)

        finally:
            # except in shutdown, the loop must continue (after a short delay)
            if not self.shutting_down:
                reactor.callLater(0.1, self._maintain_membership_record)

    def _start_leader_tracking(self):
        reactor.callLater(0, self._leadership_tracking_loop)

    @inlineCallbacks
    def _leadership_tracking_loop(self):

        try:

            # Attempt to acquire leadership lock. True indicates success;
            # False indicates there is already a leader. It's instance id
            # is then the value under the leader key service/voltha/leader.

            # attempt acquire leader lock
            self.log.debug('leadership-attempt')
            result = yield self._retry(self.consul.kv.put,
                                       self.LEADER_KEY,
                                       self.instance_id,
                                       acquire=self.session_id)

            # read it back before being too happy; seeing our session id is a
            # proof and now we have the change id that we can use to reliably
            # track any changes. In an unlikely scenario where the leadership
            # key gets wiped out administratively since the previous line,
            # the returned record can be None. Handle it.
            (index, record) = yield self._retry(self.consul.kv.get,
                                                self.LEADER_KEY)
            self.log.debug('leadership-key',
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

            # using consul's watch feature, start tracking any changes to key
            last = record
            while last is not None:
                # this shall return only when update is made to leader key
                (index, updated) = yield self._retry(self.consul.kv.get,
                                                     self.LEADER_KEY,
                                                     index=index)
                self.log.debug('leader-key-change',
                               index=index, updated=updated)
                if updated is None or updated != last:
                    # leadership has changed or vacated (or forcefully
                    # removed), apply now
                    break
                last = updated

        except Exception, e:
            self.log.exception('unexpected-error-leader-trackin', e=e)

        finally:
            # except in shutdown, the loop must continue (after a short delay)
            if not self.shutting_down:
                reactor.callLater(1, self._leadership_tracking_loop)

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
        self.log.info('became-leader')
        self.leader = Leader(self)
        return self.leader.start()

    def _just_lost_leadership(self):
        self.log.info('lost-leadership')
        return self._halt_leader()

    def _halt_leader(self):
        d = self.leader.halt()
        self.leader = None
        return d

    @inlineCallbacks
    def _retry(self, func, *args, **kw):
        while 1:
            try:
                result = yield func(*args, **kw)
                self._clear_backoff()
                break
            except ConsulException, e:
                yield self._backoff('consul-not-up')
            except ConnectionError, e:
                yield self._backoff('cannot-connect-to-consul')
            except StaleMembershipEntryException, e:
                yield self._backoff('stale-membership-record-in-the-way')
            except Exception, e:
                if not self.shutting_down:
                    self.log.exception(e)
                yield self._backoff('unknown-error')

        returnValue(result)
