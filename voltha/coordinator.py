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

# TODO move this to the consul.twisted async client once it is available.
# Note:
# We use https://github.com/cablehead/python-consul for consul client.
# It's master branch already provides support for Twisted, but the latest
# released version (0.6.1) was cut before twisted support was added. So keep
# an eye on when 0.6.2 comes out and move over to the twisted interface once
# it's available.

from consul import ConsulException
from consul.twisted import Consul
from requests import ConnectionError
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.task import LoopingCall

from asleep import asleep


class StaleMembershipEntryException(Exception):
    pass


class Coordinator(object):

    CONNECT_RETRY_INTERVAL_SEC = 1
    RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]
    LEADER_KEY = 'service/voltha/leader'
    MEMBERSHIP_PREFIX = 'service/voltha/members/'

    def __init__(self,
                 internal_host_address,
                 external_host_address,
                 instance_id,
                 rest_port,
                 consul='localhost:8500'):

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

        self.log = get_logger()
        self.log.info('initializing-coordinator')

        host = consul.split(':')[0].strip()
        port = int(consul.split(':')[1].strip())

        # TODO need to handle reconnect events properly
        self.consul = Consul(host=host, port=port)

        reactor.callLater(0, self.async_init)
        self.log.info('initialized-coordinator')

    @inlineCallbacks
    def async_init(self):
        yield self.create_session()
        yield self.create_membership_record()
        yield self.start_leader_tracking()

    @inlineCallbacks
    def shutdown(self):
        self.shutting_down = True
        yield self.delete_session()  # this will delete the leader lock too

    def backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries,
                                           len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        self.log.error(msg, retry_in=wait_time)
        return asleep(wait_time)

    def clear_backoff(self):
        if self.retries:
            self.log.info('reconnected-to-consul', after_retries=self.retries)
            self.retries = 0

    @inlineCallbacks
    def create_session(self):

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
    def delete_session(self):
        yield self.consul.session.destroy(self.session_id)

    @inlineCallbacks
    def create_membership_record(self):
        yield self._retry(self._create_membership_record)
        reactor.callLater(0, self._maintain_membership_record)

    @inlineCallbacks
    def _create_membership_record(self):
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
                    yield self._create_membership_record()

        except Exception, e:
            self.log.exception('unexpected-error-leader-trackin', e=e)

        finally:
            # no matter what, the loop need to continue (after a short delay)
            reactor.callAfter(0.1, self._maintain_membership_record)

    def start_leader_tracking(self):
        reactor.callLater(0, self._leadership_tracking_loop)

    @inlineCallbacks
    def _leadership_tracking_loop(self):

        try:

            # Attempt to acquire leadership lock. True indicates success,
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
                        self._assert_leadership()
                    else:
                        pass  # confusion; need to retry leadership
                else:
                    leader_id = record['Value']
                    self._assert_nonleadership(leader_id)

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
            # no matter what, the loop need to continue (after a short delay)
            reactor.callLater(1, self._leadership_tracking_loop)

    def _assert_leadership(self):
        """(Re-)assert leadership"""
        if not self.i_am_leader:
            self.i_am_leader = True
            self.leader_id = self.instance_id
            self._just_gained_leadership()

    def _assert_nonleadership(self, leader_id):
        """(Re-)assert non-leader role"""

        # update leader_id anyway
        self.leader_id = leader_id

        if self.i_am_leader:
            self.i_am_leader = False
            self._just_lost_leadership()

    def _just_gained_leadership(self):
        self.log.info('became-leader')

    def _just_lost_leadership(self):
        self.log.info('lost-leadership')

    @inlineCallbacks
    def _retry(self, func, *args, **kw):
        while 1:
            try:
                result = yield func(*args, **kw)
                break
            except ConsulException, e:
                yield self.backoff('consul-not-upC')
            except ConnectionError, e:
                yield self.backoff('cannot-connect-to-consul')
            except StaleMembershipEntryException, e:
                yield self.backoff('stale-membership-record-in-the-way')
            except Exception, e:
                self.log.exception(e)
                yield self.backoff('unknown-error')

        returnValue(result)
