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


class Coordinator(object):

    CONNECT_RETRY_INTERVAL_SEC = 1
    RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]

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

        self.session_id = None
        self.i_am_leader = False

        self.log = get_logger()
        self.log.info('initializing-coordinator')

        host = consul.split(':')[0].strip()
        port = int(consul.split(':')[1].strip())

        # TODO need to handle reconnect events properly
        self.consul = Consul(host=host, port=port)

        reactor.callLater(0, self.async_init)
        self.log.info('initialized-coordinator')

    @inlineCallbacks
    def shutdown(self):
        yield self.delete_session()

    @inlineCallbacks
    def async_init(self):
        yield self.create_session()
        yield self.create_membership_record()
        yield self.elect_leader()

    def backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries,
                                           len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        self.log.error(msg + ', retrying in %s second(s)' % wait_time)
        return asleep(wait_time)

    def clear_backoff(self):
        if self.retries:
            self.log.info('Reconnected to consul agent after %d retries'
                          % self.retries)
            self.retries = 0

    @inlineCallbacks
    def kv_put(self, key, value, retry=True):
        while 1:
            try:
                response = yield self.consul.kv.put(key, value)
                self.clear_backoff()
                returnValue(response)

            except ConsulException, e:
                if retry:
                    yield self.backoff('Consul not yet up')
                else:
                    raise e
            except ConnectionError, e:
                if retry:
                    yield self.backoff('Cannot connect to consul agent')
                else:
                    raise e
            except Exception, e:
                self.log.exception(e)
                if retry:
                    yield self.backoff('Unknown error')
                else:
                    raise e

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
                behavior='delete', ttl=10)
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
        # create ephemeral k/v registering this instance in the
        # service/voltha/members/<instance-id> node
        result = yield self.consul.kv.put(
            'service/voltha/members/%s' % self.instance_id, 'alive',
            acquire=self.session_id)
        assert result is True

    @inlineCallbacks
    def elect_leader(self):
        """
        Attempt to become the leader by acquiring the leader key and
        track the leader anyway
        """

        # attempt acquire leader lock
        result = yield self.consul.kv.put('service/voltha/leader',
                                          self.instance_id,
                                          acquire=self.session_id)

        # read it back before being too happy; seeing our session id is a
        # proof and now we have the change id that we can use to reliably
        # track any changes

        # TODO continue from here !!!
        if result is True:
            self.i_am_leader = True

    @inlineCallbacks
    def _retry(self, func, *args, **kw):
        while 1:
            try:
                result = yield func(*args, **kw)
                break
            except ConsulException, e:
                yield self.backoff('Consul not yet up')
            except ConnectionError, e:
                yield self.backoff('Cannot connect to consul agent')
            except Exception, e:
                self.log.exception(e)
                yield self.backoff('Unknown error')

        returnValue(result)
