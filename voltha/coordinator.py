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
# We use https://github.com/cablehead/python-consul for consul client. It's master
# branch already provides support for Twisted, but the latest released version (0.6.1)
# was cut before twisted support was added. So keep an eye on when 0.6.2 comes out and
# move over to the twisted interface once it's available.

from consul import Consul, ConsulException
from requests import ConnectionError
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks

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

        self.log = get_logger()
        self.log.info('initializing-coordinator')

        host = consul.split(':')[0].strip()
        port = int(consul.split(':')[1].strip())
        self.consul = Consul(host=host, port=port)  # TODO need to handle reconnect events properly

        reactor.callLater(0, self.async_init)
        self.log.info('initialized-coordinator')

    @inlineCallbacks
    def async_init(self):
        yield self.kv_put('voltha/instances/%s/status' % self.instance_id, 'up')
        yield self.register()

    def backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries, len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        self.log.error(msg + ', retrying in %s second(s)' % wait_time)
        return asleep(wait_time)

    def clear_backoff(self):
        if self.retries:
            self.log.info('Reconnected to consul agent after %d retries' % self.retries)
            self.retries = 0

    @inlineCallbacks
    def kv_put(self, key, value, retry=True):
        while 1:
            try:
                self.consul.kv.put(key, value)
                self.clear_backoff()
                break
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
    def register(self, retry=True):
        while 1:
            try:
                kw = dict(
                    name='voltha-%s' % self.instance_id,
                    address=self.internal_host_address,
                    port=self.rest_port
                )
                self.consul.agent.service.register(**kw)
                self.log.info('registered-with-consul', **kw)
                break
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
