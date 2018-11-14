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
from consul import Consul, ConsulException
from common.utils.asleep import asleep
from requests import ConnectionError
from twisted.internet.defer import inlineCallbacks, returnValue

import etcd3
import structlog


class ConsulStore(object):
    """ Config kv store for consul with a cache for quicker subsequent reads

        TODO: This will block the reactor. Should either change
        whole call stack to yield or put the put/delete transactions into a
        queue to write later with twisted. Will need a transaction
        log to ensure we don't lose anything.
        Making the whole callstack yield is troublesome because other tasks can
        come in on the side and start modifying things which could be bad.
    """

    CONNECT_RETRY_INTERVAL_SEC = 1
    RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]

    def __init__(self, host, port, path_prefix):

        self.log = structlog.get_logger()
        self._consul = Consul(host=host, port=port)
        self.host = host
        self.port = port
        self._path_prefix = path_prefix
        self._cache = {}
        self.retries = 0

    def make_path(self, key):
        return '{}/{}'.format(self._path_prefix, key)

    def __getitem__(self, key):
        if key in self._cache:
            return self._cache[key]
        value = self._kv_get(self.make_path(key))
        if value is not None:
            # consul turns empty strings to None, so we do the reverse here
            self._cache[key] = value['Value'] or ''
            return value['Value'] or ''
        else:
            raise KeyError(key)

    def __contains__(self, key):
        if key in self._cache:
            return True
        value = self._kv_get(self.make_path(key))
        if value is not None:
            self._cache[key] = value['Value']
            return True
        else:
            return False

    def __setitem__(self, key, value):
        try:
            assert isinstance(value, basestring)
            self._cache[key] = value
            self._kv_put(self.make_path(key), value)
        except Exception, e:
            self.log.exception('cannot-set-item', e=e)

    def __delitem__(self, key):
        self._cache.pop(key, None)
        self._kv_delete(self.make_path(key))

    @inlineCallbacks
    def _backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries,
                                           len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        self.log.error(msg, retry_in=wait_time)
        yield asleep(wait_time)

    def _redo_consul_connection(self):
        self._consul = Consul(host=self.host, port=self.port)
        self._cache.clear()

    def _clear_backoff(self):
        if self.retries:
            self.log.info('reconnected-to-consul', after_retries=self.retries)
            self.retries = 0

    def _get_consul(self):
        return self._consul

    # Proxy methods for consul with retry support
    def _kv_get(self, *args, **kw):
        return self._retry('GET', *args, **kw)

    def _kv_put(self, *args, **kw):
        return self._retry('PUT', *args, **kw)

    def _kv_delete(self, *args, **kw):
        return self._retry('DELETE', *args, **kw)

    def _retry(self, operation, *args, **kw):
        while 1:
            try:
                consul = self._get_consul()
                self.log.debug('consul', consul=consul, operation=operation,
                         args=args)
                if operation == 'GET':
                    index, result = consul.kv.get(*args, **kw)
                elif operation == 'PUT':
                     result = consul.kv.put(*args, **kw)
                elif operation == 'DELETE':
                    result = consul.kv.delete(*args, **kw)
                else:
                    # Default case - consider operation as a function call
                    result = operation(*args, **kw)
                self._clear_backoff()
                break
            except ConsulException, e:
                self.log.exception('consul-not-up', e=e)
                self._backoff('consul-not-up')
            except ConnectionError, e:
                self.log.exception('cannot-connect-to-consul', e=e)
                self._backoff('cannot-connect-to-consul')
            except Exception, e:
                self.log.exception(e)
                self._backoff('unknown-error')
            self._redo_consul_connection()

        return result


class EtcdStore(object):
    """ Config kv store for etcd with a cache for quicker subsequent reads

        TODO: This will block the reactor. Should either change
        whole call stack to yield or put the put/delete transactions into a
        queue to write later with twisted. Will need a transaction
        log to ensure we don't lose anything.
        Making the whole callstack yield is troublesome because other tasks can
        come in on the side and start modifying things which could be bad.
    """

    CONNECT_RETRY_INTERVAL_SEC = 1
    RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]

    def __init__(self, host, port, path_prefix):

        self.log = structlog.get_logger()
        self._etcd = etcd3.client(host=host, port=port)
        self.host = host
        self.port = port
        self._path_prefix = path_prefix
        self._cache = {}
        self.retries = 0

    def make_path(self, key):
        return '{}/{}'.format(self._path_prefix, key)

    def __getitem__(self, key):
        if key in self._cache:
            return self._cache[key]
        (value, meta) = self._kv_get(self.make_path(key))
        if value is not None:
            self._cache[key] = value
            return value
        else:
            raise KeyError(key)

    def __contains__(self, key):
        if key in self._cache:
            return True
        (value, meta) = self._kv_get(self.make_path(key))
        if value is not None:
            self._cache[key] = value
            return True
        else:
            return False

    def __setitem__(self, key, value):
        try:
            assert isinstance(value, basestring)
            self._cache[key] = value
            self._kv_put(self.make_path(key), value)
        except Exception, e:
            self.log.exception('cannot-set-item', e=e)

    def __delitem__(self, key):
        self._cache.pop(key, None)
        self._kv_delete(self.make_path(key))

    @inlineCallbacks
    def _backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries,
                                           len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        self.log.error(msg, retry_in=wait_time)
        yield asleep(wait_time)

    def _redo_etcd_connection(self):
        self._etcd = etcd3.client(host=self.host, port=self.port)
        self._cache.clear()

    def _clear_backoff(self):
        if self.retries:
            self.log.info('reconnected-to-etcd', after_retries=self.retries)
            self.retries = 0

    def _get_etcd(self):
        return self._etcd

    # Proxy methods for etcd with retry support
    def _kv_get(self, *args, **kw):
        return self._retry('GET', *args, **kw)

    def _kv_put(self, *args, **kw):
        return self._retry('PUT', *args, **kw)

    def _kv_delete(self, *args, **kw):
        return self._retry('DELETE', *args, **kw)

    def _retry(self, operation, *args, **kw):

        # etcd data sometimes contains non-utf8 sequences, replace
        self.log.debug('backend-op',
                  operation=operation,
                  args=map(lambda x : unicode(x,'utf8','replace'), args),
                  kw=kw)

        while 1:
            try:
                etcd = self._get_etcd()
                self.log.debug('etcd', etcd=etcd, operation=operation,
                    args=map(lambda x : unicode(x,'utf8','replace'), args))
                if operation == 'GET':
                    (value, meta) = etcd.get(*args, **kw)
                    result = (value, meta)
                elif operation == 'PUT':
                    result = etcd.put(*args, **kw)
                elif operation == 'DELETE':
                    result = etcd.delete(*args, **kw)
                else:
                    # Default case - consider operation as a function call
                    result = operation(*args, **kw)
                self._clear_backoff()
                break
            except Exception, e:
                self.log.exception(e)
                self._backoff('unknown-error-with-etcd')
            self._redo_etcd_connection()

        return result


def load_backend(store_id, store_prefix, args):
    """ Return the kv store backend based on the command line arguments
    """

    def load_consul_store():
        instance_core_store_prefix = '{}/{}'.format(store_prefix, store_id)

        host, port = args.consul.split(':', 1)
        return ConsulStore(host, int(port), instance_core_store_prefix)

    def load_etcd_store():
        instance_core_store_prefix = '{}/{}'.format(store_prefix, store_id)

        host, port = args.etcd.split(':', 1)
        return EtcdStore(host, int(port), instance_core_store_prefix)

    loaders = {
        'none': lambda: None,
        'consul': load_consul_store,
        'etcd': load_etcd_store
    }

    return loaders[args.backend]()
