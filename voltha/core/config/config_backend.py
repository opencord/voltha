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
from consul import Consul

import structlog

log = structlog.get_logger()


class ConsulStore(object):
    """ Config kv store for consul with a cache for quicker subsequent reads

        TODO: This will block the reactor. Should either change
        whole call stack to yield or put the put/delete transactions into a
        queue to write later with twisted. Will need a transaction
        log to ensure we don't lose anything.
        Making the whole callstack yield is troublesome because other tasks can
        come in on the side and start modifying things which could be bad.
    """

    def __init__(self, host, port, path_prefix):
        self._consul = Consul(host=host, port=port)
        self._path_prefix = path_prefix
        self._cache = {}

    def make_path(self, key):
        return '{}/{}'.format(self._path_prefix, key)

    def __getitem__(self, key):
        if key in self._cache:
            return self._cache[key]
        index, value = self._consul.kv.get(self.make_path(key))
        if value is not None:
            # consul turns empty strings to None, so we do the reverse here
            self._cache[key] = value['Value'] or ''
            return value['Value'] or ''
        else:
            raise KeyError(key)

    def __contains__(self, key):
        if key in self._cache:
            return True
        index, value = self._consul.kv.get(self.make_path(key))
        if value is not None:
            self._cache[key] = value['Value']
            return True
        else:
            return False

    def __setitem__(self, key, value):
        try:
            assert isinstance(value, basestring)
            self._cache[key] = value
            self._consul.kv.put(self.make_path(key), value)
        except Exception, e:
            log.exception('cannot-set-item', e=e)

    def __delitem__(self, key):
        self._cache.pop(key, None)
        self._consul.kv.delete(self.make_path(key))


def load_backend(store_id, store_prefix, args):
    """ Return the kv store backend based on the command line arguments
    """
    # TODO: Make this more dynamic

    def load_consul_store():
        instance_core_store_prefix = '{}/{}'.format(store_prefix, store_id)

        host, port = args.consul.split(':', 1)
        return ConsulStore(host, int(port), instance_core_store_prefix)

    loaders = {
        'none': lambda: None,
        'consul': load_consul_store
    }

    return loaders[args.backend]()
