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
import os
import sys
import inspect
from structlog import get_logger

log = get_logger()


class NetconfRPCMapper:
    # Keeps the mapping between a Netconf RPC request and a voltha GPRC
    # request.  Singleton class.


    instance = None

    def __init__(self, work_dir, grpc_client):
        self.work_dir = work_dir
        self.grpc_client = grpc_client
        self.rpc_map = {}

    def _add_rpc_map(self, func_name, func_ref):
        if not self.rpc_map.has_key(func_name):
            log.debug('adding-function', name=func_name, ref=func_ref)
            self.rpc_map[func_name] = func_ref

    def _add_module_rpc(self, mod):
        for name, ref in self.list_functions(mod):
            self._add_rpc_map(name, ref)

    def is_mod_function(self, mod, func):
        return inspect.isfunction(func) and inspect.getmodule(func) == mod

    def list_functions(self, mod):
        return [(func.__name__, func) for func in mod.__dict__.itervalues()
                if self.is_mod_function(mod, func)]

    def load_modules(self):
        if self.work_dir not in sys.path:
            sys.path.insert(0, self.work_dir)

        for fname in [f for f in os.listdir(self.work_dir)
                      if f.endswith('_rpc_gw.py')]:
            modname = fname[:-len('.py')]
            log.debug('load-modules', modname=modname)
            try:
                m = __import__(modname)
                self._add_module_rpc(m)
            except Exception, e:
                log.exception('loading-module-exception', modname=modname, e=e)

    def get_function(self, service, method):
        if service:
            func_name = ''.join([service, '_', method])
        else:
            func_name = method

        if self.rpc_map.has_key(func_name):
            return self.rpc_map[func_name]
        else:
            return None

    def is_rpc_exist(self, rpc_name):
        return self.rpc_map.has_key(rpc_name)


def get_nc_rpc_mapper_instance(work_dir=None, grpc_client=None):
    if NetconfRPCMapper.instance == None:
        NetconfRPCMapper.instance = NetconfRPCMapper(work_dir, grpc_client)
    return NetconfRPCMapper.instance
