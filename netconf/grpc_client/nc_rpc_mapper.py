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
from netconf.constants import Constants as C

log = get_logger()


class NetconfRPCMapper:
    # Keeps the mapping between a Netconf RPC request and a voltha GPRC
    # request.  Singleton class.


    instance = None

    def __init__(self, work_dir, grpc_client):
        self.work_dir = work_dir
        self.grpc_client = grpc_client
        self.rpc_map = {}
        self.yang_defs = {}

    def _add_rpc_map(self, func_name, func_ref):
        if not self.rpc_map.has_key(func_name):
            log.debug('adding-function', name=func_name, ref=func_ref)
            self.rpc_map[func_name] = func_ref

    def _add_module_rpc(self, mod):
        for name, ref in self.list_functions(mod):
            self._add_rpc_map(name, ref)

    def _add_m(self, mod):
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

        # load the yang definition
        for fname in [f for f in os.listdir(self.work_dir)
                      if f.endswith(C.YANG_MESSAGE_DEFINITIONS_FILE)]:
            modname = fname[:-len('.py')]
            try:
                m = __import__(modname)
                for name, ref in self.list_functions(m):
                    self.yang_defs[name] = ref
            except Exception, e:
                log.exception('loading-yang-module-exception', modname=modname,
                              e=e)

    def get_fields_from_yang_defs(self, service, method):
        # Get the return type of that method
        func_name = self._get_function_name(service, method)
        return_type_func_name = ''.join(['get_return_type_', func_name])
        if self.rpc_map.has_key(return_type_func_name):
            type_name = self.rpc_map[return_type_func_name]()
            log.info('get-yang-defs', type_name=type_name, service=service,
                     method=method)
            if type_name:
                # Type name is in the form "<package-name>_pb2".<message_name>
                name = type_name.split('.')
                if len(name) == 2:
                    package = name[0][:-len('_pb2')]
                    message_name = name[1]
                    if self.yang_defs.has_key('get_fields'):
                        return self.yang_defs['get_fields'](package,
                                                            message_name)
                else:
                    log.info('Incorrect-type-format', type_name=type_name,
                             service=service,
                             method=method)
        return None

    def get_fields_from_type_name(self, module_name, type_name):
        if self.yang_defs.has_key('get_fields'):
            return self.yang_defs['get_fields'](module_name,
                                                type_name)

    def get_function(self, service, method):

        func_name = self._get_function_name(service, method)

        if self.rpc_map.has_key(func_name):
            return self.rpc_map[func_name]
        else:
            return None

    def get_xml_tag(self, service, method):
        func_name = self._get_function_name(service, method)
        xml_tag_func_name = ''.join(['get_xml_tag_', func_name])
        if self.rpc_map.has_key(xml_tag_func_name):
            tag = self.rpc_map[xml_tag_func_name]()
            if tag == '':
                return None
            else:
                return tag
        else:
            return None

    def get_list_items_name(self, service, method):
        func_name = self._get_function_name(service, method)
        list_items_name = ''.join(['get_list_items_name_', func_name])
        if self.rpc_map.has_key(list_items_name):
            name = self.rpc_map[list_items_name]()
            if name == '':
                return None
            else:
                return name
        else:
            return None

    def is_rpc_exist(self, rpc_name):
        return self.rpc_map.has_key(rpc_name)

    def _get_function_name(self, service, method):
        if service:
            return ''.join([service, '_', method])
        else:
            return method


def get_nc_rpc_mapper_instance(work_dir=None, grpc_client=None):
    if NetconfRPCMapper.instance == None:
        NetconfRPCMapper.instance = NetconfRPCMapper(work_dir, grpc_client)
    return NetconfRPCMapper.instance
