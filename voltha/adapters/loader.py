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

"""
Loader to load each adapter.
In this initial simple implementation we scan all subdirs in this directory,
look for a python module with the same name as the subdir, and if module
has a class that implements the IAdapterInterface, instantiate class and
add it to plugins.
"""
import os

import structlog
from twisted.internet.defer import inlineCallbacks, returnValue
from zope.interface.verify import verifyClass

from voltha.adapters.interface import IAdapterInterface
from voltha.northbound.grpc.grpc_server import get_nbi_server
from voltha.protos.adapter_pb2 import add_AdapterServiceServicer_to_server, \
    AdapterServiceServicer, Adapters

log = structlog.get_logger()


mydir = os.path.abspath(os.path.dirname(__file__))


class AdapterLoader(AdapterServiceServicer):

    def __init__(self, config):
        self.config = config
        self.adapters = {}  # adapter-name -> adapter instance
        get_nbi_server().register(add_AdapterServiceServicer_to_server, self)

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        for adapter_name, adapter_class in self.find_adapters():
            config = self.load_adapter_config(adapter_name)
            adapter = adapter_class(config)
            yield adapter.start()
            self.adapters[adapter_name] = adapter
        log.info('started')
        returnValue(self)

    @inlineCallbacks
    def stop(self):
        log.debug('stopping')
        for adapter in self.adapters.values():
            yield adapter.stop()
        self.adapters = {}
        log.info('stopped')

    def find_adapters(self):
        subdirs = os.walk(mydir).next()[1]
        for subdir in subdirs:
            adapter_name = subdir
            py_file = os.path.join(mydir, subdir, subdir + '.py')
            if os.path.isfile(py_file):
                try:
                    package_name = __package__ + '.' + subdir
                    pkg = __import__(package_name, None, None, [adapter_name])
                    module = getattr(pkg, adapter_name)
                except ImportError, e:
                    log.warn('cannot-load', file=py_file, e=e)
                    continue

                for attr_name in dir(module):
                    cls = getattr(module, attr_name)
                    if isinstance(cls, type) and \
                            IAdapterInterface.implementedBy(cls):
                        verifyClass(IAdapterInterface, cls)
                        yield adapter_name, cls


    def load_adapter_config(self, adapter_name):
        """
        Opportunistically load persisted adapter configuration
        :param adapter_name: name of adapter
        :return: AdapterConfig
        """
        # TODO

    # gRPC service method implementations. BE CAREFUL; THESE ARE CALLED ON
    # the gRPC threadpool threads.

    def ListAdapters(self, request, context):
        log.info('list-adapters', request=request)
        items = [a.adapter_descriptor() for a in self.adapters.itervalues()]
        return Adapters(items=items)
