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
from zope.interface import implementer
from zope.interface.verify import verifyClass

from voltha.adapters.interface import IAdapterInterface
from voltha.core.adapter_agent import AdapterAgent
from voltha.registry import IComponent
from voltha.adapters.iadapter import IAdapter, OltAdapter, OnuAdapter

log = structlog.get_logger()


mydir = os.path.abspath(os.path.dirname(__file__))


@implementer(IComponent)
class AdapterLoader(object):

    def __init__(self, config):
        self.config = config
        self.adapter_agents = {}  # adapter-name -> adapter instance

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        for adapter_name, adapter_class in self._find_adapters():
            agent = AdapterAgent(adapter_name, adapter_class)
            yield agent.start()
            self.adapter_agents[adapter_name] = agent
        log.info('started')
        returnValue(self)

    @inlineCallbacks
    def stop(self):
        log.debug('stopping')
        for proxy in self.adapter_agents.values():
            yield proxy.stop()
        self.adapter_agents = {}
        log.info('stopped')

    def get_agent(self, adapter_name):
        return self.adapter_agents[adapter_name]

    def _find_adapters(self):
        subdirs = os.walk(mydir).next()[1]
        for subdir in subdirs:
            try:
                adapter_name = subdir
                py_file = os.path.join(mydir, subdir, subdir + '.py')
                if os.path.isfile(py_file):
                    try:
                        package_name = __package__ + '.' + subdir
                        pkg = __import__(package_name, None, None, [adapter_name])
                        module = getattr(pkg, adapter_name)
                    except ImportError, e:
                        log.exception('cannot-load', file=py_file, e=e)
                        continue

                    for attr_name in dir(module):
                        cls = getattr(module, attr_name)
                        if isinstance(cls, type) and \
                                cls is not IAdapter and \
                                cls is not OltAdapter and \
                                cls is not OnuAdapter and \
                                IAdapterInterface.implementedBy(cls):
                            verifyClass(IAdapterInterface, cls)
                            if cls.__module__.rsplit('.', 1)[0] != package_name:
                                continue

                            yield adapter_name, cls
            except Exception, e:
                log.exception('failed', e=e)
