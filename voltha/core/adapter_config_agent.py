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
Singleton agent responsible for managing adapter config
"""
import structlog
from twisted.internet.defer import inlineCallbacks

from voltha.core.config.config_proxy import CallbackType
from voltha.registry import registry


class AdapterConfigAgent(object):
    __instance = None

    def __new__(cls, core):
        if cls.__instance == None:
            cls.__instance = object.__new__(cls, core)
            cls.__instance.__sealed = False
        return cls.__instance

    def __init__(self, core):
        if self.__sealed == True:
            return
        self.core = core
        self.root_proxy = self.core.get_proxy('/')
        self.self_proxies = {}
        self.__sealed = True

        self.log = structlog.get_logger()

    def add_adapter_config(self, adapter_config):
        self.log.debug('starting')

        self.self_proxies[adapter_config.id] = self.core.get_proxy(
            '/adapters/{}'.format(adapter_config.id))

        self.self_proxies[adapter_config.id].register_callback(
            CallbackType.PRE_UPDATE, self._review_adapter_config)
        self.self_proxies[adapter_config.id].register_callback(
            CallbackType.POST_UPDATE, self._process_adapter_config)

        # The device specific adapters ADD the adapter config when 
        # the adapter is initialized the first time. 
        # We do not want to call _process_adapter_config in this 
        # case as this would recursively go and update config
        # for the adapter in that case.
        # We will just register the callbacks that need to get
        # invoked when the adapter config is updated.

        self.log.info('started')

    def _review_adapter_config(self, adapter_config=None):
        # Make sure the update is restricted to the AdapterConfig
        # Any inadvertant attempt to modify the vendor and version
        # of the adapter should not be allowed.
        if adapter_config.id in self.self_proxies.keys():
            current_config = self.self_proxies[adapter_config.id].get()
            adapter_config.vendor = current_config.vendor
            adapter_config.version = current_config.version

    @inlineCallbacks
    def _process_adapter_config(self, adapter_config):
        adapter_agent = registry('adapter_loader').get_agent(adapter_config.id)
        yield adapter_agent.update_adapter_config(adapter_config)
