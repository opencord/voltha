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
Voltha's CORE components.
"""
import structlog
from zope.interface import implementer

from common.utils.grpc_utils import twisted_async
from voltha.core.config.config_root import ConfigRoot
from voltha.protos import third_party
from voltha.protos.voltha_pb2 import add_VolthaServiceServicer_to_server, \
    Voltha, VolthaServiceServicer
from voltha.registry import IComponent, registry

log = structlog.get_logger()


@implementer(IComponent)
class VolthaCore(VolthaServiceServicer):

    def __init__(self, **kw):

        self.stopped = False
        self.config_root = self._mk_config_root(**kw)
        registry('grpc_server').register(
            add_VolthaServiceServicer_to_server, self)

    def start(self):
        log.debug('starting')
        pass
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    def get_proxy(self, path, exclusive=False):
        return self.config_root.get_proxy(path, exclusive)

    def _mk_config_root(self, **kw):
        root_data = Voltha(**kw)
        return ConfigRoot(root_data)

    # gRPC service method implementations. BE CAREFUL; THESE ARE CALLED ON
    # the gRPC threadpool threads.

    @twisted_async
    def GetVoltha(self, request, context):
        log.info('get-voltha', request=request)
        return self.config_root.get('/', deep=1)
