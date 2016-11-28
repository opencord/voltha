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
Dispatcher is responsible to dispatch incoming "global" gRPC requests
to the respective Voltha instance (leader, peer instance, local). Local
calls are forwarded to the LocalHandler.
"""
import structlog

from voltha.protos.voltha_pb2 import VolthaLocalServiceStub

log = structlog.get_logger()


class Dispatcher(object):

    def __init__(self, core, instance_id):
        self.core = core
        self.instance_id = instance_id
        self.local_handler = None

    def start(self):
        log.debug('starting')
        self.local_handler = self.core.get_local_handler()
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        log.info('stopped')

    def dispatch(self, instance_id, stub, method_name, input, context):
        log.debug('dispatch', instance_id=instance_id, stub=stub,
                  _method_name=method_name, input=input)
        # special case if instance_id is us
        if instance_id == self.instance_id:
            # for now, we assume it is always the local stub
            assert stub == VolthaLocalServiceStub
            method = getattr(self.local_handler, method_name)
            log.debug('dispatching', method=method)
            res = method(input, context=context)
            log.debug('dispatch-success', res=res)
            return res

        else:
            log.warning('no-real-dispatch-yet')
            raise KeyError()

    def instance_id_by_logical_device_id(self, logical_device_id):
        log.warning('temp-mapping-logical-device-id')
        # TODO no true dispatchong yet, we blindly map everything to self
        return self.instance_id

    def instance_id_by_device_id(self, device_id):
        log.warning('temp-mapping-logical-device-id')
        # TODO no true dispatchong yet, we blindly map everything to self
        return self.instance_id
