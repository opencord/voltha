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

import grpc
from grpc._channel import _Rendezvous


class GrpcClient(object):
    def __init__(self, log):
        self.channel = None
        self.connected = False
        self.log = log

    def connect(self, endpoint):
        if self.connected:
            return
        try:
            self.log.info('insecurely-connecting', endpoint=endpoint)
            self.channel = grpc.insecure_channel(endpoint)
            self.connected = True
            self.log.info('insecurely-connected', endpoint=endpoint)
            return

        except _Rendezvous, e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                self.log.info('grpc-endpoint-not-available')
            else:
                self.log.exception(e)

        except Exception, e:
            self.log.exception('cannot-connect', endpoint=endpoint)
