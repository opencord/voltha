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

"""Temp client code to test grpc server"""

import grpc

from voltha.northbound.grpc import pb2_loader
from voltha.core.protos import voltha_pb2


def run():
    channel = grpc.insecure_channel('localhost:50055')
    stub = voltha_pb2.HealthServiceStub(channel)
    response = stub.GetHealthStatus(voltha_pb2.NullMessage())
    print 'Health state:', response.state

if __name__ == '__main__':
    run()
