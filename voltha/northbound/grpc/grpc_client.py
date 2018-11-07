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

"""Temp client code to test grpc server"""

import grpc

from voltha.protos import schema_pb2, schema_pb2_grpc
from voltha.protos import voltha_pb2, voltha_pb2_grpc
from voltha.protos import health_pb2_grpc
from google.protobuf.empty_pb2 import Empty


def run():

    channel = grpc.insecure_channel('localhost:50055')

    # Test fetch the schema
    stub = schema_pb2_grpc.SchemaServiceStub(channel)
    res = stub.GetSchema(Empty())
    print '\nSchema:\n'
    for key in res.protos:
        print '%s %s file begins %s\n' % (30 * '~', key, (35 - len(key)) * '~')
        print res.protos[key]
        print '%s %s file ends %s' % (30 * '~', key, (37 - len(key)) * '~')
    for key in res.descriptors:
        print '%s -> descriptor of %d bytes' % (key, len(res.descriptors[key]))

    # Ping health state as an example
    stub = health_pb2_grpc.HealthServiceStub(channel)
    res = stub.GetHealthStatus(Empty())
    print '\nHealth state:', res.state

    # Try another API
    stub = voltha_pb2_grpc.ExampleServiceStub(channel)
    res = stub.ListAddresses(Empty())
    print '\nExample objects returned:\n', res.addresses

if __name__ == '__main__':
    run()
