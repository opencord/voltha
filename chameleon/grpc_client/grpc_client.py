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
gRPC client meant to connect to a gRPC server endpoint,
and query the end-point's schema by calling
SchemaService.Schema(NullMessage) and all of its
semantics are derived from the recovered schema.
"""
import os
import sys
from random import randint
from zlib import decompress

import grpc
from consul import Consul
from structlog import get_logger

from chameleon.protos.schema_pb2 import NullMessage, SchemaServiceStub

log = get_logger()


class GrpcClient(object):

    def __init__(self, consul_endpoint, work_dir, endpoint='localhost:50055'):
        self.consul_endpoint = consul_endpoint
        self.endpoint = endpoint
        self.work_dir = work_dir
        self.plugin_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '../protoc_plugins'))

        self.channel = None
        self.schema = None

        self.shutting_down = False

    def run(self):
        self.connect()
        return self

    def shutdown(self):
        if self.shutting_down:
            return
        self.shutting_down = True
        pass

    def connect(self):
        """(re-)connect to end-point"""
        if self.shutting_down:
            return

        try:
            if self.endpoint.startswith('@'):
                _endpoint = self.get_endpoint_from_consul(self.endpoint[1:])
            else:
                _endpoint = self.endpoint

            log.info('connecting', endpoint=_endpoint)
            self.channel = grpc.insecure_channel(_endpoint)

            self._retrieve_schema()
            self._compile_proto_files()

        except Exception, e:
            log.exception('cannot-connect', endpoint=_endpoint)

    def get_endpoint_from_consul(self, service_name):
        """Look up an appropriate grpc endpoint (host, port) from
           consul, under the service name specified by service-name
        """
        host = self.consul_endpoint.split(':')[0].strip()
        port = int(self.consul_endpoint.split(':')[1].strip())

        consul = Consul(host=host, port=port)
        _, services = consul.catalog.service(service_name)

        if len(services) == 0:
            raise Exception('Cannot find service %s in consul' % service_name)

        # pick a random entry
        # TODO should we prefer local IP addresses? Probably.

        service = services[randint(0, len(services) - 1)]
        endpoint = '{}:{}'.format(service['ServiceAddress'],
                                  service['ServicePort'])
        return endpoint

    def _retrieve_schema(self):
        """Retrieve schema from gRPC end-point"""
        assert isinstance(self.channel, grpc.Channel)
        stub = SchemaServiceStub(self.channel)
        schema = stub.GetSchema(NullMessage())

        os.system('mkdir -p %s' % self.work_dir)
        os.system('rm -fr /tmp/%s/*' %
                  self.work_dir.replace('/tmp/', ''))  # safer

        for fname in schema.protos:
            content = schema.protos[fname]
            log.debug('saving-proto',
                      fname=fname, dir=self.work_dir, length=len(content))
            with open(os.path.join(self.work_dir, fname), 'w') as f:
                f.write(content)

        for fname in schema.descriptors:
            content = decompress(schema.descriptors[fname])
            log.debug('saving-descriptor',
                      fname=fname, dir=self.work_dir, length=len(content))
            with open(os.path.join(self.work_dir, fname), 'wb') as f:
                f.write(content)

    def _compile_proto_files(self):

        google_api_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__),
            '../protos/third_party'
        ))

        for fname in [f for f in os.listdir(self.work_dir)
                      if f.endswith('.proto')]:
            log.info('compiling', file=fname)

            cmd = (
                'cd %s && '
                'env PATH=%s '
                'python -m grpc.tools.protoc '
                '-I. '
                '-I%s '
                '--python_out=. '
                '--grpc_python_out=. '
                '--plugin=protoc-gen-gw=%s/gw_gen.py '
                '--gw_out=. '
                '%s' % (
                    self.work_dir,
                    ':'.join([os.environ['PATH'], self.plugin_dir]),
                    google_api_dir,
                    self.plugin_dir,
                    fname)
            )
            log.debug('executing', cmd=cmd)
            os.system(cmd)

        # test-load each _pb2 file to see all is right
        if self.work_dir not in sys.path:
            sys.path.insert(0, self.work_dir)

        for fname in [f for f in os.listdir(self.work_dir)
                      if f.endswith('_pb2.py')]:
            modname = fname[:-len('.py')]
            log.debug('test-import', modname=modname)
            _ = __import__(modname)

    def invoke(self, stub, method_name, request):
        response = getattr(stub(self.channel), method_name)(request)
        return response
