#!/usr/bin/env python
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

import os

from klein import Klein
from simplejson import dumps, load
from structlog import get_logger
from twisted.internet import reactor, endpoints
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.tcp import Port
from twisted.web.server import Site
from twisted.web.static import File

log = get_logger()

'''
## To be automated as part of the template
from voltha.protos.voltha_pb2 import *
from protobuf_to_dict import protobuf_to_dict, dict_to_protobuf

def add_routes(app, grpc_client):

    @app.route('/health', methods=['GET'])
    def get_health(server, request):
        log.debug('get-health-req', request=request, server=server)
        req = NullMessage()
        res = grpc_client.invoke(
            HealthServiceStub, 'GetHealthStatus', req)
        data = protobuf_to_dict(res, use_enum_labels=True)
        request.setHeader('Content-Type', 'application/json')
        log.debug('get-health-res', **data)
        return dumps(data)

    @app.route('/addresses', methods=['GET'])
    def list_addresses(server, request):
        log.debug('list-addresses-req', request=request, server=server)
        req = NullMessage()
        res = grpc_client.invoke(
            ExampleServiceStub, 'ListAddresses', req)
        data = protobuf_to_dict(res, use_enum_labels=True)
        request.setHeader('Content-Type', 'application/json')
        log.debug('list-addresses-res', **data)
        return dumps(data)

    @app.route('/addresses/<string:id>', methods=['GET'])
    def get_address(server, request, id):
        log.debug('get-address-req', request=request, server=server, id=id)
        req = ID(id=id)
        res = grpc_client.invoke(
            ExampleServiceStub, 'GetAddress', req)
        data = protobuf_to_dict(res, use_enum_labels=True)
        request.setHeader('Content-Type', 'application/json')
        log.debug('get-address-res', **data)
        return dumps(data)

    @app.route('/addresses/<string:id>', methods=['DELETE'])
    def delete_address(server, request, id):
        log.debug('delete-address-req', request=request, server=server, id=id)
        req = ID(id=id)
        res = grpc_client.invoke(
            ExampleServiceStub, 'DeleteAddress', req)
        data = protobuf_to_dict(res, use_enum_labels=True)
        request.setHeader('Content-Type', 'application/json')
        log.debug('delete-address-res', **data)
        return dumps(data)

    @app.route('/addresses', methods=['PATCH'])
    def update_address(server, request):
        log.debug('update-address-req', request=request, server=server)
        data = load(request.content)
        req = dict_to_protobuf(Address, data)
        res = grpc_client.invoke(
            ExampleServiceStub, 'UpdateAddress', req)
        data = protobuf_to_dict(res, use_enum_labels=True)
        request.setHeader('Content-Type', 'application/json')
        log.debug('update-address-res', **data)
        return dumps(data)

## end
'''

class WebServer(object):

    app = Klein()

    def __init__(self, port, work_dir, grpc_client):
        self.port = port
        self.site = None
        self.work_dir = work_dir
        self.grpc_client = grpc_client

        self.swagger_ui_root_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '../swagger_ui'))

        self.tcp_port = None

    @inlineCallbacks
    def run(self):
        yield self._open_endpoint()
        yield self._load_generated_routes()
        returnValue(self)

    def _load_generated_routes(self):
        for fname in os.listdir(self.work_dir):
            if fname.endswith('_gw.py'):
                module_name = fname.replace('.py', '')
                print 'module_name', module_name
                m = __import__(module_name)
                print dir(m)
                assert hasattr(m, 'add_routes')
                m.add_routes(self.app, self.grpc_client)

    @inlineCallbacks
    def _open_endpoint(self):
        endpoint = endpoints.TCP4ServerEndpoint(reactor, self.port)
        self.site = Site(self.app.resource())
        self.tcp_port = yield endpoint.listen(self.site)
        log.info('web-server-started', port=self.port)
        self.endpoint = endpoint

    @inlineCallbacks
    def shutdown(self):
        if self.tcp_porte is not None:
            assert isinstance(self.tcp_port, Port)
            yield self.tcp_port.socket.close()

    # static swagger_ui website as landing page (for now)

    @app.route('/', branch=True)
    def static(self, request):
        try:
            log.debug(request=request)
            return File(self.swagger_ui_root_dir)
        except Exception, e:
            log.exception('file-not-found', request=request)

    # static swagger.json file to serve the schema

    @app.route('/v1/swagger.json')
    def swagger_json(self, request):
        try:
            return File(os.path.join(self.work_dir, 'swagger.json'))
        except Exception, e:
            log.exception('file-not-found', request=request)
