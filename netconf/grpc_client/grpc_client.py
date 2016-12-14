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
gRPC client meant to connect to a gRPC server endpoint, and query the
end-point's schema by calling SchemaService.Schema(Empty) and all of its
semantics are derived from the recovered schema.
"""

import os
import sys
from random import randint
from zlib import decompress

import grpc
from consul import Consul
from grpc._channel import _Rendezvous
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from werkzeug.exceptions import ServiceUnavailable

from common.utils.asleep import asleep
from netconf.protos import third_party
from netconf.protos.schema_pb2 import SchemaServiceStub
from google.protobuf.empty_pb2 import Empty
from common.utils.consulhelpers import get_endpoint_from_consul
from netconf.protos.voltha_pb2  import VolthaLocalServiceStub, \
    VolthaGlobalServiceStub
from twisted.internet import threads
from google.protobuf import empty_pb2
from google.protobuf.json_format import MessageToDict, ParseDict
from simplejson import dumps, load

log = get_logger()


class GrpcClient(object):
    """
    Connect to a gRPC server, fetch its schema, and process the downloaded
    proto schema files.  The goal is to convert the proto schemas into yang
    schemas which would be exposed to the Netconf client.
    """
    RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]

    def __init__(self, consul_endpoint, work_dir,
                 grpc_endpoint='localhost:50055',
                 reconnect_callback=None,
                 on_start_callback=None):
        self.consul_endpoint = consul_endpoint
        self.grpc_endpoint = grpc_endpoint
        self.work_dir = work_dir
        self.reconnect_callback = reconnect_callback
        self.on_start_callback = on_start_callback

        self.plugin_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '../protoc_plugins'))

        self.channel = None
        self.local_stub = None
        self.schema = None
        self.retries = 0
        self.shutting_down = False
        self.connected = False

    def start(self):
        log.debug('starting')
        if not self.connected:
            reactor.callLater(0, self.connect)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        if self.shutting_down:
            return
        self.shutting_down = True
        log.info('stopped')


    def set_on_start_callback(self, on_start_callback):
        self.on_start_callback = on_start_callback
        return self


    def set_reconnect_callback(self, reconnect_callback):
        self.reconnect_callback = reconnect_callback
        return self


    def resolve_endpoint(self, endpoint):
        ip_port_endpoint = endpoint
        if endpoint.startswith('@'):
            try:
                ip_port_endpoint = get_endpoint_from_consul(
                    self.consul_endpoint, endpoint[1:])
                log.info('endpoint-found',
                         endpoint=endpoint, ip_port=ip_port_endpoint)
            except Exception as e:
                log.error('service-not-found-in-consul', endpoint=endpoint,
                          exception=repr(e))
                return None, None
        if ip_port_endpoint:
            host, port = ip_port_endpoint.split(':', 2)
            return host, int(port)


    @inlineCallbacks
    def connect(self):
        """
        (Re-)Connect to end-point
        """
        if self.shutting_down or self.connected:
            return

        try:
            host, port = self.resolve_endpoint(self.grpc_endpoint)

            # If host and port is not set then we will retry
            if host and port:
                log.info('grpc-endpoint-connecting', host=host, port=port)
                self.channel = grpc.insecure_channel('{}:{}'.format(host, port))

                # yang_from = self._retrieve_schema()
                # log.info('proto-to-yang-schema', file=yang_from)
                # self._compile_proto_files(yang_from)
                self._clear_backoff()

                if self.on_start_callback is not None:
                    reactor.callLater(0, self.on_start_callback)

                self.connected = True
                if self.reconnect_callback is not None:
                    reactor.callLater(0, self.reconnect_callback)

                self.local_stub = VolthaLocalServiceStub(self.channel)
                self.global_stub = VolthaGlobalServiceStub(self.channel)

                return

        except _Rendezvous, e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                log.info('grpc-endpoint-not-available')
            else:
                log.exception(e)
            yield self._backoff('not-available')

        except Exception, e:
            if not self.shutting_down:
                log.exception('cannot-connect', endpoint=_endpoint)
            yield self._backoff('unknown-error')

        reactor.callLater(0, self.connect)

    def _backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries,
                                           len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        log.error(msg, retry_in=wait_time)
        return asleep(wait_time)

    def _clear_backoff(self):
        if self.retries:
            log.info('reconnected', after_retries=self.retries)
            self.retries = 0

    def _retrieve_schema(self):
        """
        Retrieve schema from gRPC end-point, and save all *.proto files in
        the work directory.
        """
        assert isinstance(self.channel, grpc.Channel)
        stub = SchemaServiceStub(self.channel)
        # try:
        schemas = stub.GetSchema(Empty())
        # except _Rendezvous, e:
        #     if e.code == grpc.StatusCode.UNAVAILABLE:
        #
        #     else:
        #         raise e

        os.system('mkdir -p %s' % self.work_dir)
        os.system('rm -fr /tmp/%s/*' %
                  self.work_dir.replace('/tmp/', ''))  # safer

        for proto_file in schemas.protos:
            proto_fname = proto_file.file_name
            # TODO: Do we need to process a set of files using a prefix
            # instead of just one?
            proto_content = proto_file.proto
            log.info('saving-proto', fname=proto_fname, dir=self.work_dir,
                      length=len(proto_content))
            with open(os.path.join(self.work_dir, proto_fname), 'w') as f:
                f.write(proto_content)

            desc_content = decompress(proto_file.descriptor)
            desc_fname = proto_fname.replace('.proto', '.desc')
            log.info('saving-descriptor', fname=desc_fname, dir=self.work_dir,
                      length=len(desc_content))
            with open(os.path.join(self.work_dir, desc_fname), 'wb') as f:
                f.write(desc_content)
        return schemas.yang_from

    def _compile_proto_files(self, yang_from):
        """
        For each *.proto file in the work directory, compile the proto
        file into the respective *_pb2.py file as well as generate the
        corresponding yang schema.
        :return: None
        """
        log.info('start')
        google_api_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '../protos/third_party'
        ))

        log.info('google-api', api_dir=google_api_dir)

        netconf_base_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '../..'
        ))
        log.info('netconf-dir', dir=netconf_base_dir)


        for fname in [f for f in os.listdir(self.work_dir)
                      if f.endswith('.proto')]:
            log.info('filename', file=fname)

            need_yang = fname == yang_from
            log.debug('compiling',
                      file=fname,
                      yang_schema_required=need_yang)
            cmd = (
                'cd %s && '
                'env PATH=%s PYTHONPATH=%s '
                'python -m grpc.tools.protoc '
                '-I. '
                '-I%s '
                '--python_out=. '
                '--grpc_python_out=. '
                '--plugin=protoc-gen-custom=%s/proto2yang.py '
                '%s'
                '%s' % (
                    self.work_dir,
                    ':'.join([os.environ['PATH'], self.plugin_dir]),
                    ':'.join([google_api_dir, netconf_base_dir]),
                    google_api_dir,
                    self.plugin_dir,
                    '--custom_out=. ' if need_yang else '',
                    fname)
            )
            log.debug('executing', cmd=cmd, file=fname)
            os.system(cmd)
            log.info('compiled', file=fname)

        # # test-load each _pb2 file to see all is right
        # if self.work_dir not in sys.path:
        #     sys.path.insert(0, self.work_dir)
        #
        # for fname in [f for f in os.listdir(self.work_dir)
        #               if f.endswith('_pb2.py')]:
        #     modname = fname[:-len('.py')]
        #     log.debug('test-import', modname=modname)
        #     _ = __import__(modname)

        #TODO: find a different way to test the generated yang files

    @inlineCallbacks
    def get_voltha_instance(self):
        try:
            res = yield threads.deferToThread(
                    self.local_stub.GetVolthaInstance, empty_pb2.Empty())

            out_data = MessageToDict(res, True, True)
            returnValue(out_data)
        except Exception, e:
            log.error('failure', exception=repr(e))


    #TODO: should be generated code
    @inlineCallbacks
    def invoke_voltha_api(self, key):
        # key = ''.join([service, '-', method])
        try:
            if key == 'VolthaGlobalService-GetVoltha':
                res = yield threads.deferToThread(
                    self.global_stub.GetVoltha, empty_pb2.Empty())
            elif key == 'VolthaLocalService-GetVolthaInstance':
                res = yield threads.deferToThread(
                    self.local_stub.GetVolthaInstance, empty_pb2.Empty())
            elif key == 'VolthaLocalService-GetHealth':
                res = yield threads.deferToThread(
                    self.local_stub.GetHealth, empty_pb2.Empty())
            elif key == 'VolthaLocalService-ListAdapters':
                res = yield threads.deferToThread(
                    self.local_stub.ListAdapters, empty_pb2.Empty())
            elif key == 'VolthaLocalService-ListLogicalDevices':
                res = yield threads.deferToThread(
                    self.local_stub.ListLogicalDevices, empty_pb2.Empty())
            elif key == 'VolthaLocalService-ListDevices':
                res = yield threads.deferToThread(
                    self.local_stub.ListDevices, empty_pb2.Empty())
            elif key == 'VolthaLocalService-ListDeviceTypes':
                res = yield threads.deferToThread(
                    self.local_stub.ListDeviceTypes, empty_pb2.Empty())
            elif key == 'VolthaLocalService-ListDeviceGroups':
                res = yield threads.deferToThread(
                    self.local_stub.ListDeviceGroups, empty_pb2.Empty())
            else: # for now just return voltha instance data
                res = yield threads.deferToThread(
                    self.local_stub.GetVolthaInstance, empty_pb2.Empty())

            out_data = MessageToDict(res, True, True)
            returnValue(out_data)
        except Exception, e:
            log.error('failure', exception=repr(e))


