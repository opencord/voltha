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

"""gRPC server endpoint"""
import os
import uuid
from Queue import Queue
from collections import OrderedDict
from os.path import abspath, basename, dirname, join, walk
import grpc
from concurrent import futures
from structlog import get_logger
import zlib

from zope.interface import implementer

from common.utils.grpc_utils import twisted_async
from voltha.core.logical_device_agent import LogicalDeviceAgent
from voltha.protos import voltha_pb2, voltha_pb2_grpc, schema_pb2, schema_pb2_grpc, health_pb2_grpc
from google.protobuf.empty_pb2 import Empty

from voltha.registry import IComponent

log = get_logger()


class SchemaService(schema_pb2_grpc.SchemaServiceServicer):

    def __init__(self, thread_pool):
        self.thread_pool = thread_pool
        protos = self._load_schema()
        self.schemas = schema_pb2.Schemas(protos=protos,
                                          swagger_from='voltha.proto',
                                          yang_from='voltha.proto')

    def stop(self):
        pass

    def _load_schema(self):
        """Pre-load schema file so that we can serve it up (file sizes
           are small enough to do so
        """
        proto_dir = abspath(join(dirname(__file__), '../../protos'))

        def find_files(dir, suffix):
            proto_files = [
                join(dir, fname) for fname in os.listdir(dir)
                if fname.endswith(suffix)
            ]
            return proto_files

        proto_map = OrderedDict()  # to have deterministic data
        for proto_file in find_files(proto_dir, '.proto'):
            with open(proto_file, 'r') as f:
                proto_content = f.read()
            fname = basename(proto_file)
            # assure no two files have the same basename
            assert fname not in proto_map

            desc_file = proto_file.replace('.proto', '.desc')
            with open(desc_file, 'r') as f:
                descriptor_content = zlib.compress(f.read())

            proto_map[fname] = schema_pb2.ProtoFile(
                file_name=fname,
                proto=proto_content,
                descriptor=descriptor_content
            )

        return proto_map.values()

    def GetSchema(self, request, context):
        """Return current schema files and descriptor"""
        return self.schemas


class HealthService(health_pb2_grpc.HealthServiceServicer):

    def __init__(self, thread_pool):
        self.thread_pool = thread_pool

    def stop(self):
        pass

    def GetHealthStatus(self, request, context):
        """Return current health status of a Voltha instance
        """
        log.info('get-health-status', request=request)
        res = voltha_pb2.HealthStatus(
            state=voltha_pb2.HealthStatus.HEALTHY
        )
        return res

'''
class VolthaLogicalLayer(voltha_pb2_grpc.VolthaLogicalLayerServicer):
    # TODO still a mock

    def __init__(self, threadpool):
        self.threadpool = threadpool
        self.devices = [LogicalDeviceAgent(self, 1)]
        self.devices_map = dict((d.info.id, d) for d in self.devices)
        self.packet_in_queue = Queue()

        self.stopped = False

    def stop(self):
        self.stopped = True

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Note that all GRPC method implementations are not called on the main
    # (twisted) thread. We shall contain them here and not spread calls on
    # "foreign" threads elsewhere in the application. So all calls out from
    # these methods shall be called with the callFromThread pattern.
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    @twisted_async
    def ListLogicalDevices(self, request, context):
        return voltha_pb2.LogicalDevices(
            items=[voltha_pb2.LogicalDevice(
                id=d.info.id,
                datapath_id=d.info.datapath_id,
                desc=d.info.desc
            ) for d in self.devices])

    @twisted_async
    def GetLogicalDevice(self, request, context):
        return self.devices_map[request.id].info

    @twisted_async
    def ListLogicalDevicePorts(self, request, context):
        device_model = self.devices_map[request.id]
        return voltha_pb2.LogicalPorts(items=device_model.ports)

    @twisted_async
    def UpdateFlowTable(self, request, context):
        device_model = self.devices_map[request.id]
        device_model.update_flow_table(request.flow_mod)
        return Empty()

    @twisted_async
    def ListDeviceFlows(self, request, context):
        device_model = self.devices_map[request.id]
        flows = device_model.list_flows()
        return voltha_pb2.Flows(items=flows)

    @twisted_async
    def UpdateGroupTable(self, request, context):
        device_model = self.devices_map[request.id]
        device_model.update_group_table(request.group_mod)
        return Empty()

    @twisted_async
    def ListDeviceFlowGroups(self, request, context):
        device_model = self.devices_map[request.id]
        groups = device_model.list_groups()
        return voltha_pb2.FlowGroups(items=groups)

    def StreamPacketsOut(self, request_iterator, context):

        @twisted_async
        def forward_packet_out(packet_out):
            device_model = self.devices_map[packet_out.id]
            device_model.packet_out(packet_out.packet_out)

        for request in request_iterator:
            forward_packet_out(packet_out=request)

        return Empty()

    def ReceivePacketsIn(self, request, context):
        while 1:
            packet_in = self.packet_in_queue.get()
            yield packet_in

    def send_packet_in(self, device_id, ofp_packet_in):
        """Must be called on the twisted thread"""
        packet_in = voltha_pb2.PacketIn(id=device_id, packet_in=ofp_packet_in)
        self.packet_in_queue.put(packet_in)
'''

@implementer(IComponent)
class VolthaGrpcServer(object):

    def __init__(self, port=50055):
        self.port = port
        log.info('init-grpc-server', port=self.port)
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=10)
        self.server = grpc.server(self.thread_pool)
        self.services = []

    def start(self):
        log.debug('starting')

        # add each service unit to the server and also to the list
        for activator_func, service_class in (
            (schema_pb2_grpc.add_SchemaServiceServicer_to_server, SchemaService),
            (health_pb2_grpc.add_HealthServiceServicer_to_server, HealthService),
        ):
            service = service_class(self.thread_pool)
            self.register(activator_func, service)

        # open port
        self.server.add_insecure_port('[::]:%s' % self.port)

        # strat the server
        self.server.start()

        log.info('started')
        return self

    def stop(self, grace=0):
        log.debug('stopping')
        for service in self.services:
            service.stop()
        self.server.stop(grace)
        self.thread_pool.shutdown(False)
        log.info('stopped')

    def register(self, activator_func, service):
        """
        Allow late registration of gRPC servicers
        :param activator_func: The gRPC "add_XYZServicer_to_server method
        autogenerated by protoc.
        :param service: The object implementing the service.
        :return: None
        """
        self.services.append(service)
        activator_func(service, self.server)


# This is to allow running the GRPC server in stand-alone mode

if __name__ == '__main__':

    server = VolthaGrpcServer().start()

    import time
    _ONE_DAY_IN_SECONDS = 60 * 60 * 24
    try:
        while 1:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop()


