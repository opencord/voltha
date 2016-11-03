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

"""gRPC server endpoint"""
import os
import uuid
from Queue import Queue
from os.path import abspath, basename, dirname, join, walk
import grpc
from concurrent import futures
from structlog import get_logger
import zlib

from common.utils.grpc_utils import twisted_async
from voltha.core.device_model import DeviceModel
from voltha.protos import voltha_pb2, schema_pb2

log = get_logger()


class SchemaService(schema_pb2.SchemaServiceServicer):

    def __init__(self):
        proto_map, descriptor_map = self._load_schema()
        self.schema = schema_pb2.Schema(
            protos=proto_map,
            descriptors=descriptor_map
        )

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

        proto_map = {}
        for fpath in find_files(proto_dir, '.proto'):
            with open(fpath, 'r') as f:
                content = f.read()
            fname = basename(fpath)
            # assure no two files have the same basename
            assert fname not in proto_map
            proto_map[fname] = content

        descriptor_map = {}
        for fpath in find_files(proto_dir, '.desc'):
            with open(fpath, 'r') as f:
                content = f.read()
            fname = basename(fpath)
            # assure no two files have the same basename
            assert fname not in descriptor_map
            descriptor_map[fname] = zlib.compress(content)

        return proto_map, descriptor_map

    def GetSchema(self, request, context):
        """Return current schema files and descriptor"""
        return self.schema


class HealthService(voltha_pb2.HealthServiceServicer):

    def __init__(self, thread_pool):
        self.thread_pool = thread_pool

    def GetHealthStatus(self, request, context):
        """Return current health status of a Voltha instance
        """
        log.info('get-health-status', request=request)
        res = voltha_pb2.HealthStatus(
            state=voltha_pb2.HealthStatus.OVERLOADED  # HEALTHY
        )
        return res


class ExampleService(voltha_pb2.ExampleServiceServicer):

    def __init__(self, thread_pool):
        from random import randint
        self.thread_pool = thread_pool
        self.db = dict((id, voltha_pb2.Address(
            id=id,
            street="%d 1st Street" % randint(1, 4000),
            city="Petaluma",
            zip=94954,
            state="CA"
        )) for id in (uuid.uuid5(uuid.NAMESPACE_OID, str(i)).get_hex()
                      for i in xrange(1000, 1005)))

    def GetAddress(self, request, context):
        log.info('get-address', request=request)
        return self.db[request.id]

    def ListAddresses(self, request, context):
        log.info('list-addresses', request=request)
        res = voltha_pb2.Addresses(
            addresses=self.db.values()
        )
        return res

    def CreateAddress(self, request, context):
        log.info('create-address', request=request)
        id = uuid.uuid4().get_hex()
        request.id = id
        self.db[id] = request
        return request

    def DeleteAddress(self, request, context):
        log.info('delete-address', request=request)
        del self.db[request.id]
        return voltha_pb2.NullMessage()

    def UpdateAddress(self, request, context):
        log.info('update-address', request=request)
        updated = self.db[request.id]
        updated.MergeFrom(request)
        return updated


class VolthaLogicalLayer(voltha_pb2.VolthaLogicalLayerServicer):
    # TODO still a mock

    def __init__(self, threadpool):
        self.threadpool = threadpool
        self.devices = [DeviceModel(self, 1)]
        self.devices_map = dict((d.info.id, d) for d in self.devices)
        self.packet_in_queue = Queue()

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
        return voltha_pb2.NullMessage()

    @twisted_async
    def ListDeviceFlows(self, request, context):
        device_model = self.devices_map[request.id]
        flows = device_model.list_flows()
        return voltha_pb2.Flows(items=flows)

    @twisted_async
    def UpdateGroupTable(self, request, context):
        device_model = self.devices_map[request.id]
        device_model.update_group_table(request.group_mod)
        return voltha_pb2.NullMessage()

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

    def ReceivePacketsIn(self, request, context):
        while 1:
            packet_in = self.packet_in_queue.get()
            yield packet_in

    def send_packet_in(self, device_id, ofp_packet_in):
        """Must be called on the twisted thread"""
        packet_in = voltha_pb2.PacketIn(id=device_id, packet_in=ofp_packet_in)
        self.packet_in_queue.put(packet_in)


class VolthaGrpcServer(object):

    def __init__(self, port=50055):
        self.port = port
        log.info('init-grpc-server', port=self.port)
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=10)
        self.server = grpc.server(self.thread_pool)

        schema_pb2.add_SchemaServiceServicer_to_server(
            SchemaService(), self.server)
        voltha_pb2.add_HealthServiceServicer_to_server(
            HealthService(self.thread_pool), self.server)
        voltha_pb2.add_ExampleServiceServicer_to_server(
            ExampleService(self.thread_pool), self.server)
        voltha_pb2.add_VolthaLogicalLayerServicer_to_server(
            VolthaLogicalLayer(self.thread_pool), self.server)

        self.server.add_insecure_port('[::]:%s' % self.port)

    def run(self):
        log.info('starting-grpc-server')
        self.server.start()
        return self

    def shutdown(self, grace=0):
        self.server.stop(grace)


# This is to allow running the GRPC server in stand-alone mode

if __name__ == '__main__':

    server = VolthaGrpcServer().run()

    import time
    _ONE_DAY_IN_SECONDS = 60 * 60 * 24
    try:
        while 1:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.shutdown()


