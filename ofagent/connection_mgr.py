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

import sys

from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue

from common.utils.asleep import asleep
from common.utils.consulhelpers import get_endpoint_from_consul
from structlog import get_logger
import grpc
from protos import voltha_pb2
from grpc_client import GrpcClient

from agent import Agent

class ConnectionManager(object):

    log = get_logger()

    def __init__(self, consul_endpoint, voltha_endpoint, controller_endpoint,
                 voltha_retry_interval=0.5, devices_refresh_interval=60):

        self.log.info('Initializing connection manager')
        self.controller_endpoint = controller_endpoint
        self.consul_endpoint = consul_endpoint
        self.voltha_endpoint = voltha_endpoint

        self.channel = None
        self.connected_devices = None
        self.unprocessed_devices = None
        self.agent_map = {}
        self.grpc_client = None
        self.device_id_map = None

        self.voltha_retry_interval = voltha_retry_interval
        self.devices_refresh_interval = devices_refresh_interval

        self.running = False

    @inlineCallbacks
    def run(self):
        if self.running:
            return

        self.log.info('Running connection manager')

        self.running = True

        # Get voltha grpc endpoint
        self.channel = self.get_grpc_channel_with_voltha()

        # Connect to voltha using grpc and fetch the list of logical devices
        yield self.get_list_of_logical_devices_from_voltha()

        # Create shared gRPC API object
        self.grpc_client = GrpcClient(self.channel, self.device_id_map)

        # Instantiate an OpenFlow agent for each logical device
        self.refresh_openflow_agent_connections()

        reactor.addSystemEventTrigger('before', 'shutdown', self.shutdown)
        reactor.callLater(0, self.monitor_connections)

        returnValue(self)


    def shutdown(self):
        # clean up all controller connections
        for key, value in enumerate(self.agent_map):
            value.stop()
        self.running = False
        # TODO: close grpc connection to voltha

    def resolve_endpoint(self, endpoint):
        ip_port_endpoint = endpoint
        if endpoint.startswith('@'):
            try:
                ip_port_endpoint = get_endpoint_from_consul(
                    self.consul_endpoint, endpoint[1:])
                self.log.info(
                    'Found endpoint {} service at {}'.format(endpoint,
                                                             ip_port_endpoint))
            except Exception as e:
                self.log.error('Failure to locate {} service from '
                               'consul {}:'.format(endpoint, repr(e)))
                return
        if ip_port_endpoint:
            host, port = ip_port_endpoint.split(':', 2)
            return host, int(port)

    def get_grpc_channel_with_voltha(self):
        self.log.info('Resolving voltha endpoint {} from consul'.format(
            self.voltha_endpoint))
        host, port = self.resolve_endpoint(self.voltha_endpoint)
        assert host is not None
        assert port is not None
        # Create grpc channel to Voltha
        channel = grpc.insecure_channel('{}:{}'.format(host, port))
        self.log.info('Acquired a grpc channel to voltha')
        return channel


    @inlineCallbacks
    def get_list_of_logical_devices_from_voltha(self):
        while True:
            self.log.info('Retrieve devices from voltha')
            try:
                stub = voltha_pb2.VolthaLogicalLayerStub(self.channel)
                devices = stub.ListLogicalDevices(
                    voltha_pb2.NullMessage()).items
                for device in devices:
                    self.log.info("Devices {} -> {}".format(device.id,
                                                            device.datapath_id))
                self.unprocessed_devices = devices
                self.device_id_map = dict(
                    (device.datapath_id, device.id) for device in devices)
                return
            except Exception as e:
                self.log.error('Failure to retrieve devices from '
                               'voltha: {}'.format(repr(e)))

            self.log.info('reconnect', after_delay=self.voltha_retry_interval)
            yield asleep(self.voltha_retry_interval)


    def refresh_openflow_agent_connections(self):
        # Compare the new device list again the previous
        # For any new device, an agent connection will be created.  For
        # existing device that are no longer part of the list then that
        # agent connection will be stopped

        # If the ofagent has no previous devices then just add them
        if self.connected_devices is None:
            datapath_ids_to_add = [device.datapath_id for device in self.unprocessed_devices]
        else:
            previous_datapath_ids = [device.datapath_id for device in self.connected_devices]
            current_datapath_ids = [device.datapath_id for device in self.unprocessed_devices]
            datapath_ids_to_add = [d for d in current_datapath_ids if
                                 d not in previous_datapath_ids]
            datapath_ids_to_remove = [d for d in previous_datapath_ids if
                                 d not in current_datapath_ids]

            # Check for no change
            if not datapath_ids_to_add and not datapath_ids_to_remove:
                self.log.info('No new devices found.  No OF agent update '
                              'required')
                return

            self.log.info('Updating OF agent connections.')
            print self.agent_map

            # Stop previous agents
            for datapath_id in datapath_ids_to_remove:
                if self.agent_map.has_key(datapath_id):
                    self.agent_map[datapath_id].stop()
                    del self.agent_map[datapath_id]
                    self.log.info('Removed OF agent with datapath id {'
                                  '}'.format(datapath_id))

        # Add the new agents
        for datapath_id in datapath_ids_to_add:
            self.agent_map[datapath_id] = Agent(self.controller_endpoint,
                                                datapath_id,
                                                self.grpc_client)
            self.agent_map[datapath_id].run()
            self.log.info('Launched OF agent with datapath id {}'.format(
                datapath_id))

        # replace the old device list with the new ones
        self.connected_devices = self.unprocessed_devices
        self.unprocessed_devices = None

    @inlineCallbacks
    def monitor_connections(self):
        while True:
            # sleep first
            yield asleep(self.devices_refresh_interval)
            self.log.info('Monitor connections')
            yield self.get_list_of_logical_devices_from_voltha()
            self.refresh_openflow_agent_connections()

# class Model(object):
#     def __init__(self, id, path):
#         self.id=id
#         self.datapath_id=path,


# if __name__ == '__main__':
#     conn = ConnectionManager("10.0.2.15:3181", "localhost:50555",
#                              "10.100.198.150:6633")
#
#     conn.connected_devices = None
#     model1 = Model('12311', 'wdadsa1')
#     model2 = Model('12312', 'wdadsa2')
#     model3 = Model('12313', 'wdadsa3')
#     model4 = Model('12314', 'wdadsa4')
#
#     conn.unprocessed_devices = [model1, model2, model3]
#
#     conn.refresh_openflow_agent_connections()
#
#
#     # val = [device.datapath_id for device in conn.connected_devices]
#     # print val
#     #
#     # for (id,n) in enumerate(val):
#     #     print n
#
#
#     conn.unprocessed_devices = [model1, model2, model3]
#
#     conn.refresh_openflow_agent_connections()
#
#     conn.unprocessed_devices = [model1, model2, model4]
#
#     conn.refresh_openflow_agent_connections()