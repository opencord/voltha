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
import os

import sys

from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue

from common.utils.asleep import asleep
from common.utils.consulhelpers import get_endpoint_from_consul
from structlog import get_logger
import grpc
from grpc import StatusCode
from grpc._channel import _Rendezvous
from ofagent.protos import third_party
from protos import voltha_pb2
from grpc_client import GrpcClient

from agent import Agent
from google.protobuf.empty_pb2 import Empty


log = get_logger()
# _ = third_party

class ConnectionManager(object):

    def __init__(self, consul_endpoint, voltha_endpoint, controller_endpoints,
                 voltha_retry_interval=0.5, devices_refresh_interval=5):

        log.info('init-connection-manager')
        log.info('list-of-controllers',controller_endpoints=controller_endpoints)
        self.controller_endpoints = controller_endpoints
        self.consul_endpoint = consul_endpoint
        self.voltha_endpoint = voltha_endpoint

        self.channel = None
        self.grpc_client = None  # single, shared gRPC client to Voltha

        self.agent_map = {}  # (datapath_id, controller_endpoint) -> Agent()
        self.device_id_to_datapath_id_map = {}

        self.voltha_retry_interval = voltha_retry_interval
        self.devices_refresh_interval = devices_refresh_interval

        self.running = False

    def start(self):

        if self.running:
            return

        log.debug('starting')

        self.running = True

        # Get voltha grpc endpoint
        self.channel = self.get_grpc_channel_with_voltha()

        # Create shared gRPC API object
        self.grpc_client = GrpcClient(self, self.channel).start()

        # Start monitoring logical devices and manage agents accordingly
        reactor.callLater(0, self.monitor_logical_devices)

        log.info('started')

        return self

    def stop(self):
        log.debug('stopping')
        # clean up all controller connections
        for agent in self.agent_map.itervalues():
            agent.stop()
        self.running = False
        self.grpc_client.stop()
        del self.channel
        log.info('stopped')

    def resolve_endpoint(self, endpoint):
        ip_port_endpoint = endpoint
        if endpoint.startswith('@'):
            try:
                ip_port_endpoint = get_endpoint_from_consul(
                    self.consul_endpoint, endpoint[1:])
                log.info(
                    'Found endpoint {} service at {}'.format(endpoint,
                                                             ip_port_endpoint))
            except Exception as e:
                log.error('Failure to locate {} service from '
                               'consul {}:'.format(endpoint, repr(e)))
                log.error('Committing suicide...')
                # Committing suicide in order to let docker restart ofagent
                os.system("kill -15 {}".format(os.getpid()))
        if ip_port_endpoint:
            host, port = ip_port_endpoint.split(':', 2)
            return host, int(port)

    def get_grpc_channel_with_voltha(self):
        log.info('Resolving voltha endpoint {} from consul'.format(
            self.voltha_endpoint))
        host, port = self.resolve_endpoint(self.voltha_endpoint)
        assert host is not None
        assert port is not None
        # Create grpc channel to Voltha
        channel = grpc.insecure_channel('{}:{}'.format(host, port))
        log.info('Acquired a grpc channel to voltha')
        return channel

    @inlineCallbacks
    def get_list_of_logical_devices_from_voltha(self):

        while True:
            log.info('Retrieve devices from voltha')
            try:
                stub = voltha_pb2.VolthaLocalServiceStub(self.channel)
                devices = stub.ListLogicalDevices(Empty()).items
                for device in devices:
                    log.info("Devices {} -> {}".format(device.id,
                                                       device.datapath_id))
                returnValue(devices)

            except _Rendezvous, e:
                if e.code() == StatusCode.UNAVAILABLE:
                    os.system("kill -15 {}".format(os.getpid()))

            except Exception as e:
                log.error('Failure to retrieve devices from '
                               'voltha: {}'.format(repr(e)))

            log.info('reconnect', after_delay=self.voltha_retry_interval)
            yield asleep(self.voltha_retry_interval)

    def refresh_agent_connections(self, devices):
        """
        Based on the new device list, update the following state in the class:
        * agent_map
        * datapath_map
        * device_id_map
        :param devices: full device list freshly received from Voltha
        :return: None
        """

        # Use datapath ids for deciding what's new and what's obsolete
        desired_datapath_ids = set(d.datapath_id for d in devices)
        current_datapath_ids = set(datapath_ids[0] for datapath_ids in self.agent_map.iterkeys())

        # if identical, nothing to do
        if desired_datapath_ids == current_datapath_ids:
            return

        # ... otherwise calculate differences
        to_add = desired_datapath_ids.difference(current_datapath_ids)
        to_del = current_datapath_ids.difference(desired_datapath_ids)

        # remove what we don't need
        for datapath_id in to_del:
            self.delete_agent(datapath_id)

        # start new agents as needed
        for device in devices:
            if device.datapath_id in to_add:
                self.create_agent(device)

        log.debug('updated-agent-list', count=len(self.agent_map))
        log.debug('updated-device-id-to-datapath-id-map',
                  map=str(self.device_id_to_datapath_id_map))

    def create_agent(self, device):
        datapath_id = device.datapath_id
        device_id = device.id
        for controller_endpoint in self.controller_endpoints:
            agent = Agent(controller_endpoint, datapath_id,
                      device_id, self.grpc_client)
            agent.start()
            self.agent_map[(datapath_id,controller_endpoint)] = agent
            self.device_id_to_datapath_id_map[device_id] = datapath_id

    def delete_agent(self, datapath_id):
        for controller_endpoint in self.controller_endpoints:
            agent = self.agent_map[(datapath_id,controller_endpoint)]
            device_id = agent.get_device_id()
            agent.stop()
            del self.agent_map[(datapath_id,controller_endpoint)]
            del self.device_id_to_datapath_id_map[device_id]

    @inlineCallbacks
    def monitor_logical_devices(self):
        while True:
            # should change to a gRPC streaming call
            # see https://jira.opencord.org/browse/CORD-821

            # get current list from Voltha
            devices = yield self.get_list_of_logical_devices_from_voltha()

            # update agent list and mapping tables as needed
            self.refresh_agent_connections(devices)

            # wait before next poll
            yield asleep(self.devices_refresh_interval)
            log.info('Monitor connections')

    def forward_packet_in(self, device_id, ofp_packet_in):
        datapath_id = self.device_id_to_datapath_id_map.get(device_id, None)
        if datapath_id:
           for controller_endpoint in self.controller_endpoints:
               agent = self.agent_map[(datapath_id,controller_endpoint)]
               agent.forward_packet_in(ofp_packet_in)

    def forward_change_event(self, device_id, event):
        datapath_id = self.device_id_to_datapath_id_map.get(device_id, None)
        if datapath_id:
           for controller_endpoint in self.controller_endpoints:
               agent = self.agent_map[(datapath_id,controller_endpoint)]
               agent.forward_change_event(event)
