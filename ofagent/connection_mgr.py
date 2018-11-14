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
from protos.voltha_pb2 import OfAgentSubscriber
from grpc_client import GrpcClient

from agent import Agent
from common.utils.dockerhelpers import get_my_containers_name


# _ = third_party

class ConnectionManager(object):
    def __init__(self, consul_endpoint, vcore_endpoint, vcore_grpc_timeout,
                 controller_endpoints, instance_id,
                 enable_tls=False, key_file=None, cert_file=None,
                 vcore_retry_interval=0.5, devices_refresh_interval=5,
                 subscription_refresh_interval=5):

        self.log = get_logger()
        self.log.info('init-connection-manager')
        self.log.info('list-of-controllers',
                      controller_endpoints=controller_endpoints)

        self.controller_endpoints = controller_endpoints
        self.consul_endpoint = consul_endpoint
        self.vcore_endpoint = vcore_endpoint
        self.grpc_timeout = vcore_grpc_timeout
        self.instance_id = instance_id
        self.enable_tls = enable_tls
        self.key_file = key_file
        self.cert_file = cert_file

        self.channel = None
        self.grpc_client = None  # single, shared gRPC client to vcore

        self.agent_map = {}  # (datapath_id, controller_endpoint) -> Agent()
        self.device_id_to_datapath_id_map = {}

        self.vcore_retry_interval = vcore_retry_interval
        self.devices_refresh_interval = devices_refresh_interval
        self.subscription_refresh_interval = subscription_refresh_interval
        self.subscription = None

        self.running = False

    def start(self):

        if self.running:
            return

        self.log.debug('starting')

        self.running = True

        # Start monitoring the vcore grpc channel
        reactor.callInThread(self.monitor_vcore_grpc_channel)

        # Start monitoring logical devices and manage agents accordingly
        reactor.callLater(0, self.monitor_logical_devices)

        self.log.info('started')

        return self

    def stop(self):
        self.log.debug('stopping')
        # clean up all controller connections
        for agent in self.agent_map.itervalues():
            agent.stop()
        self.running = False

        self._reset_grpc_attributes()

        self.log.info('stopped')

    def resolve_endpoint(self, endpoint):
        ip_port_endpoint = endpoint
        if endpoint.startswith('@'):
            try:
                ip_port_endpoint = get_endpoint_from_consul(
                    self.consul_endpoint, endpoint[1:])
                self.log.info(
                    '{}-service-endpoint-found'.format(endpoint), address=ip_port_endpoint)
            except Exception as e:
                self.log.error('{}-service-endpoint-not-found'.format(endpoint), exception=repr(e))
                self.log.error('committing-suicide')
                # Committing suicide in order to let docker restart ofagent
                os.system("kill -15 {}".format(os.getpid()))
        if ip_port_endpoint:
            host, port = ip_port_endpoint.split(':', 2)
            return host, int(port)

    def _reset_grpc_attributes(self):
        self.log.debug('start-reset-grpc-attributes')

        if self.grpc_client is not None:
            self.grpc_client.stop()

        if self.channel is not None:
            del self.channel

        self.is_alive = False
        self.channel = None
        self.subscription = None
        self.grpc_client = None

        self.log.debug('stop-reset-grpc-attributes')

    def _assign_grpc_attributes(self):
        self.log.debug('start-assign-grpc-attributes')

        host, port = self.resolve_endpoint(self.vcore_endpoint)
        self.log.info('revolved-vcore-endpoint', endpoint=self.vcore_endpoint, host=host, port=port)

        assert host is not None
        assert port is not None

        # Establish a connection to the vcore GRPC server
        self.channel = grpc.insecure_channel('{}:{}'.format(host, port))
        self.is_alive = True

        self.log.debug('stop-assign-grpc-attributes')

    @inlineCallbacks
    def monitor_vcore_grpc_channel(self):
        self.log.debug('start-monitor-vcore-grpc-channel')

        while self.running:
            try:
                # If a subscription is not yet assigned then establish new GRPC connection
                # ... otherwise keep using existing connection details
                if self.subscription is None:
                    self._assign_grpc_attributes()

                # Send subscription request to register the current ofagent instance
                container_name = self.instance_id
                if self.grpc_client is None:
                    self.grpc_client = GrpcClient(self, self.channel, self.grpc_timeout)
                subscription = yield self.grpc_client.subscribe(
                    OfAgentSubscriber(ofagent_id=container_name))

                # If the subscriber id matches the current instance
                # ... then the subscription has succeeded
                if subscription is not None and subscription.ofagent_id == container_name:
                    if self.subscription is None:
                        # Keep details on the current GRPC session and subscription
                        self.log.debug('subscription-with-vcore-successful', subscription=subscription)
                        self.subscription = subscription
                        self.grpc_client.start()

                    # Sleep a bit in between each subscribe
                    yield asleep(self.subscription_refresh_interval)

                    # Move on to next subscribe request
                    continue

                # The subscription did not succeed, reset and move on
                else:
                    self.log.info('subscription-with-vcore-unavailable', subscription=subscription)

            except _Rendezvous, e:
                self.log.error('subscription-with-vcore-terminated',exception=e, status=e.code())

            except Exception as e:
                self.log.exception('unexpected-subscription-termination-with-vcore', e=e)

            # Reset grpc details
            # The vcore instance is either not available for subscription
            # or a failure occurred with the existing communication.
            self._reset_grpc_attributes()

            # Sleep for a short period and retry
            yield asleep(self.vcore_retry_interval)

        self.log.debug('stop-monitor-vcore-grpc-channel')

    @inlineCallbacks
    def get_list_of_reachable_logical_devices_from_voltha(self):

        while self.running:
            self.log.debug('retrieve-logical-device-list')
            try:
                devices = yield \
                    self.grpc_client.list_reachable_logical_devices()

                for device in devices:
                    self.log.debug("reachable-logical-device-entry", id=device.id,
                                   datapath_id=device.datapath_id)

                returnValue(devices)

            except _Rendezvous, e:
                status = e.code()
                self.log.error('vcore-communication-failure', exception=e, status=status)
                if status == StatusCode.UNAVAILABLE or status == StatusCode.DEADLINE_EXCEEDED:
                    os.system("kill -15 {}".format(os.getpid()))

            except Exception as e:
                self.log.exception('logical-devices-retrieval-failure', exception=e)

            self.log.info('reconnect', after_delay=self.vcore_retry_interval)
            yield asleep(self.vcore_retry_interval)

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

        self.log.debug('updated-agent-list', count=len(self.agent_map))
        self.log.debug('updated-device-id-to-datapath-id-map',
                  map=str(self.device_id_to_datapath_id_map))

    def create_agent(self, device):
        datapath_id = device.datapath_id
        device_id = device.id
        for controller_endpoint in self.controller_endpoints:
            agent = Agent(controller_endpoint, datapath_id,
                          device_id, self.grpc_client, self.enable_tls,
                          self.key_file, self.cert_file)
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
        self.log.debug('start-monitor-logical-devices')

        while self.running:
            self.log.debug('monitoring-logical-devices')

            # should change to a gRPC streaming call
            # see https://jira.opencord.org/browse/CORD-821

            try:
                if self.channel is not None and self.grpc_client is not None and \
                                self.subscription is not None:
                    # get current list from Voltha
                    reachable_devices = yield \
                        self.get_list_of_reachable_logical_devices_from_voltha()

                    # update agent list and mapping tables as needed
                    self.refresh_agent_connections(reachable_devices)
                else:
                    self.log.warning('vcore-communication-unavailable')

                # wait before next poll
                yield asleep(self.devices_refresh_interval)

            except _Rendezvous, e:
                self.log.error('vcore-communication-failure', exception=repr(e), status=e.code())

            except Exception as e:
                self.log.exception('unexpected-vcore-communication-failure', exception=repr(e))

        self.log.debug('stop-monitor-logical-devices')

    def forward_packet_in(self, device_id, ofp_packet_in):
        datapath_id = self.device_id_to_datapath_id_map.get(device_id, None)
        if datapath_id:
            for controller_endpoint in self.controller_endpoints:
                agent = self.agent_map[(datapath_id, controller_endpoint)]
                agent.forward_packet_in(ofp_packet_in)

    def forward_change_event(self, device_id, event):
        datapath_id = self.device_id_to_datapath_id_map.get(device_id, None)
        if datapath_id:
            for controller_endpoint in self.controller_endpoints:
                agent = self.agent_map[(datapath_id, controller_endpoint)]
                agent.forward_change_event(event)
