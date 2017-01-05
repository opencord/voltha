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

from twisted.internet.defer import inlineCallbacks, returnValue

from common.utils.consulhelpers import get_endpoint_from_consul
from structlog import get_logger
from netconf.nc_server import NCServer

log = get_logger()


class ConnectionManager(object):
    def __init__(self,
                 consul_endpoint,
                 voltha_endpoint,
                 netconf_port,
                 server_private_key_file,
                 server_public_key_file,
                 client_public_keys_file,
                 client_passwords_file,
                 voltha_retry_interval=0.5,
                 devices_refresh_interval=5):

        log.info('init-connection-manager')
        self.netconf_port = netconf_port
        self.server_private_key_file = server_private_key_file
        self.server_public_key_file = server_public_key_file
        self.client_public_keys_file = client_public_keys_file
        self.client_passwords_file = client_passwords_file
        self.consul_endpoint = consul_endpoint
        self.voltha_endpoint = voltha_endpoint

        self.channel = None
        self.grpc_client = None  # single, shared gRPC client to Voltha

        self.nc_server = None

        self.voltha_retry_interval = voltha_retry_interval
        self.devices_refresh_interval = devices_refresh_interval

        self.running = False

    @inlineCallbacks
    def start(self):

        if self.running:
            return

        log.debug('starting')

        self.running = True

        # # Get voltha grpc endpoint
        # self.channel = self.get_grpc_channel_with_voltha()
        #
        # # Create shared gRPC API object
        # self.grpc_client = GrpcClient(self, self.channel).start()

        # Start the netconf server
        self.nc_server = yield self.start_netconf_server().start()

        log.info('started')

        returnValue(self)

    def stop(self):
        log.debug('stopping')
        self.running = False
        # clean the netconf server
        self.nc_server.stop()
        log.info('stopped')

    def resolve_endpoint(self, endpoint):
        ip_port_endpoint = endpoint
        if endpoint.startswith('@'):
            try:
                ip_port_endpoint = get_endpoint_from_consul(
                    self.consul_endpoint, endpoint[1:])
                log.debug('found-service-from-consul', endpoint=endpoint,
                          ip_port=ip_port_endpoint)

            except Exception as e:
                log.error('not-found-service-from-consul',
                          endpoint=endpoint, exception=repr(e))

                return
        if ip_port_endpoint:
            host, port = ip_port_endpoint.split(':', 2)
            return host, int(port)

    def start_netconf_server(self):
        return NCServer(self.netconf_port,
                        self.server_private_key_file,
                        self.server_public_key_file,
                        self.client_public_keys_file,
                        self.client_passwords_file,
                        self.grpc_client)
