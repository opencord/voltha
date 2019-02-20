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

import sys

import structlog
import os.path
from twisted.internet import protocol, reactor, ssl
from twisted.internet.defer import Deferred, inlineCallbacks

import loxi.of13 as of13
from common.utils.asleep import asleep
from of_connection import OpenFlowConnection
from of_protocol_handler import OpenFlowProtocolHandler

log = structlog.get_logger()


class Agent(protocol.ClientFactory):

    generation_is_defined = False
    cached_generation_id = None

    def __init__(self,
                 controller_endpoint,
                 datapath_id,
                 device_id,
                 rpc_stub,
                 enable_tls=False,
                 key_file=None,
                 cert_file=None,
                 conn_retry_interval=1):

        self.controller_endpoint = controller_endpoint
        self.datapath_id = datapath_id
        self.device_id = device_id
        self.rpc_stub = rpc_stub
        self.enable_tls = enable_tls
        self.key_file = key_file
        self.cert_file = cert_file
        self.retry_interval = conn_retry_interval

        self.running = False
        self.connector = None # will be a Connector instance once connected
        self.d_disconnected = None  # a deferred to signal reconnect loop when
                                    # TCP connection is lost
        self.connected = False
        self.exiting = False
        self.proto_handler = None

    def get_device_id(self):
        return self.device_id

    def start(self):
        log.debug('starting')
        if self.running:
            return
        self.running = True
        reactor.callLater(0, self.keep_connected)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.connected = False
        self.exiting = True
        self.connector.disconnect()
        log.info('stopped')

    def resolve_endpoint(self, endpoint):
        # enable optional resolution via consul;
        # see https://jira.opencord.org/browse/CORD-820
        host, port = endpoint.split(':', 2)
        return host, int(port)

    @inlineCallbacks
    def keep_connected(self):
        """Keep reconnecting to the controller"""
        while not self.exiting:
            host, port = self.resolve_endpoint(self.controller_endpoint)
            log.info('connecting', host=host, port=port)
            if self.enable_tls:
                try:
                    # Check that key_file and cert_file is provided and
                    # the files exist
                    if self.key_file is None or             \
                       self.cert_file is None or            \
                       not os.path.isfile(self.key_file) or \
                       not os.path.isfile(self.cert_file):
                        raise Exception('key_file "{}" or cert_file "{}"'
                                        ' is not found'.
                                         format(self.key_file, self.cert_file))
                    with open(self.key_file) as keyFile:
                        with open(self.cert_file) as certFile:
                            clientCert = ssl.PrivateCertificate.loadPEM(
                                keyFile.read() + certFile.read())

                    ctx = clientCert.options()
                    self.connector = reactor.connectSSL(host, port, self, ctx)
                    log.info('tls-enabled')

                except Exception as e:
                    log.exception('failed-to-connect', reason=e)
            else:
                self.connector = reactor.connectTCP(host, port, self)
                log.info('tls-disabled')

            self.d_disconnected = Deferred()
            yield self.d_disconnected
            log.debug('reconnect', after_delay=self.retry_interval)
            yield asleep(self.retry_interval)

    def enter_disconnected(self, event, reason):
        """Internally signal entering disconnected state"""
        self.connected = False
        if not self.exiting:
            log.error(event, reason=reason)
            self.d_disconnected.callback(None)

    def enter_connected(self):
        """Handle transitioning from disconnected to connected state"""
        log.info('connected')
        self.connected = True
        self.read_buffer = None
        reactor.callLater(0, self.proto_handler.start)

    # protocol.ClientFactory methods

    def protocol(self):
        cxn = OpenFlowConnection(self)  # Low level message handler
        self.proto_handler = OpenFlowProtocolHandler(
            self.datapath_id, self.device_id, self, cxn, self.rpc_stub)
        return cxn

    def clientConnectionFailed(self, connector, reason):
        self.enter_disconnected('connection-failed', reason)

    def clientConnectionLost(self, connector, reason):
        if not self.exiting:
            log.error('client-connection-lost',
                      reason=reason, connector=connector)

    def forward_packet_in(self, ofp_packet_in):
        if self.proto_handler is not None:
            self.proto_handler.forward_packet_in(ofp_packet_in)

    def forward_change_event(self, event):
        # assert isinstance(event, ChangeEvent)
        log.info('got-change-event', change_event=event)
        if self.proto_handler is not None:
            if event.HasField("port_status"):
                self.proto_handler.forward_port_status(event.port_status)
            elif event.HasField("flow_removed"):
                self.proto_handler.forward_flow_removed(event.flow_removed)
        else:
            log.error('unknown-change-event', change_event=event)


if __name__ == '__main__':
    """Run this to test the agent for N concurrent sessions:
       python agent [<number-of-desired-instances>]
    """

    n = 1 if len(sys.argv) < 2 else int(sys.argv[1])

    from utils import mac_str_to_tuple

    class MockRpc(object):
        @staticmethod
        def get_port_list(_):
            ports = []
            cap = of13.OFPPF_1GB_FD | of13.OFPPF_FIBER
            for pno, mac, nam, cur, adv, sup, spe in (
                    (1, '00:00:00:00:00:01', 'onu1', cap, cap, cap,
                     of13.OFPPF_1GB_FD),
                    (2, '00:00:00:00:00:02', 'onu2', cap, cap, cap,
                     of13.OFPPF_1GB_FD),
                    (129, '00:00:00:00:00:81', 'olt', cap, cap, cap,
                     of13.OFPPF_1GB_FD)
            ):
                port = of13.common.port_desc(pno, mac_str_to_tuple(mac), nam,
                                             curr=cur, advertised=adv,
                                             supported=sup,
                                             curr_speed=spe, max_speed=spe)
                ports.append(port)
            return ports

    stub = MockRpc()
    agents = [Agent('localhost:6653', 256 + i, stub).start() for i in range(n)]

    def shutdown():
        [a.stop() for a in agents]

    reactor.addSystemEventTrigger('before', 'shutdown', shutdown)
    reactor.run()
