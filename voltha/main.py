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

"""Virtual OLT Hardware Abstraction main entry point"""

import argparse
import os
import time

import yaml
from simplejson import dumps
from twisted.internet.defer import inlineCallbacks
from zope.interface import implementer

from common.event_bus import EventBusClient
from common.manhole import Manhole
from common.structlog_setup import setup_logging
from common.utils.dockerhelpers import get_my_containers_name
from common.utils.nethelpers import get_my_primary_interface, \
    get_my_primary_local_ipv4
from voltha.adapters.loader import AdapterLoader
from voltha.coordinator import Coordinator
from voltha.core.core import VolthaCore
from voltha.northbound.diagnostics import Diagnostics
from voltha.northbound.grpc.grpc_server import VolthaGrpcServer
from voltha.northbound.kafka.kafka_proxy import KafkaProxy, get_kafka_proxy
from voltha.northbound.rest.health_check import init_rest_service
from voltha.protos.common_pb2 import LogLevel
from voltha.registry import registry, IComponent
from common.frameio.frameio import FrameIOManager


VERSION = '0.9.0'

defs = dict(
    config=os.environ.get('CONFIG', './voltha.yml'),
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    external_host_address=os.environ.get('EXTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
    fluentd=os.environ.get('FLUENTD', None),
    grpc_port=os.environ.get('GRPC_PORT', 50055),
    instance_id=os.environ.get('INSTANCE_ID', os.environ.get('HOSTNAME', '1')),
    internal_host_address=os.environ.get('INTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
    interface=os.environ.get('INTERFACE', get_my_primary_interface()),
    rest_port=os.environ.get('REST_PORT', 8880),
    kafka=os.environ.get('KAFKA', 'localhost:9092'),
    manhole_port=os.environ.get('MANHOLE_PORT', 12222),
)


def parse_args():
    parser = argparse.ArgumentParser()

    _help = ('Path to voltha.yml config file (default: %s). '
             'If relative, it is relative to main.py of voltha.'
             % defs['config'])
    parser.add_argument('-c', '--config',
                        dest='config',
                        action='store',
                        default=defs['config'],
                        help=_help)

    _help = '<hostname>:<port> to consul agent (default: %s)' % defs['consul']
    parser.add_argument(
        '-C', '--consul', dest='consul', action='store',
        default=defs['consul'],
        help=_help)

    _help = ('<hostname> or <ip> at which Voltha is reachable from outside '
             'the cluster (default: %s)' % defs['external_host_address'])
    parser.add_argument('-E', '--external-host-address',
                        dest='external_host_address',
                        action='store',
                        default=defs['external_host_address'],
                        help=_help)

    _help = ('port number of the GRPC service exposed by voltha (default: %s)'
             % defs['grpc_port'])
    parser.add_argument('-g', '--grpc-port',
                        dest='grpc_port',
                        action='store',
                        default=defs['grpc_port'],
                        help=_help)

    _help = ('<hostname>:<port> to fluentd server (default: %s). (If not '
             'specified (None), the address from the config file is used'
             % defs['fluentd'])
    parser.add_argument('-F', '--fluentd',
                        dest='fluentd',
                        action='store',
                        default=defs['fluentd'],
                        help=_help)

    _help = ('<hostname> or <ip> at which Voltha is reachable from inside the'
             'cluster (default: %s)' % defs['internal_host_address'])
    parser.add_argument('-H', '--internal-host-address',
                        dest='internal_host_address',
                        action='store',
                        default=defs['internal_host_address'],
                        help=_help)

    _help = ('unique string id of this voltha instance (default: %s)'
             % defs['instance_id'])
    parser.add_argument('-i', '--instance-id',
                        dest='instance_id',
                        action='store',
                        default=defs['instance_id'],
                        help=_help)

    # TODO placeholder, not used yet
    _help = 'ETH interface to send (default: %s)' % defs['interface']
    parser.add_argument('-I', '--interface',
                        dest='interface',
                        action='store',
                        default=defs['interface'],
                        help=_help)

    _help = 'open ssh manhole at given port'
    parser.add_argument('-m', '--manhole-port',
                        dest='manhole_port',
                        action='store',
                        type=int,
                        default=None,
                        help=_help)

    _help = 'omit startup banner log lines'
    parser.add_argument('-n', '--no-banner',
                        dest='no_banner',
                        action='store_true',
                        default=False,
                        help=_help)

    _help = 'do not emit periodic heartbeat log messages'
    parser.add_argument('-N', '--no-heartbeat',
                        dest='no_heartbeat',
                        action='store_true',
                        default=False,
                        help=_help)

    _help = ('port number for the rest service (default: %d)'
             % defs['rest_port'])
    parser.add_argument('-R', '--rest-port',
                        dest='rest_port',
                        action='store',
                        type=int,
                        default=defs['rest_port'],
                        help=_help)

    _help = "suppress debug and info logs"
    parser.add_argument('-q', '--quiet',
                        dest='quiet',
                        action='count',
                        help=_help)

    _help = 'enable verbose logging'
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='count',
                        help=_help)

    _help = ('use docker container name as voltha instance id'
             ' (overrides -i/--instance-id option)')
    parser.add_argument('--instance-id-is-container-name',
                        dest='instance_id_is_container_name',
                        action='store_true',
                        default=False,
                        help=_help)

    _help = ('<hostname>:<port> of the kafka broker (default: %s). (If not '
             'specified (None), the address from the config file is used'
             % defs['kafka'])
    parser.add_argument('-K', '--kafka',
                        dest='kafka',
                        action='store',
                        default=defs['kafka'],
                        help=_help)

    args = parser.parse_args()

    # post-processing

    if args.instance_id_is_container_name:
        args.instance_id = get_my_containers_name()

    return args


def load_config(args):
    path = args.config
    if path.startswith('.'):
        dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(dir, path)
    path = os.path.abspath(path)
    with open(path) as fd:
        config = yaml.load(fd)
    return config


def print_banner(log):
    log.info(' _    ______  __  ________  _____ ')
    log.info('| |  / / __ \/ / /_  __/ / / /   |')
    log.info('| | / / / / / /   / / / /_/ / /| |')
    log.info('| |/ / /_/ / /___/ / / __  / ___ |')
    log.info('|___/\____/_____/_/ /_/ /_/_/  |_|')
    log.info('(to stop: press Ctrl-C)')


@implementer(IComponent)
class Main(object):

    def __init__(self):

        self.args = args = parse_args()
        self.config = load_config(args)

        verbosity_adjust = (args.verbose or 0) - (args.quiet or 0)
        self.log = setup_logging(self.config.get('logging', {}),
                                 args.instance_id,
                                 verbosity_adjust=verbosity_adjust,
                                 fluentd=args.fluentd)

        # configurable variables from voltha.yml file
        #self.configurable_vars = self.config.get('Constants', {})

        if not args.no_banner:
            print_banner(self.log)

        self.startup_components()

        if not args.no_heartbeat:
            self.start_heartbeat()
            self.start_kafka_heartbeat(args.instance_id)

        self.manhole = None

    def start(self):
        self.start_reactor()  # will not return except Keyboard interrupt

    def stop(self):
        pass

    def get_args(self):
        """Allow access to command line args"""
        return self.args

    def get_config(self):
        """Allow access to content of config file"""
        return self.config

    @inlineCallbacks
    def startup_components(self):
        try:
            self.log.info('starting-internal-components')

            registry.register('main', self)

            yield registry.register(
                'coordinator',
                Coordinator(
                    internal_host_address=self.args.internal_host_address,
                    external_host_address=self.args.external_host_address,
                    rest_port=self.args.rest_port,
                    instance_id=self.args.instance_id,
                    config=self.config,
                    consul=self.args.consul)
            ).start()

            init_rest_service(self.args.rest_port)

            yield registry.register(
                'grpc_server',
                VolthaGrpcServer(self.args.grpc_port)
            ).start()

            yield registry.register(
                'kafka_proxy',
                KafkaProxy(
                    self.args.consul,
                    self.args.kafka,
                    config=self.config.get('kafka-proxy', {})
                )
            ).start()

            yield registry.register(
                'core',
                VolthaCore(
                    instance_id=self.args.instance_id,
                    version=VERSION,
                    log_level=LogLevel.INFO
                )
            ).start()

            yield registry.register(
                'frameio',
                FrameIOManager()
            ).start()

            yield registry.register(
                'adapter_loader',
                AdapterLoader(config=self.config.get('adapter_loader', {}))
            ).start()

            yield registry.register(
                'diag',
                Diagnostics(config=self.config.get('diagnostics', {}))
            ).start()

            if self.args.manhole_port is not None:
                self.start_manhole(self.args.manhole_port)

            self.log.info('started-internal-services')

        except Exception as e:
            self.log.exception('Failure to start all components {}'.format(e))

    def start_manhole(self, port):
        self.manhole = Manhole(
            port,
            pws=dict(admin='adminpw'),
            eventbus = EventBusClient(),
            **registry.components
        )

    @inlineCallbacks
    def shutdown_components(self):
        """Execute before the reactor is shut down"""
        self.log.info('exiting-on-keyboard-interrupt')
        for component in reversed(registry.iterate()):
            yield component.stop()

    def start_reactor(self):
        from twisted.internet import reactor
        reactor.callWhenRunning(
            lambda: self.log.info('twisted-reactor-started'))
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.shutdown_components)
        reactor.run()

    def start_heartbeat(self):

        t0 = time.time()
        t0s = time.ctime(t0)

        def heartbeat():
            self.log.debug(status='up', since=t0s, uptime=time.time() - t0)

        from twisted.internet.task import LoopingCall
        lc = LoopingCall(heartbeat)
        lc.start(10)

    # Temporary function to send a heartbeat message to the external kafka
    # broker
    def start_kafka_heartbeat(self, instance_id):
        # For heartbeat we will send a message to a specific "voltha-heartbeat"
        #  topic.  The message is a protocol buf
        # message
        message = dumps(dict(
            type='heartbeat',
            voltha_instance=instance_id,
            ip=get_my_primary_local_ipv4()
        ))
        topic = "heartbeat.voltha"

        from twisted.internet.task import LoopingCall
        kafka_proxy = get_kafka_proxy()
        if kafka_proxy:
            lc = LoopingCall(kafka_proxy.send_message, topic, message)
            lc.start(10)
            pass
        else:
            self.log.error('Kafka proxy has not been created!')


if __name__ == '__main__':
    Main().start()
