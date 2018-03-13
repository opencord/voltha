#!/usr/bin/env python
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
import argparse
import os
import sys
import yaml
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
#sys.path.append(os.path.join(base_dir, '/netconf/protos/third_party'))

from common.structlog_setup import setup_logging
from common.utils.dockerhelpers import get_my_containers_name
from common.utils.nethelpers import get_my_primary_local_ipv4
#from netconf.grpc_client.grpc_client import GrpcClient
#from netconf.nc_server import NCServer
from dashd.dashd_impl import DashDaemon


defs = dict(
    config=os.environ.get('CONFIG', './dashd.yml'),
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    external_host_address=os.environ.get('EXTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
    grafana_url=os.environ.get('GRAFANA_URL', 
                                        'http://admin:admin@localhost:8882/api'),
    kafka=os.environ.get('KAFKA', None),
    topic=os.environ.get('KAFKA_TOPIC', 'voltha.kpis'),
    docker_host=os.environ.get('DOCKER_HOST', None),

    instance_id=os.environ.get('INSTANCE_ID', os.environ.get('HOSTNAME', '1')),
    internal_host_address=os.environ.get('INTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
)


def parse_args():
    parser = argparse.ArgumentParser("Manage Grafana dashboards")

    _help = ('Path to dashd.yml config file (default: %s). '
             'If relative, it is relative to main.py of dashd.'
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

    _help = '<hostname>:<port> to the kafka bus (default: %s)' % defs['kafka']
    parser.add_argument(
        '-k', '--kafka', dest='kafka', action='store',
        default=defs['kafka'],
        help=_help)

    _help = 'The kafka topic to listen to (default: %s)' % defs['topic']
    parser.add_argument(
        '-t', '--topic', dest='topic', action='store',
        default=defs['topic'],
        help=_help)

    _help = 'The URL of the Grafana server (default: %s)' % \
            defs['grafana_url']
    parser.add_argument(
        '-g', '--grafana_url', dest='grafana_url', action='store',
        default=defs['grafana_url'],
        help=_help)

    _help = 'The docker host ip (default %s)' % \
            defs['docker_host']
    parser.add_argument(
        '-d', '--docker_host', dest='docker_host', action='store',
        default=defs['docker_host'],
        help=_help)

    _help = ('unique string id of this netconf server instance (default: %s)'
             % defs['instance_id'])
    parser.add_argument('-i', '--instance-id',
                        dest='instance_id',
                        action='store',
                        default=defs['instance_id'],
                        help=_help)

    _help = 'omit startup banner log lines'
    parser.add_argument('-n', '--no-banner',
                        dest='no_banner',
                        action='store_true',
                        default=False,
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

    _help = ('use docker container name as netconf server instance id'
             ' (overrides -i/--instance-id option)')
    parser.add_argument('--instance-id-is-container-name',
                        dest='instance_id_is_container_name',
                        action='store_true',
                        default=False,
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


banner = r'''
 __
|  \  _ _  __ _         _
||\ |/ ' |/ /| |__   __| |
||/ | o  |\ \|  _ \ / _  |
|__/ \_._|/_/|_| |_|\__._|
'''


def print_banner(log):
    for line in banner.strip('\n').splitlines():
        log.info(line)
    log.info('(to stop: press Ctrl-C)')


class Main(object):
    def __init__(self):

        self.args = args = parse_args()
        self.config = load_config(args)

        verbosity_adjust = (args.verbose or 0) - (args.quiet or 0)
        self.log = setup_logging(self.config.get('logging', {}),
                                 args.instance_id,
                                 verbosity_adjust=verbosity_adjust)

        self.dashd_server = None

        self.dashd_server_started = False

        self.exiting = False

        if not args.no_banner:
            print_banner(self.log)

        self.startup_components()

    def start(self):
        #pass
        self.start_reactor()  # will not return except Keyboard interrupt

    @inlineCallbacks
    def startup_components(self):
        try:
            args = self.args

            self.log.info('starting-dash-daemon', consul=args.consul,
                                                 grafana_url=args.grafana_url,
                                                 topic=args.topic)
            self.dashd_server = yield \
                    DashDaemon(args.consul, #'10.0.2.15:8500',
                               args.kafka,
                               args.grafana_url, #'http://admin:admin@localhost:8882/api',
                               topic=args.topic )  #"voltha.kpis")

            reactor.callWhenRunning(self.dashd_server.start)

            self.log.info('started')
        except:
            e = sys.exc_info()
            print("ERROR: ", e)


    @inlineCallbacks
    def shutdown_components(self):
        """Execute before the reactor is shut down"""
        self.log.info('exiting-on-keyboard-interrupt')
        self.exiting = True

    def start_reactor(self):
        reactor.callWhenRunning(
            lambda: self.log.info('twisted-reactor-started'))

        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.shutdown_components)
        reactor.run()


if __name__ == '__main__':
    Main().start()
