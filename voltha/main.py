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

from structlog_setup import setup_logging
from coordinator import Coordinator


defs = dict(
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    instance_id=os.environ.get('INSTANCE_ID', '1'),
    config=os.environ.get('CONFIG', './voltha.yml'),
    interface=os.environ.get('INTERFACE', 'eth0'),
    internal_host_address=os.environ.get('INTERNAL_HOST_ADDRESS', 'localhost'),
    external_host_address=os.environ.get('EXTERNAL_HOST_ADDRESS', 'localhost'),
    fluentd=os.environ.get('FLUENTD', None)
)


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--config', dest='config', action='store',
                        default=defs['config'],
                        help='Path to voltha.yml config file (default: %s). '
                        'If relative, it is relative to main.py of voltha.' % defs['config'])

    parser.add_argument('-C', '--consul', dest='consul', action='store',
                        default=defs['consul'],
                        help='<hostname>:<port> to consul agent (default: %s)' % defs['consul'])

    parser.add_argument('-E', '--external-host-address', dest='external_host_address', action='store',
                        default=defs['external_host_address'],
                        help='<hostname> or <ip> at which Voltha is reachable from outside the cluster'
                        '(default: %s)' % defs['external_host_address'])

    parser.add_argument('-F', '--fluentd', dest='fluentd', action='store',
                        default=defs['fluentd'],
                        help='<hostname>:<port> to fluentd server (default: %s).'
                             '(If not specified (None), the address from the config file is used'
                             % defs['fluentd'])

    parser.add_argument('-H', '--internal-host-address', dest='internal_host_address', action='store',
                        default=defs['internal_host_address'],
                        help='<hostname> or <ip> at which Voltha is reachable from inside the cluster'
                        '(default: %s)' % defs['internal_host_address'])

    parser.add_argument('-i', '--instance-id', dest='instance_id', action='store',
                        default=defs['instance_id'],
                        help='unique string id of this voltha instance (default: %s)' % defs['interface'])

    # TODO placeholder, not used yet
    parser.add_argument('-I', '--interface', dest='interface', action='store',
                        default=defs['interface'],
                        help='ETH interface to send (default: %s)' % defs['interface'])

    parser.add_argument('-n', '--no-banner', dest='no_banner', action='store_true', default=False,
                        help='omit startup banner log lines')

    parser.add_argument('-N', '--no-heartbeat', dest='no_heartbeat', action='store_true', default=False,
                        help='do not emit periodic heartbeat log messages')

    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', default=False,
                        help="suppress debug and info logs")

    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='enable verbose logging')

    return parser.parse_args()


def load_config(args):
    path = args.config
    if path.startswith('.'):
        dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(dir, path)
    path = os.path.abspath(path)
    with open(path) as fd:
        config = yaml.load(fd)
    return config


def print_banner(args, log):
    log.info(' _    ______  __  ________  _____ ')
    log.info('| |  / / __ \/ / /_  __/ / / /   |')
    log.info('| | / / / / / /   / / / /_/ / /| |')
    log.info('| |/ / /_/ / /___/ / / __  / ___ |')
    log.info('|___/\____/_____/_/ /_/ /_/_/  |_|')
    log.info('(to stop: press Ctrl-C)')


def startup(log, args, config):
    log.info('starting-internal-services')
    coordinator = Coordinator(
        internal_host_address=args.internal_host_address,
        external_host_address=args.external_host_address,
        instance_id=args.instance_id,
        consul=args.consul)
    log.info('started-internal-services')


def cleanup(log):
    """Execute before the reactor is shut down"""
    log.info('exiting-on-keyboard-interrupt')


def start_reactor(args, log):
    from twisted.internet import reactor
    reactor.callWhenRunning(lambda: log.info('twisted-reactor-started'))
    reactor.addSystemEventTrigger('before', 'shutdown', lambda: cleanup(log))
    reactor.run()


def start_heartbeat(log):

    t0 = time.time()
    t0s = time.ctime(t0)

    def heartbeat():
        log.info(status='up', since=t0s, uptime=time.time() - t0)

    from twisted.internet.task import LoopingCall
    lc = LoopingCall(heartbeat)
    lc.start(10)


def main():

    args = parse_args()

    config = load_config(args)

    log = setup_logging(config.get('logging', {}), fluentd=args.fluentd)

    if not args.no_banner:
        print_banner(args, log)

    if not args.no_heartbeat:
        start_heartbeat(log)

    startup(log, args, config)

    start_reactor(args, log)  # will not return except Keyboard interrupt


if __name__ == '__main__':
    main()
