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

import argparse
import os

import yaml
from podder import Podder

from common.structlog_setup import setup_logging
from common.utils.nethelpers import get_my_primary_local_ipv4

defs = dict(
    slaves=os.environ.get('SLAVES', './slaves.yml'),
    config=os.environ.get('CONFIG', './podder.yml'),
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    external_host_address=os.environ.get('EXTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
    grpc_endpoint=os.environ.get('GRPC_ENDPOINT', 'localhost:50055'),
    fluentd=os.environ.get('FLUENTD', None),
    instance_id=os.environ.get('INSTANCE_ID', os.environ.get('HOSTNAME', '1')),
    internal_host_address=os.environ.get('INTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
    work_dir=os.environ.get('WORK_DIR', '/tmp/podder')
)

def parse_args():

    parser = argparse.ArgumentParser()

    _help = ('Path to podder.yml config file (default: %s). '
             'If relative, it is relative to main.py of podder.'
             % defs['config'])
    parser.add_argument('-c', '--config',
                        dest='config',
                        action='store',
                        default=defs['config'],
                        help=_help)

    _help = ('Path to slaves configuration file (default %s).'
            'If relative, it is relative to main.py of podder.'
             % defs['slaves'])
    parser.add_argument('-s', '--slaves',
                        dest='slaves',
                        action='store',
                        default=defs['slaves'],
                        help=_help)

    _help = '<hostname>:<port> to consul agent (default: %s)' % defs['consul']
    parser.add_argument(
        '-C', '--consul', dest='consul', action='store',
        default=defs['consul'],
        help=_help)


    _help = ('<hostname>:<port> to fluentd server (default: %s). (If not '
             'specified (None), the address from the config file is used'
             % defs['fluentd'])
    parser.add_argument('-F', '--fluentd',
                        dest='fluentd',
                        action='store',
                        default=defs['fluentd'],
                        help=_help)

    _help = ('unique string id of this ofagent instance (default: %s)'
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


    args = parser.parse_args()

    # post-processing

    return args

def load_config(config):
    path = config
    if path.startswith('.'):
        dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(dir, path)
    path = os.path.abspath(path)
    with open(path) as fd:
        config = yaml.load(fd)
    return config

banner = r'''
 _____
|     |          |    |
|     |          |    |
|_____|_____ ____|____| ___   _
|     |     |    |    |/ _ \ /
|     |_____|____|____|\____|
'''

def print_banner(log):
    for line in banner.strip('\n').splitlines():
        log.info(line)
    log.info('(to stop: press Ctrl-C)')

class Main(object):

    def __init__(self):
        self.args = args = parse_args()
        self.config = load_config(args.config)
        self.slave_config = load_config(args.slaves)

        verbosity_adjust = (args.verbose or 0) - (args.quiet or 0)
        self.log = setup_logging(self.config.get('logging', {}),
                                 args.instance_id,
                                 verbosity_adjust=verbosity_adjust,
                                 fluentd=args.fluentd)

        self.consul_manager = None

        if not args.no_banner:
            print_banner(self.log)

    def start(self):
        self.startup_components()

    def startup_components(self):
        self.log.info('starting-internal-components')
        args = self.args
        self.podder = Podder(args, self.slave_config)
        self.log.info('started-internal-components')
        self.podder.run()


if __name__ == '__main__':
    Main().start()
