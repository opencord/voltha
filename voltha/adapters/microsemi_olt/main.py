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
import time
from common.structlog_setup import setup_logging
from common.utils.dockerhelpers import get_my_containers_name
import os
from twisted.internet import reactor
from voltha.adapters.microsemi_olt.microsemi import RubyAdapter
import yaml

defs = dict(
    config=os.environ.get('CONFIG', './ruby.yml'),
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    grpc_endpoint=os.environ.get('GRPC_ENDPOINT', 'localhost:50055'),
    fluentd=os.environ.get('FLUENTD', None),
    instance_id=os.environ.get('INSTANCE_ID', os.environ.get('HOSTNAME', '1'))
)

def parse_args():

    parser = argparse.ArgumentParser()

    _help = ('Path to ruby.yml config file (default: %s). '
             'If relative, it is relative to main.py of microsemi.'
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


    _help = ('<hostname>:<port> to fluentd server (default: %s). (If not '
             'specified (None), the address from the config file is used'
             % defs['fluentd'])
    parser.add_argument('-F', '--fluentd',
                        dest='fluentd',
                        action='store',
                        default=defs['fluentd'],
                        help=_help)

    _help = ('gRPC end-point to connect to. It can either be a direct'
             'definition in the form of <hostname>:<port>, or it can be an'
             'indirect definition in the form of @<service-name> where'
             '<service-name> is the name of the grpc service as registered'
             'in consul (example: @voltha-grpc). (default: %s'
             % defs['grpc_endpoint'])
    parser.add_argument('-G', '--grpc-endpoint',
                        dest='grpc_endpoint',
                        action='store',
                        default=defs['grpc_endpoint'],
                        help=_help)

    _help = ('unique string id of this ofagent instance (default: %s)'
             % defs['instance_id'])
    parser.add_argument('-i', '--instance-id',
                        dest='instance_id',
                        action='store',
                        default=defs['instance_id'],
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

    _help = ('use docker container name as ofagent instance id'
             ' (overrides -i/--instance-id option)')
    parser.add_argument('--instance-id-is-container-name',
                        dest='instance_id_is_container_name',
                        action='store_true',
                        default=False,
                        help=_help)

    _help = 'omit startup banner log lines'
    parser.add_argument('-n', '--no-banner',
                        dest='no_banner',
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
 ________  ___  ___  ________      ___    ___
|\   __  \|\  \|\  \|\   __  \    |\  \  /  /|
\ \  \|\  \ \  \\\  \ \  \|\ /_   \ \  \/  / /
 \ \   _  _\ \  \\\  \ \   __  \   \ \    / /
  \ \  \\  \\ \  \\\  \ \  \|\  \   \/  /  /
   \ \__\\ _\\ \_______\ \_______\__/  / /
    \|__|\|__|\|_______|\|_______|\___/ /
                                 \|___|/
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
                                 verbosity_adjust=verbosity_adjust,
                                 fluentd=args.fluentd)

        # components
        self.ruby_adapter = None

        self.exiting = False

        if not args.no_banner:
            print_banner(self.log)

        self.startup_components()

    def start(self):
        self.start_reactor()  # will not return except Keyboard interrupt

    def startup_components(self):
        self.log.info('starting-internal-components')
        args = self.args
        self.ruby_adapter = RubyAdapter(args, self.config).start()
        self.log.info('started ruby adapter')

    def shutdown_components(self):
        """Execute before the reactor is shut down"""
        self.log.info('exiting-on-keyboard-interrupt')
        self.exiting = True
        if self.ruby_adapter is not None:
            self.ruby_adapter.stop()

    def start_reactor(self):
        reactor.callWhenRunning(
            lambda: self.log.info('twisted-reactor-started'))

        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.shutdown_components)
        reactor.run()

if __name__ == '__main__':
    Main().start()
