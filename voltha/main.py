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

import yaml

from structlog_setup import setup_logging, DEFAULT_FLUENT_SERVER


def parse_args():

    parser = argparse.ArgumentParser()

    # generic parameters
    parser.add_argument('--no-banner', dest='no_banner', action='store_true', default=False,
                        help='omit startup banner log lines')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='enable verbose logging')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', default=False,
                        help="suppress debug and info logs")
    parser.add_argument('-c', '--config', dest='config', action='store', default='./voltha.yml',
                        help='Path to voltha.yml config file. If relative, it is relative to main.py of voltha')

    # placeholder
    parser.add_argument('-i', '--interface', dest='interface', action='store', default='eth0',
                        help='ETH interface to send (default: eth0)')

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


def cleanup(log):
    """Execute before the reactor is shut down"""
    log.info('exiting-on-keyboard-interrupt')


def start_reactor(args, log):
    from twisted.internet import reactor
    reactor.callWhenRunning(lambda: log.info('twisted-reactor-started'))
    reactor.addSystemEventTrigger('before', 'shutdown', lambda: cleanup(log))
    reactor.run()


def main():
    args = parse_args()
    config = load_config(args)
    log = setup_logging(config.get('logging', {}))
    if not args.no_banner:
        print_banner(args, log)
    start_reactor(args, log)  # will not return except Keyboard interrupt


if __name__ == '__main__':
    main()
