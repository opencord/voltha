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

""" virtual OLT Hardware Abstraction """

import argparse
import logging
import sys
import structlog


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--interface', dest='interface', action='store', default='eth0',
                        help='ETH interface to send (default: eth0)')
    parser.add_argument('--no-banner', dest='no_banner', action='store_true', default=False,
                        help='omit startup banner log lines')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='verbose print out')

    return parser.parse_args()


def setup_logging(args):
    """
    Set up logging such that:
    - The primary logging entry method is structlog (see http://structlog.readthedocs.io/en/stable/index.html)
    - By default, the logging backend is Python standard lib logger
    - In the future, fluentd or other backends will be supported too
    """

    # Configure standard logging
    DATEFMT = '%Y-%m-%dT%H:%M:%S'
    FORMAT = '%(asctime)-15s.%(msecs)03d %(levelname)-8s %(msg)s'
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(stream=sys.stdout, level=level, format=FORMAT, datefmt=DATEFMT)

    # Hook up structlog to standard logging
    processors = [
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.KeyValueRenderer(),  # structlog.processorsJSONRenderer(),

    ]
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory(), processors=processors)

    # Mark first line of log
    log = structlog.get_logger()
    log.info("first-line")
    return log


def print_banner(args, log):
    log.info(' _    ______  __  ________  _____ ')
    log.info('| |  / / __ \/ / /_  __/ / / /   |')
    log.info('| | / / / / / /   / / / /_/ / /| |')
    log.info('| |/ / /_/ / /___/ / / __  / ___ |')
    log.info('|___/\____/_____/_/ /_/ /_/_/  |_|')


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
    log = setup_logging(args)
    if not args.no_banner:
        print_banner(args, log)
    start_reactor(args, log)  # will not return except Keyboard interrupt


if __name__ == '__main__':
    main()
