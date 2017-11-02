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

"""
PON Simulator process, able to move packets across NNI and UNIs, as well
as take MGMT calls via gRPC.
It can only work on Linux.
"""
import argparse
import os

import yaml
from twisted.internet.defer import inlineCallbacks

from common.structlog_setup import setup_logging
from grpc_server import GrpcServer
from realio import RealIo
from ponsim import PonSim
from ponsim import XPonSim

defs = dict(
    config=os.environ.get('CONFIG', './ponsim.yml'),
    grpc_port=int(os.environ.get('GRPC_PORT', 50060)),
    name=os.environ.get('NAME', 'pon1'),
    onus=int(os.environ.get("ONUS", 1)),
    device_type='ponsim'
)


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
 ____   __   __ _  ____  __  _  _
(  _ \ /  \ (  ( \/ ___)(  )( \/ )
 ) __/(  O )/    /\___ \ )( / \/ \
(__)   \__/ \_)__)(____/(__)\_)(_/
'''

def print_banner(log):
    for line in banner.strip('\n').splitlines():
        log.info(line)
    log.info('(to stop: press Ctrl-C)')


def parse_args():

    parser = argparse.ArgumentParser()

    _help = ('Path to ponsim.yml config file (default: %s). '
             'If relative, it is relative to main.py of ponsim.'
             % defs['config'])
    parser.add_argument('-c', '--config',
                        dest='config',
                        action='store',
                        default=defs['config'],
                        help=_help)

    _help = ('port number of the GRPC service exposed by voltha (default: %s)'
             % defs['grpc_port'])
    parser.add_argument('-g', '--grpc-port',
                        dest='grpc_port',
                        action='store',
                        default=defs['grpc_port'],
                        help=_help)

    _help = ('number of ONUs to simulate (default: %d)' % defs['onus'])
    parser.add_argument('-o', '--onus',
                        dest='onus',
                        action='store',
                        type=int,
                        default=defs['onus'],
                        help=_help)

    _help = ('name of the PON natework used as a prefix for all network'
             ' resource created on behalf of the PON (default: %s)' %
             defs['name'])
    parser.add_argument('-N', '--name',
                        dest='name',
                        action='store',
                        default=defs['name'],
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

    _help = 'enable generation of simulated alarms'
    parser.add_argument('-a', '--alarm-simulation',
                        dest='alarm_simulation',
                        action='store_true',
                        default=False,
                        help=_help)

    _help = 'frequency of simulated alarms (in seconds)'
    parser.add_argument('-f', '--alarm-frequency',
                        dest='alarm_frequency',
                        action='store',
                        type=int,
                        metavar="[5-300]",
                        choices=range(5,301),
                        default=60,
                        help=_help)

    _help = 'omit startup banner log lines'
    parser.add_argument('-n', '--no-banner',
                        dest='no_banner',
                        action='store_true',
                        default=False,
                        help=_help)

    _help = ('device type - ponsim or bal'
             ' (default: %s)' % defs['device_type'])
    parser.add_argument('-d', '--device_type',
                        dest='device_type',
                        action='store',
                        default=defs['device_type'],
                        help=_help)

    args = parser.parse_args()

    return args


class Main(object):

    def __init__(self):

        self.args = args = parse_args()
        self.config = load_config(args)

        verbosity_adjust = (args.verbose or 0) - (args.quiet or 0)
        self.log = setup_logging(self.config.get('logging', {}),
                                 args.name,
                                 verbosity_adjust=verbosity_adjust)

        # components
        self.io = None
        self.ponsim = None
        self.x_pon_sim = None
        self.grpc_server = None
        self.grpc_services = None
        self.device_type = args.device_type

        self.alarm_config = dict()
        self.alarm_config['simulation'] = self.args.alarm_simulation
        self.alarm_config['frequency'] = self.args.alarm_frequency

        if not args.no_banner:
            print_banner(self.log)

        self.startup_components()

    def start(self):
        self.start_reactor()  # will not return except Keyboard interrupt

    @inlineCallbacks
    def startup_components(self):
        try:
            self.log.info('starting-internal-components')

            iface_map = self.setup_networking_assets(self.args.name,
                                                     self.args.onus)
            self.io = yield RealIo(iface_map).start()
            self.ponsim = PonSim(self.args.onus, self.io.egress, self.alarm_config)
            self.io.register_ponsim(self.ponsim)

            self.x_pon_sim = XPonSim()

            self.grpc_server = GrpcServer(self.args.grpc_port,
                                          self.ponsim,
                                          self.x_pon_sim,
                                          self.device_type)
            yield self.grpc_server.start()

            self.log.info('started-internal-services')

        except Exception, e:
            self.log.exception('startup-failed', e=e)

    @inlineCallbacks
    def shutdown_components(self):
        """Execute before the reactor is shut down"""
        self.log.info('exiting-on-keyboard-interrupt')
        try:
            if self.io is not None:
                yield self.io.stop()
            self.teardown_networking_assets(self.args.name, self.args.onus)
            if self.grpc_server is not None:
                yield self.grpc_server.stop()
        except Exception, e:
            self.log.exception('shutdown-failed', e=e)

    def start_reactor(self):
        from twisted.internet import reactor
        reactor.callWhenRunning(
            lambda: self.log.info('twisted-reactor-started'))
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.shutdown_components)
        reactor.run()

    def setup_networking_assets(self, prefix, n_unis):
        # setup veth pairs for NNI and each UNI, using prefix and port numbers
        port_map = dict()
        for portnum in [0] + range(128, 128 + n_unis):
            external_name = '%s_%d' % (prefix, portnum)
            internal_name = external_name + 'sim'
            os.system('sudo ip link add dev {} type veth peer name {}'.format(
                external_name, internal_name
            ))
            os.system('sudo ip link set {} up'.format(external_name))
            os.system('sudo ip link set {} up'.format(internal_name))
            if portnum == 0:
                os.system('sudo brctl addif ponmgmt {}'.format(external_name))
            port_map[portnum] = internal_name
        return port_map

    def teardown_networking_assets(self, prefix, n_unis):
        # undo all the networking stuff
        for portnum in [0] + range(128, 128 + n_unis):
            external_name = '%s_%d' % (prefix, portnum)
            os.system('sudo ip link del {}'.format(external_name))


if __name__ == '__main__':
    Main().start()
