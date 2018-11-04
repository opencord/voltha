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
sys.path.append(os.path.join(base_dir, '/netconf/protos/third_party'))

from common.structlog_setup import setup_logging
from common.utils.dockerhelpers import get_my_containers_name
from common.utils.nethelpers import get_my_primary_local_ipv4
from netconf.grpc_client.grpc_client import GrpcClient
from netconf.nc_server import NCServer

defs = dict(
    config=os.environ.get('CONFIG', './netconf.yml'),
    logconfig=os.environ.get('LOGCONFIG', './logconfig.yml'),
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    external_host_address=os.environ.get('EXTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
    netconf_port=os.environ.get('NETCONF_PORT', '1830'),
    server_private_key_file=os.environ.get('SERVER_PRIVATE_KEY_FILE',
                                           'server.key'),
    server_public_key_file=os.environ.get('SERVER_PRIVATE_KEY_FILE',
                                          'server.key.pub'),
    client_public_keys_file=os.environ.get('CLIENT_PUBLIC_KEYS_FILE',
                                           'client_keys'),
    client_passwords_file=os.environ.get('CLIENT_PASSWORD_FILE',
                                         'client_passwords'),
    grpc_endpoint=os.environ.get('GRPC_ENDPOINT', 'localhost:50055'),
    instance_id=os.environ.get('INSTANCE_ID', os.environ.get('HOSTNAME', '1')),
    internal_host_address=os.environ.get('INTERNAL_HOST_ADDRESS',
                                         get_my_primary_local_ipv4()),
    work_dir=os.environ.get('WORK_DIR', '/tmp/netconf')
)


def parse_args():
    parser = argparse.ArgumentParser()

    _help = ('Path to netconf.yml config file (default: %s). '
             'If relative, it is relative to main.py of ofagent.'
             % defs['config'])
    parser.add_argument('-c', '--config',
                        dest='config',
                        action='store',
                        default=defs['config'],
                        help=_help)

    _help = ('Path to logconfig.yml config file (default: %s). '
             'If relative, it is relative to main.py of voltha.'
             % defs['logconfig'])
    parser.add_argument('-l', '--logconfig',
                        dest='logconfig',
                        action='store',
                        default=defs['logconfig'],
                        help=_help)

    _help = '<hostname>:<port> to consul agent (default: %s)' % defs['consul']
    parser.add_argument(
        '-C', '--consul', dest='consul', action='store',
        default=defs['consul'],
        help=_help)

    _help = ('<hostname> or <ip> at which netconf is reachable from '
             'outside the cluster (default: %s)' % defs[
                 'external_host_address'])
    parser.add_argument('-E', '--external-host-address',
                        dest='external_host_address',
                        action='store',
                        default=defs['external_host_address'],
                        help=_help)

    _help = ('<port> of netconf server (default: %s). (If not '
             'specified (None), the port from the config file is used'
             % defs['netconf_port'])
    parser.add_argument('-N', '--netconf_port',
                        dest='netconf_port',
                        action='store',
                        default=defs['netconf_port'],
                        help=_help)

    _help = (
    '<server private key file name> used by the netconf server. (If not '
    'specified (None), the file name from the config file is used (default: %s)'
    % defs['server_private_key_file'])
    parser.add_argument('-S', '--server_private_key_file',
                        dest='server_private_key_file',
                        action='store',
                        default=defs['server_private_key_file'],
                        help=_help)

    _help = ('<server public key file name> used by the netconf server. (If '
             'not specified (None), the file name from the config file is '
             'used (default: %s) '
             % defs['server_public_key_file'])
    parser.add_argument('-P', '--server_public_key_file',
                        dest='server_public_key_file',
                        action='store',
                        default=defs['server_public_key_file'],
                        help=_help)

    _help = ('<client public key file name> used by the netconf server. (If '
             'not specified (None), the file name from the config file is '
             'used(default: %s) '
             % defs['client_public_keys_file'])
    parser.add_argument('-X', '--client_public_keys_file',
                        dest='client_public_keys_file',
                        action='store',
                        default=defs['client_public_keys_file'],
                        help=_help)

    _help = ('<client password file name> used by the netconf server. (If '
             'not specified (None), the file name from the config file is '
             'used (default: %s) '
             % defs['client_passwords_file'])
    parser.add_argument('-U', '--client_passwords_file',
                        dest='client_passwords_file',
                        action='store',
                        default=defs['client_passwords_file'],
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

    _help = ('<hostname> or <ip> at which netconf server is reachable from '
             'inside the cluster (default: %s)' % defs[
                 'internal_host_address'])
    parser.add_argument('-H', '--internal-host-address',
                        dest='internal_host_address',
                        action='store',
                        default=defs['internal_host_address'],
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

    _help = ('work dir to compile and assemble generated files (default=%s)'
             % defs['work_dir'])
    parser.add_argument('-w', '--work-dir',
                        dest='work_dir',
                        action='store',
                        default=defs['work_dir'],
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


def load_config(args, configname='config'):
    argdict = vars(args)
    path = argdict[configname]
    if path.startswith('.'):
        dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(dir, path)
    path = os.path.abspath(path)
    with open(path) as fd:
        config = yaml.load(fd)
    return config


banner = r'''
 _   _      _                   __   ____
| \ | | ___| |_ ___ ___  _ __  / _| / ___|  ___ _ ____   _____ _ __
|  \| |/ _ \ __/ __/ _ \| '_ \| |_  \___ \ / _ \ '__\ \ / / _ \ '__|
| |\  |  __/ || (_| (_) | | | |  _|  ___) |  __/ |   \ V /  __/ |
|_| \_|\___|\__\___\___/|_| |_|_|   |____/ \___|_|    \_/ \___|_|
'''


def print_banner(log):
    for line in banner.strip('\n').splitlines():
        log.info(line)
    log.info('(to stop: press Ctrl-C)')


class Main(object):
    def __init__(self):

        self.args = args = parse_args()
        self.config = load_config(args)
        self.logconfig = load_config(args, 'logconfig')

        verbosity_adjust = (args.verbose or 0) - (args.quiet or 0)
        self.log = setup_logging(self.logconfig,
                                 args.instance_id,
                                 verbosity_adjust=verbosity_adjust)

        # components
        self.nc_server = None
        self.grpc_client = None  # single, shared gRPC client to Voltha

        self.netconf_server_started = False

        self.exiting = False

        if not args.no_banner:
            print_banner(self.log)

        self.startup_components()

    def start(self):
        self.start_reactor()  # will not return except Keyboard interrupt

    @inlineCallbacks
    def startup_components(self):
        self.log.info('starting')
        args = self.args

        self.grpc_client = yield \
            GrpcClient(args.consul, args.work_dir, args.grpc_endpoint)

        self.nc_server =  yield \
                NCServer(int(args.netconf_port),
                         args.server_private_key_file,
                         args.server_public_key_file,
                         args.client_public_keys_file,
                         args.client_passwords_file,
                         self.grpc_client)

        # set on start callback
        self.grpc_client.set_on_start_callback(self._start_netconf_server)

        # set the callback if there is a reconnect with voltha.
        self.grpc_client.set_reconnect_callback(self.nc_server.reload_capabilities)

        # start grpc client
        self.grpc_client.start()

        self.log.info('started')

    @inlineCallbacks
    def _start_netconf_server(self):
        if not self.netconf_server_started:
            self.log.info('starting')
            yield self.nc_server.start()
            self.netconf_server_started = True
            self.log.info('started')
        else:
            self.log.info('server-already-started')

    @inlineCallbacks
    def shutdown_components(self):
        """Execute before the reactor is shut down"""
        self.log.info('exiting-on-keyboard-interrupt')
        self.exiting = True

        if self.grpc_client is not None:
            yield self.grpc_client.stop()

        if self.nc_server is not None:
            yield self.nc_server.stop()


    def start_reactor(self):
        reactor.callWhenRunning(
            lambda: self.log.info('twisted-reactor-started'))

        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.shutdown_components)
        reactor.run()


if __name__ == '__main__':
    Main().start()
