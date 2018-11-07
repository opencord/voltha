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
import structlog
import argparse
import time

from concurrent import futures
import grpc

from voltha.adapters.asfvolt16_olt.protos.bal_pb2_grpc import BalServicer, add_BalServicer_to_server
from voltha.adapters.asfvolt16_olt.protos.bal_pb2 import BalErr
from voltha.adapters.asfvolt16_olt.protos.bal_errno_pb2 import BAL_ERR_OK

log = structlog.get_logger()

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

class BalHandler(BalServicer):
    def __init__(self):
        pass

    def BalApiInit(self, request, context):
        log.info('olt-connection-successful', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalApiFinish(self, request, context):
        log.info('BalApi', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalCfgSet(self, request, context):
        log.info('olt-activation-successful', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalAccessTerminalCfgSet(self, request, context):
        log.info('olt-activation-successful', request=request)
        return BalErr(err=BAL_ERR_OK)

    def BalCfgClear(self, request, context):
        log.info('BalCfClear', request=request)
        return BalErr(err=BAL_ERR_OK)

class GrpcServer(object):
    def __init__(self, port):
        self.port = port
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    def start(self):
        log.debug('starting')
        add_BalServicer_to_server(BalHandler(), self.server)
        self.server.add_insecure_port('[::]:%s' % self.port)
        self.server.start()
        log.info('started')

    def stop(self, grace=0):
        log.debug('stopping')
        self.server.stop(grace)
        log.info('stopped')

def parse_args():
    parser = argparse.ArgumentParser()
    _help = ('port number of the GRPC service exposed by voltha (default: 50599)')
    parser.add_argument('-g', '--grpc-port',
                        dest='grpc_port',
                        action='store',
                        default=50060,
                        help=_help)
    args = parser.parse_args()
    return args

class Main(object):
    def __init__(self):
        self.args = parse_args()
        self.grpc_server = GrpcServer(self.args.grpc_port)

    def start(self):
        self.grpc_server.start()
        try:
            while True:
                time.sleep(_ONE_DAY_IN_SECONDS)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
            self.grpc_server.stop(0)

if __name__ == '__main__':
    Main().start()
