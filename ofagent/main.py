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

"""TODO This is a POC placeholder """
import os

import grpc
import yaml
from twisted.internet import reactor

from agent import Agent
from common.utils.structlog_setup import setup_logging
from protos import voltha_pb2

from grpc_client import GrpcClient


def load_config(path):
    if path.startswith('.'):
        dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(dir, path)
    path = os.path.abspath(path)
    with open(path) as fd:
        config = yaml.load(fd)
    return config


if __name__ == '__main__':

    # Load config and setup logging
    config = load_config('./ofagent.yml')
    setup_logging(config.get('logging', {}), '1')


    # Create grpc channel to Voltha and grab client stub
    channel = grpc.insecure_channel('localhost:50055')

    # Connect to voltha using grpc and fetch the list of logical devices
    stub = voltha_pb2.VolthaLogicalLayerStub(channel)
    devices = stub.ListLogicalDevices(voltha_pb2.NullMessage()).items
    print 'device id and datapaht_id list:'
    for device in devices:
        print '\t{} -> {}'.format(device.id, device.datapath_id)

    # make a device.datapath_id -> device.id map (this will need to be actively
    # managed in the real agent based on devices coming and going
    device_id_map = dict((device.datapath_id, device.id) for device in devices)

    # Create shared gRPC API object
    grpc_client = GrpcClient(channel, device_id_map)

    # Instantiate an OpenFlow agent for each logical device
    agents = [
        Agent('localhost:6633', device.datapath_id, grpc_client).run()
        for device in devices
    ]

    def shutdown():
        [a.stop() for a in agents]

    reactor.addSystemEventTrigger('before', 'shutdown', shutdown)
    reactor.run()
