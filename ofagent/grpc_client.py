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
The gRPC client layer for the OpenFlow agent
"""
from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks, returnValue

from protos.voltha_pb2 import ID, VolthaLogicalLayerStub, FlowTableUpdate


class GrpcClient(object):

    def __init__(self, channel, device_id_map):
        self.channel = channel
        self.device_id_map = device_id_map
        self.logical_stub = VolthaLogicalLayerStub(channel)

    @inlineCallbacks
    def get_port_list(self, datapath_id):
        device_id = self.device_id_map[datapath_id]
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.logical_stub.ListLogicalDevicePorts, req)
        returnValue(res.items)

    @inlineCallbacks
    def get_device_info(self, datapath_id):
        device_id = self.device_id_map[datapath_id]
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.logical_stub.GetLogicalDevice, req)
        returnValue(res)

    @inlineCallbacks
    def update_flow_table(self, datapath_id, flow_mod):
        device_id = self.device_id_map[datapath_id]
        req = FlowTableUpdate(
            id=device_id,
            flow_mod=flow_mod
        )
        res = yield threads.deferToThread(
            self.logical_stub.UpdateFlowTable, req)
        returnValue(res)

    @inlineCallbacks
    def list_flows(self, datapath_id):
        device_id = self.device_id_map[datapath_id]
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.logical_stub.ListDeviceFlows, req)
        returnValue(res.items)
