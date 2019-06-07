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

"""
The gRPC client layer for the OpenFlow agent
"""
from Queue import Queue, Empty
import os

from grpc import StatusCode
from grpc._channel import _Rendezvous
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue

from protos.voltha_pb2 import ID, FlowTableUpdate, MeterModUpdate, \
    FlowGroupTableUpdate, PacketOut
from protos.voltha_pb2_grpc import VolthaLocalServiceStub
from protos.logical_device_pb2 import LogicalPortId
from google.protobuf import empty_pb2


class GrpcClient(object):

    def __init__(self, connection_manager, channel, grpc_timeout):

        self.log = get_logger()

        self.connection_manager = connection_manager
        self.channel = channel
        self.grpc_timeout = grpc_timeout
        self.local_stub = VolthaLocalServiceStub(channel)

        self.stopped = False

        self.packet_out_queue = Queue()  # queue to send out PacketOut msgs
        self.packet_in_queue = DeferredQueue()  # queue to receive PacketIn
        self.change_event_queue = DeferredQueue()  # queue change events

        self.count_pkt_in = 0
        self.count_pkt_out = 0

    def start(self):
        self.log.debug('starting', grpc_timeout=self.grpc_timeout)
        self.start_packet_out_stream()
        self.start_packet_in_stream()
        self.start_change_event_in_stream()
        reactor.callLater(0, self.packet_in_forwarder_loop)
        reactor.callLater(0, self.change_event_processing_loop)
        self.log.info('started')
        return self

    def stop(self):
        self.log.debug('stopping')
        self.stopped = True
        self.log.info('stopped')

    def start_packet_out_stream(self):

        def packet_generator():
            while 1:
                try:
                    packet = self.packet_out_queue.get(block=True, timeout=1.0)
                except Empty:
                    if self.stopped:
                        return
                else:
                    self.count_pkt_out += 1
                    self.log.debug('counters grpc_client OUT - {}'.format(self.count_pkt_out))
                    yield packet

        def stream_packets_out():
            generator = packet_generator()
            try:
                self.local_stub.StreamPacketsOut(generator)
            except _Rendezvous, e:
                self.log.error('grpc-exception', status=e.code())
                if e.code() == StatusCode.UNAVAILABLE:
                    os.system("kill -15 {}".format(os.getpid()))

        reactor.callInThread(stream_packets_out)

    def start_packet_in_stream(self):

        def receive_packet_in_stream():
            streaming_rpc_method = self.local_stub.ReceivePacketsIn
            iterator = streaming_rpc_method(empty_pb2.Empty())
            try:
                for packet_in in iterator:
                    reactor.callFromThread(self.packet_in_queue.put,
                                           packet_in)
                    self.log.debug('enqued-packet-in',
                              packet_in=packet_in,
                              queue_len=len(self.packet_in_queue.pending))
                    self.count_pkt_in += 1
                    self.log.debug('counters grpc_client IN - {}'.format(self.count_pkt_in))
            except _Rendezvous, e:
                self.log.error('grpc-exception', status=e.code())
                if e.code() == StatusCode.UNAVAILABLE:
                    os.system("kill -15 {}".format(os.getpid()))

        reactor.callInThread(receive_packet_in_stream)

    def start_change_event_in_stream(self):

        def receive_change_events():
            streaming_rpc_method = self.local_stub.ReceiveChangeEvents
            iterator = streaming_rpc_method(empty_pb2.Empty())
            try:
                for event in iterator:
                    reactor.callFromThread(self.change_event_queue.put, event)
                    self.log.debug('enqued-change-event',
                              change_event=event,
                              queue_len=len(self.change_event_queue.pending))
            except _Rendezvous, e:
                self.log.error('grpc-exception', status=e.code())
                if e.code() == StatusCode.UNAVAILABLE:
                    os.system("kill -15 {}".format(os.getpid()))

        reactor.callInThread(receive_change_events)

    @inlineCallbacks
    def change_event_processing_loop(self):
        while True:
            try:
                event = yield self.change_event_queue.get()
                device_id = event.id
                self.connection_manager.forward_change_event(device_id, event)
            except Exception, e:
                self.log.exception('failed-in-packet-in-handler', e=e)
            if self.stopped:
                break

    @inlineCallbacks
    def packet_in_forwarder_loop(self):
        while True:
            packet_in = yield self.packet_in_queue.get()
            device_id = packet_in.id
            ofp_packet_in = packet_in.packet_in
            self.log.debug('grpc client to send packet-in')
            self.connection_manager.forward_packet_in(device_id, ofp_packet_in)
            if self.stopped:
                break

    def send_packet_out(self, device_id, packet_out):
        self.log.debug('grpc client to send packet-out')
        packet_out = PacketOut(id=device_id, packet_out=packet_out)
        self.packet_out_queue.put(packet_out)

    @inlineCallbacks
    def get_port(self, device_id, port_id):
        req = LogicalPortId(id=device_id, port_id=port_id)
        res = yield threads.deferToThread(
            self.local_stub.GetLogicalDevicePort, req, timeout=self.grpc_timeout)
        returnValue(res)

    @inlineCallbacks
    def get_port_list(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDevicePorts, req, timeout=self.grpc_timeout)
        returnValue(res.items)

    @inlineCallbacks
    def enable_port(self, device_id, port_id):
        req = LogicalPortId(
            id=device_id,
            port_id=port_id
        )
        res = yield threads.deferToThread(
            self.local_stub.EnableLogicalDevicePort, req, timeout=self.grpc_timeout)
        returnValue(res)

    @inlineCallbacks
    def disable_port(self, device_id, port_id):
        req = LogicalPortId(
            id=device_id,
            port_id=port_id
        )
        res = yield threads.deferToThread(
            self.local_stub.DisableLogicalDevicePort, req, timeout=self.grpc_timeout)
        returnValue(res)

    @inlineCallbacks
    def get_device_info(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.GetLogicalDevice, req, timeout=self.grpc_timeout)
        returnValue(res)

    @inlineCallbacks
    def update_flow_table(self, device_id, flow_mod):
        req = FlowTableUpdate(
            id=device_id,
            flow_mod=flow_mod
        )
        res = yield threads.deferToThread(
            self.local_stub.UpdateLogicalDeviceFlowTable, req, timeout=self.grpc_timeout)
        returnValue(res)

    @inlineCallbacks
    def update_meter_mod_table(self, device_id, meter_mod):
        req = MeterModUpdate(
            id=device_id,
            meter_mod=meter_mod
        )
        res = yield threads.deferToThread(
            self.local_stub.UpdateLogicalDeviceMeterTable, req, timeout=self.grpc_timeout)
        returnValue(res)

    @inlineCallbacks
    def update_group_table(self, device_id, group_mod):
        req = FlowGroupTableUpdate(
            id=device_id,
            group_mod=group_mod
        )
        res = yield threads.deferToThread(
            self.local_stub.UpdateLogicalDeviceFlowGroupTable, req, timeout=self.grpc_timeout)
        returnValue(res)

    @inlineCallbacks
    def list_flows(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDeviceFlows, req, timeout=self.grpc_timeout)
        returnValue(res.items)

    @inlineCallbacks
    def list_groups(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDeviceFlowGroups, req, timeout=self.grpc_timeout)
        returnValue(res.items)

    @inlineCallbacks
    def list_meters(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDeviceMeters, req, timeout=self.grpc_timeout)
        returnValue(res.items)

    @inlineCallbacks
    def list_ports(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDevicePorts, req, timeout=self.grpc_timeout)
        returnValue(res.items)

    @inlineCallbacks
    def list_logical_devices(self):
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDevices, empty_pb2.Empty(), timeout=self.grpc_timeout)
        returnValue(res.items)

    @inlineCallbacks
    def list_reachable_logical_devices(self):
        res = yield threads.deferToThread(
            self.local_stub.ListReachableLogicalDevices, empty_pb2.Empty(),
            timeout=self.grpc_timeout)
        returnValue(res.items)

    @inlineCallbacks
    def subscribe(self, subscriber):
        res = yield threads.deferToThread(
            self.local_stub.Subscribe, subscriber, timeout=self.grpc_timeout)
        returnValue(res)
