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

from grpc import StatusCode
from grpc._channel import _Rendezvous
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue

from protos.voltha_pb2 import ID, VolthaLocalServiceStub, FlowTableUpdate, \
    FlowGroupTableUpdate, PacketOut
from google.protobuf import empty_pb2


log = get_logger()


class GrpcClient(object):

    def __init__(self, connection_manager, channel):

        self.connection_manager = connection_manager
        self.channel = channel
        self.local_stub = VolthaLocalServiceStub(channel)

        self.stopped = False

        self.packet_out_queue = Queue()  # queue to send out PacketOut msgs
        self.packet_in_queue = DeferredQueue()  # queue to receive PacketIn
        self.change_event_queue = DeferredQueue()  # queue change events

    def start(self):
        log.debug('starting')
        self.start_packet_out_stream()
        self.start_packet_in_stream()
        self.start_change_event_in_stream()
        reactor.callLater(0, self.packet_in_forwarder_loop)
        reactor.callLater(0, self.change_event_processing_loop)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.stopped = True
        log.info('stopped')

    def start_packet_out_stream(self):

        def packet_generator():
            while 1:
                try:
                    packet = self.packet_out_queue.get(block=True, timeout=1.0)
                except Empty:
                    if self.stopped:
                        return
                else:
                    yield packet

        def stream_packets_out():
            generator = packet_generator()
            self.local_stub.StreamPacketsOut(generator)

        reactor.callInThread(stream_packets_out)

    def start_packet_in_stream(self):

        def receive_packet_in_stream():
            streaming_rpc_method = self.local_stub.ReceivePacketsIn
            iterator = streaming_rpc_method(empty_pb2.Empty(), timeout=1.0)
            while not self.stopped:
                try:
                    for packet_in in iterator:
                        reactor.callFromThread(self.packet_in_queue.put,
                                               packet_in)
                        log.debug('enqued-packet-in',
                                  packet_in=packet_in,
                                  queue_len=len(self.packet_in_queue.pending))
                except _Rendezvous, e:
                    if e.code() == StatusCode.DEADLINE_EXCEEDED:
                        continue
                    raise

        reactor.callInThread(receive_packet_in_stream)

    def start_change_event_in_stream(self):

        def receive_change_events():
            streaming_rpc_method = self.local_stub.ReceiveChangeEvents
            iterator = streaming_rpc_method(empty_pb2.Empty(), timeout=1.0)
            while not self.stopped:
                try:
                    for event in iterator:
                        reactor.callFromThread(self.change_event_queue.put, event)
                        log.debug('enqued-change-event',
                                  change_event=event,
                                  queue_len=len(self.change_event_queue.pending))
                except _Rendezvous, e:
                    if e.code() == StatusCode.DEADLINE_EXCEEDED:
                        continue
                    raise

        reactor.callInThread(receive_change_events)

    @inlineCallbacks
    def change_event_processing_loop(self):
        while True:
            try:
                event = yield self.change_event_queue.get()
                device_id = event.id
                self.connection_manager.forward_change_event(device_id, event)
            except Exception, e:
                log.exception('failed-in-packet-in-handler', e=e)
            if self.stopped:
                break

    @inlineCallbacks
    def packet_in_forwarder_loop(self):
        while True:
            packet_in = yield self.packet_in_queue.get()
            device_id = packet_in.id
            ofp_packet_in = packet_in.packet_in
            self.connection_manager.forward_packet_in(device_id, ofp_packet_in)
            if self.stopped:
                break

    def send_packet_out(self, device_id, packet_out):
        packet_out = PacketOut(id=device_id, packet_out=packet_out)
        self.packet_out_queue.put(packet_out)

    @inlineCallbacks
    def get_port_list(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDevicePorts, req)
        returnValue(res.items)

    @inlineCallbacks
    def get_device_info(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.GetLogicalDevice, req)
        returnValue(res)

    @inlineCallbacks
    def update_flow_table(self, device_id, flow_mod):
        req = FlowTableUpdate(
            id=device_id,
            flow_mod=flow_mod
        )
        res = yield threads.deferToThread(
            self.local_stub.UpdateLogicalDeviceFlowTable, req)
        returnValue(res)

    @inlineCallbacks
    def update_group_table(self, device_id, group_mod):
        req = FlowGroupTableUpdate(
            id=device_id,
            group_mod=group_mod
        )
        res = yield threads.deferToThread(
            self.local_stub.UpdateLogicalDeviceFlowGroupTable, req)
        returnValue(res)

    @inlineCallbacks
    def list_flows(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDeviceFlows, req)
        returnValue(res.items)

    @inlineCallbacks
    def list_groups(self, device_id):
        req = ID(id=device_id)
        res = yield threads.deferToThread(
            self.local_stub.ListLogicalDeviceFlowGroups, req)
        returnValue(res.items)
