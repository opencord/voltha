#!/usr/bin/env python
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
from Queue import Queue

import grpc
from google.protobuf.empty_pb2 import Empty
from twisted.internet import reactor
from twisted.internet import threads
from twisted.internet.defer import Deferred, inlineCallbacks, DeferredQueue, \
    returnValue

from common.utils.asleep import asleep
from streaming_pb2 import ExperimentalServiceStub, Echo, Packet

t0 = time.time()


def pr(s):
    print '%lf %s' % (time.time() - t0, s)


class ClientServices(object):

    def async_receive_stream(self, func, *args, **kw):
        queue = DeferredQueue()
        def _execute():
            for result in func(*args, **kw):
                reactor.callFromThread(queue.put, result)
        _ = threads.deferToThread(_execute)
        while 1:
            yield queue.get()

    @inlineCallbacks
    def echo_loop(self, stub, prefix='', interval=1.0):
        """Send an echo message and print its return value"""
        seq = 0
        while 1:
            msg = 'ECHO%05d' % seq
            pr('{}sending echo {}'.format(prefix, msg))
            request = Echo(msg=msg, delay=interval)
            response = yield threads.deferToThread(stub.GetEcho, request)
            pr('{}    got echo {}'.format(prefix, response.msg))
            seq += 1
            yield asleep(interval)

    @inlineCallbacks
    def receive_async_events(self, stub):
        e = Empty()
        for next in self.async_receive_stream(stub.ReceiveStreamedEvents, e):
            event = yield next
            if event.seq % 100 == 0:
                pr('event received: %s %s %s' % (
                   event.seq, event.type, event.details))

    @inlineCallbacks
    def send_packet_stream(self, stub, interval):
        queue = Queue()

        @inlineCallbacks
        def get_next_from_queue():
            packet = yield queue.get()
            returnValue(packet)

        def packet_generator():
            while 1:
                packet = queue.get(block=True)
                yield packet

        def stream(stub):
            """This is executed on its own thread"""
            generator = packet_generator()
            result = stub.SendPackets(generator)
            print 'Got this after sending packets:', result, type(result)
            return result

        reactor.callInThread(stream, stub)

        while 1:
            len = queue.qsize()
            if len < 100:
                packet = Packet(source=42, content='beefstew')
                queue.put(packet)
            yield asleep(interval)


if __name__ == '__main__':
    client_services = ClientServices()
    channel = grpc.insecure_channel('localhost:50050')
    stub = ExperimentalServiceStub(channel)
    reactor.callLater(0, client_services.echo_loop, stub, '', 0.2)
    reactor.callLater(0, client_services.echo_loop, stub, 40*' ', 2)
    reactor.callLater(0, client_services.receive_async_events, stub)
    reactor.callLater(0, client_services.send_packet_stream, stub, 0.0000001)
    reactor.run()
