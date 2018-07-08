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

import grpc
from concurrent import futures
from concurrent.futures import Future
from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue

from common.utils.asleep import asleep
from google.protobuf.empty_pb2 import Empty

from common.utils.grpc_utils import twisted_async
from streaming_pb2 import add_ExperimentalServiceServicer_to_server, \
    AsyncEvent, ExperimentalServiceServicer, Echo


class ShutDown(object):
    stop = False  # semaphore for all loops to stop when this flag is set


class ShuttingDown(Exception): pass


class Service(ExperimentalServiceServicer):

    def __init__(self):
        self.event_seq = 0

    @twisted_async
    @inlineCallbacks
    def GetEcho(self, request, context):
        print 'got Echo({}) request'.format(request.msg)
        yield asleep(request.delay)
        msg = request.msg + ' <<'
        print '    Echo({}) reply'.format(msg)
        returnValue(Echo(msg=msg))

    @twisted_async
    @inlineCallbacks
    def get_next_event(self):
        """called on the twisted thread"""
        yield asleep(0.000001)
        event = AsyncEvent(seq=self.event_seq, details='foo')
        self.event_seq += 1
        returnValue(event)

    def ReceiveStreamedEvents(self, request, context):
        """called on a thread-pool thread"""
        print 'got ReceiveStreamedEvents request'
        while 1:
            if ShutDown.stop:
                break
            yield self.get_next_event()

    def ReceivePackets(self, request, context):
        pass

    def SendPackets(self, request, context):
        count = 0
        for _ in request:
            count += 1
            if count % 1000 == 0:
                print '%s got %d packets' % (20 * ' ', count)
        return Empty()


if __name__ == '__main__':
    thread_pool = futures.ThreadPoolExecutor(max_workers=10)
    server = grpc.server(thread_pool)
    add_ExperimentalServiceServicer_to_server(Service(), server)
    server.add_insecure_port('[::]:50050')
    server.start()
    def shutdown():
        ShutDown.stop = True
        thread_pool.shutdown(wait=True)
        server.stop(0)
    reactor.addSystemEventTrigger('before', 'shutdown', shutdown)
    reactor.run()
