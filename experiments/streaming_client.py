#!/usr/bin/env python

import time

import grpc
from google.protobuf.empty_pb2 import Empty
from twisted.internet import reactor
from twisted.internet import threads
from twisted.internet.defer import Deferred, inlineCallbacks, DeferredQueue

from common.utils.asleep import asleep
from streaming_pb2 import ExperimentalServiceStub, Echo


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


if __name__ == '__main__':
    client_services = ClientServices()
    channel = grpc.insecure_channel('localhost:50050')
    stub = ExperimentalServiceStub(channel)
    reactor.callLater(0, client_services.echo_loop, stub, '', 0.2)
    reactor.callLater(0, client_services.echo_loop, stub, 40*' ', 2)
    reactor.callLater(0, client_services.receive_async_events, stub)
    reactor.run()
