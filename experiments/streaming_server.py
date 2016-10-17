import grpc
from concurrent import futures
from concurrent.futures import Future
from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue

from openflow_13_pb2 import add_OpenFlowServicer_to_server, \
    OpenFlowServicer
from streaming_pb2 import add_ExperimentalServiceServicer_to_server, \
    AsyncEvent, ExperimentalServiceServicer, Echo


class ShutDown(object):
    stop = False  # semaphore for all loops to stop when this flag is set


def asleep(t):
    d = Deferred()
    reactor.callLater(t, d.callback, None)
    return d


class ShuttingDown(Exception): pass


def twisted_async(func):
    """
    This decorator can be used to implement a gRPC method on the twisted
    thread, allowing asynchronous programming in Twisted while serving
    a gRPC call.

    gRPC methods normally are called on the futures.ThreadPool threads,
    so these methods cannot directly use Twisted protocol constructs.
    If the implementation of the methods needs to touch Twisted, it is
    safer (or mandatory) to wrap the method with this decorator, which will
    call the inner method from the external thread and ensure that the
    result is passed back to the foreign thread.
    """
    def in_thread_wrapper(*args, **kw):

        if ShutDown.stop:
            raise ShuttingDown()
        f = Future()

        def twisted_wrapper():
            try:
                d = func(*args, **kw)
                if isinstance(d, Deferred):

                    def _done(result):
                        f.set_result(result)
                        f.done()

                    def _error(e):
                        f.set_exception(e)
                        f.done()

                    d.addCallback(_done)
                    d.addErrback(_error)

                else:
                    f.set_result(d)
                    f.done()

            except Exception, e:
                f.set_exception(e)
                f.done()

        reactor.callFromThread(twisted_wrapper)
        result = f.result()

        return result

    return in_thread_wrapper


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
        pass


class OpenFlow(OpenFlowServicer):

    def EchoRequest(self, request, context):
        pass

    def SendPacketsOutMessages(self, request, context):
        pass

    def ReceivePacketInMessages(self, request, context):
        pass


if __name__ == '__main__':
    thread_pool = futures.ThreadPoolExecutor(max_workers=10)
    server = grpc.server(thread_pool)
    add_ExperimentalServiceServicer_to_server(Service(), server)
    add_OpenFlowServicer_to_server(OpenFlow(), server)
    server.add_insecure_port('[::]:50050')
    server.start()
    def shutdown():
        ShutDown.stop = True
        thread_pool.shutdown(wait=True)
        server.stop(0)
    reactor.addSystemEventTrigger('before', 'shutdown', shutdown)
    reactor.run()
