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
Utilities to handle gRPC server and client side code in a Twisted environment
"""
import structlog
from concurrent.futures import Future
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.python.threadable import isInIOThread


log = structlog.get_logger()


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

    Example usage:

    When implementing a gRPC server, typical pattern is:

    class SpamService(SpamServicer):

        def GetBadSpam(self, request, context):
            '''this is called from a ThreadPoolExecutor thread'''
            # generally unsafe to make Twisted calls

        @twisted_async
        def GetSpamSafely(self, request, context):
            '''this method now is executed on the Twisted main thread
            # safe to call any Twisted protocol functions

        @twisted_async
        @inlineCallbacks
        def GetAsyncSpam(self, request, context):
            '''this generator can use inlineCallbacks Twisted style'''
            result = yield some_async_twisted_call(request)
            returnValue(result)

    """
    def in_thread_wrapper(*args, **kw):

        if isInIOThread():

            return func(*args, **kw)

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
        try:
            result = f.result()
        except Exception, e:
            log.exception(e=e, func=func, args=args, kw=kw)
            raise

        return result

    return in_thread_wrapper


