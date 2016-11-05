from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.error import AlreadyCalled


class TimeOutError(Exception): pass


class DeferredWithTimeout(Deferred):
    """
    Deferred with a timeout. If neither the callback nor the errback method
    is not called within the given time, the deferred's errback will be called
    with a TimeOutError() exception.

    All other uses are the same as of Deferred().
    """
    def __init__(self, timeout=1.0):
        Deferred.__init__(self)
        self._timeout = timeout
        self.timer = reactor.callLater(timeout, self.timed_out)

    def timed_out(self):
        self.errback(
            TimeOutError('timed out after {} seconds'.format(self._timeout)))

    def callback(self, result):
        self._cancel_timer()
        return Deferred.callback(self, result)

    def errback(self, fail):
        self._cancel_timer()
        return Deferred.errback(self, fail)

    def cancel(self):
        self._cancel_timer()
        return Deferred.cancel(self)

    def _cancel_timer(self):
        try:
            self.timer.cancel()
        except AlreadyCalled:
            pass

