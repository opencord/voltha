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
from twisted.internet.defer import Deferred
from twisted.internet.defer import succeed


class MessageQueue(object):
    """
    An event driven queue, similar to twisted.internet.defer.DeferredQueue
    but which allows selective dequeing based on a predicate function.
    Unlike DeferredQueue, there is no limit on backlog, and there is no queue
    limit.
    """

    def __init__(self):
        self.waiting = []  # tuples of (d, predicate)
        self.queue = []  # messages piling up here if no one is waiting

    def reset(self):
        """
        Purge all content as well as waiters (by errback-ing their entries).
        :return: None
        """
        for d, _ in self.waiting:
            d.errback(Exception('mesage queue reset() was called'))
        self.waiting = []
        self.queue = []

    def _cancelGet(self, d):
        """
        Remove a deferred from our waiting list.
        :param d: The deferred that was been canceled.
        :return: None
        """
        for i in range(len(self.waiting)):
            if self.waiting[i][0] is d:
                self.waiting.pop(i)

    def put(self, obj):
        """
        Add an object to this queue
        :param obj: arbitrary object that will be added to the queue
        :return:
        """

        # if someone is waiting for this, return right away
        for i in range(len(self.waiting)):
            d, predicate = self.waiting[i]
            if predicate is None or predicate(obj):
                self.waiting.pop(i)
                d.callback(obj)
                return

        # otherwise...
        self.queue.append(obj)

    def get(self, predicate=None):
        """
        Attempt to retrieve and remove an object from the queue that
        matches the optional predicate.
        :return: Deferred which fires with the next object available.
        If predicate was provided, only objects for which
        predicate(obj) is True will be considered.
        """
        for i in range(len(self.queue)):
            msg = self.queue[i]
            if predicate is None or predicate(msg):
                self.queue.pop(i)
                return succeed(msg)

        # there were no matching entries if we got here, so we wait
        d = Deferred(canceller=self._cancelGet)
        self.waiting.append((d, predicate))
        return d


