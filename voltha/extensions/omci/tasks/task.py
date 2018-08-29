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
import structlog
from twisted.internet import defer, reactor
from twisted.internet.defer import failure


class WatchdogTimeoutFailure(Exception):
    """Task callback/errback not called properly before watchdog expiration"""
    pass


class Task(object):
    """
    OpenOMCI Base Task implementation

    An OMCI task can be one or more OMCI requests, comparisons, or whatever
    is needed to do a specific unit of work that needs to be ran to completion
    successfully.

    On successful completion, the task should called the 'callback' method of
    the deferred and pass back whatever is meaningful to the user/state-machine
    that launched it.

    On failure, the 'errback' routine should be called with an appropriate
    Failure object.
    """
    DEFAULT_PRIORITY = 128
    MIN_PRIORITY = 0
    MAX_PRIORITY = 255
    DEFAULT_WATCHDOG_SECS = 10          # 10 seconds
    MIN_WATCHDOG_SECS = 3               # 3 seconds
    MAX_WATCHDOG_SECS = 60              # 60 seconds

    _next_task_id = 0

    def __init__(self, name, omci_agent, device_id, priority=DEFAULT_PRIORITY,
                 exclusive=True, watchdog_timeout=DEFAULT_WATCHDOG_SECS):
        """
        Class initialization

        :param name: (str) Task Name
        :param device_id: (str) ONU Device ID
        :param priority: (int) Task priority (0..255) 255 Highest
        :param exclusive: (bool) If True, this task needs exclusive access to the
                                 OMCI Communications channel when it runs
        :param watchdog_timeout (int or float) Watchdog timeout (seconds) after task start, to
                                run longer, periodically call 'strobe_watchdog()' to reschedule.
        """
        assert Task.MIN_PRIORITY <= priority <= Task.MAX_PRIORITY, \
            'Priority should be {}..{}'.format(Task.MIN_PRIORITY, Task.MAX_PRIORITY)

        assert Task.MIN_WATCHDOG_SECS <= watchdog_timeout <= Task.MAX_WATCHDOG_SECS, \
            'Watchdog timeout should be {}..{} seconds'

        Task._next_task_id += 1
        self._task_id = Task._next_task_id
        self.log = structlog.get_logger(device_id=device_id, name=name,
                                        task_id=self._task_id)
        self.name = name
        self.device_id = device_id
        self.omci_agent = omci_agent
        self._running = False
        self._exclusive = exclusive
        self._deferred = defer.Deferred()       # Fires upon completion
        self._watchdog = None
        self._watchdog_timeout = watchdog_timeout
        self._priority = priority

    def __str__(self):
        return 'Task: {}, ID:{}, Priority: {}, Exclusive: {}, Watchdog: {}'.format(
            self.name, self.task_id, self.priority, self.exclusive, self.watchdog_timeout)

    @property
    def priority(self):
        return self._priority

    @property
    def task_id(self):
        return self._task_id

    @property
    def exclusive(self):
        return self._exclusive

    @property
    def watchdog_timeout(self):
        return self._watchdog_timeout

    @property
    def deferred(self):
        return self._deferred

    @property
    def running(self):
        # Is the Task running?
        #
        # Can be useful for tasks that use inline callbacks to detect
        # if the task has been canceled.
        #
        return self._running

    def cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._watchdog = self._watchdog, None

        for d in [d1, d2]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def start(self):
        """
        Start task operations
        """
        self.log.debug('starting')
        assert self._deferred is not None and not self._deferred.called, \
            'Cannot re-use the same task'
        self._running = True
        self.strobe_watchdog()

    def stop(self):
        """
        Stop task synchronization
        """
        self.log.debug('stopping')
        self._running = False
        self.cancel_deferred()
        self.omci_agent = None      # Should only start/stop once

    def task_cleanup(self):
        """
        This method should only be called from the TaskRunner's callback/errback
        that is added when the task is initially queued. It is responsible for
        clearing of the 'running' flag and canceling of the watchdog time
        """
        self._running = False
        d, self._watchdog = self._watchdog, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def strobe_watchdog(self):
        """
        Signal that we have not hung/deadlocked
        """
        # Create if first time (called at Task start)

        def watchdog_timeout():
            # Task may have hung (blocked) or failed to call proper success/error
            # completion callback/errback
            if not self.deferred.called:
                err_msg = 'Task {}:{} watchdog timeout'.format(self.name, self.task_id)
                self.log.error("task-watchdog-timeout", running=self.running,
                               timeout=self.watchdog_timeout, error=err_msg)

                self.deferred.errback(failure.Failure(WatchdogTimeoutFailure(err_msg)))
                self.deferred.cancel()

        if self._watchdog is not None:
            if self._watchdog.called:
                # Too late, timeout failure in progress
                self.log.warn('task-watchdog-tripped', running=self.running,
                              timeout=self.watchdog_timeout)
                return

            d, self._watchdog = self._watchdog, None
            d.cancel()

        # Schedule/re-schedule the watchdog timer
        self._watchdog = reactor.callLater(self.watchdog_timeout, watchdog_timeout)
