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
from twisted.internet import defer


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
    _next_task_id = 0

    def __init__(self, name, omci_agent, device_id, priority=DEFAULT_PRIORITY,
                 exclusive=True):
        """
        Class initialization

        :param name: (str) Task Name
        :param device_id: (str) ONU Device ID
        :param priority: (int) Task priority (0..255) 255 Highest
        :param exclusive: (bool) If True, this task needs exclusive access to the
                                 OMCI Communications channel when it runs
        """
        assert Task.MIN_PRIORITY <= priority <= Task.MAX_PRIORITY, \
            'Priority should be {}..{}'.format(Task.MIN_PRIORITY, Task.MAX_PRIORITY)

        Task._next_task_id += 1
        self._task_id = Task._next_task_id
        self.log = structlog.get_logger(device_id=device_id, name=name,
                                        task_id=self._task_id)
        self.name = name
        self.device_id = device_id
        self.omci_agent = omci_agent
        self._running = False
        self._exclusive = exclusive
        # TODO: Should we watch for a cancel on the task's deferred as well?
        self._deferred = defer.Deferred()       # Fires upon completion
        self._priority = priority

    def __str__(self):
        return 'Task: {}, ID:{}, Priority: {}, Exclusive: {}'.format(
            self.name, self.task_id, self.priority, self.exclusive)

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
        d, self._deferred = self._deferred, None
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

    def stop(self):
        """
        Stop task synchronization
        """
        self.log.debug('stopping')
        self._running = False
        self.cancel_deferred()
        self.omci_agent = None      # Should only start/stop once
