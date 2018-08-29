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
from voltha.extensions.omci.tasks.task import Task
from common.utils.asleep import asleep
from twisted.internet.defer import inlineCallbacks, failure
from twisted.internet import reactor


class SimpleTask(Task):
    def __init__(self, omci_agent, device_id,
                 exclusive=True,
                 success=True,
                 delay=0,
                 value=None,
                 priority=Task.DEFAULT_PRIORITY,
                 watchdog_timeout=Task.DEFAULT_WATCHDOG_SECS):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param exclusive: (bool) True if the task should run by itself
        :param success: (bool) True if the task should complete successfully
        :param delay: (int/float) Time it takes the task to complete
        :param priority (int) Priority of the task
        :param watchdog_timeout (int or float) Watchdog timeout after task start
        :param value: (various) The value (string, int, ...) to return if successful
                                or an Exception to send to the errBack if 'success'
                                is False
        """
        super(SimpleTask, self).__init__('Simple Mock Task',
                                         omci_agent,
                                         device_id,
                                         exclusive=exclusive,
                                         priority=priority,
                                         watchdog_timeout=watchdog_timeout)
        self._delay = delay
        self._success = success
        self._value = value
        self._local_deferred = None

    def cancel_deferred(self):
        super(SimpleTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start MIB Synchronization tasks
        """
        super(SimpleTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_task)

    def stop(self):
        """
        Shutdown MIB Synchronization tasks
        """
        self.cancel_deferred()
        super(SimpleTask, self).stop()

    @inlineCallbacks
    def perform_task(self):
        """
        Get the 'mib_data_sync' attribute of the ONU
        """
        try:
            if self._delay > 0:
                yield asleep(self._delay)

            if self._success:
                self.deferred.callback(self._value)

            self.deferred.errback(failure.Failure(self._value))

        except Exception as e:
            self.deferred.errback(failure.Failure(e))
