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

from unittest import TestCase, main
from nose.tools import raises
from twisted.internet import defer
from twisted.internet.defer import inlineCallbacks, returnValue, CancelledError
from mock.mock_task import SimpleTask
from nose.twistedtools import deferred
from voltha.extensions.omci.tasks.task_runner import TaskRunner

DEVICE_ID = 'omci-unit-tests'


class TestTaskRunner(TestCase):
    """
    Test the Task Runner Object
    """

    def setUp(self):
        # defer.setDebugging(True)
        self.runner = TaskRunner(DEVICE_ID)

    def tearDown(self):
        r, self.runner = self.runner, None
        r.stop()

    def test_default_init(self):
        self.assertFalse(self.runner.active)
        self.assertEqual(self.runner.pending_tasks, 0)
        self.assertEqual(self.runner.running_tasks, 0)
        self.assertEqual(self.runner.successful_tasks_completed, 0)
        self.assertEqual(self.runner.failed_tasks, 0)

    def test_start_stop(self):
        self.assertFalse(self.runner.active)

        self.runner.start()
        self.assertTrue(self.runner.active)

        self.runner.stop()
        self.assertFalse(self.runner.active)

    def unexpected_error(self, _failure):
        self.assertEqual('Should not be here, expected success', _failure)

    def unexpected_success(self, _results):
        self.assertEqual('Should not be here, expected a failure', _results)

    def test_simple_task_init(self):
        t = SimpleTask(None, DEVICE_ID,
                       exclusive=True, priority=0,
                       success=True, value=0, delay=0)

        self.assertEqual(t.priority, 0)
        self.assertGreater(t.task_id, 0)
        self.assertTrue(t.exclusive)
        self.assertFalse(t.deferred.called)

    def test_task_defaults_and_bound(self):
        # Make sure no one has changed some declared defaults/max/min values
        from voltha.extensions.omci.tasks.task import Task
        self.assertEqual(128, Task.DEFAULT_PRIORITY)
        self.assertEqual(0, Task.MIN_PRIORITY)
        self.assertEqual(255, Task.MAX_PRIORITY)
        self.assertEqual(10, Task.DEFAULT_WATCHDOG_SECS)
        self.assertEqual(3, Task.MIN_WATCHDOG_SECS)
        self.assertEqual(60, Task.MAX_WATCHDOG_SECS)

    @raises(AssertionError)
    def test_task_priority_min(self):
        from voltha.extensions.omci.tasks.task import Task
        _ = SimpleTask(None, DEVICE_ID, priority=Task.MIN_PRIORITY - 1)

    @raises(AssertionError)
    def test_task_priority_max(self):
        from voltha.extensions.omci.tasks.task import Task
        _ = SimpleTask(None, DEVICE_ID, priority=Task.MAX_PRIORITY + 1)

    @raises(AssertionError)
    def test_task_watchdog_min(self):
        from voltha.extensions.omci.tasks.task import Task
        _ = SimpleTask(None, DEVICE_ID, watchdog_timeout=Task.MIN_WATCHDOG_SECS - 0.000001)

    @raises(AssertionError)
    def test_task_watchdog_max(self):
        from voltha.extensions.omci.tasks.task import Task
        _ = SimpleTask(None, DEVICE_ID, watchdog_timeout=Task.MAX_WATCHDOG_SECS + 0.000001)

    @deferred(timeout=5)
    def test_simple_success(self):
        expected_result = 123

        t = SimpleTask(None, DEVICE_ID,
                       exclusive=True, priority=0,
                       success=True, value=expected_result, delay=0)

        d = self.runner.queue_task(t)
        self.assertEqual(self.runner.pending_tasks, 1)
        self.assertEqual(self.runner.running_tasks, 0)
        self.runner.start()

        def check_results(results):
            self.assertEqual(results, expected_result)
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 1)
            self.assertEqual(self.runner.failed_tasks, 0)
            self.assertTrue(self.runner.active)
            return results

        d.addCallbacks(check_results, self.unexpected_error)
        return d

    @raises(Exception)
    @deferred(timeout=5)
    def test_simple_failure(self):
        self.expected_failure = Exception('Testing a task failure')

        t = SimpleTask(None, DEVICE_ID,
                       exclusive=True, priority=0,
                       success=False, value=self.expected_failure,
                       delay=0)

        d = self.runner.queue_task(t)
        self.assertEqual(self.runner.pending_tasks, 1)
        self.assertEqual(self.runner.running_tasks, 0)
        self.runner.start()

        def expected_failure(failure):
            self.assertEqual(failure, self.expected_failure)
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 0)
            self.assertEqual(self.runner.failed_tasks, 1)
            self.assertTrue(self.runner.active)
            return failure

        d.addCallbacks(self.unexpected_success, expected_failure)
        return d

    @deferred(timeout=5)
    def test_priority(self):
        self.last_value_set = 0

        t1 = SimpleTask(None, DEVICE_ID,
                        exclusive=True, priority=1,
                        success=True, value=1, delay=0)

        t2 = SimpleTask(None, DEVICE_ID,
                        exclusive=True, priority=2,     # Should finish first
                        success=True, value=2, delay=0)

        d1 = self.runner.queue_task(t1)
        d2 = self.runner.queue_task(t2)

        def set_last_value(results):
            self.last_value_set = results

        d1.addCallbacks(set_last_value, self.unexpected_error)
        d2.addCallbacks(set_last_value, self.unexpected_error)

        self.assertEqual(self.runner.pending_tasks, 2)
        self.assertEqual(self.runner.running_tasks, 0)

        d = defer.gatherResults([d1, d2], consumeErrors=True)

        def check_results(_):
            self.assertEqual(self.last_value_set, 1)
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 2)

        d.addCallbacks(check_results, self.unexpected_error)

        self.runner.start()
        return d

    @inlineCallbacks
    def check_that_t1_t2_running_and_last_is_not(self, results):
        from common.utils.asleep import asleep
        yield asleep(0.1)

        self.assertEqual(self.runner.pending_tasks, 1)
        self.assertEqual(self.runner.running_tasks, 2)
        self.assertEqual(self.runner.successful_tasks_completed, 1)

        returnValue(results)

    @deferred(timeout=10)
    def test_concurrent(self):
        blocker = SimpleTask(None, DEVICE_ID,
                             exclusive=True, priority=10,
                             success=True, value=1, delay=0.5)

        t1 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=2)

        t2 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=2)

        last = SimpleTask(None, DEVICE_ID,
                          exclusive=True, priority=8,
                          success=True, value=1, delay=0)

        d0 = self.runner.queue_task(blocker)
        d0.addCallbacks(self.check_that_t1_t2_running_and_last_is_not,
                        self.unexpected_error)

        d1 = self.runner.queue_task(t1)
        d2 = self.runner.queue_task(t2)
        d3 = self.runner.queue_task(last)

        self.assertEqual(self.runner.pending_tasks, 4)
        self.assertEqual(self.runner.running_tasks, 0)

        d = defer.gatherResults([d0, d1, d2, d3], consumeErrors=True)

        def check_final_results(_):
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 4)
            self.assertEqual(self.runner.failed_tasks, 0)

        d.addCallbacks(check_final_results, self.unexpected_error)

        self.runner.start()
        return d

    @raises(CancelledError)
    @deferred(timeout=2)
    def test_cancel_queued(self):
        t = SimpleTask(None, DEVICE_ID,
                       exclusive=True, priority=9,
                       success=True, value=1, delay=0)

        d = self.runner.queue_task(t)
        self.assertEqual(self.runner.pending_tasks, 1)
        self.assertEqual(self.runner.running_tasks, 0)

        self.runner.cancel_task(t.task_id)
        self.assertEqual(self.runner.pending_tasks, 0)
        self.assertEqual(self.runner.running_tasks, 0)
        return d

    @raises(CancelledError)
    @deferred(timeout=2)
    def test_task_stop_queued(self):
        t = SimpleTask(None, DEVICE_ID,
                       exclusive=True, priority=9,
                       success=True, value=1, delay=0)

        d = self.runner.queue_task(t)
        self.assertEqual(self.runner.pending_tasks, 1)
        self.assertEqual(self.runner.running_tasks, 0)

        t.stop()
        self.assertEqual(self.runner.pending_tasks, 0)
        self.assertEqual(self.runner.running_tasks, 0)
        return d

    def test_task_stop_not_queued(self):
        t = SimpleTask(None, DEVICE_ID,
                       exclusive=True, priority=9,
                       success=True, value=1, delay=0)

        self.assertEqual(self.runner.pending_tasks, 0)
        self.assertEqual(self.runner.running_tasks, 0)

        t.stop()
        self.assertFalse(t.running)

    @deferred(timeout=3)
    def test_task_runner_cancel_running(self):
        # Both task run in parallel but t1 will finish first and
        # will request t2 to terminate by calling the TaskRunner's
        # cancel task method
        t1 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=0.5)
        t2 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=200)

        d1 = self.runner.queue_task(t1)
        d2 = self.runner.queue_task(t2)

        self.assertEqual(self.runner.pending_tasks, 2)
        self.assertEqual(self.runner.running_tasks, 0)

        def kill_task_t2(_, task_2_id):
            # Called on successful completion of task t1
            self.assertIsInstance(task_2_id, int)
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 1)

            # Cancel task runner and t2 task ID
            self.runner.cancel_task(task_2_id)
            self.assertEqual(self.runner.running_tasks, 0)

        d1.addCallbacks(kill_task_t2, self.unexpected_error,
                        callbackArgs=[t2.task_id])

        def expected_error(failure):
            self.assertTrue(isinstance(failure.value, CancelledError))
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 1)
            self.assertEqual(self.runner.failed_tasks, 1)

        # T2 should not finish successfully, should get a cancel error
        d2.addCallbacks(self.unexpected_success, expected_error)

        # Run it
        self.runner.start()
        return defer.gatherResults([d1, d2], consumeErrors=True)

    @deferred(timeout=3)
    def test_task_stop_running(self):
        # Run two tasks where T1 completes first and requests T2 to be
        # canceled by calling T2's stop method

        t1 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=0.5)
        t2 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=200)

        d1 = self.runner.queue_task(t1)
        d2 = self.runner.queue_task(t2)

        self.assertEqual(self.runner.pending_tasks, 2)
        self.assertEqual(self.runner.running_tasks, 0)

        def kill_task_t2(_, task_2):
            # Called on successful completion of task t1
            self.assertIsInstance(task_2, SimpleTask)
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 1)

            # Cancel by telling the task to stop itself
            task_2.stop()
            self.assertEqual(self.runner.running_tasks, 0)

        d1.addCallbacks(kill_task_t2, self.unexpected_error,
                        callbackArgs=[t2])

        def expected_error(failure):
            self.assertTrue(isinstance(failure.value, CancelledError))
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 1)
            self.assertEqual(self.runner.failed_tasks, 1)

        # T2 should not finish successfully, should get a cancel error
        d2.addCallbacks(self.unexpected_success, expected_error)

        # Run it
        self.runner.start()
        return defer.gatherResults([d1, d2], consumeErrors=True)

    @deferred(timeout=3)
    def test_task_cancel_not_queued(self):
        t = SimpleTask(None, DEVICE_ID,
                       exclusive=True, priority=9,
                       success=True, value=1, delay=0)

        self.assertEqual(self.runner.pending_tasks, 0)
        self.assertEqual(self.runner.running_tasks, 0)

        def expected_error(failure):
            self.assertTrue(isinstance(failure.value, CancelledError))
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 0)
            self.assertEqual(self.runner.failed_tasks, 0)
            # self.fail(msg='made it here')    # Uncomment to verify called

        t.deferred.addCallbacks(self.unexpected_success, expected_error)

        self.runner.start()
        t.deferred.cancel()
        self.assertFalse(t.running)
        return t.deferred

    @deferred(timeout=3)
    def test_task_deferred_cancel_running(self):
        # Run two tasks where T1 completes first and requests T2 to be
        # canceled by doing a 'cancel' on T2's deferred

        t1 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=0.5)
        t2 = SimpleTask(None, DEVICE_ID,
                        exclusive=False, priority=9,
                        success=True, value=1, delay=200)

        d1 = self.runner.queue_task(t1)
        d2 = self.runner.queue_task(t2)

        self.assertEqual(self.runner.pending_tasks, 2)
        self.assertEqual(self.runner.running_tasks, 0)

        def kill_task_t2(_, deferred_2):
            # Called on successful completion of task t1
            self.assertIsInstance(deferred_2, defer.Deferred)
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 1)

            # Cancel the deferred for T2
            deferred_2.cancel()
            self.assertEqual(self.runner.running_tasks, 0)

        d1.addCallbacks(kill_task_t2, self.unexpected_error,
                        callbackArgs=[t2.deferred])

        def expected_error(failure):
            self.assertTrue(isinstance(failure.value, CancelledError))
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 1)
            self.assertEqual(self.runner.failed_tasks, 1)
            # self.fail(msg='made it here')    # Uncomment to verify called

        # T2 should not finish successfully, should get a cancel error
        d2.addCallbacks(self.unexpected_success, expected_error)

        # Run it
        self.runner.start()
        return defer.gatherResults([d1, d2], consumeErrors=True)

    @deferred(timeout=3)
    def test_watchdog_timeout(self):
        t = SimpleTask(None, DEVICE_ID, delay=2)

        self.assertEqual(self.runner.pending_tasks, 0)
        self.assertEqual(self.runner.running_tasks, 0)
        self.assertEqual(self.runner.watchdog_timeouts, 0)

        # Actual watchdog minimum is probably to long for an automated test, reach
        # around and force ti to something smaller (kids, don't try this at home)

        t._watchdog_timeout = 0.1
        self.runner.queue_task(t)

        self.assertEqual(self.runner.pending_tasks, 1)
        self.assertEqual(self.runner.running_tasks, 0)

        def expected_error(failure):
            from voltha.extensions.omci.tasks.task import WatchdogTimeoutFailure
            self.assertTrue(isinstance(failure.value, WatchdogTimeoutFailure))
            self.assertEqual(self.runner.pending_tasks, 0)
            self.assertEqual(self.runner.running_tasks, 0)
            self.assertEqual(self.runner.successful_tasks_completed, 0)
            self.assertEqual(self.runner.failed_tasks, 1)
            self.assertEqual(self.runner.watchdog_timeouts, 1)
            self.assertEqual(self.runner.last_watchdog_failure_task, t.name)
            # self.fail(msg='made it here')    # Uncomment to verify called

        t.deferred.addCallbacks(self.unexpected_success, expected_error)

        # Run it
        self.runner.start()
        return t.deferred


if __name__ == '__main__':
    main()
