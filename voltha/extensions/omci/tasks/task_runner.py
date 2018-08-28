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
from twisted.internet import reactor


class TaskRunner(object):
    """
    Control the number of running tasks utilizing the OMCI Communications
    channel (OMCI_CC
    """
    def __init__(self, device_id, clock=None):
        self.log = structlog.get_logger(device_id=device_id)
        self._pending_queue = dict()   # task-priority -> [tasks]
        self._running_queue = dict()   # task-id -> task
        self._active = False

        self._successful_tasks = 0
        self._failed_tasks = 0
        self._watchdog_timeouts = 0
        self._last_watchdog_failure_task = ''
        self.reactor = clock if clock is not None else reactor

    def __str__(self):
        return 'TaskRunner: Pending: {}, Running:{}'.format(self.pending_tasks,
                                                            self.running_tasks)

    @property
    def active(self):
        return self._active

    @property
    def pending_tasks(self):
        """
        Get the number of tasks pending to run
        """
        count = 0
        for tasks in self._pending_queue.itervalues():
            count += len(tasks)
        return count

    @property
    def running_tasks(self):
        """
        Get the number of tasks currently running
        """
        return len(self._running_queue)

    @property
    def successful_tasks_completed(self):
        return self._successful_tasks

    @property
    def failed_tasks(self):
        return self._failed_tasks

    @property
    def watchdog_timeouts(self):
        return self._watchdog_timeouts

    @property
    def last_watchdog_failure_task(self):
        """ Task name of last tasks to fail due to watchdog"""
        return self._last_watchdog_failure_task

    # TODO: add properties for various stats as needed

    def start(self):
        """
        Start the Task runner
        """
        self.log.debug('starting', active=self._active)

        if not self._active:
            assert len(self._running_queue) == 0, 'Running task queue not empty'
            self._active = True
            self._run_next_task()

    def stop(self):
        """
        Stop the Task runner, first stopping any tasks and flushing the queue
        """
        self.log.debug('stopping', active=self._active)

        if self._active:
            self._active = False

            pq, self._pending_queue = self._pending_queue, dict()
            rq, self._running_queue = self._running_queue, dict()

            # Stop running tasks
            for task in rq.itervalues():
                try:
                    task.stop()
                except:
                    pass

            # Kill pending tasks
            for d in pq.iterkeys():
                try:
                    d.cancel()
                except:
                    pass

    def _run_next_task(self):
        """
        Search for next task to run, if one can
        :return:
        """
        self.log.debug('run-next', active=self._active,
                       num_running=len(self._running_queue),
                       num_pending=len(self._pending_queue))

        if self._active and len(self._pending_queue) > 0:
            # Cannot run a new task if a running one needs the OMCI_CC exclusively

            if any(task.exclusive for task in self._running_queue.itervalues()):
                self.log.debug('exclusive-running')
                return    # An exclusive task is already running

            try:
                priorities = [k for k in self._pending_queue.iterkeys()]
                priorities.sort(reverse=True)
                highest_priority = priorities[0] if len(priorities) else None

                if highest_priority is not None:
                    queue = self._pending_queue[highest_priority]
                    next_task = queue[0] if len(queue) else None

                    if next_task is not None:
                        if next_task.exclusive and len(self._running_queue) > 0:
                            self.log.debug('next-is-exclusive', task=str(next_task))
                            return  # Next task to run needs exclusive access

                        queue.pop(0)
                        if len(queue) == 0:
                            del self._pending_queue[highest_priority]

                        self.log.debug('starting-task', task=str(next_task),
                                       running=len(self._running_queue),
                                       pending=len(self._pending_queue))

                        self._running_queue[next_task.task_id] = next_task
                        self.reactor.callLater(0, next_task.start)

                # Run again if others are waiting
                if len(self._pending_queue):
                    self._run_next_task()

            except Exception as e:
                self.log.exception('run-next', e=e)

    def _on_task_success(self, results, task):
        """
        A task completed successfully callback
        :param results: deferred results
        :param task: (Task) The task that succeeded
        :return: deferred results
        """
        self.log.debug('task-success', task_id=str(task),
                       running=len(self._running_queue),
                       pending=len(self._pending_queue))
        try:
            assert task is not None and task.task_id in self._running_queue,\
                'Task not found in running queue'

            task.task_cleanup()
            self._successful_tasks += 1
            del self._running_queue[task.task_id]

        except Exception as e:
            self.log.exception('task-error', task=str(task), e=e)

        finally:
            reactor.callLater(0, self._run_next_task)

        return results

    def _on_task_failure(self, failure, task):
        """
        A task completed with failure callback
        :param failure: (Failure) Failure results
        :param task: (Task) The task that failed
        :return: (Failure) Failure results
        """
        from voltha.extensions.omci.tasks.task import WatchdogTimeoutFailure

        self.log.debug('task-failure', task_id=str(task),
                       running=len(self._running_queue),
                       pending=len(self._pending_queue))
        try:
            assert task is not None and task.task_id in self._running_queue,\
                'Task not found in running queue'

            task.task_cleanup()
            self._failed_tasks += 1
            del self._running_queue[task.task_id]

            if isinstance(failure.value, WatchdogTimeoutFailure):
                self._watchdog_timeouts += 1
                self._last_watchdog_failure_task = task.name

        except Exception as e:
            # Check the pending queue

            for priority, tasks in self._pending_queue.iteritems():
                found = next((t for t in tasks if t.task_id == task.task_id), None)

                if found is not None:
                    self._pending_queue[task.priority].remove(task)
                    if len(self._pending_queue[task.priority]) == 0:
                        del self._pending_queue[task.priority]
                    return failure

            self.log.exception('task-error', task=str(task), e=e)
            raise

        finally:
            reactor.callLater(0, self._run_next_task)

        return failure

    def queue_task(self, task):
        """
        Place a task on the queue to run

        :param task: (Task) task to run
        :return: (deferred) Deferred that will fire on task completion
        """
        self.log.debug('queue-task', active=self._active, task=str(task),
                       running=len(self._running_queue),
                       pending=len(self._pending_queue))

        if task.priority not in self._pending_queue:
            self._pending_queue[task.priority] = []

        task.deferred.addCallbacks(self._on_task_success, self._on_task_failure,
                                   callbackArgs=[task], errbackArgs=[task])

        self._pending_queue[task.priority].append(task)
        self._run_next_task()

        return task.deferred

    def cancel_task(self, task_id):
        """
        Cancel a pending or running task.  The cancel method will be called
        for the task's deferred

        :param task_id: (int) Task identifier
        """
        task = self._running_queue.get(task_id, None)

        if task is not None:
            try:
                task.stop()
            except Exception as e:
                self.log.exception('stop-error', task=str(task), e=e)

            reactor.callLater(0, self._run_next_task)

        else:
            for priority, tasks in self._pending_queue.iteritems():
                task = next((t for t in tasks if t.task_id == task_id), None)

                if task is not None:
                    try:
                        task.deferred.cancel()
                    except Exception as e:
                        self.log.exception('cancel-error', task=str(task), e=e)
                    return

