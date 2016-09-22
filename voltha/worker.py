#
# Copyright 2016 the original author or authors.
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
import re

from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.base import DelayedCall
from twisted.internet.defer import inlineCallbacks

from asleep import asleep


class Worker(object):
    """
    Worker side of the coordinator. An instance of this class runs in every
    voltha instance. It monitors what work is assigned to this instance by
    the leader. This is all done via consul.
    """

    ASSIGNMENT_EXTRACTOR = '^%s(?P<member_id>[^/]+)/(?P<work_id>[^/]+)$'

    log = get_logger()

    # Public methods:

    def __init__(self, instance_id, coordinator):

        self.instance_id = instance_id
        self.coord = coordinator
        self.halted = False
        self.soak_time = 0.5  # soak till assignment list settles

        self.my_workload = set()  # list of work_id's assigned to me

        self.assignment_soak_timer = None
        self.my_candidate_workload = set()  # we stash here during soaking

        self.assignment_match = re.compile(
            self.ASSIGNMENT_EXTRACTOR % self.coord.ASSIGNMENT_PREFIX).match

    @inlineCallbacks
    def start(self):
        self.log.info('worker-started')
        yield self._start_tracking_my_assignments()

    def halt(self):
        self.log.info('worker-halted')
        if isinstance(self.assignment_soak_timer, DelayedCall):
            if not self.assignment_soak_timer.called:
                self.assignment_soak_timer.cancel()

    # Private methods:

    def _start_tracking_my_assignments(self):
        reactor.callLater(0, self._track_my_assignments, 0)

    @inlineCallbacks
    def _track_my_assignments(self, index):

        try:

            # if there is no leader yet, wait for a stable leader
            d = self.coord.wait_for_a_leader()
            if not d.called:
                yield d
                # additional time to let leader update
                # assignments, to minimize potential churn
                yield asleep(5)

            (index, results) = yield self.coord.kv_get(
                self.coord.ASSIGNMENT_PREFIX + self.instance_id,
                index=index, recurse=True)

            matches = [
                (self.assignment_match(e['Key']), e) for e in results or []]

            my_workload = set([
                m.groupdict()['work_id'] for m, e in matches if m is not None
            ])

            if my_workload != self.my_workload:
                self._stash_and_restart_soak_timer(my_workload)

        except Exception, e:
            self.log.exception('assignments-track-error', e=e)
            yield asleep(1)  # to prevent flood

        finally:
            if not self.halted:
                reactor.callLater(0, self._track_my_assignments, index)

    def _stash_and_restart_soak_timer(self, candidate_workload):

        self.log.debug('re-start-assignment-soaking')

        if self.assignment_soak_timer is not None:
            if not self.assignment_soak_timer.called:
                self.assignment_soak_timer.cancel()

        self.my_candidate_workload = candidate_workload
        self.assignment_soak_timer = reactor.callLater(
            self.soak_time, self._update_assignments)

    def _update_assignments(self):
        """
        Called when finally the dust has settled on our assignments.
        :return: None
        """
        self.log.info('my-assignments-changed',
                      old_count=len(self.my_workload),
                      new_count=len(self.my_candidate_workload))
        self.my_workload, self.my_candidate_workload = \
            self.my_candidate_workload, None
