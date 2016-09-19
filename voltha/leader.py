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

from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.base import DelayedCall
from twisted.internet.defer import inlineCallbacks, DeferredList

from asleep import asleep


class Leader(object):
    """
    A single instance of this object shall exist across the whole cluster.
    This is guaranteed by the coordinator which instantiates this class
    only when it secured the leadership lock, as well as calling the halt()
    method in cases it looses the leadership lock.
    """

    ASSIGNMENT_PREFIX = 'service/voltha/assignments/'
    WORKLOAD_PREFIX = 'service/voltha/workload/'

    log = get_logger()

    # Public methods:

    def __init__(self, coordinator):
        self.coorinator = coordinator
        self.halted = False
        self.soak_time = 5  # soak till membership/workload changes settle

        self.workload = []
        self.members = []
        self.reassignment_soak_timer = None

    @inlineCallbacks
    def start(self):
        self.log.info('leader-started')
        yield self._validate_workload()
        yield self._start_tracking_assignments()

    def halt(self):
        """Suspend leadership duties immediately"""
        self.log.info('leader-halted')
        self.halted = True

        # any active cancellations, releases, etc., should happen here
        if isinstance(self.reassignment_soak_timer, DelayedCall):
            self.reassignment_soak_timer.cancel()

    # Private methods:

    @inlineCallbacks
    def _validate_workload(self):
        """
        Workload is defined as any k/v entries under the workload prefix
        in consul. Under normal operation, only the leader shall edit the
        workload list. But we make sure that in case an administrator
        manually edits the workload, we react to that properly.
        """

        # TODO for now we simply generate a fixed number of fake entries
        yield DeferredList([
            self.coorinator.kv_put(
                self.WORKLOAD_PREFIX + 'device_group_%04d' % (i + 1),
                'placeholder for device group %d data' % (i + 1))
            for i in xrange(100)
        ])

    def _start_tracking_assignments(self):
        """
        We must track both the cluster member list as well as the workload
        list. Upon change in either, we must rerun our sharding algorithm
        and reassign work as/if needed.
        """
        reactor.callLater(0, self._track_workload, 0)
        reactor.callLater(0, self._track_members, 0)

    @inlineCallbacks
    def _track_workload(self, index):

        try:
            (index, results) = yield self.coorinator.kv_get(
                self.WORKLOAD_PREFIX, index=index, recurse=True)

            workload = [e['Key'] for e in results]

            if workload != self.workload:
                self.log.info('workload-changed', workload=workload)
                self.workload = workload
                self._restart_reassignment_soak_timer()

        except Exception, e:
            self.log.exception('workload-track-error', e=e)
            yield asleep(1.0)  # to prevent flood

        finally:
            if not self.halted:
                reactor.callLater(0, self._track_workload, index)

    @inlineCallbacks
    def _track_members(self, index):

        def is_member(entry):
            key = entry['Key']
            member_id = key[len(self.coorinator.MEMBERSHIP_PREFIX):]
            return '/' not in member_id  # otherwise it is a nested key

        try:
            (index, results) = yield self.coorinator.kv_get(
                self.coorinator.MEMBERSHIP_PREFIX, index=index, recurse=True)

            members = [e['Key'] for e in results if is_member(e)]

            if members != self.members:
                self.log.info('membership-changed', members=members)
                self.members = members
                self._restart_reassignment_soak_timer()

        except Exception, e:
            self.log.exception('members-track-error', e=e)
            yield asleep(1.0)  # to prevent flood

        finally:
            if not self.halted:
                reactor.callLater(0, self._track_members, index)

    def _restart_reassignment_soak_timer(self):

        if self.reassignment_soak_timer is not None:
            assert isinstance(self.reassignment_soak_timer, DelayedCall)
            if not self.reassignment_soak_timer.called:
                self.reassignment_soak_timer.cancel()

        self.reassignment_soak_timer = reactor.callLater(
            self.soak_time, self._reassign_work)

        print self.reassignment_soak_timer

    @inlineCallbacks
    def _reassign_work(self):
        self.log.info('reassign-work')
        yield None

        # TODO continue from here

        # Plan
        # Step 1: collect current assignments from consul
        # Step 2: calculate desired assignment from current members and
        #         workload list (e.g., using consistent hashing or any other
        #         algorithm
        # Step 3: find the delta between the desired and actual assignments:
        #         these form two lists:
        #         1. new assignments to be made
        #         2. obsolete assignments to be revoked
        #         graceful handling may be desirable when moving existing
        #         assignment from existing member to another member (to make
        #         sure it is abandoned by old member before new takes charge)
        # Step 4: orchestrate the assignment by adding/deleting(/locking)
        #         entries in consul
        #
        # We must make sure while we are working on this, we do not re-enter
        # into same method!
