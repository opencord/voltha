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

import re

from hash_ring import HashRing
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.base import DelayedCall
from twisted.internet.defer import inlineCallbacks, DeferredList
from simplejson import dumps, loads

from common.utils.asleep import asleep

log = get_logger()


class ConfigMappingException(Exception):
    pass


class Leader(object):
    """
    A single instance of this object shall exist across the whole cluster.
    This is guaranteed by the coordinator which instantiates this class
    only when it secured the leadership lock, as well as calling the halt()
    method in cases it looses the leadership lock.
    """

    ID_EXTRACTOR = '^(%s)([^/]+)$'
    ASSIGNMENT_EXTRACTOR = '^%s(?P<member_id>[^/]+)/(?P<work_id>[^/]+)$'
    CORE_STORE_KEY_EXTRACTOR = '^%s(?P<core_store_id>[^/]+)/root$'

    # Public methods:

    def __init__(self, coordinator):

        self.coord = coordinator
        self.halted = False
        self.soak_time = 3  # soak till membership/workload changes settle

        self.workload = []
        self.members = []
        self.core_store_ids = []
        self.core_store_assignment = None

        self.reassignment_soak_timer = None

        self.workload_id_match = re.compile(
            self.ID_EXTRACTOR % self.coord.workload_prefix).match

        self.member_id_match = re.compile(
            self.ID_EXTRACTOR % self.coord.membership_prefix).match

        self.core_data_id_match = re.compile(
            self.CORE_STORE_KEY_EXTRACTOR % self.coord.core_store_prefix).match

        self.core_store_assignment_key = self.coord.core_store_prefix + \
                                         '/assignment'

        self.assignment_match = re.compile(
            self.ASSIGNMENT_EXTRACTOR % self.coord.assignment_prefix).match

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        yield self._validate_workload()
        yield self._start_tracking_assignments()
        log.info('started')

    def stop(self):
        """Suspend leadership duties immediately"""
        log.debug('stopping')
        self.halted = True

        # any active cancellations, releases, etc., should happen here
        if isinstance(self.reassignment_soak_timer, DelayedCall):
            if not self.reassignment_soak_timer.called:
                self.reassignment_soak_timer.cancel()

        log.info('stopped')

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
            self.coord.kv_put(
                self.coord.workload_prefix + 'device_group_%04d' % (i + 1),
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
            (index, results) = yield self.coord.kv_get(
                self.coord.workload_prefix, index=index, recurse=True)

            matches = (self.workload_id_match(e['Key']) for e in results)
            workload = [m.group(2) for m in matches if m is not None]

            if workload != self.workload:
                log.info('workload-changed',
                         old_workload_count=len(self.workload),
                         new_workload_count=len(workload))
                self.workload = workload
                self._restart_reassignment_soak_timer()

        except Exception, e:
            log.exception('workload-track-error', e=e)
            yield asleep(
                self.coord.leader_config.get(
                    self.coord.leader_config[
                        'workload_track_error_to_prevent_flood'], 1))
            # to prevent flood

        finally:
            if not self.halted:
                reactor.callLater(0, self._track_workload, index)

    @inlineCallbacks
    def _get_core_store_mappings(self):
        # Get the mapping record
        (_, mappings) = yield self.coord.kv_get(
            self.core_store_assignment_key, recurse=True)
        if mappings:
            self.core_store_assignment = loads(mappings[0]['Value'])
            return
        else:  # Key has not been created yet
            # Create the key with an empty dictionary value
            value = dict()
            result = yield self.coord.kv_put(self.core_store_assignment_key,
                                             dumps(value))
            if not result:
                raise ConfigMappingException(self.instance_id)

            # Ensure the record was created
            (_, mappings) = yield self.coord.kv_get(
                self.core_store_assignment_key, recurse=True)

            self.core_store_assignment = loads(mappings[0]['Value'])

    @inlineCallbacks
    def _update_core_store_references(self):
        try:
            # Get the current set of configs keys
            (_, results) = yield self.coord.kv_get(
                self.coord.core_store_prefix, recurse=False, keys=True)

            matches = (self.core_data_id_match(e) for e in results or [])
            core_ids = [m.group(1) for m in matches if m is not None]

            self.core_store_ids = core_ids

            # Update the config mapping
            self._get_core_store_mappings()

            log.debug('core-data', core_ids=core_ids,
                      assignment=self.core_store_assignment)

        except Exception, e:
            log.exception('get-config-error', e=e)

    @inlineCallbacks
    def _track_members(self, index):

        try:
            (index, results) = yield self.coord.kv_get(
                self.coord.membership_prefix, index=index, recurse=True)

            # Only members with valid session are considered active
            matches = (self.member_id_match(e['Key'])
                       for e in results if 'Session' in e)
            members = [m.group(2) for m in matches if m is not None]

            log.debug('active-members', active_members=members)

            # Check if the two sets are the same
            if members != self.members:
                # update the current set of config
                yield self._update_core_store_references()
                log.info('membership-changed',
                         prev_members=self.members,
                         curr_members=members,
                         core_store_mapping=self.core_store_assignment)
                self.members = members
                self._restart_core_store_reassignment_soak_timer()

        except Exception, e:
            log.exception('members-track-error', e=e)
            yield asleep(
                self.coord.leader_config.get(
                    self.coord.leader_config[
                        'members_track_error_to_prevent_flood']), 1)
            # to prevent flood

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

    def _restart_core_store_reassignment_soak_timer(self):

        if self.reassignment_soak_timer is not None:
            assert isinstance(self.reassignment_soak_timer, DelayedCall)
            if not self.reassignment_soak_timer.called:
                self.reassignment_soak_timer.cancel()

        self.reassignment_soak_timer = reactor.callLater(
            self.soak_time, self._reassign_core_stores)

    @inlineCallbacks
    def _reassign_core_stores(self):

        def _get_new_str_id(max_val_in_str):
            return str(int(max_val_in_str) + 1)

        def _get_core_data_id_from_instance(instance_name):
            for id, instance in self.core_store_assignment.iteritems():
                if instance == instance_name:
                    return id

        try:
            log.debug('reassign-core-stores', curr_members=self.members)

            # 1. clear the mapping for instances that are no longer running
            updated_mapping = dict()
            existing_active_config_members = set()
            cleared_config_ids = set()
            inactive_members = set()
            log.debug('previous-assignment',
                      core_store_assignment=self.core_store_assignment)
            if self.core_store_assignment:
                for id, instance in self.core_store_assignment.iteritems():
                    if instance not in self.members:
                        updated_mapping[id] = None
                        cleared_config_ids.add(id)
                        inactive_members.add(instance)
                    else:
                        updated_mapping[id] = instance
                        existing_active_config_members.add(instance)

            # 2. Update the mapping with the new set
            current_id = max(self.core_store_assignment) \
                if self.core_store_assignment else '0'
            for instance in self.members:
                if instance not in existing_active_config_members:
                    # Add the member to the config map
                    if cleared_config_ids:
                        # There is an empty slot
                        next_id = cleared_config_ids.pop()
                        updated_mapping[next_id] = instance
                    else:
                        # There are no empty slot, create new ids
                        current_id = _get_new_str_id(current_id)
                        updated_mapping[current_id] = instance

            self.core_store_assignment = updated_mapping
            log.debug('updated-assignment',
                      core_store_assignment=self.core_store_assignment)

            # 3. save the mapping into consul
            yield self.coord.kv_put(self.core_store_assignment_key,
                                    dumps(self.core_store_assignment))

            # 4. Assign the new workload to the newly created members
            curr_members_set = set(self.members)
            new_members = curr_members_set.difference(
                existing_active_config_members)
            for new_member in new_members:
                yield self.coord.kv_put(
                    self.coord.assignment_prefix
                    + new_member + '/' +
                    self.coord.core_storage_suffix,
                    _get_core_data_id_from_instance(new_member))

            # 5. Remove non-existent members
            for member in inactive_members:
                yield self.coord.kv_delete(
                    self.coord.assignment_prefix + member, recurse=True)
                yield self.coord.kv_delete(
                    self.coord.membership_prefix + member,
                    recurse=True)

        except Exception as e:
            log.exception('config-reassignment-failure', e=e)
            self._restart_core_store_reassignment_soak_timer()

    @inlineCallbacks
    def _reassign_work(self):

        log.info('reassign-work')

        # Plan
        #
        # Step 1: calculate desired assignment from current members and
        #         workload list (e.g., using consistent hashing or any other
        #         algorithm
        # Step 2: collect current assignments from consul
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

        try:

            # Step 1: generate wanted assignment (mapping work to members)

            ring = HashRing(self.members)
            wanted_assignments = dict()  # member_id -> set(work_id)
            _ = [
                wanted_assignments.setdefault(ring.get_node(work), set())
                    .add(work)
                for work in self.workload
            ]
            for (member, work) in sorted(wanted_assignments.iteritems()):
                log.info('assignment',
                         member=member, work_count=len(work))

            # Step 2: discover current assignment (from consul)

            (_, results) = yield self.coord.kv_get(
                self.coord.assignment_prefix, recurse=True)

            matches = [
                (self.assignment_match(e['Key']), e) for e in results or []]

            current_assignments = dict()  # member_id -> set(work_id)
            _ = [
                current_assignments.setdefault(
                    m.groupdict()['member_id'], set())
                    .add(m.groupdict()['work_id'])
                for m, e in matches if m is not None
            ]

            # Step 3: handle revoked assignments first on a per member basis

            for member_id, current_work in current_assignments.iteritems():
                assert isinstance(current_work, set)
                wanted_work = wanted_assignments.get(member_id, set())
                work_to_revoke = current_work.difference(wanted_work)

                # revoking work by simply deleting the assignment entry
                # TODO if we want some feedback to see that member abandoned
                # work, we could add a consul-based protocol here
                for work_id in work_to_revoke:
                    yield self.coord.kv_delete(
                        self.coord.assignment_prefix
                        + member_id + '/' + work_id)

            # Step 4: assign new work as needed

            for member_id, wanted_work in wanted_assignments.iteritems():
                assert isinstance(wanted_work, set)
                current_work = current_assignments.get(member_id, set())
                work_to_assign = wanted_work.difference(current_work)

                for work_id in work_to_assign:
                    yield self.coord.kv_put(
                        self.coord.assignment_prefix
                        + member_id + '/' + work_id, '')

        except Exception, e:
            log.exception('failed-reassignment', e=e)
            self._restart_reassignment_soak_timer()  # try again in a while
