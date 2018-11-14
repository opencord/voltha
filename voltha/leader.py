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
from twisted.internet.defer import inlineCallbacks, DeferredList, returnValue
from simplejson import dumps, loads

from common.utils.asleep import asleep
from common.utils.id_generation import get_next_core_id

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
    CORE_STORE_KEY_EXTRACTOR = '^%s/(?P<core_store_id>[^/]+)/root$'
    START_TIMESTAMP_EXTRACTOR = '^.*_([0-9]+)$'
    ASSIGNMENT_ID_EXTRACTOR = '^(%s)([^/]+)/core_store$'

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
        self.core_store_reassignment_soak_timer = None

        self.workload_id_match = re.compile(
            self.ID_EXTRACTOR % self.coord.workload_prefix).match

        self.member_id_match = re.compile(
            self.ID_EXTRACTOR % self.coord.membership_prefix).match

        self.core_data_id_match = re.compile(
            self.CORE_STORE_KEY_EXTRACTOR % self.coord.core_store_prefix).match

        self.core_match = re.compile(self.coord.container_name_regex).match
        self.timestamp_match = re.compile(self.START_TIMESTAMP_EXTRACTOR).match

        self.assignment_id_match = re.compile(
            self.ASSIGNMENT_ID_EXTRACTOR % self.coord.assignment_prefix).match

        self.members_tracking_sleep_to_prevent_flood = \
            self.coord.leader_config.get((self.coord.leader_config[
                'members_track_error_to_prevent_flood']), 1)

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        # yield self._validate_workload()
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

        if isinstance(self.core_store_reassignment_soak_timer, DelayedCall):
            if not self.core_store_reassignment_soak_timer.called:
                self.core_store_reassignment_soak_timer.cancel()

        log.info('stopped')

    # Private methods:


    def _start_tracking_assignments(self):
        """
        We must track both the cluster member list as well as the workload
        list. Upon change in either, we must rerun our sharding algorithm
        and reassign work as/if needed.
        """
        reactor.callLater(0, self._track_members, 0)

    @inlineCallbacks
    def _get_core_store_mappings(self):
        try:
            # Get the mapping record
            (_, mappings) = yield self.coord.kv_get(
                self.coord.core_store_assignment_key, recurse=True)
            if mappings:
                self.core_store_assignment = loads(mappings[0]['Value'])
                return
            else:  # Key has not been created yet
                # Create the key with an empty dictionary value
                value = dict()
                result = yield self.coord.kv_put(
                    self.coord.core_store_assignment_key,
                    dumps(value))
                if not result:
                    raise ConfigMappingException(self.instance_id)

                # Ensure the record was created
                (_, mappings) = yield self.coord.kv_get(
                    self.coord.core_store_assignment_key, recurse=True)

                self.core_store_assignment = loads(mappings[0]['Value'])

        except Exception, e:
            log.exception('error', e=e)

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
            log.exception('error-update-store', e=e)

    def _sanitize_member_list(self, members):
        # This method removes any duplicates from the member list using the
        # voltha number from the member id and the time that voltha instance
        # started, again from the member id.  This method is meaningful only
        # in a clustered environment (e.g. Docker swarm or Kubernetes). In
        # a non-cluster environment the member id is formatted differently.
        # In such a case, the method below will create an exception and
        # return the member list as is.

        try:
            unique_members = {}
            update_occurred = False
            log.info('members', members=members)
            for member in members:
                log.info('member', member=member)
                # Extract the swarm assigned number of the voltha instance
                voltha_number = self.core_match(member['id']).group(1)
                timestamp = self.timestamp_match(member['id']).group(1)
                if voltha_number not in unique_members:
                    unique_members[voltha_number] = {'id': member['id'],
                                                     'timestamp': timestamp,
                                                     'host': member['host']}
                else:
                    # Verify whether if this member has the latest timestamp.  If
                    # yes, overwrite the previous one
                    if unique_members[voltha_number]['timestamp'] < timestamp:
                        unique_members[voltha_number] = {'id': member['id'],
                                                         'timestamp': timestamp,
                                                         'host': member['host']}
                    update_occurred = True

            if update_occurred:
                updated_members = []
                for _, unique_member in unique_members.iteritems():
                    updated_members.append({'host': unique_member['host'],
                                            'id': unique_member['id']})
                return updated_members
            else:
                return members
        except Exception as e:
            log.exception('extraction-error', e=e)
            return members

    @inlineCallbacks
    def _is_temporal_state(self, members):
        try:
            # First get the current core assignments
            (_, results) = yield self.coord.kv_get(
                self.coord.assignment_prefix,
                recurse=True)

            log.debug('core-assignments', assignment=results)
            if results:
                old_assignment = [
                        {'id': self.assignment_id_match(e['Key']).group(2),
                        'core': e['Value']}
                    for e in results]

                # If there are no curr_assignments then we are starting the
                # system. In this case we should keep processing
                if len(old_assignment) == 0:
                    returnValue(False)

                # Tackle the simplest scenario - #members >= #old_assignment
                if members is not None and len(members) >= len(old_assignment):
                    returnValue(False)

                # Everything else is a temporal state
                log.info('temporal-state-detected', members=members,
                         old_assignments=old_assignment)

                returnValue(True)
            else:
                returnValue(False)
        except Exception as e:
            log.exception('temporal-state-error', e=e)
            returnValue(True)

    @inlineCallbacks
    def _track_members(self, index):
        previous_index = index
        try:
            log.debug('member-tracking-before')
            is_timeout, (tmp_index, results) = yield \
                                    self.coord.coordinator_get_with_timeout(
                                            key=self.coord.membership_prefix,
                                            recurse=True,
                                            index=index,
                                            timeout=10)
            # Check whether we are still the leader - a new regime may be in
            # place by the time we see a membership update
            if self.halted:
                log.info('I am no longer the leader')
                return

            if is_timeout:
                log.debug('timeout-or-no-membership-changed')
                return

            # This can happen if consul went down and came back with no data
            if not results:
                log.error('no-active-members')
                # Bail out of leadership and go for an early election
                self.coord._just_lost_leadership()
                return

            # After timeout event the index returned from
            # coordinator_get_with_timeout is None.  If we are here it's not a
            # timeout, therefore the index is a valid one.
            index=tmp_index

            log.info('membership-tracking-data', index=index, results=results)

            if previous_index != index:
                log.info('membership-updated',
                         previous_index=previous_index, index=index)

                # Rebuild the membership, if any

                # Only members with valid session are considered active
                members = [{'id': self.member_id_match(e['Key']).group(2),
                            'host': loads(e['Value'])['host_address']}
                           for e in results if 'Session' in e]

                if members:
                    updated_members = self._sanitize_member_list(members)
                else:
                    updated_members = None

                log.info('active-members', active_members=members,
                         sanitized_members=updated_members)

                # Check if we are in a temporal state.  If true wait for the
                #  next membership changes
                temporal_state = yield self._is_temporal_state(updated_members)
                if temporal_state:
                    log.info('temporal-state-detected')
                    pass # Wait for next member list change
                elif updated_members != self.members:
                    # if the two sets are the same
                    # update the current set of config
                    yield self._update_core_store_references()
                    log.info('membership-changed',
                             prev_members=self.members,
                             curr_members=updated_members,
                             core_store_mapping=self.core_store_assignment)
                    self.members = updated_members
                    self._restart_core_store_reassignment_soak_timer()
            else:
                log.debug('no-membership-change', index=index)

        except Exception, e:
            log.exception('members-track-error', e=e)
            # to prevent flood
            yield asleep(self.members_tracking_sleep_to_prevent_flood)
        finally:
            if not self.halted:
                reactor.callLater(1, self._track_members, index)

    def _restart_reassignment_soak_timer(self):

        if self.reassignment_soak_timer is not None:
            assert isinstance(self.reassignment_soak_timer, DelayedCall)
            if not self.reassignment_soak_timer.called:
                self.reassignment_soak_timer.cancel()

        self.reassignment_soak_timer = reactor.callLater(
            self.soak_time, self._reassign_work)

    def _restart_core_store_reassignment_soak_timer(self):

        if self.core_store_reassignment_soak_timer is not None:
            assert isinstance(self.core_store_reassignment_soak_timer, DelayedCall)
            if not self.core_store_reassignment_soak_timer.called:
                self.core_store_reassignment_soak_timer.cancel()

        self.core_store_reassignment_soak_timer = reactor.callLater(
            self.soak_time, self._reassign_core_stores)

    @inlineCallbacks
    def _reassign_core_stores(self):

        def _get_core_data_id_from_instance(instance_name):
            for id, instance in self.core_store_assignment.iteritems():
                if instance and instance['id'] == instance_name:
                    return id

        try:
            log.info('core-members', curr_members=self.members,
                     prev_members=self.core_store_assignment)

            # 1. clear the mapping for instances that are no longer running
            updated_mapping = dict()
            existing_active_config_members = set()
            cleared_config_ids = set()
            inactive_members = set()
            if self.core_store_assignment:
                for id, instance in self.core_store_assignment.iteritems():
                    if instance not in self.members:
                        updated_mapping[id] = None
                        cleared_config_ids.add(id)
                        if instance:
                            inactive_members.add(instance['id'])
                    else:
                        updated_mapping[id] = instance
                        existing_active_config_members.add(instance['id'])

            # 2. Update the mapping with the new set
            current_id = max(self.core_store_assignment) \
                if self.core_store_assignment else '0000'
            for instance in self.members:
                if instance['id'] not in existing_active_config_members:
                    # Add the member to the config map
                    if cleared_config_ids:
                        # There is an empty slot
                        next_id = cleared_config_ids.pop()
                        updated_mapping[next_id] = instance
                    else:
                        # There are no empty slot, create new ids
                        current_id = get_next_core_id(current_id)
                        updated_mapping[current_id] = instance

            self.core_store_assignment = updated_mapping
            log.info('updated-assignment',
                     core_store_assignment=self.core_store_assignment,
                     inactive_members=inactive_members)

            # 3. save the mapping into consul
            yield self.coord.kv_put(self.coord.core_store_assignment_key,
                                    dumps(self.core_store_assignment))

            # 4. Assign the new workload to the newly created members
            curr_members_set = set([m['id'] for m in self.members])
            new_members = curr_members_set.difference(
                existing_active_config_members)
            for new_member_id in new_members:
                yield self.coord.kv_put(
                    self.coord.assignment_prefix
                    + new_member_id + '/' +
                    self.coord.core_storage_suffix,
                    _get_core_data_id_from_instance(new_member_id))

            # 5. Remove non-existent members
            for member_id in inactive_members:
                yield self.coord.kv_delete(
                    self.coord.assignment_prefix + member_id, recurse=True)
                yield self.coord.kv_delete(
                    self.coord.membership_prefix + member_id,
                    recurse=True)

        except Exception as e:
            log.exception('config-reassignment-failure', e=e)
            self._restart_core_store_reassignment_soak_timer()
