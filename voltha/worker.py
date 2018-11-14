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

from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.base import DelayedCall
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from simplejson import dumps, loads

from common.utils.asleep import asleep

log = get_logger()


class Worker(object):
    """
    Worker side of the coordinator. An instance of this class runs in every
    voltha instance. It monitors what work is assigned to this instance by
    the leader. This is all done via consul.
    """

    ASSIGNMENT_EXTRACTOR = '^%s(?P<member_id>[^/]+)/(?P<work_id>[^/]+)$'

    # Public methods:

    def __init__(self, instance_id, coordinator):

        self.instance_id = instance_id
        self.coord = coordinator
        self.halted = False
        self.soak_time = 0.5  # soak till assignment list settles

        self.my_workload = set()  # list of work_id's assigned to me

        self.assignment_soak_timer = None
        self.assignment_core_store_soak_timer = None
        self.my_candidate_workload = set()  # we stash here during soaking

        self.assignment_match = re.compile(
            self.ASSIGNMENT_EXTRACTOR % self.coord.assignment_prefix).match

        self.mycore_store_id = None

        self.wait_for_core_store_assignment = Deferred()

        self.peers_map = None

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        yield self._start_tracking_my_assignments()
        yield self._start_tracking_my_peers()
        log.info('started')
        returnValue(self)

    def stop(self):
        log.debug('stopping')
        self.halted = True
        if isinstance(self.assignment_soak_timer, DelayedCall):
            if not self.assignment_soak_timer.called:
                self.assignment_soak_timer.cancel()

        if isinstance(self.assignment_core_store_soak_timer, DelayedCall):
            if not self.assignment_core_store_soak_timer.called:
                self.assignment_core_store_soak_timer.cancel()

        log.info('stopped')

    @inlineCallbacks
    def get_core_store_id(self):
        if self.mycore_store_id:
            returnValue(self.mycore_store_id)
        else:
            # Let's wait until we get assigned a store_id from the leader
            val = yield self.wait_for_core_store_assignment
            returnValue(val)

    # Private methods:
    def _start_tracking_my_assignments(self):
        reactor.callLater(0, self._track_my_assignments, 0)

    def _start_tracking_my_peers(self):
        reactor.callLater(0, self._track_my_peers, 0)

    @inlineCallbacks
    def _track_my_assignments(self, index):
        try:
            # if there is no leader yet, wait for a stable leader
            d = self.coord.wait_for_a_leader()
            if not d.called:
                yield d
                # additional time to let leader update
                # assignments, to minimize potential churn
                yield asleep(self.coord.worker_config.get(
                    self.coord.worker_config['time_to_let_leader_update'], 5))

            (index, results) = yield self.coord.kv_get(
                self.coord.assignment_prefix + self.instance_id,
                index=index, recurse=True)

            # 1. Check whether we have been assigned a full voltha instance
            if results and not self.mycore_store_id:
                # We have no store id set yet
                core_stores = [c['Value'] for c in results if
                               c['Key'] == self.coord.assignment_prefix +
                               self.instance_id + '/' +
                               self.coord.core_storage_suffix and c['Value']]
                if core_stores:
                    self.mycore_store_id = core_stores[0]
                    log.debug('store-assigned',
                              mycore_store_id=self.mycore_store_id)
                    self._stash_and_restart_core_store_soak_timer()

            # 2.  Check whether we have been assigned a work item
            if results and self.mycore_store_id:
                # Check for difference between current worload and newer one
                # TODO: Depending on how workload gets load balanced we may
                # need to add workload distribution here
                pass

        except Exception, e:
            log.exception('assignments-track-error', e=e)
            yield asleep(
                self.coord.worker_config.get(
                    self.coord.worker_config[
                        'assignments_track_error_to_avoid_flood'], 1))
            # to prevent flood

        finally:
            if not self.halted and not self.mycore_store_id:
                reactor.callLater(0, self._track_my_assignments, index)

    @inlineCallbacks
    def _track_my_peers(self, index):
        try:
            prev_index = index
            if self.mycore_store_id:
                # Wait for updates to the store assigment key
                is_timeout, (tmp_index, mappings) = yield \
                                self.coord.coordinator_get_with_timeout(
                                    key=self.coord.core_store_assignment_key,
                                    recurse=True,
                                    index=index,
                                    timeout=10)

                if is_timeout:
                    return

                # After timeout event the index returned from
                # coordinator_get_with_timeout is None.  If we are here it's
                # not a timeout, therefore the index is a valid one.
                index=tmp_index

                if mappings and index != prev_index:
                    new_map = loads(mappings[0]['Value'])
                    # Remove my id from my peers list
                    new_map.pop(self.mycore_store_id)
                    if self.peers_map is None or self.peers_map != new_map:
                        self.coord.publish_peers_map_change(new_map)
                        self.peers_map = new_map
                        log.info('peer-mapping-changed', mapping=new_map)
                else:
                    log.debug('no-mapping-change', mappings=mappings,
                              index=index, prev_index=prev_index)

        except Exception, e:
            log.exception('peer-track-error', e=e)
            yield asleep(
                self.coord.worker_config.get(
                    self.coord.worker_config[
                        'assignments_track_error_to_avoid_flood'], 1))
            # to prevent flood
        finally:
            if not self.halted:
                # Wait longer if we have not received a core id yet
                reactor.callLater(1 if self.mycore_store_id else 5,
                                  self._track_my_peers, index)

    def _stash_and_restart_soak_timer(self, candidate_workload):

        log.debug('re-start-assignment-soaking')

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
        log.debug('my-assignments-changed',
                  old_count=len(self.my_workload),
                  new_count=len(self.my_candidate_workload),
                  workload=self.my_workload)
        self.my_workload, self.my_candidate_workload = \
            self.my_candidate_workload, None

    def _stash_and_restart_core_store_soak_timer(self):

        log.debug('re-start-assignment-config-soaking')

        if self.assignment_core_store_soak_timer is not None:
            if not self.assignment_core_store_soak_timer.called:
                self.assignment_core_store_soak_timer.cancel()

        self.assignment_core_store_soak_timer = reactor.callLater(
            self.soak_time, self._process_config_assignment)

    def _process_config_assignment(self):
        log.debug('process-config-assignment',
                  mycore_store_id=self.mycore_store_id)
        self.wait_for_core_store_assignment.callback(self.mycore_store_id)
