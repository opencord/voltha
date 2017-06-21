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

"""
Singleton agent responsible for managing alarm filters
"""
import structlog
from twisted.internet.defer import inlineCallbacks

from voltha.core.config.config_proxy import CallbackType
from voltha.protos.voltha_pb2 import \
    AlarmFilter, AlarmFilterRuleKey


class AlarmFilterAgent(object):
    __instance = None

    def __new__(cls, core):
        if cls.__instance == None:
            cls.__instance = object.__new__(cls, core)
        return cls.__instance

    def __init__(self, core):
        self.core = core
        self.root_proxy = self.core.get_proxy('/')
        self.self_proxies = {}

        self.log = structlog.get_logger()

    def add_filter(self, alarm_filter):
        self.log.debug('starting')

        self.self_proxies[alarm_filter.id] = self.core.get_proxy(
            '/alarm_filters/{}'.format(alarm_filter.id))

        self.self_proxies[alarm_filter.id].register_callback(
            CallbackType.PRE_UPDATE, self._review_filter)
        self.self_proxies[alarm_filter.id].register_callback(
            CallbackType.POST_UPDATE, self._process_filter)

        self._process_filter(alarm_filter)

        self.log.info('started')

        return self

    def remove_filter(self, alarm_filter):
        self.log.debug('stopping')

        self._review_filter(alarm_filter, teardown=True)

        self.self_proxies[alarm_filter.id].unregister_callback(
            CallbackType.PRE_UPDATE, self._review_filter)
        self.self_proxies[alarm_filter.id].unregister_callback(
            CallbackType.POST_UPDATE, self._process_filter)

        del self.self_proxies[alarm_filter.id]

        self.log.info('stopped', alarm_filter=alarm_filter.id)

    # Remove filters referencing the specified device
    def remove_device_filters(self, device):
        self.log.debug('cleaning')
        all_filters = self.root_proxy.get('/alarm_filters')
        for filter in all_filters:
            for r in filter.rules:
                if r.key == AlarmFilterRuleKey.device_id and r.value == device.id:
                    self.root_proxy.remove('/alarm_filters/{}'.format(filter.id))
                    break

        self.log.debug('cleaned')

    def _review_filter(self, alarm_filter=None, teardown=False):
        # UPDATE scenario:
        #
        # When a filter is updated, we need to review the content of the previous filter
        # to ensure that nothing is left un-managed and not cleaned up.  If the filter
        # actually changed, it will be re-applied (including suppression)
        #
        # TEAR DOWN scenario:
        # When a filter is deleted, we need to go through the rules
        # and revert anything that was configured when the filter was first created.

        if alarm_filter is not None:
            current_filter = self.self_proxies[alarm_filter.id].get()

            # Find any rules contained in the filter that might have changed
            rules_to_clean = [r for r in current_filter.rules if r not in alarm_filter.rules]

            if not rules_to_clean and not teardown:
                # There are no rules from the current filter that require a clean up
                return

            # Un-suppress devices that are no longer referenced
            self._manage_suppression(current_filter)

    def _process_filter(self, alarm_filter):
        assert isinstance(alarm_filter, AlarmFilter)
        self._manage_suppression(alarm_filter, True)

    @inlineCallbacks
    def _manage_suppression(self, alarm_filter, suppress=False):
        # Pull out all filters
        all_filters = self.root_proxy.get('/alarm_filters')

        # Build a list of all devices that have filters against them
        all_device_ids = set()
        for filter in all_filters:
            if filter.id != alarm_filter.id:
                ids = [r.value for r in filter.rules if r.key == AlarmFilterRuleKey.device_id]
                all_device_ids.update(ids)

        for rule in alarm_filter.rules:
            # Check if it's a device_id rule and that it wasn't already processed by another filter
            if rule.key == AlarmFilterRuleKey.device_id and rule.value not in all_device_ids:
                # A suppression call will occur only for device ids that exist on the system
                assert rule.value in self.core.device_agents

                if suppress:
                    yield self.core.device_agents[rule.value].suppress_alarm(alarm_filter)
                else:
                    yield self.core.device_agents[rule.value].unsuppress_alarm(alarm_filter)