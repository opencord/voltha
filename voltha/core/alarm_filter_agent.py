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
An alarm filter agent is instantiated for each alarm filter .
"""
import structlog
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.core.config.config_proxy import CallbackType
from voltha.protos.voltha_pb2 import \
    AlarmFilter, AlarmFilterRuleKey


class AlarmFilterAgent(object):

    def __init__(self, core, alarm_filter):

        self.core = core
        self._tmp_alarm_filter = alarm_filter

        self.root_proxy = core.get_proxy('/')
        self.self_proxy = core.get_proxy('/alarm_filters/{}'.format(alarm_filter.id))

        self.self_proxy.register_callback(
            CallbackType.PRE_UPDATE, self._cleanup_filter)
        self.self_proxy.register_callback(
            CallbackType.POST_UPDATE, self._process_filter)

        self.adapter_agent = None
        self.log = structlog.get_logger(alarm_filter_id=alarm_filter.id)

    @inlineCallbacks
    def start(self):
        self.log.debug('starting')

        yield self._process_filter(self._tmp_alarm_filter)
        del self._tmp_alarm_filter

        self.log.info('started')
        returnValue(self)

    @inlineCallbacks
    def stop(self):
        self.log.debug('stopping')

        yield self._cleanup_filter()

        self.self_proxy.unregister_callback(
            CallbackType.PRE_UPDATE, self._cleanup_filter)
        self.self_proxy.unregister_callback(
            CallbackType.POST_UPDATE, self._process_filter)
        self.log.info('stopped')

    @inlineCallbacks
    def _cleanup_filter(self, alarm_filter=None):
        # Pull out the current filter
        current_filter = self.self_proxy.get()

        if alarm_filter is None:
            alarm_filter = current_filter

        # Find any changes that might have occurred
        rules_to_clean = [r for r in alarm_filter.rules if r.key == AlarmFilterRuleKey.device_id]

        if rules_to_clean:
            # Pull out all filters
            all_filters = self.root_proxy.get('/alarm_filters')

            # Build a list of all devices that have filters against them
            all_device_ids = set()
            for filter in all_filters:
                if filter.id != alarm_filter.id:
                    ids = [r.value for r in filter.rules if r.key == AlarmFilterRuleKey.device_id]
                    all_device_ids.update(ids)

            # Unsuppress alarms for devices from the old filter (if any)
            for rule in rules_to_clean:
                # If a changed rule happens to be of device_id type, then we need to clean up
                # Only unsuppress if the device is not used in another filter
                if rule.key == AlarmFilterRuleKey.device_id and rule.value not in all_device_ids:
                    # An unsuppression call will occur for a filter that contains a device_id rule.
                    assert rule.value in self.core.device_agents
                    yield self.core.device_agents[rule.value].unsuppress_alarms(alarm_filter)

    @inlineCallbacks
    def _process_filter(self, alarm_filter):
        assert isinstance(alarm_filter, AlarmFilter)

        # Pull out all filters
        all_filters = self.root_proxy.get('/alarm_filters')

        all_device_ids = set()
        for filter in all_filters:
            if filter.id != alarm_filter.id:
                ids = [r.value for r in filter.rules if r.key == AlarmFilterRuleKey.device_id]
                all_device_ids.update(ids)

        # Suppress alarms for devices from the old filter (if any)
        for rule in alarm_filter.rules:
            # Check if it's a device_id rule and that it wasn't already processed by another filter
            if rule.key == AlarmFilterRuleKey.device_id and rule.value not in all_device_ids:
                # A suppression call will occur for any filter that contains a device_id rule.
                assert rule.value in self.core.device_agents
                yield self.core.device_agents[rule.value].suppress_alarms(alarm_filter)

