# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import structlog
from enum import Enum

log = structlog.get_logger()


class TCont(object):
    """
    Class to wrap TCont capabilities
    """
    def __init__(self, alloc_id, traffic_descriptor, best_effort=None, name=None):
        self.alloc_id = alloc_id
        self.traffic_descriptor = traffic_descriptor
        self.best_effort = best_effort
        self.name = name

    def __str__(self):
        return "TCont: {}, alloc-id: {}".format(self.name,self.alloc_id)


class TrafficDescriptor(object):
    """
    Class to wrap the uplink traffic descriptor.
    """
    class AdditionalBwEligibility(Enum):
        NON_ASSURED_SHARING = 1
        BEST_EFFORT_SHARING = 2
        NONE = 3
        DEFAULT = NONE

        @staticmethod
        def to_string(value):
            return {
                TrafficDescriptor.AdditionalBwEligibility.NON_ASSURED_SHARING: "non-assured-sharing",
                TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING: "best-effort-sharing",
                TrafficDescriptor.AdditionalBwEligibility.NONE: "none"
            }.get(value, "unknown")

    def __init__(self, fixed, assured, maximum,
                 additional=AdditionalBwEligibility.DEFAULT,
                 best_effort=None,
                 name=None):
        self.name = name
        self.fixed_bandwidth = fixed       # bps
        self.assured_bandwidth = assured   # bps
        self.maximum_bandwidth = maximum   # bps
        self.additional_bandwidth_eligibility = additional
        self.best_effort = best_effort\
            if additional == TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING\
            else None

    def __str__(self):
        return "TrafficDescriptor: {}, {}/{}/{}".format(self.name,
                                                        self.fixed_bandwidth,
                                                        self.assured_bandwidth,
                                                        self.maximum_bandwidth)

    def to_dict(self):
        val = {
            'fixed-bandwidth': self.fixed_bandwidth,
            'assured-bandwidth': self.assured_bandwidth,
            'maximum-bandwidth': self.maximum_bandwidth,
            'additional-bandwidth-eligibility':
                TrafficDescriptor.AdditionalBwEligibility.to_string(
                    self.additional_bandwidth_eligibility)
        }
        return val


class BestEffort(object):
    def __init__(self, bandwidth, priority, weight):
        self.bandwidth = bandwidth   # bps
        self.priority = priority     # 0.255
        self.weight = weight         # 0..100

    def __str__(self):
        return "BestEffort: {}/p-{}/w-{}".format(self.bandwidth,
                                                 self.priority,
                                                 self.weight)

    def to_dict(self):
        val = {
            'bandwidth': self.bandwidth,
            'priority': self.priority,
            'weight': self.weight
        }
        return val





