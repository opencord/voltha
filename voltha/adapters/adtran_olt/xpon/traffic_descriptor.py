# Copyright 2017-present Adtran, Inc.
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

from enum import Enum


class TrafficDescriptor(object):
    """
    Class to wrap the uplink traffic descriptor.
    """
    class AdditionalBwEligibility(Enum):
        NONE = 0
        BEST_EFFORT_SHARING = 1
        NON_ASSURED_SHARING = 2             # Should match xpon.py values
        DEFAULT = NONE

        @staticmethod
        def to_string(value):
            return {
                TrafficDescriptor.AdditionalBwEligibility.NON_ASSURED_SHARING: "non-assured-sharing",
                TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING: "best-effort-sharing",
                TrafficDescriptor.AdditionalBwEligibility.NONE: "none"
            }.get(value, "unknown")

        @staticmethod
        def from_value(value):
            """
            Matches both Adtran and xPON values
            :param value:
            :return:
            """
            return {
                0: TrafficDescriptor.AdditionalBwEligibility.NONE,
                1: TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING,
                2: TrafficDescriptor.AdditionalBwEligibility.NON_ASSURED_SHARING,
            }.get(value, TrafficDescriptor.AdditionalBwEligibility.DEFAULT)

    def __init__(self, fixed, assured, maximum,
                 additional=AdditionalBwEligibility.DEFAULT,
                 best_effort=None):
        self.fixed_bandwidth = fixed       # bps
        self.assured_bandwidth = assured   # bps
        self.maximum_bandwidth = maximum   # bps
        self.additional_bandwidth_eligibility = additional
        self.best_effort = best_effort\
            if additional == TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING\
            else None

    def __str__(self):
        return "TrafficDescriptor: {}/{}/{}".format(self.fixed_bandwidth,
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

