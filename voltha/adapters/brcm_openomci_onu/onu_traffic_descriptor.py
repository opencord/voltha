#
# Copyright 2018 the original author or authors.
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

import structlog
from twisted.internet.defer import inlineCallbacks, returnValue, succeed


NONE = 0
BEST_EFFORT_SHARING = 1
NON_ASSURED_SHARING = 2             # Should match xpon.py values
DEFAULT = NONE


class OnuTrafficDescriptor(object):
    """
    Broadcom ONU specific implementation
    """
    def __init__(self, fixed, assured, maximum,
                 additional=DEFAULT,
                 best_effort=None,
                 name=None):

        self.log = structlog.get_logger(fixed=fixed, assured=assured, maximum=maximum, additional=additional)
        self.log.debug('function-entry')

        self.name = name
        self.fixed_bandwidth = fixed       # bps
        self.assured_bandwidth = assured   # bps
        self.maximum_bandwidth = maximum   # bps
        self.additional_bandwidth_eligibility = additional

        self.best_effort = best_effort if additional == BEST_EFFORT_SHARING else None


    @staticmethod
    def to_string(value):
        log = structlog.get_logger()
        log.debug('function-entry', value=value)
        return {
            NON_ASSURED_SHARING: "non-assured-sharing",
            BEST_EFFORT_SHARING: "best-effort-sharing",
            NONE: "none"
        }.get(value, "unknown")


    @staticmethod
    def from_value(value):
        log = structlog.get_logger()
        log.debug('function-entry', value=value)
        return {
            0: NONE,
            1: BEST_EFFORT_SHARING,
            2: NON_ASSURED_SHARING,
        }.get(value, DEFAULT)


    def __str__(self):
        self.log.debug('function-entry')
        return "OnuTrafficDescriptor: {}, {}/{}/{}".format(self.name,
                                                        self.fixed_bandwidth,
                                                        self.assured_bandwidth,
                                                        self.maximum_bandwidth)

    def to_dict(self):
        self.log.debug('function-entry')
        val = {
            'fixed-bandwidth': self.fixed_bandwidth,
            'assured-bandwidth': self.assured_bandwidth,
            'maximum-bandwidth': self.maximum_bandwidth,
            'additional-bandwidth-eligibility': OnuTrafficDescriptor.to_string(self.additional_bandwidth_eligibility)
        }
        return val


    @staticmethod
    def create(traffic_disc):
        log = structlog.get_logger()
        log.debug('function-entry',traffic_disc=traffic_disc)

        additional = OnuTrafficDescriptor.from_value(
            traffic_disc['additional-bw-eligibility-indicator'])

        # TODO: this is all stub code.  Doesnt do anything yet. tech profiles will likely make this clearer
        best_effort = None

        return OnuTrafficDescriptor(traffic_disc['fixed-bandwidth'],
                                    traffic_disc['assured-bandwidth'],
                                    traffic_disc['maximum-bandwidth'],
                                    name=traffic_disc['name'],
                                    best_effort=best_effort,
                                    additional=additional)

    @inlineCallbacks
    def add_to_hardware(self, omci):
       self.log.debug('function-entry', omci=omci)
       results = succeed('TODO: Implement me')
       returnValue(results)



