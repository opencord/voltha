# Copyright 2017-present CIG, Inc.
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
import json
from enum import Enum
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from twisted.internet.defer import succeed, inlineCallbacks, returnValue
from cig_olt_device import *

log = structlog.get_logger()

class TCont(object):
    """
    Class to wrap TCont capabilities
    """
    def __init__(self, alloc_id, traffic_descriptor, best_effort=None,
                 name=None, ident=None, vont_ani=None):
        self.alloc_id = alloc_id
        self.traffic_descriptor = traffic_descriptor
        self.best_effort = best_effort
        self.name = name
        self.pon_id = None
        self.onu_id = None
        self.id = ident
        self.vont_ani = vont_ani        # (string) reference

    def __str__(self):
        return "TCont: {}, alloc-id: {}".format(self.name, self.alloc_id)

    @staticmethod
    def create(data, td):
        assert isinstance(data, TcontsConfigData)
        assert isinstance(td, TrafficDescriptor)

        return TCont(data.alloc_id, td, best_effort=td.best_effort,
                     name=data.name, ident=data.id, vont_ani=data.interface_reference)

    def _get_onu(self, olt):
        onu = None
        log.info('tcont _get_onu.')
        try:
            vont_ani = olt.v_ont_anis.get(self.vont_ani)
            ch_pair = olt.channel_pairs.get(vont_ani['preferred-channel-pair'])
            ch_term = next((term for term in olt.channel_terminations.itervalues()
                            if term['channel-pair'] == ch_pair['name']), None)
            log.info('tcont _get_onu pon.')
            pon = olt.pon(ch_term['xgs-ponid'])
            log.info('tcont _get_onu pon.', pon._name)
            onu = pon.onu(vont_ani['onu-id'])
            log.info('tcont _get_onu onu.', onu._name)
        except Exception:
            pass

        return onu

    def xpon_create(self, olt):
        # Look up any associated ONU. May be None if pre-provisioning
        onu = self._get_onu(olt)

        if onu is not None:
            onu.add_tcont(self)
        #pass

    def xpon_update(self, olt):
        # Look up any associated ONU. May be None if pre-provisioning
        onu = self._get_onu(olt)

        if onu is not None:
            pass            # TODO: Not yet supported
        #pass

    def xpon_delete(self, olt):
        # Look up any associated ONU. May be None if pre-provisioning
        onu = self._get_onu(olt)

        if onu is not None:
            onu.remove_tcont(self.alloc_id)
        #pass


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
                 best_effort=None,
                 name=None,
                 ident=None):
        self.name = name
        self.id = ident
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

    @staticmethod
    def create(data):
        assert isinstance(data, TrafficDescriptorProfileData)

        additional = TrafficDescriptor.AdditionalBwEligibility.from_value(
            data.additional_bw_eligibility_indicator)

        if additional == TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
            best_effort = BestEffort(data.maximum_bandwidth,
                                     data.priority,
                                     data.weight)
        else:
            best_effort = None

        return TrafficDescriptor(data.fixed_bandwidth, data.assured_bandwidth,
                                 data.maximum_bandwidth,
                                 name=data.name,
                                 ident=data.id,
                                 best_effort=best_effort,
                                 additional=additional)

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

    def xpon_create(self, olt, tcont):
        # Look up any associated ONU. May be None if pre-provisioning
        pass                    # TODO

    def xpon_update(self, olt, tcont):
        # Look up any associated ONU. May be None if pre-provisioning
        pass            # TODO: Not yet supported


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

class Gemport(object):
    """
    Class to wrap TCont capabilities
    """
    def __init__(self, gem_id, traffic_class, name=None, uni_name=None, aes_indicator=None, tcont_name=None):
        log.info('gemport init.')
        self.gem_id = gem_id
        self.traffic_class = traffic_class
        self.name = name
        self.uni_name = uni_name
        self.aes_indicator = aes_indicator
        self.tcont_name = tcont_name
        
        self.pon_id = None
        self.onu_id = None
        self.tcont_id = None
        self.tcont = None
        self.pon = None
        self.onu = None

        strlist = uni_name.split('.')
        self.cvlan = int(strlist[len(strlist)-1])
        log.info('gemport init self.cvlan.', self.cvlan)
        
    def __str__(self):
        return "GemPort: {}, Tcont: {}, gem-id: {}".format(self.name,
                                                              self.tcont_name,
                                                              self.gem_id)

    @staticmethod
    def create(data):
        log.info('gemport create.')
        assert isinstance(data, GemportsConfigData)

        return Gemport(data.gemport_id, data.traffic_class, data.name, data.itf_ref, data.aes_indicator, data.tcont_ref)


    def _get_onu(self, olt):
        onu = None
        log.info('gemport _get_onu.')
        
        tcont = olt._tconts.get(self.tcont_name)
        log.info('self.tcont_name.',self.tcont_name)
        if tcont is None:
            log.info('tcont is None.')
            return None

        self.tcont = tcont
        vont_ani = olt.v_ont_anis.get(tcont.vont_ani)
        if vont_ani is None:
            log.info('vont_ani is None.')
            return None
        
        ch_pair = olt.channel_pairs.get(vont_ani['preferred-channel-pair'])
        if ch_pair is None:
            log.info('ch_pair is None.')
            return None
        ch_term = next((term for term in olt.channel_terminations.itervalues()
                        if term['channel-pair'] == ch_pair['name']), None)
        if ch_term is None:
            log.info('ch_term is None.')
            return None

        self.pon_id = ch_term['xgs-ponid']
        self.onu_id = vont_ani['onu-id']
        self.tcont_id = tcont.alloc_id
        
        log.info('gemport _get_onu.', self.pon_id)
        pon = olt.pon(ch_term['xgs-ponid'])
        log.info('gemport _get_onu pon.', pon._name)
        self.pon = pon
        onu = pon.onu(vont_ani['onu-id'])
        log.info('gemport _get_onu onu.', onu._name)
        self.onu = onu
        
        return onu

    def xpon_create(self, olt):
        # Look up any associated ONU. May be None if pre-provisioning
        log.info('gemport xpon_create.')
        onu = self._get_onu(olt)

        if onu is not None:
            onu.add_gemport(self)

    def xpon_update(self, olt):
        # Look up any associated ONU. May be None if pre-provisioning
        log.info('gemport xpon_update.')

        if self.onu is not None:
            pass            # TODO: Not yet supported
        #pass

    def xpon_delete(self, olt):
        # Look up any associated ONU. May be None if pre-provisioning
        log.info('gemport xpon_delete.')

        if self.onu is not None:
            self.onu.remove_gemport(self.gem_id)







