#
# Copyright 2017-present Adtran, Inc.
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

import random

import structlog
from enum import Enum
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_100GB_FD, OFPPF_FIBER, OFPPS_LIVE, ofp_port

import voltha.core.flow_decomposer as fd

log = structlog.get_logger()

EVC_MAP_NAME_INGRESS_FORMAT = 'EVCMap-VOLTHA-ingress-{}'
EVC_MAP_NAME_EGRESS_FORMAT = 'EVCMap-VOLTHA-egress-{}'

EVC_MAP_NAME_INGRESS_REGEX_FORMAT = EVC_MAP_NAME_INGRESS_FORMAT.format('regex here')
EVC_MAP_NAME_EGRESS_REGEX_FORMAT = EVC_MAP_NAME_EGRESS_FORMAT.format('regex here')

class EVCMap(object):
    """
    Class to wrap EVC functionality
    """
    class EvcConnection(Enum):
        NO_EVC_CONNECTION = 0
        EVC = 1
        DISCARD = 2

    class Priority_Option(Enum):
        INHERIT_PRIORITY = 0
        EXPLICIT_PRIORITY = 1

    def __init__(self, flow, handler, evc, is_ingress_map):
        self._installed = False
        self._status_message = None
        self._flow = flow
        self._handler = handler

        self._name = None
        self._enabled = True
        self._uni_port = None
        self._evc_connection = EVCMap.EvcConnection.NO_EVC_CONNECTION
        self._evc_name = None

        self._men_priority = EVCMap.Priority_Option.INHERIT_PRIORITY
        self._men_pri = 0  # If Explicit Priority

        self._c_tag = -1
        self._men_ctag_priority = EVCMap.Priority_Option.INHERIT_PRIORITY
        self._men_ctag_pri = 0  # If Explicit Priority

        self._match_ce_vlan_id = -1
        self._match_untagged = True
        self._match_destination_mac_address = None
        self._match_l2cp = False
        self._match_broadcast = False
        self._match_multicast = False
        self._match_unicast = False
        self._match_igmp = False

        self._evc = evc
        self._is_ingress_map = is_ingress_map

        self._valid = self.decode()

    @staticmethod
    def createIngressMap(flow, device, evc):
        return EVCMap(flow, device, evc, True)

    @staticmethod
    def createEgressMap(flow, device, evc):
        return EVCMap(flow, device, evc, False)

    @property
    def valid(self):
        return self._valid

    @property
    def installed(self):
        return self._installed

    @property
    def status(self):
        return self._status_message

    def install(self):
        if not self._installed:
            pass

        return self._installed

    def remove(self):
        if self._installed:
            pass

        return not self._installed

    def _decode(self):
        self._name = 'EVC-MAP-{}-{}'.format('i' if self._is_ingress_map else 'e', self._flow.id)

        return self._decode_traffic_selector() and self._decode_traffic_treatment()

    def _decode_traffic_selector(self):
        self._status_message('TODO: Not yet implemented')
        return False

    def _decode_traffic_treatment(self):
        self._status_message('TODO: Not yet implemented')
        return False



