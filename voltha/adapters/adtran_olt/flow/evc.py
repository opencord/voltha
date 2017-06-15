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

from enum import Enum
import structlog
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_100GB_FD, OFPPF_FIBER, OFPPS_LIVE, ofp_port

import voltha.core.flow_decomposer as fd

log = structlog.get_logger()

_evc_list = {}      # Key -> Name: List of encoded EVCs

EVC_NAME_FORMAT = 'EVC-VOLTHA-{}-{}'
EVC_NAME_REGEX = 'EVC-VOLTHA-{}'.format('regex-here')
DEFAULT_STPID = 0x8100


class EVC(object):
    """
    Class to wrap EVC functionality
    """
    class SwitchingMethod(Enum):
        SINGLE_TAGGED = 0
        DOUBLE_TAGGED = 1
        MAC_SWITCHED = 2

    class Men2UniManipulation(Enum):
        SYMETRIC = 0
        POP_OUT_TAG_ONLY = 1

    class ElineFlowType(Enum):
        NNI_TO_UNI = 0,
        UNI_TO_NNI = 1,
        NNI_TO_NNI = 2,
        ACL_FILTER = 3,
        UNKNOWN = 4,
        UNSUPPORTED = 5     # Or Invalid

    def __init__(self, flow_entry):
        self._installed = False
        self._status_message = None
        self._parent = flow_entry           # FlowEntry parent
        self._flow = flow_entry.flow
        self._handler = flow_entry.handler
        self._evc_maps = []                 # One if E-Line

        self._flow_type = EVC.ElineFlowType.UNKNOWN

        # EVC related properties
        self._name = EVC.flow_to_name(flow_entry.flow, flow_entry.handler)
        self._enabled = True
        self._ce_vlan_preservation = True
        self._men_ports = []
        self._s_tag = -1
        self._stpid = DEFAULT_STPID

        self._switching_method = EVC.SwitchingMethod.SINGLE_TAGGED
        self._men_to_uni_tag_manipulation = EVC.Men2UniManipulation.SYMETRIC

        self._valid = self._decode()

    @staticmethod
    def flow_to_name(flow, handler):
        return EVC_NAME_FORMAT.format(flow.id, handler.id)

    @staticmethod
    def create(flow_entry):
        # Does it already exist?

        evc = _evc_list.get(EVC.flow_to_name(flow_entry.flow, flow_entry.handler))

        if evc is None:
            evc = EVC(flow_entry.flow, flow_entry.handler)

            if evc is not None:
                pass    # Look up any EVC that
                return
            pass        # Start decode here

        return evc

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
            if self._name in _evc_list:
                self._status_message = "EVC '{}' already is installed".format(self._name)
                raise Exception(self._status_message)   # TODO: A unique exception type would work here

            raise NotImplemented('TODO: Implement this')
            # xml = '<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">' \
            #       '<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs">' \
            #       '<adtn-evc:evc xmlns:adtn-evc="http://www.adtran.com/ns/yang/adtran-evcs">'
            #
            # xml += '<adtn-evc:name>' + name + '</adtn-evc:name>'
            #
            # if stag:
            #     xml += '<adtn-evc:stag>' + stag + '</adtn-evc:stag>'
            #
            # if preserve:
            #     xml += '<adtn-evc:ce-vlan-preservation>' + preserve + '</adtn-evc:ce-vlan-preservation>'
            #
            # if enabled:
            #     xml += '<adtn-evc:enabled>' + enabled + '</adtn-evc:enabled>'
            # else:
            #     xml += '<adtn-evc:enabled>' + "true" + '</adtn-evc:enabled>'
            #
            # xml += '</adtn-evc:evc></evc></config>'
            #
            # print "Creating EVC %s" % name
            #
            # print mgr.mgr.edit_config(target="running",
            #                           config=xml,
            #                           default_operation="merge",
            #                           format="xml")

            self._installed = True
            _evc_list[self.name] = self
            pass

        return self._installed

    def remove(self):
        if self._installed:
            raise NotImplemented('TODO: Implement this')
            # xml = '<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">' \
            #       '<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs">' \
            #       '<adtn-evc:evc xmlns:adtn-evc="http://www.adtran.com/ns/yang/adtran-evcs" nc:operation="delete">'
            #
            # xml += '<adtn-evc:name>' + name + '</adtn-evc:name>'
            #
            # xml += '</adtn-evc:evc></evc></config>'
            #
            # print "Deleting EVC %s" % name
            #
            # print mgr.mgr.edit_config(target="running",
            #                           config=xml,
            #                           default_operation="merge",
            #                           format="xml")

            self._installed = False
            _evc_list.pop(self.name)
            pass

        return not self._installed

    def enable(self):
        if not self._enabled:
            raise NotImplemented("TODO: Implement this")
            self._enabled = False

    def disable(self):
        if self._enabled:
            raise NotImplemented("TODO: Implement this")
            self._enabled = True

    def _decode(self):
        """
        Examine flow rules and extract appropriate settings for both this EVC
        and creates any EVC-Maps required.
        """
        from evc_map import EVCMap

        # Determine this flow's type

        status = self._decode_traffic_selector() and self._decode_traffic_treatment()

        if status:
            ingress_map = EVCMap.createIngressMap(self._flow, self._device)
            egress_map = EVCMap.createEgressMap(self._flow, self._device)

            status = ingress_map.valid and egress_map.valid

            if status:
                self._evc_maps.append(ingress_map)
                self._evc_maps.append(egress_map)
            else:
                self._status_message = 'Ingress MAP invalid: {}'.format(ingress_map.status)\
                    if not ingress_map.valid else 'Egress MAP invalid: {}'.format(egress_map.status)

        return status

    def _is_men_port(self, port):
        return port in self._handler.northbound_ports(port)

    def _is_uni_port(self, port):
        return port in self._handler.southbound_ports(port)

    def _is_logical_port(self, port):
        return not self._is_men_port(port) and not self._is_uni_port(port)

    def _get_port_name(self, port):
        if self._is_logical_port(port):
            raise NotImplemented('TODO: Logical ports not yet supported')

        if self._is_men_port(port):
            return self._handler.northbound_ports[port].name

        return None

    def _decode_traffic_selector(self):
        """
        Extract EVC related traffic selection settings
        """
        in_port = fd.get_in_port(self._flow)
        assert in_port is not None

        if self._is_men_port(in_port):
            log.debug('in_port is a MEN Port', port=in_port)
            self._men_ports.append(self._get_port_name(in_port))
        else:
            pass    # UNI Ports handled in the EVC Maps

        for field in fd.get_ofb_fields(self._flow):
            log.debug('Found OFB field', field=field)
            self._status_message = 'Unsupported field.type={}'.format(field.type)
            return False

        return True

    def _decode_traffic_treatment(self):
        out_port = fd.get_out_port(self._flow)
        num_outputs = 0

        if self._is_men_port(out_port):
            log.debug('out_port is a MEN Port', port=out_port)
            self._men_ports.append(self._get_port_name(out_port))
        else:
            pass  # UNI Ports handled in the EVC Maps

        for action in fd.get_actions(self._flow):
            if action.type == fd.OUTPUT:
                num_outputs += 1            # Handled earlier
                assert num_outputs <= 1     # Only E-LINE supported and no UNI<->UNI

            else:
                # TODO: May need to modify ce-preservation
                log.debug('Found action', action=action)

        return True

    # BULK operations

    @staticmethod
    def enable_all(regex_=EVC_NAME_REGEX):
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def disable_all(regex_=EVC_NAME_REGEX):
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def remove_all(regex_=EVC_NAME_REGEX):
        """
        Remove all matching EVCs and associated EVC MAPs from hardware

        :param regex_: (String) Regular expression for name matching
        """
        raise NotImplemented("TODO: Implement this")

