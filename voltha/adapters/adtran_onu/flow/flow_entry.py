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

from enum import IntEnum
import voltha.core.flow_decomposer as fd
from voltha.core.flow_decomposer import *
from voltha.protos.openflow_13_pb2 import OFPP_MAX

log = structlog.get_logger()

# IP Protocol numbers
_supported_ip_protocols = [
    1,          # ICMP
    2,          # IGMP
    6,          # TCP
    17,         # UDP
]


class FlowEntry(object):
    """
    Provide a class that wraps the flow rule and also provides state/status for a FlowEntry.

    When a new flow is sent, it is first decoded to check for any potential errors. If None are
    found, the entry is created and it is analyzed to see if it can be combined to with any other flows
    to create or modify an existing EVC.

    Note: Since only E-LINE is supported, modification of an existing EVC is not performed.
    """
    class FlowDirection(IntEnum):
        UPSTREAM = 0          # UNI port to ANI Port
        DOWNSTREAM = 1        # ANI port to UNI Port
        ANI = 2               # ANI port to ANI Port
        UNI = 3               # UNI port to UNI Port
        OTHER = 4             # Unable to determine

    _flow_dir_map = {
        (FlowDirection.UNI, FlowDirection.ANI): FlowDirection.UPSTREAM,
        (FlowDirection.ANI, FlowDirection.UNI): FlowDirection.DOWNSTREAM
    }

    upstream_flow_types = {FlowDirection.UPSTREAM}
    downstream_flow_types = {FlowDirection.DOWNSTREAM}

    # Well known EtherTypes
    class EtherType(IntEnum):
        EAPOL = 0x888E
        IPv4 = 0x0800
        IPv6 = 0x86DD
        ARP = 0x0806
        LLDP = 0x88CC

    # Well known IP Protocols
    class IpProtocol(IntEnum):
        IGMP = 2
        UDP = 17

    def __init__(self, flow, handler):
        self._handler = handler
        self.flow_id = flow.id
        self._flow_direction = FlowEntry.FlowDirection.OTHER
        self._is_multicast = False
        self.tech_profile_id = None

        # Selection properties
        self.in_port = None
        self.vlan_vid = None
        self.vlan_pcp = None
        self.etype = None
        self.proto = None
        self.ipv4_dst = None
        self.udp_dst = None         # UDP Port #
        self.udp_src = None         # UDP Port #
        self.inner_vid = None

        # Actions
        self.out_port = None
        self.pop_vlan = False
        self.push_vlan_tpid = None
        self.set_vlan_vid = None
        self._name = self.create_flow_name()

    def __str__(self):
        return 'flow_entry: {}, in: {}, out: {}, vid: {}, inner:{}, eth: {}, IP: {}'.format(
            self.name, self.in_port, self.out_port, self.vlan_vid, self.inner_vid,
            self.etype, self.proto)

    def __repr__(self):
        return str(self)

    @property
    def name(self):
        return self._name    # TODO: Is a name really needed in production?

    def create_flow_name(self):
        return 'flow-{}-{}'.format(self.device_id, self.flow_id)

    @property
    def handler(self):
        return self._handler

    @property
    def device_id(self):
        return self.handler.device_id

    @property
    def flow_direction(self):
        return self._flow_direction

    @property
    def is_multicast_flow(self):
        return self._is_multicast

    @staticmethod
    def create(flow, handler):
        """
        Create the appropriate FlowEntry wrapper for the flow.  This method returns a two
        results.

        The first result is the flow entry that was created. This could be a match to an
        existing flow since it is a bulk update.  None is returned only if no match to
        an existing entry is found and decode failed (unsupported field)

        :param flow:   (Flow) Flow entry passed to VOLTHA adapter
        :param handler: (DeviceHandler) handler for the device
        :return: (FlowEntry) Created flow entry, None on decode failure
        """
        # Exit early if it already exists
        try:
            flow_entry = FlowEntry(flow, handler)

            if not flow_entry.decode(flow):
                return None

            # TODO: Do we want to do the OMCI here ?

            return flow_entry

        except Exception as e:
            log.exception('flow-entry-processing', e=e)
            return None

    def decode(self, flow):
        """
        Examine flow rules and extract appropriate settings
        """
        log.debug('start-decode')
        status = self._decode_traffic_selector(flow) and self._decode_traffic_treatment(flow)

        if status:
            ani_ports = [pon.port_number for pon in self._handler.pon_ports]
            uni_ports = [uni.port_number for uni in self._handler.uni_ports]

            # Determine direction of the flow
            def port_type(port_number):
                if port_number in ani_ports:
                    return FlowEntry.FlowDirection.ANI

                elif port_number in uni_ports:
                    return FlowEntry.FlowDirection.UNI

                return FlowEntry.FlowDirection.OTHER

            self._flow_direction = FlowEntry._flow_dir_map.get((port_type(self.in_port),
                                                                port_type(self.out_port)),
                                                               FlowEntry.FlowDirection.OTHER)
        return status

    def _decode_traffic_selector(self, flow):
        """
        Extract traffic selection settings
        """
        self.in_port = fd.get_in_port(flow)

        if self.in_port > OFPP_MAX:
            log.warn('logical-input-ports-not-supported')
            return False

        for field in fd.get_ofb_fields(flow):
            if field.type == IN_PORT:
                assert self.in_port == field.port, 'Multiple Input Ports found in flow rule'

            elif field.type == VLAN_VID:
                self.vlan_vid = field.vlan_vid & 0xfff
                log.debug('*** field.type == VLAN_VID', value=field.vlan_vid, vlan_id=self.vlan_vid)
                self._is_multicast = False  # TODO: self.vlan_id in self._handler.multicast_vlans

            elif field.type == VLAN_PCP:
                log.debug('*** field.type == VLAN_PCP', value=field.vlan_pcp)
                self.vlan_pcp = field.vlan_pcp

            elif field.type == ETH_TYPE:
                log.debug('*** field.type == ETH_TYPE', value=field.eth_type)
                self.etype = field.eth_type

            elif field.type == IP_PROTO:
                log.debug('*** field.type == IP_PROTO', value=field.ip_proto)
                self.proto = field.ip_proto

                if self.proto not in _supported_ip_protocols:
                    log.error('Unsupported IP Protocol', ip_proto=self.proto)
                    return False

            elif field.type == IPV4_DST:
                log.debug('*** field.type == IPV4_DST', value=field.ipv4_dst)
                self.ipv4_dst = field.ipv4_dst

            elif field.type == UDP_DST:
                log.debug('*** field.type == UDP_DST', value=field.udp_dst)
                self.udp_dst = field.udp_dst

            elif field.type == UDP_SRC:
                log.debug('*** field.type == UDP_SRC', value=field.udp_src)
                self.udp_src = field.udp_src

            elif field.type == METADATA:
                log.debug('*** field.type == METADATA', value=field.table_metadata)
                self.inner_vid = field.table_metadata
                log.debug('*** field.type == METADATA', value=field.table_metadata,
                          inner_vid=self.inner_vid)
            else:
                log.warn('unsupported-selection-field', type=field.type)
                self._status_message = 'Unsupported field.type={}'.format(field.type)
                return False

        return True

    def _decode_traffic_treatment(self, flow):
        self.out_port = fd.get_out_port(flow)

        if self.out_port > OFPP_MAX:
            log.warn('logical-output-ports-not-supported')
            return False

        for act in fd.get_actions(flow):
            if act.type == fd.OUTPUT:
                assert self.out_port == act.output.port, 'Multiple Output Ports found in flow rule'
                pass           # Handled earlier

            elif act.type == POP_VLAN:
                log.debug('*** action.type == POP_VLAN')
                self.pop_vlan = True

            elif act.type == PUSH_VLAN:
                log.debug('*** action.type == PUSH_VLAN', value=act.push)
                tpid = act.push.ethertype
                self.push_tpid = tpid
                assert tpid == 0x8100, 'Only TPID 0x8100 is currently supported'

            elif act.type == SET_FIELD:
                log.debug('*** action.type == SET_FIELD', value=act.set_field.field)
                assert (act.set_field.field.oxm_class == ofp.OFPXMC_OPENFLOW_BASIC)
                field = act.set_field.field.ofb_field
                if field.type == VLAN_VID:
                    self.set_vlan_vid = field.vlan_vid & 0xfff

            else:
                log.warn('unsupported-action', action=act)
                self._status_message = 'Unsupported action.type={}'.format(act.type)
                return False

        return True
