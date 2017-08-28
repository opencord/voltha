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

from evc import EVC
from evc_map import EVCMap
from enum import Enum

import voltha.core.flow_decomposer as fd
from voltha.core.flow_decomposer import *
from voltha.protos.openflow_13_pb2 import OFPP_CONTROLLER, OFPP_LOCAL, OFPP_ANY, OFPP_MAX
from twisted.internet.defer import returnValue, inlineCallbacks, succeed, gatherResults

log = structlog.get_logger()

# IP Protocol numbers
_supported_ip_protocols = [
    1,          # ICMP
    2,          # IGMP
    6,          # TCP
    17,         # UDP
]

_existing_flow_entries = {}  # device-id -> flow dictionary
                             #                  |
                             #                  +-> flow-id -> flow-entry


class FlowEntry(object):
    """
    Provide a class that wraps the flow rule and also provides state/status for a FlowEntry.

    When a new flow is sent, it is first decoded to check for any potential errors. If None are
    found, the entry is created and it is analyzed to see if it can be combined to with any other flows
    to create or modify an existing EVC.

    Note: Since only E-LINE is supported, modification of an existing EVC is not performed.
    """
    class FlowDirection(Enum):
        UPSTREAM = 0          # UNI port to NNI Port
        DOWNSTREAM = 1        # NNI port to UNI Port
        NNI = 2               # NNI port to NNI Port
        UNI = 3               # UNI port to UNI Port
        OTHER = 4             # Unable to determine

    _flow_dir_map = {
        (FlowDirection.UNI, FlowDirection.NNI): FlowDirection.UPSTREAM,
        (FlowDirection.NNI, FlowDirection.UNI): FlowDirection.DOWNSTREAM,
        (FlowDirection.UNI, FlowDirection.UNI): FlowDirection.UNI,
        (FlowDirection.NNI, FlowDirection.NNI): FlowDirection.NNI,
    }

    # Well known EtherTypes
    class EtherType(Enum):
        EAPOL = 0x888E
        IPv4 = 0x0800
        ARP = 0x0806

    # Well known IP Protocols
    class IpProtocol(Enum):
        IGMP = 2
        UDP = 17

    def __init__(self, flow, handler):
        self._flow = flow
        self._handler = handler
        self.evc = None              # EVC this flow is part of
        self.evc_map = None          # EVC-MAP this flow is part of
        self._flow_direction = FlowEntry.FlowDirection.OTHER
        self.onu_vid = None

        self._name = self._create_flow_name()
        # A value used to locate possible related flow entries
        self.signature = None

        # Selection properties
        self.in_port = None
        self.vlan_id = None
        self.pcp = None
        self.eth_type = None
        self.ip_protocol = None
        self.ipv4_dst = None
        self.udp_dst = None         # UDP Port #
        self.udp_src = None         # UDP Port #
        self.inner_vid = None

        # Actions
        self.output = None
        self.pop_vlan = 0
        self.push_vlan_tpid = []
        self.push_vlan_id = []

    @property
    def name(self):
        return self._name    # TODO: Is a name really needed in production?

    # TODO: Is a name really needed in production?
    def _create_flow_name(self):
        return 'flow-{}-{}'.format(self.device_id, self.flow_id)

    @property
    def flow(self):
        return self._flow

    @property
    def flow_id(self):
        return self.flow.id

    @property
    def handler(self):
        return self._handler

    @property
    def device_id(self):
        return self.handler.device_id

    @property
    def flow_direction(self):
        return self._flow_direction

    @staticmethod
    def create(flow, handler):
        """
        Create the appropriate FlowEntry wrapper for the flow.  This method returns a two
        results.

        The first result is the flow entry that was created. This could be a match to an
        existing flow since it is a bulk update.  None is returned only if no match to
        an existing entry is found and decode failed (unsupported field)

        The second result is the EVC this flow should be added to. This could be an
        existing flow (so your adding another EVC-MAP) or a brand new EVC (no existing
        EVC-MAPs).  None is returned if there are not a valid EVC that can be created YET.

        :param flow:   (Flow) Flow entry passed to VOLTHA adapter
        :param handler: (AdtranDeviceHandler) handler for the device

        :return: (FlowEntry, EVC)
        """
        # Exit early if it already exists
        try:
            flow_entry = FlowEntry(flow, handler)

            if flow_entry.device_id not in _existing_flow_entries:
                _existing_flow_entries[flow_entry.device_id] = {}

            flow_table = _existing_flow_entries[flow_entry.device_id]

            if flow_entry.flow_id in flow_table:
                return flow_entry, None

            #########################################
            # A new flow, decode it into the items of interest

            if not flow_entry._decode():
                return None, None

            # Look for any matching flows in the other direction that might help make an EVC
            # and then save it off in the device specific flow table
            # TODO: For now, only support for E-LINE services between NNI and UNI

            flow_candidates = [_flow for _flow in flow_table.itervalues()
                               if _flow.signature == flow_entry.signature and
                               _flow.in_port == flow_entry.output and
                               (_flow.flow_direction == FlowEntry.FlowDirection.UPSTREAM or
                                _flow.flow_direction == FlowEntry.FlowDirection.DOWNSTREAM)
                               ]

            flow_table[flow_entry.flow_id] = flow_entry

            # TODO: For now, only support for E-LINE services between NNI and UNI
            if len(flow_candidates) == 0 or (flow_entry.flow_direction != FlowEntry.FlowDirection.UPSTREAM and
                                             flow_entry.flow_direction != FlowEntry.FlowDirection.DOWNSTREAM):
                return flow_entry, None

            # Possible candidate found.  Currently, the logical_device_agent sends us the load downstream
            # flow first and then all the matching upstreams. So we should have only one match

            if flow_entry.flow_direction == FlowEntry.FlowDirection.DOWNSTREAM:
                downstream_flow = flow_entry
            else:
                assert len(flow_candidates) != 0
                downstream_flow = flow_candidates[0]

            if flow_entry.flow_direction == FlowEntry.FlowDirection.UPSTREAM:
                upstream_flows = [flow_entry]
            else:
                upstream_flows = flow_candidates

            return flow_entry, FlowEntry._create_evc_and_maps(downstream_flow, upstream_flows)

        except Exception as e:
            log.exception('flow_entry-processing', e=e)

    @staticmethod
    def _create_evc_and_maps(downstream_flow, upstream_flows):
        """
        Give a set of flows, find (or create) the EVC and any needed EVC-MAPs

        :param downstream_flow: NNI -> UNI flow (provides much of the EVC values)
        :param upstream_flows: UNI -> NNI flows (provides much of the EVC-MAP values)

        :return: EVC object
        """
        # Get any existing EVC if a flow is already created

        if downstream_flow.evc is None:
            downstream_flow.evc = EVC(downstream_flow)

        evc = downstream_flow.evc
        if not evc.valid:
            return None

        # Create EVC-MAPs
        for flow in upstream_flows:
            if flow.evc_map is None:
                flow.evc_map = EVCMap.create_ingress_map(flow, evc)

        all_valid = all(flow.evc_map.valid for flow in upstream_flows)

        return evc if all_valid else None

    def _decode(self):
        """
        Examine flow rules and extract appropriate settings
        """
        status = self._decode_traffic_selector() and self._decode_traffic_treatment()

        if status:
            # Determine direction of the flow

            def port_type(port_number):
                if port_number in self._handler.northbound_ports:
                    return FlowEntry.FlowDirection.NNI
                elif port_number <= OFPP_MAX:
                    return FlowEntry.FlowDirection.UNI
                return FlowEntry.FlowDirection.OTHER

            self._flow_direction = FlowEntry._flow_dir_map.get((port_type(self.in_port), port_type(self.output)),
                                                               FlowEntry.FlowDirection.OTHER)

        # Create a signature that will help locate related flow entries on a device.
        # These are not exact, just ones that may be put together to make an EVC. The
        # basic rules are:
        #
        # 1 - Same device
        dev_id = self._handler.device_id

        # 2 - Port numbers in increasing order
        ports = [self.in_port, self.output]
        ports.sort()

        # 3 - The outer VID

        push_len = len(self.push_vlan_id)
        assert push_len <= 2

        outer = self.vlan_id or None if push_len == 0 else self.push_vlan_id[0]

        # 4 - The inner VID.
        if self.inner_vid is not None:
            inner = self.inner_vid
        else:
            inner = self.vlan_id if (push_len > 0 and outer is not None) else None
            self.onu_vid = inner if self._flow_direction == FlowEntry.FlowDirection.UPSTREAM else None

        self.signature = '{}'.format(dev_id)
        for port in ports:
            self.signature += '.{}'.format(port)
        self.signature += '.{}.{}'.format(outer, inner)

        return status

    def _decode_traffic_selector(self):
        """
        Extract EVC related traffic selection settings
        """
        self.in_port = fd.get_in_port(self._flow)

        if self.in_port > OFPP_MAX:
            log.warn('Logical-input-ports-not-supported')
            return False

        for field in fd.get_ofb_fields(self._flow):
            if field.type == IN_PORT:
                pass   # Handled earlier

            elif field.type == VLAN_VID:
                # log.info('*** field.type == VLAN_VID', value=field.vlan_vid & 0xfff)
                self.vlan_id = field.vlan_vid & 0xfff

            elif field.type == VLAN_PCP:
                # log.info('*** field.type == VLAN_PCP', value=field.vlan_pcp)
                self.pcp = field.vlan_pcp

            elif field.type == ETH_TYPE:
                # log.info('*** field.type == ETH_TYPE', value=field.eth_type)
                self.eth_type = field.eth_type

            elif field.type == IP_PROTO:
                # log.info('*** field.type == IP_PROTO', value=field.ip_proto)
                self.ip_protocol = field.ip_proto

                if self.ip_protocol not in _supported_ip_protocols:
                    # log.error('Unsupported IP Protocol')
                    return False

            elif field.type == IPV4_DST:
                # log.info('*** field.type == IPV4_DST', value=field.ipv4_dst)
                self.ipv4_dst = field.ipv4_dst

            elif field.type == UDP_DST:
                # log.info('*** field.type == UDP_DST', value=field.udp_dst)
                self.udp_dst = field.udp_dst

            elif field.type == UDP_SRC:
                # log.info('*** field.type == UDP_SRC', value=field.udp_src)
                self.udp_src = field.udp_src

            elif field.type == METADATA:
                # log.info('*** field.type == METADATA', value=field.table_metadata)
                self.inner_vid = field.table_metadata

            else:
                log.warn('unsupported-selection-field', type=field.type)
                self._status_message = 'Unsupported field.type={}'.format(field.type)
                return False

        return True

    def _decode_traffic_treatment(self):
        self.output = fd.get_out_port(self._flow)

        if self.output > OFPP_MAX:
            log.warn('Logical-output-ports-not-supported')
            return False

        for act in fd.get_actions(self._flow):
            if act.type == fd.OUTPUT:
                pass           # Handled earlier

            elif act.type == POP_VLAN:
                # log.info('*** action.type == POP_VLAN')
                self.pop_vlan += 1

            elif act.type == PUSH_VLAN:
                # log.info('*** action.type == PUSH_VLAN', value=act.push)
                # TODO: Do we want to test the ethertype for support?
                tpid = act.push.ethertype
                self.push_vlan_tpid.append(tpid)

            elif act.type == SET_FIELD:
                # log.info('*** action.type == SET_FIELD', value=act.set_field.field)
                assert (act.set_field.field.oxm_class == ofp.OFPXMC_OPENFLOW_BASIC)
                field = act.set_field.field.ofb_field
                if field.type == VLAN_VID:
                    self.push_vlan_id.append(field.vlan_vid & 0xfff)

            else:
                # TODO: May need to modify ce-preservation
                log.warn('unsupported-action', action=act)
                self._status_message = 'Unsupported action.type={}'.format(act.type)
                return False

        return True

    @staticmethod
    def drop_missing_flows(device_id, valid_flow_ids):
        flow_table = _existing_flow_entries.get(device_id, None)
        if flow_table is None:
            return succeed('No table')

        flows_to_drop = [flow for flow_id, flow in flow_table.items() if flow_id not in valid_flow_ids]
        if len(flows_to_drop) == 0:
            return succeed('No flows')

        return gatherResults([flow.remove() for flow in flows_to_drop])

    @inlineCallbacks
    def remove(self):
        """
        Remove this flow entry from the list of existing entries and drop EVC
        if needed
        """
        # Remove from exiting table list
        device_id = self._handler.device_id
        flow_id = self._flow.id
        flow_table = _existing_flow_entries.get(device_id, None)

        if flow_table is None or flow_id not in flow_table:
            returnValue(succeed('NOP'))

        del flow_table[flow_id]
        if len(flow_table) == 0:
            del _existing_flow_entries[device_id]

        # Remove flow from the hardware
        try:
            dl = []
            if self.evc_map is not None:
                dl.append(self.evc_map.delete())

            if self.evc is not None:
                dl.append(self.evc.delete())

            yield gatherResults(dl)

        except Exception as e:
            log.exception('removal', e=e)

        self.evc_map = None
        self.evc = None
        returnValue('Done')

    ######################################################
    # Bulk operations

    @staticmethod
    def remove_all():
        """
        Remove all matching EVCs and associated EVC MAPs from hardware

        :param regex_: (String) Regular expression for name matching
        """
        raise NotImplemented("TODO: Implement this")

