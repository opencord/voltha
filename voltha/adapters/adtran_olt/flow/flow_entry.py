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

from evc import EVC
from evc_map import EVCMap
from enum import Enum

import voltha.core.flow_decomposer as fd
from voltha.core.flow_decomposer import *
from voltha.protos.openflow_13_pb2 import OFPP_MAX
from twisted.internet import defer
from twisted.internet.defer import returnValue, inlineCallbacks, succeed, gatherResults

log = structlog.get_logger()

# IP Protocol numbers
_supported_ip_protocols = [
    1,          # ICMP
    2,          # IGMP
    6,          # TCP
    17,         # UDP
]

_existing_downstream_flow_entries = {}  # device-id -> signature-table
                                        #                  |
                                        #                  +-> downstream-signature
                                        #                        |
                                        #                        +-> 'evc' -> EVC
                                        #                        |
                                        #                        +-> flow-ids -> flow-entry

_existing_upstream_flow_entries = {}  # device-id -> flow dictionary
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
        self._flow = flow           # TODO: Remove later
        self._handler = handler
        self.flow_id = flow.id
        self.evc = None              # EVC this flow is part of
        self.evc_map = None          # EVC-MAP this flow is part of
        self._flow_direction = FlowEntry.FlowDirection.OTHER
        self._logical_port = None    # Currently ONU VID is logical port if not doing xPON
        self._is_multicast = False

        # A value used to locate possible related flow entries
        self.signature = None
        self.downstream_signature = None  # Valid for upstream EVC-MAP Flows

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

        self._name = self.create_flow_name()

    def __str__(self):
        return 'flow_entry: {}, in: {}, out: {}'.format(self.name, self.in_port,
                                                        self.output)

    @property
    def name(self):
        return self._name    # TODO: Is a name really needed in production?

    def create_flow_name(self):
        return 'flow-{}-{}'.format(self.device_id, self.flow_id)

    @property
    def flow(self):
        return self._flow

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

    @property
    def logical_port(self):
        return self._logical_port   # NNI or UNI Logical Port

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

            if not flow_entry._decode():
                return None, None

            if flow_entry.device_id not in _existing_downstream_flow_entries:
                _existing_downstream_flow_entries[flow_entry.device_id] = {}

            if flow_entry.device_id not in _existing_upstream_flow_entries:
                _existing_upstream_flow_entries[flow_entry.device_id] = {}

            downstream_sig_table = _existing_downstream_flow_entries[flow_entry.device_id]
            upstream_flow_table = _existing_upstream_flow_entries[flow_entry.device_id]

            if flow_entry.flow_direction == FlowEntry.FlowDirection.UPSTREAM and\
                    flow_entry.flow_id in upstream_flow_table:
                return flow_entry, None

            if flow_entry.flow_direction == FlowEntry.FlowDirection.DOWNSTREAM and\
                    flow_entry.signature in downstream_sig_table and\
                    flow_entry.flow_id in downstream_sig_table[flow_entry.signature]:
                return flow_entry, None

            # Look for any matching flows in the other direction that might help make an EVC
            # and then save it off in the device specific flow table
            # TODO: For now, only support for E-LINE services between NNI and UNI

            downstream_flow = None
            upstream_flows = None
            downstream_sig = None

            if flow_entry._is_multicast:        # Uni-directional flow
                assert flow_entry._flow_direction == FlowEntry.FlowDirection.DOWNSTREAM, \
                    'Only downstream Multicast supported'
                downstream_flow = flow_entry
                downstream_sig = flow_entry.signature
                upstream_flows = []

            elif flow_entry.flow_direction == FlowEntry.FlowDirection.DOWNSTREAM:
                downstream_flow = flow_entry
                downstream_sig = flow_entry.signature

            elif flow_entry.flow_direction == FlowEntry.FlowDirection.UPSTREAM:
                downstream_sig = flow_entry.downstream_signature

            if downstream_sig is None:
                return None, None

            if downstream_sig not in downstream_sig_table:
                downstream_sig_table[downstream_sig] = {}
                downstream_sig_table[downstream_sig]['evc'] = None

            downstream_flow_table = downstream_sig_table[downstream_sig]
            evc = downstream_flow_table['evc']

            # Save to proper flow table
            if flow_entry.flow_direction == FlowEntry.FlowDirection.UPSTREAM:
                upstream_flow_table[flow_entry.flow_id] = flow_entry
                downstream_flow = evc.flow_entry if evc is not None else \
                    next((_flow for _flow in downstream_flow_table.itervalues() if isinstance(_flow, FlowEntry)), None)

            elif flow_entry.flow_direction == FlowEntry.FlowDirection.DOWNSTREAM:
                downstream_flow_table[flow_entry.flow_id] = flow_entry

            # Now find all the upstream flows
            if downstream_flow is not None:
                upstream_flows = [_flow for _flow in upstream_flow_table.itervalues()
                                  if _flow.downstream_signature == downstream_flow.signature]
                if len(upstream_flows) == 0 and not downstream_flow.is_multicast_flow:
                    upstream_flows = None

            # Compute EVC and and maps

            evc = FlowEntry._create_evc_and_maps(evc, downstream_flow, upstream_flows)
            if evc is not None and evc.valid and downstream_flow_table['evc'] is None:
                downstream_flow_table['evc'] = evc

            return flow_entry, evc

        except Exception as e:
            log.exception('flow_entry-processing', e=e)
            return None, None

    @staticmethod
    def _create_evc_and_maps(evc, downstream_flow, upstream_flows):
        """
        Give a set of flows, find (or create) the EVC and any needed EVC-MAPs

        :param evc: (EVC) Existing EVC for downstream flow. May be null if not created
        :param downstream_flow: (FlowEntry) NNI -> UNI flow (provides much of the EVC values)
        :param upstream_flows: (list of FlowEntry) UNI -> NNI flows (provides much of the EVC-MAP values)

        :return: EVC object
        """
        if (evc is None and downstream_flow is None) or upstream_flows is None:
            return None

        # Get any existing EVC if a flow is already created

        if downstream_flow.evc is None:
            if evc is not None:
                downstream_flow.evc = evc

            elif downstream_flow.is_multicast_flow:
                from mcast import MCastEVC
                downstream_flow.evc = MCastEVC.create(downstream_flow)

            else:
                downstream_flow.evc = EVC(downstream_flow)

        if not downstream_flow.evc.valid:
            return None

        # Create EVC-MAPs. Note upstream_flows is empty list for multicast

        for flow in upstream_flows:
            if flow.evc_map is None:
                flow.evc_map = EVCMap.create_ingress_map(flow, downstream_flow.evc)

        all_maps_valid = all(flow.evc_map.valid for flow in upstream_flows) \
            or downstream_flow.is_multicast_flow

        return downstream_flow.evc if all_maps_valid else None

    @property
    def _needs_acl_support(self):
        """
        TODO: This is only while there is only a single downstream exception flow
        """
        if self.ipv4_dst is not None:  # In case MCAST downstream has ACL on it
            return False

        return self.eth_type is not None or self.ip_protocol is not None or\
            self.ipv4_dst is not None or self.udp_dst is not None or self.udp_src is not None

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
        # 4 - The inner VID.  Wildcard if downstream

        push_len = len(self.push_vlan_id)
        if push_len == 0:
            outer = self.vlan_id
            inner = self.inner_vid
        else:
            outer = self.push_vlan_id[-1]
            if push_len == 1:
                inner = self.vlan_id
            else:
                inner = self.push_vlan_id[-2]

        upstream_sig = '{}'.format(dev_id)
        downstream_sig = '{}'.format(dev_id)

        for port in ports:
            upstream_sig += '.{}'.format(port)
            downstream_sig += '.{}'.format(port if self.handler.is_nni_port(port) else '*')

        upstream_sig += '.{}.{}'.format(outer, inner)
        downstream_sig += '.{}.*'.format(outer)

        if self._flow_direction == FlowEntry.FlowDirection.DOWNSTREAM:
            self.signature = downstream_sig
        else:
            self.signature = upstream_sig
            self.downstream_signature = downstream_sig

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
                assert self.in_port == field.port, 'Multiple Input Ports found in flow rule'

                if self._handler.is_nni_port(self.in_port):
                    self._logical_port = self.in_port

            elif field.type == VLAN_VID:
                # log.info('*** field.type == VLAN_VID', value=field.vlan_vid & 0xfff)
                self.vlan_id = field.vlan_vid & 0xfff
                self._is_multicast = self.vlan_id in self._handler.multicast_vlans

                if self._handler.is_pon_port(self.in_port):
                    self._logical_port = self.vlan_id

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
                assert self.output == act.output.port, 'Multiple Output Ports found in flow rule'
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
        dl = []

        flow_table = _existing_upstream_flow_entries.get(device_id)
        if flow_table is not None:
            flows_to_drop = [flow for flow_id, flow in flow_table.items()
                             if flow_id not in valid_flow_ids]
            dl.extend([flow.remove() for flow in flows_to_drop])

        sig_table = _existing_downstream_flow_entries.get(device_id)
        if sig_table is not None:
            for flow_table in sig_table.itervalues():
                flows_to_drop = [flow for flow_id, flow in flow_table.items()
                                 if isinstance(flow, FlowEntry) and flow_id not in valid_flow_ids]
                dl.extend([flow.remove() for flow in flows_to_drop])

        return gatherResults(dl, consumeErrors=True)

    @inlineCallbacks
    def remove(self):
        """
        Remove this flow entry from the list of existing entries and drop EVC
        if needed
        """
        # Remove from exiting table list

        device_id = self._handler.device_id
        flow_id = self._flow.id
        flow_table = None
        sig_table = None

        if self.flow_direction == FlowEntry.FlowDirection.UPSTREAM:
            flow_table = _existing_upstream_flow_entries.get(device_id)

        elif self.flow_direction == FlowEntry.FlowDirection.DOWNSTREAM:
            sig_table = _existing_downstream_flow_entries.get(device_id)
            flow_table = sig_table.get(self.signature)

        if flow_table is None or flow_id not in flow_table:
            returnValue(succeed('NOP'))

        # Remove from flow table and clean up flow table if empty

        del flow_table[flow_id]
        evc_map, self.evc_map = self.evc_map, None
        evc = None

        if self.flow_direction == FlowEntry.FlowDirection.UPSTREAM:
            if len(flow_table) == 0:
                del _existing_upstream_flow_entries[device_id]

        elif self.flow_direction == FlowEntry.FlowDirection.DOWNSTREAM:
            flow_evc = flow_table['evc']

            # If this flow owns the EVC, assign it to a remaining flow
            if flow_evc is not None and flow_id == flow_evc.flow_entry.flow_id:
                flow_table['evc'].flow_entry = next((_flow for _flow in flow_table.itervalues()
                                                     if isinstance(_flow, FlowEntry)
                                                     and _flow.flow_id != flow_id), None)

            if len(flow_table) == 1:   # Only 'evc' entry present
                evc = flow_evc
                del flow_table['evc']
                del sig_table[self.signature]
                if len(sig_table) == 0:
                    del _existing_downstream_flow_entries[device_id]
            else:
                assert flow_table['evc'] is not None, 'EVC flow re-assignment error'

        # Remove flow from the hardware
        try:
            dl = []
            if evc_map is not None:
                dl.append(evc_map.delete())

            if evc is not None:
                dl.append(evc.delete())

            yield gatherResults(dl)

        except Exception as e:
            log.exception('removal', e=e)

        self.evc = None
        returnValue(succeed('Done'))

    @staticmethod
    def find_evc_map_flows(onu):
        """
        For a given OLT, find all the EVC Maps for a specific ONU
        :param onu: (Onu) onu
        :return: (list) of matching flows
        """
        # EVCs are only in the downstream table, EVC Map are in upstream

        device_id = onu.device_id
        onu_ports = onu.uni_ports

        all_flow_entries = _existing_upstream_flow_entries.get(device_id) or {}
        evc_maps = [flow_entry.evc_map for flow_entry in all_flow_entries.itervalues()
                    if flow_entry.in_port in onu_ports
                    and flow_entry.evc_map is not None
                    and flow_entry.evc_map.valid]

        return evc_maps

    @staticmethod
    def sync_flows_by_onu(onu, reflow=False):
        """
        Check status of all flows on a per-ONU basis. Called when values
        within the ONU are modified that may affect traffic.

        :param onu: (Onu) ONU to examine
        :param reflow: (boolean) Flag, if True, requests that the flow be sent to
                                 hardware even if the values in hardware are
                                 consistent with the current flow settings
        """
        evc_maps = FlowEntry.find_evc_map_flows(onu)
        evcs = {}

        for evc_map in evc_maps:
            if reflow or evc_map.reflow_needed():
                evc_map.installed = False

            if not evc_map.installed:
                evc = evc_map.evc
                if evc is not None:
                    evcs[evc.name] = evc

        for evc in evcs.itervalues():
            evc.installed = False
            evc.schedule_install(delay=2)

    ######################################################
    # Bulk operations

    @staticmethod
    def remove_all():
        """
        Remove all matching EVCs and associated EVC MAPs from hardware

        :param regex_: (String) Regular expression for name matching
        """
        raise NotImplemented("TODO: Implement this")

