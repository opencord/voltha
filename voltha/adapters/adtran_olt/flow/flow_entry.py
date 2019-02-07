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
from enum import IntEnum
from utility_evc import UtilityEVC
import voltha.core.flow_decomposer as fd
from voltha.core.flow_decomposer import *
from voltha.protos.openflow_13_pb2 import OFPP_MAX, OFPP_CONTROLLER, OFPVID_PRESENT, OFPXMC_OPENFLOW_BASIC
from twisted.internet.defer import returnValue, inlineCallbacks, gatherResults

log = structlog.get_logger()

# IP Protocol numbers
_supported_ip_protocols = [
    1,  # ICMP
    2,  # IGMP
    6,  # TCP
    17, # UDP
]


class FlowEntry(object):
    """
    Provide a class that wraps the flow rule and also provides state/status for a FlowEntry.

    When a new flow is sent, it is first decoded to check for any potential errors. If None are
    found, the entry is created and it is analyzed to see if it can be combined to with any other flows
    to create or modify an existing EVC.

    Note: Since only E-LINE is supported, modification of an existing EVC is not performed.
    """
    class PortType(IntEnum):
        NNI = 0         # NNI Port
        UNI = 1         # UNI Port
        PON = 2         # PON Port (all UNIs on PON)
        CONTROLLER = 3  # Controller port (packet in/out)

    class FlowDirection(IntEnum):
        UPSTREAM = 0          # UNI port to NNI Port
        DOWNSTREAM = 1        # NNI port to UNI Port
        CONTROLLER_UNI = 2    # Trap packet on UNI and send to controller
        NNI_PON = 3           # NNI port to PON Port (all UNIs) - Utility VLAN & multicast

        # The following are not yet supported
        CONTROLLER_NNI = 4    # Trap packet on NNI and send to controller
        CONTROLLER_PON = 5    # Trap packet on all UNIs of a PON and send to controller
        NNI_NNI = 6           # NNI port to NNI Port
        UNI_UNI = 7           # UNI port to UNI Port
        OTHER = 9             # Unable to determine

    upstream_flow_types = {FlowDirection.UPSTREAM, FlowDirection.CONTROLLER_UNI}
    downstream_flow_types = {FlowDirection.DOWNSTREAM, FlowDirection.NNI_PON}

    LEGACY_CONTROL_VLAN = 4000

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
        self._flow = flow
        self._handler = handler
        self.flow_id = flow.id
        self.evc = None              # EVC this flow is part of
        self.evc_map = None          # EVC-MAP this flow is part of
        self._flow_direction = FlowEntry.FlowDirection.OTHER
        self._logical_port = None    # Currently ONU VID is logical port if not doing xPON
        self._is_multicast = False
        self._is_acl_flow = False
        self._bandwidth = None

        # A value used to locate possible related flow entries
        self._signature = None
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
        self.pop_vlan = False
        self.push_vlan_tpid = None
        self.push_vlan_id = None

        self._name = None

    def __str__(self):
        return 'flow_entry: {}, in: {}, out: {}, vid: {}, inner:{}, eth: {}, IP: {}'.format(
            self.name, self.in_port, self.output, self.vlan_id, self.inner_vid,
            self.eth_type, self.ip_protocol)

    def __repr__(self):
        return str(self)

    @property
    def name(self):
        if self._name is None:
            self._name = 'flow-{}-{}'.format(self.device_id, self.flow_id)
        return self._name    # TODO: Is a name really needed in production?

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
    def bandwidth(self):
        """ Bandwidth in Mbps (if any) """
        return self._bandwidth

    @property
    def flow_direction(self):
        return self._flow_direction

    @property
    def is_multicast_flow(self):
        return self._is_multicast

    @property
    def is_acl_flow(self):
        return self._is_acl_flow or self._needs_acl_support

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

            ######################################################################
            # Decode the flow entry
            if not flow_entry._decode(flow):
                # TODO: When we support individual flow mods, we will need to return
                #       this flow back always
                return None, None

            ######################################################################
            # Initialize flow_entry database (dicts) if needed and determine if
            # the flows have already been handled.
            downstream_sig_table = flow_entry.handler.downstream_flows
            upstream_flow_table = flow_entry.handler.upstream_flows

            log.debug('flow-entry-decoded', flow=flow_entry, signature=flow_entry.signature,
                      downstream_signature=flow_entry.downstream_signature)

            if flow_entry.flow_direction in FlowEntry.upstream_flow_types and\
                    flow_entry.flow_id in upstream_flow_table:
                log.debug('flow-entry-upstream-exists', flow=flow_entry)
                return flow_entry, None

            if flow_entry.flow_direction in FlowEntry.downstream_flow_types:
                sig_table = downstream_sig_table.get(flow_entry.signature)
                if sig_table is not None and flow_entry in sig_table.flows:
                    log.debug('flow-entry-downstream-exists', flow=flow_entry)
                    return flow_entry, None

            ######################################################################
            # Look for any matching flows in the other direction that might help
            # make an EVC and then save it off in the device specific flow table
            #
            # TODO: For now, only support for E-LINE services between NNI and UNI
            downstream_flow = None
            upstream_flows = None
            downstream_sig = None

            if flow_entry._is_multicast:        # Uni-directional flow
                assert flow_entry._flow_direction in FlowEntry.downstream_flow_types, \
                    'Only downstream Multicast supported'
                downstream_flow = flow_entry
                downstream_sig = flow_entry.signature
                upstream_flows = []

            elif flow_entry.flow_direction in FlowEntry.downstream_flow_types:
                downstream_flow = flow_entry
                downstream_sig = flow_entry.signature

            elif flow_entry.flow_direction in FlowEntry.upstream_flow_types:
                downstream_sig = flow_entry.downstream_signature

            if downstream_sig is None:
                # TODO: When we support individual flow mods, we will need to return
                #       this flow back always
                log.debug('flow-entry-empty-downstream', flow=flow_entry)
                return None, None

            # Make sure a slot exists for the downstream signature and get its flow table
            downstream_sig_table = downstream_sig_table.add(downstream_sig)
            evc = downstream_sig_table.evc

            # Save the new flow_entry to proper flow table
            if flow_entry.flow_direction in FlowEntry.upstream_flow_types:
                upstream_flow_table.add(flow_entry)
                downstream_flow = evc.flow_entry if evc is not None else \
                    next((_flow for _flow in downstream_sig_table.flows.itervalues()
                          if isinstance(_flow, FlowEntry)), None)

            elif flow_entry.flow_direction in FlowEntry.downstream_flow_types:
                downstream_sig_table.flows.add(flow_entry)

            # Now find all the upstream flows
            if downstream_flow is not None:
                upstream_flows = [_flow for _flow in upstream_flow_table.itervalues()
                                  if _flow.downstream_signature == downstream_flow.signature]
                if len(upstream_flows) == 0 and not downstream_flow.is_multicast_flow:
                    upstream_flows = None

            log.debug('flow-entry-search-results', flow=flow_entry,
                      downstream_flow=downstream_flow, upstream_flows=upstream_flows)

            ######################################################################
            # Compute EVC and and maps
            evc = FlowEntry._create_evc_and_maps(evc, downstream_flow, upstream_flows)

            # Save off EVC (if we have one) for this flow if it is new
            if evc is not None and evc.valid and downstream_sig_table.evc is None:
                downstream_sig_table.evc = evc

            return flow_entry, evc

        except Exception as e:
            log.exception('flow-entry-processing', e=e)
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
        log.debug('flow-evc-and-maps', downstream_flow=downstream_flow,
                  upstream_flows=upstream_flows)

        if (evc is None and downstream_flow is None) or upstream_flows is None:
            return None

        # Get any existing EVC if a flow is already created
        if downstream_flow.evc is None:
            if evc is not None:
                downstream_flow.evc = evc

            elif downstream_flow.is_multicast_flow:
                from mcast import MCastEVC
                downstream_flow.evc = MCastEVC.create(downstream_flow)

            elif downstream_flow.is_acl_flow:
                downstream_flow.evc = downstream_flow.get_utility_evc()
            else:
                downstream_flow.evc = EVC(downstream_flow)

        if not downstream_flow.evc.valid:
            log.debug('flow-evc-and-maps-downstream-invalid',
                      downstream_flow=downstream_flow,
                      upstream_flows=upstream_flows)
            return None

        # Create EVC-MAPs. Note upstream_flows is empty list for multicast
        # For Packet In/Out support. The upstream flows for will have matching
        # signatures. So the first one to get created should create the EVC and
        # if it needs and ACL, do so then. The second one should just reference
        # the first map.
        #
        #    If the second has and ACL, then it should add it to the map.
        #    TODO: What to do if the second (or third, ...) is the data one.
        #          What should it do then?
        sig_map_map = {f.signature: f.evc_map for f in upstream_flows
                       if f.evc_map is not None}

        for flow in upstream_flows:
            if flow.evc_map is None:
                if flow.signature in sig_map_map:
                    # Found an explicitly matching existing EVC-MAP. Add flow to this EVC-MAP
                    flow.evc_map = sig_map_map[flow.signature].add_flow(flow, downstream_flow.evc)
                else:
                    # May need to create a MAP or search for an existing ACL/user EVC-Map
                    # upstream_flow_table = _existing_upstream_flow_entries[flow.device_id]
                    upstream_flow_table = flow.handler.upstream_flows
                    existing_flow = EVCMap.find_matching_ingress_flow(flow, upstream_flow_table)

                    if existing_flow is None:
                        flow.evc_map = EVCMap.create_ingress_map(flow, downstream_flow.evc)
                    else:
                        flow.evc_map = existing_flow.add_flow(flow, downstream_flow.evc)

        all_maps_valid = all(flow.evc_map.valid for flow in upstream_flows) \
            or downstream_flow.is_multicast_flow

        log.debug('flow-evc-and-maps-downstream',
                  downstream_flow=downstream_flow,
                  upstream_flows=upstream_flows, all_valid=all_maps_valid)

        return downstream_flow.evc if all_maps_valid else None

    def get_utility_evc(self, use_default_vlan_id=False):
        assert self.is_acl_flow, 'Utility evcs are for acl flows only'
        return UtilityEVC.create(self, use_default_vlan_id)

    @property
    def _needs_acl_support(self):
        if self.ipv4_dst is not None:  # In case MCAST downstream has ACL on it
            return False

        return self.eth_type is not None or self.ip_protocol is not None or\
            self.ipv4_dst is not None or self.udp_dst is not None or self.udp_src is not None

    @property
    def signature(self):
        if self._signature is None:
            # These are not exact, just ones that may be put together to make an EVC. The
            # basic rules are:
            #
            # 1 - Port numbers in increasing order
            ports = sorted(filter(None, [self.in_port, self.output]))
            assert len(ports) == 2, 'Invalid port count: {}'.format(len(ports))

            # 3 - The outer VID
            # 4 - The inner VID.  Wildcard if downstream
            if self.push_vlan_id is None:
                outer = self.vlan_id
                inner = self.inner_vid
            else:
                outer = self.push_vlan_id
                inner = self.vlan_id

            downstream_sig = '.'.join(map(str, (
                ports[0],
                ports[1] if self.handler.is_nni_port(ports[1]) else '*',
                outer,
                '*'
            )))

            if self._flow_direction in FlowEntry.downstream_flow_types:
                self._signature = downstream_sig
            elif self._flow_direction in FlowEntry.upstream_flow_types:
                self._signature = '.'.join(map(str, (ports[0], ports[1], outer, inner)))
                self.downstream_signature = downstream_sig
            else:
                log.error('unsupported-flow')
        return self._signature

    def _decode(self, flow):
        """
        Examine flow rules and extract appropriate settings
        """
        log.debug('start-decode')
        status = self._decode_traffic_selector(flow) and self._decode_traffic_treatment(flow)

        # Determine direction of the flow and apply appropriate modifications
        # to the decoded flows
        if status:
            if not self._decode_flow_direction():
                return False

            if self._flow_direction in FlowEntry.downstream_flow_types:
                status = self._apply_downstream_mods()
            elif self._flow_direction in FlowEntry.upstream_flow_types:
                status = self._apply_upstream_mods()
            else:
                # TODO: Need to code this - Perhaps this is an NNI_PON for Multicast support?
                log.error('unsupported-flow-direction')
                status = False

            log.debug('flow-evc-decode', direction=self._flow_direction, is_acl=self._is_acl_flow,
                      inner_vid=self.inner_vid, vlan_id=self.vlan_id, pop_vlan=self.pop_vlan,
                      push_vid=self.push_vlan_id, status=status)

        # Create a signature that will help locate related flow entries on a device.
        if status:
            status = self.signature is not None
            log.debug('flow-evc-decode', upstream_sig=self.signature, downstream_sig=self.downstream_signature)
        return status

    def _decode_traffic_selector(self, flow):
        """
        Extract EVC related traffic selection settings
        """
        self.in_port = fd.get_in_port(flow)

        if self.in_port > OFPP_MAX:
            log.warn('logical-input-ports-not-supported', in_port=self.in_port)
            return False

        for field in fd.get_ofb_fields(flow):
            if field.type == IN_PORT:
                if self._handler.is_nni_port(self.in_port) or self._handler.is_uni_port(self.in_port):
                    self._logical_port = self.in_port

            elif field.type == VLAN_VID:
                if field.vlan_vid >= OFPVID_PRESENT + 4095:
                    self.vlan_id = None             # pre-ONOS v1.13.5 or old EAPOL Rule
                else:
                    self.vlan_id = field.vlan_vid & 0xfff

                log.debug('*** field.type == VLAN_VID', value=field.vlan_vid, vlan_id=self.vlan_id)

            elif field.type == VLAN_PCP:
                log.debug('*** field.type == VLAN_PCP', value=field.vlan_pcp)
                self.pcp = field.vlan_pcp

            elif field.type == ETH_TYPE:
                log.debug('*** field.type == ETH_TYPE', value=field.eth_type)
                self.eth_type = field.eth_type

            elif field.type == IP_PROTO:
                log.debug('*** field.type == IP_PROTO', value=field.ip_proto)
                self.ip_protocol = field.ip_proto

                if self.ip_protocol not in _supported_ip_protocols:
                    log.error('Unsupported IP Protocol', protocol=self.ip_protocol)
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
                if self._handler.is_nni_port(self.in_port):
                    # Downstream flow
                    log.debug('*** field.type == METADATA', value=field.table_metadata)

                    if field.table_metadata > 4095:
                        # ONOS v1.13.5 or later. c-vid in upper 32-bits
                        vid = field.table_metadata & 0x0FFF
                        if vid > 0:
                            self.inner_vid = vid        # CTag is never '0'
                
                    elif field.table_metadata > 0:
                        # Pre-ONOS v1.13.5 (vid without the 4096 offset)
                        self.inner_vid = field.table_metadata
                
                else:
                    # Upstream flow
                    pass   # Not used upstream at this time

                log.debug('*** field.type == METADATA', value=field.table_metadata,
                          inner_vid=self.inner_vid)
            else:
                log.warn('unsupported-selection-field', type=field.type)
                self._status_message = 'Unsupported field.type={}'.format(field.type)
                return False

        return True

    def _decode_traffic_treatment(self, flow):
        # Loop through traffic treatment
        for act in fd.get_actions(flow):
            if act.type == fd.OUTPUT:
                self.output = act.output.port

            elif act.type == POP_VLAN:
                log.debug('*** action.type == POP_VLAN')
                self.pop_vlan = True

            elif act.type == PUSH_VLAN:
                log.debug('*** action.type == PUSH_VLAN', value=act.push)
                tpid = act.push.ethertype
                self.push_vlan_tpid = tpid

            elif act.type == SET_FIELD:
                log.debug('*** action.type == SET_FIELD', value=act.set_field.field)
                assert (act.set_field.field.oxm_class == OFPXMC_OPENFLOW_BASIC)
                field = act.set_field.field.ofb_field

                if field.type == VLAN_VID:
                    self.push_vlan_id = field.vlan_vid & 0xfff
                else:
                    log.debug('unsupported-set-field')
            else:
                log.warn('unsupported-action', action=act)
                self._status_message = 'Unsupported action.type={}'.format(act.type)
                return False

        return True

    def _decode_flow_direction(self):
        # Determine direction of the flow
        def port_type(port_number):
            if port_number in self.handler.northbound_ports:
                return FlowEntry.PortType.NNI

            elif port_number in self.handler.southbound_ports:
                return FlowEntry.PortType.PON

            elif port_number <= OFPP_MAX:
                return FlowEntry.PortType.UNI

            elif port_number in {OFPP_CONTROLLER, 0xFFFFFFFD}:      # OFPP_CONTROLLER is wrong in proto-file
                return FlowEntry.PortType.CONTROLLER

            return FlowEntry.PortType.OTHER

        flow_dir_map = {
            (FlowEntry.PortType.UNI, FlowEntry.PortType.NNI):        FlowEntry.FlowDirection.UPSTREAM,
            (FlowEntry.PortType.NNI, FlowEntry.PortType.UNI):        FlowEntry.FlowDirection.DOWNSTREAM,
            (FlowEntry.PortType.UNI, FlowEntry.PortType.CONTROLLER): FlowEntry.FlowDirection.CONTROLLER_UNI,
            (FlowEntry.PortType.NNI, FlowEntry.PortType.PON):        FlowEntry.FlowDirection.NNI_PON,
            # The following are not yet supported
            # (FlowEntry.PortType.NNI, FlowEntry.PortType.CONTROLLER): FlowEntry.FlowDirection.CONTROLLER_NNI,
            # (FlowEntry.PortType.PON, FlowEntry.PortType.CONTROLLER): FlowEntry.FlowDirection.CONTROLLER_PON,
            # (FlowEntry.PortType.NNI, FlowEntry.PortType.NNI):        FlowEntry.FlowDirection.NNI_NNI,
            # (FlowEntry.PortType.UNI, FlowEntry.PortType.UNI):        FlowEntry.FlowDirection.UNI_UNI,
        }
        self._flow_direction = flow_dir_map.get((port_type(self.in_port), port_type(self.output)),
                                                FlowEntry.FlowDirection.OTHER)
        return self._flow_direction != FlowEntry.FlowDirection.OTHER

    def _apply_downstream_mods(self):
        # This is a downstream flow.  It could be any one of the following:
        #
        #   Legacy control VLAN:
        #       This is the old VLAN 4000 that was used to attach EAPOL and other
        #       controller flows to. Eventually these will change to CONTROLLER_UNI
        #       flows.  For these, use the 'utility' VLAN instead so 4000 if available
        #       for other uses (AT&T uses it for downstream multicast video).
        #
        #   Multicast VLAN:
        #       This is downstream multicast data.
        #       TODO: Test this to see if this needs to be in a separate NNI_PON mod-method
        #
        #   User Data flow:
        #       This is for user data.  Eventually we may need to support ACLs?
        #
        # May be for to controller flow downstream (no ethType)
        if self.vlan_id == FlowEntry.LEGACY_CONTROL_VLAN and self.eth_type is None and self.pcp == 0:
            return False    # Do not install this flow.  Utility VLAN is in charge

        elif self.flow_direction == FlowEntry.FlowDirection.NNI_PON and \
                self.vlan_id == self.handler.utility_vlan:
            # Utility VLAN downstream flow/EVC
            self._is_acl_flow = True

        elif self.vlan_id in self.handler.multicast_vlans:
            #  multicast (ethType = IP)                         # TODO: May need to be an NNI_PON flow
            self._is_multicast = True
            self._is_acl_flow = True

        else:
            # Currently do not support ACLs on user data flows downstream
            assert not self._needs_acl_support    # User data, no special modifications needed at this time

        return True

    def _apply_upstream_mods(self):
        #
        # This is an upstream flow.  It could be any of the following
        #
        #   ACL/Packet capture:
        #       This is either a legacy (FlowDirection.UPSTREAM) or a new one
        #       that specifies an output port of controller (FlowDirection.CONTROLLER_UNI).
        #       Either way, these need to be placed on the Utility VLAN if the ONU attached
        #       does not have a user-data flow (C-Tag).  If there is a C-Tag available,
        #       then place it on that VLAN.
        #
        #       Once a user-data flow is established, move any of the ONUs ACL flows
        #       over to that VLAN (this is handled elsewhere).
        #
        #   User Data flows:
        #       No special modifications are needed
        #
        try:
            # Do not handle PON level ACLs in this method
            assert(self._flow_direction != FlowEntry.FlowDirection.CONTROLLER_PON)

            # Is this a legacy (VLAN 4000) upstream to-controller flow
            if self._needs_acl_support and FlowEntry.LEGACY_CONTROL_VLAN == self.push_vlan_id:
                self._flow_direction = FlowEntry.FlowDirection.CONTROLLER_UNI
                self._is_acl_flow = True
                self.push_vlan_id = self.handler.utility_vlan

            return True

        except Exception as e:
            # TODO: Need to support flow retry if the ONU is not yet activated   !!!!
            log.exception('tag-fixup', e=e)
            return False

    @staticmethod
    def drop_missing_flows(handler, valid_flow_ids):
        dl = []
        try:
            flow_table = handler.upstream_flows
            flows_to_drop = [flow for flow_id, flow in flow_table.items()
                             if flow_id not in valid_flow_ids]
            dl.extend([flow.remove() for flow in flows_to_drop])

            for sig_table in handler.downstream_flows.itervalues():
                flows_to_drop = [flow for flow_id, flow in sig_table.flows.items()
                                 if isinstance(flow, FlowEntry) and flow_id not in valid_flow_ids]
                dl.extend([flow.remove() for flow in flows_to_drop])

        except Exception as _e:
            pass

        return gatherResults(dl, consumeErrors=True) if len(dl) > 0 else returnValue('no-flows-to-drop')

    @inlineCallbacks
    def remove(self):
        """
        Remove this flow entry from the list of existing entries and drop EVC
        if needed
        """
        # Remove from exiting table list
        flow_id = self.flow_id
        flow_table = None

        if self.flow_direction in FlowEntry.upstream_flow_types:
            flow_table = self._handler.upstream_flows

        elif self.flow_direction in FlowEntry.downstream_flow_types:
            sig_table = self._handler.downstream_flows.get(self.signature)
            flow_table = sig_table.flows if sig_table is not None else None

        if flow_table is None or flow_id not in flow_table.keys():
            returnValue('NOP')

        # Remove from flow table and clean up flow table if empty
        flow_table.remove(flow_id)
        evc_map, self.evc_map = self.evc_map, None
        evc = None

        if self.flow_direction in FlowEntry.downstream_flow_types:
            sig_table = self._handler.downstream_flows.get(self.signature)
            if len(flow_table) == 0:   # Only 'evc' entry present
                evc = sig_table.evc
            else:
                assert sig_table.evc is not None, 'EVC flow re-assignment error'

        # Remove flow from the hardware
        try:
            dl = []
            if evc_map is not None:
                dl.append(evc_map.delete(self))

            if evc is not None:
                dl.append(evc.delete())

            yield gatherResults(dl, consumeErrors=True)

        except Exception as e:
            log.exception('removal', e=e)

        if self.flow_direction in FlowEntry.downstream_flow_types:
            # If this flow owns the EVC, assign it to a remaining flow
            sig_table = self._handler.downstream_flows.get(self.signature)
            flow_evc = sig_table.evc

            if flow_evc is not None and flow_evc.flow_entry is not None and flow_id == flow_evc.flow_entry.flow_id:
                flow_evc.flow_entry = next((_flow for _flow in flow_table.itervalues()
                                           if isinstance(_flow, FlowEntry)
                                           and _flow.flow_id != flow_id), None)

        # If evc was deleted, remove the signature table since now flows exist with
        # that signature
        if evc is not None:
            self._handler.downstream_flows.remove(self.signature)

        self.evc = None
        returnValue('Done')

    @staticmethod
    def find_evc_map_flows(onu):
        """
        For a given OLT, find all the EVC Maps for a specific ONU
        :param onu: (Onu) onu
        :return: (list) of matching flows
        """
        # EVCs are only in the downstream table, EVC Maps are in upstream
        onu_ports = onu.uni_ports

        all_flow_entries = onu.olt.upstream_flows
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
                evc_map.needs_update = False

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
    def clear_all(handler):
        """
        Remove all flows for the device.

        :param handler: voltha adapter device handler
        """
        handler.downstream_flows.clear()
        handler.upstream_flows.clear()

    @staticmethod
    def get_packetout_info(handler, logical_port):
        """
        Find parameters needed to send packet out successfully to the OLT.

        :param handler: voltha adapter device handler
        :param logical_port: (int) logical port number for packet to go out.

        :return: physical port number, ctag, stag, evcmap name
        """
        from ..onu import Onu

        for flow_entry in handler.upstream_flows.itervalues():
            log.debug('get-packetout-info', flow_entry=flow_entry)

            # match logical port
            if flow_entry.evc_map is not None and flow_entry.evc_map.valid and \
               flow_entry.logical_port == logical_port:
                evc_map = flow_entry.evc_map
                gem_ids_and_vid = evc_map.gem_ids_and_vid

                # must have valid gem id
                if len(gem_ids_and_vid) > 0:
                    for onu_id, gem_ids_with_vid in gem_ids_and_vid.iteritems():
                        log.debug('get-packetout-info', onu_id=onu_id, 
                                  gem_ids_with_vid=gem_ids_with_vid)
                        if len(gem_ids_with_vid) > 0:
                            gem_ids = gem_ids_with_vid[0]
                            ctag = gem_ids_with_vid[1]
                            gem_id = gem_ids[0]     # TODO: always grab first in list
                            return flow_entry.in_port, ctag, Onu.gem_id_to_gvid(gem_id), \
                                evc_map.get_evcmap_name(onu_id, gem_id)
        return None, None, None, None
