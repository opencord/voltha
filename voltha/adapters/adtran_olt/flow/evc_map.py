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

import xmltodict
import re
import structlog
from enum import Enum
from acl import ACL
from twisted.internet import defer, reactor
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
from ncclient.operations.rpc import RPCError
from voltha.adapters.openolt.protos import openolt_pb2


log = structlog.get_logger()

# NOTE: For the EVC Map name, the ingress-port number is the VOLTHA port number (not pon-id since
#       it covers NNI ports as well in order to handle the NNI-NNI case.  For flows that
#       cover an entire pon, the name will have the ONU ID and GEM ID appended to it upon
#       installation with a period as a separator.

EVC_MAP_NAME_FORMAT = 'VOLTHA-{}-{}'   # format(logical-ingress-port-number, flow-id)
EVC_MAP_NAME_REGEX_ALL = 'VOLTHA-*'


class EVCMap(object):
    """
    Class to wrap EVC functionality
    """
    class EvcConnection(Enum):
        NO_EVC_CONNECTION = 0
        EVC = 1
        DISCARD = 2
        DEFAULT = NO_EVC_CONNECTION

        @staticmethod
        def xml(value):
            # Note we do not have XML for 'EVC' enumeration.
            if value is None:
                value = EVCMap.EvcConnection.DEFAULT
            if value == EVCMap.EvcConnection.DISCARD:
                return '<no-evc-connection/>'
            elif value == EVCMap.EvcConnection.DISCARD:
                return 'discard/'
            raise ValueError('Invalid EvcConnection enumeration')

    class PriorityOption(Enum):
        INHERIT_PRIORITY = 0
        EXPLICIT_PRIORITY = 1
        DEFAULT = INHERIT_PRIORITY

        @staticmethod
        def xml(value):
            if value is None:
                value = EVCMap.PriorityOption.DEFAULT
            if value == EVCMap.PriorityOption.INHERIT_PRIORITY:
                return '<inherit-pri/>'
            elif value == EVCMap.PriorityOption.EXPLICIT_PRIORITY:
                return '<explicit-pri/>'
            raise ValueError('Invalid PriorityOption enumeration')

    def __init__(self, flow, evc, is_ingress_map):
        self._handler = flow.handler      # Same for all Flows attached to this EVC MAP
        self._flows = {flow.flow_id: flow}
        self._evc = None
        self._new_acls = dict()           # ACL Name -> ACL Object (To be installed into h/w)
        self._existing_acls = dict()      # ACL Name -> ACL Object (Already in H/w)
        self._is_ingress_map = is_ingress_map
        self._pon_id = None
        self._onu_id = None               # Remains None if associated with a multicast flow
        self._installed = False
        self._needs_update = False
        self.status = None
        self._deferred = None
        self._name = None
        self._enabled = True
        self._uni_port = None
        self._evc_connection = EVCMap.EvcConnection.DEFAULT
        self._men_priority = EVCMap.PriorityOption.DEFAULT
        self._men_pri = 0  # If Explicit Priority

        self._c_tag = None
        self._men_ctag_priority = EVCMap.PriorityOption.DEFAULT
        self._men_ctag_pri = 0  # If Explicit Priority
        self._match_ce_vlan_id = None
        self._match_untagged = False
        self._match_destination_mac_address = None
        self._match_l2cp = False
        self._match_broadcast = False
        self._match_multicast = False
        self._match_unicast = False
        self._match_igmp = False

        from common.tech_profile.tech_profile import DEFAULT_TECH_PROFILE_TABLE_ID
        self._tech_profile_id = DEFAULT_TECH_PROFILE_TABLE_ID
        self._gem_ids_and_vid = {}      # { key -> onu-id, value -> tuple(sorted GEM Port IDs, onu_vid) }
        self._upstream_bandwidth = None
        self._shaper_name = None

        # ACL logic
        self._eth_type = None
        self._ip_protocol = None
        self._ipv4_dst = None
        self._udp_dst = None
        self._udp_src = None

        try:
            self._valid = self._decode(evc)

        except Exception as e:
            log.exception('decode', e=e)
            self._valid = False

    def __str__(self):
        return "EVCMap-{}: UNI: {}, hasACL: {}".format(self._name, self._uni_port,
                                                       self._needs_acl_support)

    @staticmethod
    def create_ingress_map(flow, evc, dry_run=False):
        evc_map = EVCMap(flow, evc, True)

        if evc_map._valid and not dry_run:
            evc.add_evc_map(evc_map)
            evc_map._evc = evc

        return evc_map

    @staticmethod
    def create_egress_map(flow, evc, dry_run=False):
        evc_map = EVCMap(flow, evc, False)

        if evc_map._valid and not dry_run:
            evc.add_evc_map(evc_map)
            evc_map._evc = evc

        return evc_map

    @property
    def valid(self):
        return self._valid

    @property
    def installed(self):
        return self._installed

    @property
    def needs_update(self):
        """ True if an parameter/ACL/... needs update or map needs to be reflowed after a failure"""
        return self._needs_update

    @needs_update.setter
    def needs_update(self, value):
        assert not value, 'needs update can only be reset'                # Can only reset
        self._needs_update = False

    @property
    def name(self):
        return self._name

    @property
    def evc(self):
        return self._evc

    @property
    def _needs_acl_support(self):
        if self._ipv4_dst is not None:  # In case MCAST downstream has ACL on it
            return False

        return self._eth_type is not None or self._ip_protocol is not None or\
            self._udp_dst is not None or self._udp_src is not None

    @property
    def pon_id(self):
        return self._pon_id     # May be None

    @property
    def onu_id(self):
        return self._onu_id     # May be None if associated with a multicast flow

    # @property
    # def onu_ids(self):
    #     return self._gem_ids_and_vid.keys()

    @property
    def gem_ids_and_vid(self):
        return self._gem_ids_and_vid.copy()

    @staticmethod
    def _xml_header(operation=None):
        return '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps"{}><evc-map>'.\
            format('' if operation is None else ' xc:operation="{}"'.format(operation))

    @staticmethod
    def _xml_trailer():
        return '</evc-map></evc-maps>'

    def get_evcmap_name(self, onu_id, gem_id):
        return'{}.{}.{}.{}'.format(self.name, self.pon_id, onu_id, gem_id)

    def _common_install_xml(self):
        xml = '<enabled>{}</enabled>'.format('true' if self._enabled else 'false')
        xml += '<uni>{}</uni>'.format(self._uni_port)

        evc_name = self._evc.name if self._evc is not None else None
        if evc_name is not None:
            xml += '<evc>{}</evc>'.format(evc_name)
        else:
            xml += EVCMap.EvcConnection.xml(self._evc_connection)

        xml += '<match-untagged>{}</match-untagged>'.format('true'
                                                            if self._match_untagged
                                                            else 'false')

        # TODO: The following is not yet supported (and in some cases, not decoded)
        # self._men_priority = EVCMap.PriorityOption.INHERIT_PRIORITY
        # self._men_pri = 0  # If Explicit Priority
        #
        # self._men_ctag_priority = EVCMap.PriorityOption.INHERIT_PRIORITY
        # self._men_ctag_pri = 0  # If Explicit Priority
        #
        # self._match_ce_vlan_id = None
        # self._match_untagged = True
        # self._match_destination_mac_address = None
        return xml

    def _ingress_install_xml(self, onu_s_gem_ids_and_vid, acl_list, create):
        from ..onu import Onu

        if len(acl_list):
            xml = '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps"' +\
                   '         xmlns:adtn-evc-map-acl="http://www.adtran.com/ns/yang/adtran-evc-map-access-control-list">'
        else:
            xml = '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps">'

        for onu_or_vlan_id, gem_ids_and_vid in onu_s_gem_ids_and_vid.iteritems():
            first_gem_id = True
            gem_ids = gem_ids_and_vid[0]
            vid = gem_ids_and_vid[1]
            ident = '{}.{}'.format(self._pon_id, onu_or_vlan_id)

            for gem_id in gem_ids:
                xml += '<evc-map{}>'.format('' if not create else ' xc:operation="create"')
                xml += '<name>{}.{}.{}</name>'.format(self.name, ident, gem_id)
                xml += '<ce-vlan-id>{}</ce-vlan-id>'.format(Onu.gem_id_to_gvid(gem_id))

                # GEM-IDs are a sorted list (ascending). First gemport handles downstream traffic
                if first_gem_id and (self._c_tag is not None or vid is not None):
                    first_gem_id = False
                    vlan = vid or self._c_tag
                    xml += '<network-ingress-filter>'
                    xml += '<men-ctag>{}</men-ctag>'.format(vlan)  # Added in August 2017 model
                    xml += '</network-ingress-filter>'

                if len(acl_list):
                    xml += '<adtn-evc-map-acl:access-lists>'
                    for acl in acl_list:
                        xml += ' <adtn-evc-map-acl:ingress-acl>'
                        xml += acl.evc_map_ingress_xml()
                        xml += ' </adtn-evc-map-acl:ingress-acl>'
                    xml += '</adtn-evc-map-acl:access-lists>'
                xml += self._common_install_xml()
                xml += '</evc-map>'
        xml += '</evc-maps>'
        return xml

    def _egress_install_xml(self):
        xml = EVCMap._xml_header()
        xml += '<name>{}</name>'.format(self.name)
        xml += self._common_install_xml()
        xml += EVCMap._xml_trailer()
        return xml

    def _ingress_remove_acl_xml(self, onu_s_gem_ids_and_vid, acl):
        xml = '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps"' +\
               ' xmlns:adtn-evc-map-acl="http://www.adtran.com/ns/yang/adtran-evc-map-access-control-list">'
        for onu_or_vlan_id, gem_ids_and_vid in onu_s_gem_ids_and_vid.iteritems():
            first_gem_id = True
            vid = gem_ids_and_vid[1]
            ident = '{}.{}'.format(self._pon_id, onu_or_vlan_id) if vid is None \
                else onu_or_vlan_id

            for gem_id in gem_ids_and_vid[0]:
                xml += '<evc-map>'
                xml += '<name>{}.{}.{}</name>'.format(self.name, ident, gem_id)
                xml += '<adtn-evc-map-acl:access-lists>'
                xml += ' <adtn-evc-map-acl:ingress-acl xc:operation="delete">'
                xml += acl.evc_map_ingress_xml()
                xml += ' </adtn-evc-map-acl:ingress-acl>'
                xml += '</adtn-evc-map-acl:access-lists>'
                xml += '</evc-map>'
        xml += '</evc-maps>'
        return xml

    @inlineCallbacks
    def install(self):
        def gem_ports():
            ports = []
            for gems_and_vids in self._gem_ids_and_vid.itervalues():
                ports.extend(gems_and_vids[0])
            return ports

        log.debug('install-evc-map', valid=self._valid, gem_ports=gem_ports())

        if self._valid and len(gem_ports()) > 0:
            # Install ACLs first (if not yet installed)
            work_acls = self._new_acls.copy()
            self._new_acls = dict()

            log.debug('install-evc-map-acls', install_acls=len(work_acls))
            for acl in work_acls.itervalues():
                try:
                    yield acl.install()

                except Exception as e:
                    log.exception('acl-install-failed', name=self.name, e=e)
                    self._new_acls.update(work_acls)
                    raise

            # Any user-data flows attached to this map ?
            c_tag = None
            for flow_id, flow in self._flows.items():
                c_tag = flow.inner_vid or flow.vlan_id or c_tag

            self._c_tag = c_tag

            # Now EVC-MAP
            if not self._installed or self._needs_update:
                log.debug('needs-install-or-update', installed=self._installed, update=self._needs_update)
                is_installed = self._installed
                self._installed = True
                try:
                    self._cancel_deferred()

                    log.info('upstream-bandwidth')
                    try:
                        yield self.update_upstream_flow_bandwidth()

                    except Exception as e:
                        log.exception('upstream-bandwidth-failed', name=self.name, e=e)
                        raise

                    map_xml = self._ingress_install_xml(self._gem_ids_and_vid, work_acls.values(),
                                                        not is_installed) \
                        if self._is_ingress_map else self._egress_install_xml()

                    log.debug('install', xml=map_xml, name=self.name)
                    results = yield self._handler.netconf_client.edit_config(map_xml)
                    self._installed = results.ok
                    self._needs_update = results.ok
                    self.status = '' if results.ok else results.error

                    if results.ok:
                        self._existing_acls.update(work_acls)
                    else:
                        self._new_acls.update(work_acls)

                except RPCError as rpc_err:
                    if rpc_err.tag == 'data-exists':    # Known race due to bulk-flow operation
                        pass

                except Exception as e:
                    log.exception('evc-map-install-failed', name=self.name, e=e)
                    self._installed = is_installed
                    self._new_acls.update(work_acls)
                    raise

                # Install any needed shapers
                if self._installed:
                    try:
                        yield self.update_downstream_flow_bandwidth()

                    except Exception as e:
                        log.exception('shaper-install-failed', name=self.name, e=e)
                        raise

        returnValue(self._installed and self._valid)

    def _ingress_remove_xml(self, onus_gem_ids_and_vid):
        xml = '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps"' + \
              ' xc:operation="delete">'

        for onu_id, gem_ids_and_vid in onus_gem_ids_and_vid.iteritems():
            for gem_id in gem_ids_and_vid[0]:
                xml += '<evc-map>'
                xml += '<name>{}.{}.{}</name>'.format(self.name, onu_id, gem_id)
                xml += '</evc-map>'
        xml += '</evc-maps>'
        return xml

    def _egress_remove_xml(self):
        return EVCMap._xml_header('delete') + \
               '<name>{}</name>'.format(self.name) + EVCMap._xml_trailer()

    def _remove(self):
        if not self.installed:
            returnValue('Not installed')

        log.info('removing', evc_map=self)

        def _success(rpc_reply):
            log.debug('remove-success', rpc_reply=rpc_reply)
            self._installed = False

        def _failure(failure):
            log.error('remove-failed', failure=failure)
            self._installed = False

        def _remove_acls(_):
            acls, self._new_acls = self._new_acls, dict()
            existing, self._existing_acls = self._existing_acls, dict()
            acls.update(existing)

            dl = []
            for acl in acls.itervalues():
                dl.append(acl.remove())

            if len(dl) > 0:
                defer.gatherResults(dl, consumeErrors=True)

        def _remove_shaper(_):
            if self._shaper_name is not None:
                self.update_downstream_flow_bandwidth(remove=True)

        map_xml = self._ingress_remove_xml(self._gem_ids_and_vid) if self._is_ingress_map \
            else self._egress_remove_xml()

        d = self._handler.netconf_client.edit_config(map_xml)
        d.addCallbacks(_success, _failure)
        d.addBoth(_remove_acls)
        d.addBoth(_remove_shaper)
        return d

    @inlineCallbacks
    def delete(self, flow):
        """
        Remove from hardware and delete/clean-up EVC-MAP Object

        :param flow: (FlowEntry) Specific flow to remove from the MAP or None if all
                                 flows should be removed
        :return:
        """
        flows = [flow] if flow is not None else list(self._flows.values())
        removing_all = len(flows) == len(self._flows)

        log.debug('delete', removing_all=removing_all)
        if not removing_all:
            for f in flows:
                self._remove_flow(f)

        else:
            if self._evc is not None:
                self._evc.remove_evc_map(self)
                self._evc = None

            self._valid = False
            self._cancel_deferred()
            try:
                yield self._remove()

            except Exception as e:
                log.exception('removal', e=e)

        returnValue('Done')

    def reflow_needed(self):
        log.debug('reflow-needed', installed=self.installed, needs_update=self.needs_update)
        reflow = not self.installed or self.needs_update

        if not reflow:
            pass  # TODO: implement retrieve & compare of EVC Map parameters

        return reflow

    @staticmethod
    def find_matching_ingress_flow(flow, upstream_flow_table):
        """
        Look for an existing EVC-MAP that may match this flow.  Called when upstream signature
        for a flow does not make match. This can happen if an ACL flow is added and only an User
        Data flow exists, or if only an ACL flow exists.

        :param flow: (FlowEntry) flow to add
        :param upstream_flow_table: (dict of FlowEntry) Existing upstream flows for this device,
                                     including the flow we are looking to add
        :return: (EVCMap) if appropriate one is found, else None
        """
        # A User Data flow will have:
        #      signature: <dev>.1.5.2.242
        #       down-sig: <dev>.1.*.2.*
        #   logical-port: 66
        #    is-acl-flow: False
        #
        # An ACL flow will have:
        #      signature: <dev>.1.5.[4092 or 4094].None    (untagged VLAN == utility VLAN case)
        #       down-sig: <dev>.1.*.[4092 or 4094].*
        #   logical-port: 66
        #    is-acl-flow: True
        #
        # Reduce the upstream flow table to only those that match the ingress,
        # and logical-ports match (and is not this flow) and have a map

        log.debug('find-matching-ingress-flow', logical_port=flow.logical_port, flow=flow.output)
        candidate_flows = [f for f in upstream_flow_table.itervalues() if
                           f.in_port == flow.in_port and
                           f.logical_port == flow.logical_port and
                           f.output == flow.output and
                           f.evc_map is not None]        # This weeds out this flow

        log.debug('find-matching-ingress-flow', candidate_flows=candidate_flows)
        return candidate_flows[0].evc_map if len(candidate_flows) > 0 else None

    def add_flow(self, flow, evc):
        """
        Add a new flow to an existing EVC-MAP. This can be called to add:
          o an ACL flow to an existing utility EVC, or
          o an ACL flow to an existing User Data Flow, or
          o a User Data Flow to an existing ACL flow (and this needs the EVC updated
            as well.

        Note that the Downstream EVC provided is the one that matches this flow. If
        this is adding an ACL to and existing User data flow, we DO NOT want to
        change the EVC Map's EVC

        :param flow: (FlowEntry) New flow
        :param evc: (EVC) Matching EVC for downstream flow
        """
        from flow_entry import FlowEntry
        # Create temporary EVC-MAP
        assert flow.flow_direction in FlowEntry.upstream_flow_types, \
            'Only Upstream flows additions are supported at this time'

        log.debug('add-flow-to-evc', flow=flow, evc=evc)

        tmp_map = EVCMap.create_ingress_map(flow, evc, dry_run=True) \
            if flow.flow_direction in FlowEntry.upstream_flow_types \
            else EVCMap.create_egress_map(flow, evc, dry_run=True)

        if tmp_map is None or not tmp_map.valid:
            return None

        self._flows[flow.flow_id] = flow
        self._needs_update = True

        # Are there ACLs to add to any existing (or empty) ACLs
        if len(tmp_map._new_acls) > 0:
            self._new_acls.update(tmp_map._new_acls)        # New ACL flow
            log.debug('add-acl-flows', map=str(self), new=tmp_map._new_acls)

        # Look up existing EVC for this flow. If it is a service EVC for
        # Packet In/Out, and this is a regular flow, migrate to the newer EVC
        if self._evc.service_evc and not evc.service_evc:
            log.info('new-evc-for-map', old=self._evc.name, new=evc.name)
            self._evc.remove_evc_map(self)
            evc.add_evc_map(self)
            self._evc = evc

        return self

    @inlineCallbacks
    def _remove_flow(self, flow):
        """
        Remove a specific flow from an EVC_MAP. This includes removing any
        ACL entries associated with the flow and could result in moving the
        EVC-MAP over to another EVC.

        :param flow: (FlowEntry) Flow to remove
        """
        try:
            del self._flows[flow.flow_id]

            log('remove-flow-to-evc', flow=flow)
            # Remove any ACLs
            acl_name = ACL.flow_to_name(flow)
            acl = None

            # if not yet installed just remove it from list
            if acl_name in self._new_acls:
                del self._new_acls[acl_name]
            else:
                acl = self._existing_acls[acl_name]
            if acl is not None:
                # Remove ACL from EVC-MAP entry

                try:
                    map_xml = self._ingress_remove_acl_xml(self._gem_ids_and_vid, acl)
                    log.debug('remove', xml=map_xml, name=acl.name)
                    results = yield self._handler.netconf_client.edit_config(map_xml)
                    if results.ok:
                        del self._existing_acls[acl.name]

                    # Scan EVC to see if it needs to move back to the Utility
                    # or Untagged EVC from a user data EVC
                    if self._evc and not self._evc.service_evc and\
                        len(self._flows) > 0 and\
                            all(f.is_acl_flow for f in self._flows.itervalues()):

                        self._evc.remove_evc_map(self)
                        first_flow = self._flows.itervalues().next()
                        self._evc = first_flow.get_utility_evc(True)
                        self._evc.add_evc_map(self)
                        log.debug('moved-acl-flows-to-utility-evc', newevcname=self._evc.name)

                        self._needs_update = True
                        self._evc.schedule_install()

                except Exception as e:
                    log.exception('acl-remove-from-evc', e=e)

                # Remove ACL itself
                try:
                    yield acl.remove()

                except Exception as e:
                    log.exception('acl-remove', e=e)

        except Exception as e:
            log.exception('remove-failed', e=e)

    @staticmethod
    def create_evc_map_name(flow):
        # Note: When actually installed into the OLT, the .onu_id.gem_port is
        #       appended to the name
        return EVC_MAP_NAME_FORMAT.format(flow.logical_port, flow.flow_id)

    @staticmethod
    def decode_evc_map_name(name):
        """
        Reverse engineer EVC-MAP name parameters. Helpful in quick packet-in
        processing

        :param name: (str) EVC Map Name
        :return: (dict) Logical Ingress Port, OpenFlow Flow-ID
        """
        items = name.split('-') if name is not None else dict()

        # Note: When actually installed into the OLT, the .onu_id.gem_port is
        #       appended to the name
        return {'ingress-port': items[1],
                'flow-id': items[2].split('.')[0]} if len(items) > 2 else dict()

    @inlineCallbacks
    def update_upstream_flow_bandwidth(self):
        """
        Upstream flow bandwidth comes from the flow_entry related to this EVC-MAP
        and if no bandwidth property is found, allow full bandwidth
        """
        # all flows should should be on the same PON
        flow = self._flows.itervalues().next()
        is_pon = flow.handler.is_pon_port(flow.in_port)

        if self._is_ingress_map and is_pon:
            pon_port = flow.handler.get_southbound_port(flow.in_port)
            if pon_port is None:
                returnValue('no PON')

            session = self._handler.rest_client
            # TODO: Refactor with tech profiles
            tconts = None               # pon_port.tconts
            traffic_descriptors = None  # pon_port.traffic_descriptors

            if traffic_descriptors is None or tconts is None:
                returnValue('no TDs on PON')

            bandwidth = self._upstream_bandwidth or 10000000000

            if self.pon_id is not None and self.onu_id is not None:
                name = 'tcont-{}-{}-data'.format(self.pon_id, self.onu_id)
                td = traffic_descriptors.get(name)
                tcont = tconts.get(name)

                if td is not None and tcont is not None:
                    alloc_id = tcont.alloc_id
                    td.maximum_bandwidth = bandwidth
                    try:
                        results = yield td.add_to_hardware(session)
                        log.debug('td-modify-results', results=results)

                    except Exception as _e:
                        pass

    @inlineCallbacks
    def update_downstream_flow_bandwidth(self, remove=False):
        """
        Downstream flow bandwidth is extracted from the related EVC flow_entry
        bandwidth property. It is written to this EVC-MAP only if it is found
        """
        xml = None
        results = None

        if remove:
            name, self._shaper_name = self._shaper_name, None
            if name is not None:
                xml = self._shaper_remove_xml(name)
        else:
            if self._evc is not None and self._evc.flow_entry is not None \
                    and self._evc.flow_entry.bandwidth is not None:
                self._shaper_name = self._name
                xml = self._shaper_install_xml(self._shaper_name,
                                               self._evc.flow_entry.bandwidth * 1000)  # kbps
        if xml is not None:
            try:
                log.info('downstream-bandwidth', xml=xml, name=self.name, remove=remove)
                results = yield self._handler.netconf_client.edit_config(xml)

            except RPCError as rpc_err:
                if rpc_err.tag == 'data-exists':
                    pass

            except Exception as e:
                log.exception('downstream-bandwidth', name=self.name, remove=remove, e=e)
                raise

        returnValue(results)

    def _shaper_install_xml(self, name, bandwidth):
        xml = '<adtn-shaper:shapers xmlns:adtn-shaper="http://www.adtran.com/ns/yang/adtran-traffic-shapers" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="merge">'
        for onu_id, gem_ids_and_vid in self._gem_ids_and_vid.iteritems():
            for gem_id in gem_ids_and_vid[0]:
                xml += ' <adtn-shaper:shaper>'
                xml += '  <adtn-shaper:name>{}.{}.{}</adtn-shaper:name>'.format(name, onu_id, gem_id)
                xml += '  <adtn-shaper:enabled>true</adtn-shaper:enabled>'
                xml += '  <adtn-shaper:rate>{}</adtn-shaper:rate>'.format(bandwidth)
                xml += '  <adtn-shaper-evc-map:evc-map xmlns:adtn-shaper-evc-map="http://www.adtran.com/ns/yang/adtran-traffic-shaper-evc-maps">{}.{}.{}</adtn-shaper-evc-map:evc-map>'.format(self.name, onu_id, gem_id)
                xml += ' </adtn-shaper:shaper>'
        xml += '</adtn-shaper:shapers>'
        return xml

    def _shaper_remove_xml(self, name):
        xml = '<adtn-shaper:shapers xmlns:adtn-shaper="http://www.adtran.com/ns/yang/adtran-traffic-shapers" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="delete">'
        for onu_id, gem_ids_and_vid in self._gem_ids_and_vid.iteritems():
            for gem_id in gem_ids_and_vid[0]:
                xml += ' <adtn-shaper:shaper >'
                xml += '  <adtn-shaper:name>{}.{}.{}</adtn-shaper:name>'.format(name, onu_id, gem_id)
                xml += ' </adtn-shaper:shaper>'
        xml += '</adtn-shaper:shapers>'
        return xml

    def _setup_tech_profiles(self):
        # Set up the TCONT / GEM Ports for this connection (Downstream only of course)
        # all flows should have same GEM port setup
        flow = self._flows.itervalues().next()
        is_pon = flow.handler.is_pon_port(flow.in_port)

        if self._is_ingress_map and is_pon:
            pon_port = flow.handler.get_southbound_port(flow.in_port)

            if pon_port is None:
                return

            onu = next((onu for onu in pon_port.onus if onu.logical_port == flow.logical_port), None)

            if onu is None:       # TODO: Add multicast support later (self.onu_id == None)
                return

            self._pon_id = pon_port.pon_id
            self._onu_id = onu.onu_id

            # Identify or allocate TCONT and GEM Ports.  If the ONU has been informed of the
            # GEM PORTs that belong to it, the tech profiles were already set up by a previous
            # flows
            onu_gems = onu.gem_ids(self._tech_profile_id)

            if len(onu_gems) > 0:
                self._gem_ids_and_vid[onu.onu_id] = (onu_gems, flow.vlan_id)
                return

            uni_id = self._handler.platform.uni_id_from_uni_port(flow.logical_port)
            pon_profile = self._handler.tech_profiles[self.pon_id]
            alloc_id = None

            try:
                (ofp_port_name, ofp_port_no) = self._handler.get_ofp_port_name(self.pon_id,
                                                                               self.onu_id,
                                                                               flow.logical_port)
                if ofp_port_name is None:
                    log.error("port-name-not-found")
                    return

                # Check tech profile instance already exists for derived port name
                tech_profile = pon_profile.get_tech_profile_instance(self._tech_profile_id,
                                                                     ofp_port_name)
                log.debug('Get-tech-profile-instance-status',
                          tech_profile_instance=tech_profile)

                if tech_profile is None:
                    # create tech profile instance
                    tech_profile = pon_profile.create_tech_profile_instance(self._tech_profile_id,
                                                                            ofp_port_name,
                                                                            self.pon_id)
                    if tech_profile is None:
                        raise Exception('Tech-profile-instance-creation-failed')
                else:
                    log.debug('Tech-profile-instance-already-exist-for-given port-name',
                              ofp_port_name=ofp_port_name)

                # upstream scheduler
                us_scheduler = pon_profile.get_us_scheduler(tech_profile)

                # downstream scheduler
                ds_scheduler = pon_profile.get_ds_scheduler(tech_profile)

                # create Tcont protobuf
                pb_tconts = pon_profile.get_tconts(tech_profile, us_scheduler, ds_scheduler)

                # create TCONTs & GEM Ports locally
                for pb_tcont in pb_tconts:
                    from ..xpon.olt_tcont import OltTCont
                    tcont = OltTCont.create(pb_tcont,
                                            self.pon_id,
                                            self.onu_id,
                                            self._tech_profile_id,
                                            uni_id,
                                            ofp_port_no)
                    if tcont is not None:
                        onu.add_tcont(tcont)

                # Fetch alloc id and gemports from tech profile instance
                alloc_id = tech_profile.us_scheduler.alloc_id

                onu_gems = [gem.gemport_id for gem in tech_profile.upstream_gem_port_attribute_list]

                for gem in tech_profile.upstream_gem_port_attribute_list:
                    from ..xpon.olt_gem_port import OltGemPort
                    gem_port = OltGemPort.create(self._handler,
                                                 gem,
                                                 tech_profile.us_scheduler.alloc_id,
                                                 self._tech_profile_id,
                                                 self.pon_id,
                                                 self.onu_id,
                                                 uni_id,
                                                 ofp_port_no)
                    if gem_port is not None:
                        onu.add_gem_port(gem_port)

                self._gem_ids_and_vid = {onu.onu_id: (onu_gems, flow.vlan_id)}

                # Send technology profile information to ONU
                reactor.callLater(0, self._handler.setup_onu_tech_profile, self._pon_id,
                                  self.onu_id, flow.logical_port)

            except BaseException as e:
                log.exception(exception=e)

            # Update the allocated alloc_id and gem_port_id for the ONU/UNI to KV store
            pon_intf_onu_id = (self.pon_id, self.onu_id, uni_id)
            resource_manager = self._handler.resource_mgr.resource_managers[self.pon_id]

            resource_manager.update_alloc_ids_for_onu(pon_intf_onu_id, list([alloc_id]))
            resource_manager.update_gemport_ids_for_onu(pon_intf_onu_id, onu_gems)

            self._handler.resource_mgr.update_gemports_ponport_to_onu_map_on_kv_store(onu_gems,
                                                                                      self.pon_id,
                                                                                      self.onu_id,
                                                                                      uni_id)

    def _decode(self, evc):
        from evc import EVC
        from flow_entry import FlowEntry

        # Only called from initializer, so first flow is only flow
        flow = self._flows.itervalues().next()

        self._name = EVCMap.create_evc_map_name(flow)

        if evc:
            self._evc_connection = EVCMap.EvcConnection.EVC
        else:
            self.status = 'Can only create EVC-MAP if EVC supplied'
            return False

        is_pon = flow.handler.is_pon_port(flow.in_port)
        is_uni = flow.handler.is_uni_port(flow.in_port)

        if flow.bandwidth is not None:
            self._upstream_bandwidth = flow.bandwidth * 1000000

        if is_pon or is_uni:
            # Preserve CE VLAN tag only if utility VLAN/EVC
            self._uni_port = flow.handler.get_port_name(flow.in_port)
            evc.ce_vlan_preservation = evc.ce_vlan_preservation or False
        else:
            self.status = 'EVC-MAPS without UNI or PON ports are not supported'
            return False    # UNI Ports handled in the EVC Maps

        # ACL logic
        self._eth_type = flow.eth_type

        if self._eth_type == FlowEntry.EtherType.IPv4:
            self._ip_protocol = flow.ip_protocol
            self._ipv4_dst = flow.ipv4_dst

            if self._ip_protocol == FlowEntry.IpProtocol.UDP:
                self._udp_dst = flow.udp_dst
                self._udp_src = flow.udp_src

        # If no match of VLAN this may be for untagged traffic or upstream and needs to
        # match the gem-port vid

        self._setup_tech_profiles()

        # self._match_untagged = flow.vlan_id is None and flow.inner_vid is None
        self._c_tag = flow.inner_vid or flow.vlan_id

        # If a push of a single VLAN is present with a POP of the VLAN in the EVC's
        # flow, then this is a traditional EVC flow

        evc.men_to_uni_tag_manipulation = EVC.Men2UniManipulation.POP_OUT_TAG_ONLY
        evc.switching_method = EVC.SwitchingMethod.DOUBLE_TAGGED \
            if self._c_tag is not None else EVC.SwitchingMethod.SINGLE_TAGGED

        try:
            acl = ACL.create(flow)
            if acl.name not in self._new_acls:
                self._new_acls[acl.name] = acl

        except Exception as e:
            log.exception('ACL-decoding', e=e)
            return False

        return True

    # Bulk operations

    @staticmethod
    def remove_all(client, regex_=EVC_MAP_NAME_REGEX_ALL):
        """
        Remove all matching EVC Maps from hardware

        :param client: (ncclient) NETCONF Client to use
        :param regex_: (String) Regular expression for name matching
        :return: (deferred)
        """
        # Do a 'get' on the evc-map config an you should get the names
        get_xml = """
        <filter>
          <evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps">
            <evc-map>
              <name/>
            </evc-map>
          </evc-maps>
        </filter>
        """
        log.debug('query', xml=get_xml, regex=regex_)

        def request_failed(results, operation):
            log.error('{}-failed'.format(operation), results=results)
            # No further actions. Periodic poll later on will scrub any old EVC-Maps if needed

        def delete_complete(results):
            log.debug('delete-complete', results=results)

        def do_delete(rpc_reply, regexpr):
            log.debug('query-complete', rpc_reply=rpc_reply)

            if rpc_reply.ok:
                result_dict = xmltodict.parse(rpc_reply.data_xml)
                entries = result_dict['data'].get('evc-maps') or {}

                if 'evc-map' in entries:
                    p = re.compile(regexpr)

                    if isinstance(entries['evc-map'], list):
                        names = {entry['name'] for entry in entries['evc-map']
                                 if 'name' in entry and p.match(entry['name'])}
                    else:
                        names = set()
                        for item in entries['evc-map'].items():
                            if isinstance(item, tuple) and item[0] == 'name':
                                names.add(item[1])
                                break

                    if len(names) > 0:
                        del_xml = '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps"' + \
                                 ' xc:operation = "delete">'
                        for name in names:
                            del_xml += '<evc-map>'
                            del_xml += '<name>{}</name>'.format(name)
                            del_xml += '</evc-map>'
                        del_xml += '</evc-maps>'
                        log.debug('removing', xml=del_xml)

                        return client.edit_config(del_xml)

            return succeed('no entries')

        d = client.get(get_xml)
        d.addCallbacks(do_delete, request_failed, callbackArgs=[regex_], errbackArgs=['get'])
        d.addCallbacks(delete_complete, request_failed, errbackArgs=['edit-config'])
        return d

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass
