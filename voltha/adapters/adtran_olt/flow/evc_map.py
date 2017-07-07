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

import structlog
from enum import Enum
from twisted.internet.defer import inlineCallbacks, returnValue

log = structlog.get_logger()

EVC_MAP_NAME_INGRESS_FORMAT = 'EVCMap-VOLTHA-ingress-{}'
EVC_MAP_NAME_EGRESS_FORMAT = 'EVCMap-VOLTHA-egress-{}'

EVC_MAP_NAME_INGRESS_REGEX_FORMAT = EVC_MAP_NAME_INGRESS_FORMAT.format('regex here')
EVC_MAP_NAME_EGRESS_REGEX_FORMAT = EVC_MAP_NAME_EGRESS_FORMAT.format('regex here')

_xml_header = '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps"><evc-map>'
_xml_trailer = '</evc-map></evc-maps>'


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

    def __init__(self, flow, evc, is_ingress_map):
        self._flow = flow
        self._evc = evc
        self._is_ingress_map = is_ingress_map
        self._installed = False
        self._status_message = None

        self._name = None
        self._enabled = True
        self._uni_port = None
        self._evc_connection = EVCMap.EvcConnection.NO_EVC_CONNECTION
        self._evc_name = None

        self._men_priority = EVCMap.PriorityOption.INHERIT_PRIORITY
        self._men_pri = 0  # If Explicit Priority

        self._c_tag = None
        self._men_ctag_priority = EVCMap.PriorityOption.INHERIT_PRIORITY
        self._men_ctag_pri = 0  # If Explicit Priority

        self._match_ce_vlan_id = None
        self._match_untagged = True
        self._match_destination_mac_address = None
        self._match_l2cp = False
        self._match_broadcast = False
        self._match_multicast = False
        self._match_unicast = False
        self._match_igmp = False

        # ACL logic
        self._eth_type = None
        self._ip_protocol = None
        self._ipv4_dst = None
        self._udp_dst = None
        self._udp_src = None

        try:
            self._valid = self._decode()

        except Exception as e:
            log.exception('Failure during EVCMap decode', e=e)
            self._valid = False

        if self._valid:
            evc.add_evc_map(self)
        else:
            self._evc = None

    @staticmethod
    def create_ingress_map(flow, evc):
        return EVCMap(flow, evc, True)

    @staticmethod
    def create_egress_map(flow, evc):
        return EVCMap(flow, evc, False)

    @property
    def valid(self):
        return self._valid

    @property
    def installed(self):
        return self._installed

    @property
    def name(self):
        return self._name

    @property
    def status(self):
        return self._status_message

    @status.setter
    def status(self, value):
        self._status_message = value

    @property
    def _needs_acl_support(self):
        return self._eth_type is None and self._ip_protocol is None and\
               self._ipv4_dst is None and self._udp_dst is None and self._udp_src is None

    @inlineCallbacks
    def install(self):
        if self._valid and not self._installed:
            xml = '<evc-maps xmlns="http://www.adtran.com/ns/yang/adtran-evc-maps">' \
                  '<evc-map>'
            xml += '<name>{}</name>'.format(self.name)
            xml += '<enabled>{}</enabled>'.format(self._enabled)
            xml += '<uni>{}</uni>'.format(self._uni_port)

            if self._evc_name is not None:
                xml += '<evc>{}</evc>'.format(self._evc_name)
            else:
                xml += EVCMap.EvcConnection.xml(self._evc_connection)

            if self._match_untagged:
                xml += '<match-untagged>True</match-untagged>'
            elif self._c_tag is not None:
                xml += '<ctag>{}</ctag>'.format(self._c_tag)

            xml += _xml_trailer

            log.debug("Creating EVC-MAP {}: '{}'".format(self.name, xml))

            if self._needs_acl_support:
                self._installed = True              # TODO: Support ACLs
            else:
                try:
                    results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                                  default_operation='create',
                                                                                  lock_timeout=30)
                    self._installed = results.ok
                    if results.ok:
                        self.status = ''
                    else:
                        self.status = results.error        # TODO: Save off error status

                except Exception as e:
                    log.exception('Failed to install EVC-MAP', name=self.name, e=e)
                    raise

        # TODO: The following is not yet supported
        # self._men_priority = EVCMap.PriorityOption.INHERIT_PRIORITY
        # self._men_pri = 0  # If Explicit Priority
        #
        # self._c_tag = None
        # self._men_ctag_priority = EVCMap.PriorityOption.INHERIT_PRIORITY
        # self._men_ctag_pri = 0  # If Explicit Priority
        #
        # self._match_ce_vlan_id = None
        # self._match_untagged = True
        # self._match_destination_mac_address = None
        # self._match_l2cp = False
        # self._match_broadcast = False
        # self._match_multicast = False
        # self._match_unicast = False
        # self._match_igmp = False
        # self._eth_type = None
        # self._ip_protocol = None
        # self._ipv4_dst = None
        # self._udp_dst = None
        # self._udp_src = None

        returnValue(self._installed and self._valid)

    @inlineCallbacks
    def remove(self):
        if self._installed:
            xml = _xml_header + '<name>{}</name>'.format(self.name) + _xml_trailer

            log.debug("Deleting EVC-MAP {}: '{}'".format(self.name, xml))

            if self._needs_acl_support:
                self._installed = False              # TODO: Support ACLs
            else:
                try:
                    results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                                  default_operation='delete',
                                                                                  lock_timeout=30)
                    self._installed = not results.ok
                    if results.ok:
                        self.status = ''
                    else:
                        self.status = results.error      # TODO: Save off error status

                except Exception as e:
                    log.exception('Failed to remove EVC-MAP', name=self.name, e=e)
                    raise

            # TODO: Do we remove evc reference here or maybe have a 'delete' function?

        returnValue(self._installed)

    @inlineCallbacks
    def enable(self):
        if self.installed and not self._enabled:
            xml = _xml_header + '<name>{}</name>'.format(self.name)
            xml += '<enabled>true</enabled>' + _xml_trailer

            log.debug("Enabling EVC-MAP {}: '{}'".format(self.name, xml))

            if self._needs_acl_support:
                self._enabled = True             # TODO: Support ACLs
            else:
                try:
                    results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                                  default_operation='merge',
                                                                                  lock_timeout=30)
                    self._enabled = results.ok
                    if results.ok:
                        self.status = ''
                    else:
                        self.status = results.error      # TODO: Save off error status

                except Exception as e:
                    log.exception('Failed to enable EVC-MAP', name=self.name, e=e)
                    raise

        returnValue(self.installed and self._enabled)

    @inlineCallbacks
    def disable(self):
        if self.installed and self._enabled:
            xml = _xml_header + '<name>{}</name>'.format(self.name)
            xml += '<enabled>false</enabled>' + _xml_trailer

            log.debug("Disabling EVC-MAP {}: '{}'".format(self.name, xml))

            if self._needs_acl_support:
                self._enabled = False              # TODO: Support ACLs
            else:
                try:
                    results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                                  default_operation='merge',
                                                                                  lock_timeout=30)
                    self._enabled = not results.ok
                    if results.ok:
                        self.status = ''
                    else:
                        self.status = results.error     # TODO: Save off error status

                except Exception as e:
                    log.exception('Failed to disable EVC-MAP', name=self.name, e=e)
                    raise

        returnValue(self.installed and not self._enabled)

    @inlineCallbacks
    def delete(self):
        """
        Remove from hardware and delete/clean-up
        """
        try:
            self._valid = False
            succeeded = yield self.remove()
            # TODO: On timeout or other NETCONF error, should we schedule cleanup later?

        except Exception:
            succeeded = False

        finally:
            self._flow = None
            evc, self._evc = self._evc, None
            if evc is not None:
                evc.remove_evc_map(self)

        returnValue(succeeded)

    def _decode(self):
        from evc import EVC
        from flow_entry import FlowEntry

        flow = self._flow

        self._name = 'EVC-MAP-{}-{}'.format('i' if self._is_ingress_map else 'e', flow.flow_id)

        if self._evc:
            self._evc_connection = EVCMap.EvcConnection.EVC
            self._evc_name = self._evc.name
        else:
            self._status_message = 'Can only create EVC-MAP if EVC supplied'
            return False

        if flow.handler.is_pon_port(flow.in_port) or flow.handler.is_uni_port(flow.in_port):
            self._uni_port = self._flow.handler.get_port_name(flow.in_port)
        else:
            self._status_message = 'EVC-MAPS without UNI or PON ports are not supported'
            return False    # UNI Ports handled in the EVC Maps

        # If no match of VLAN this may be for untagged traffic

        if flow.vlan_id is None and flow.inner_vid is None:
            self._match_untagged = True
        else:
            self._match_untagged = False
            self._c_tag = flow.inner_vid

        # If a push of a single VLAN is present with a POP of the VLAN in the EVC's
        # flow, then this is a traditional EVC flow

        if len(flow.push_vlan_id) == 1 and self._evc.flow_entry.pop_vlan == 1:
            self._evc.men_to_uni_tag_manipulation = EVC.Men2UniManipulation.SYMETRIC
            self._evc.switching_method = EVC.SwitchingMethod.SINGLE_TAGGED
            self._evc.stpid = flow.push_vlan_tpid[0]

        elif len(flow.push_vlan_id) == 2 and self._evc.flow_entry.pop_vlan == 1:
            self._evc.men_to_uni_tag_manipulation = EVC.Men2UniManipulation.POP_OUT_TAG_ONLY
            self._evc.switching_method = EVC.SwitchingMethod.DOUBLE_TAGGED
            # self._match_ce_vlan_id = 'TODO: something maybe'
            raise NotImplementedError('TODO: Not supported/needed yet')

        # ACL logic

        self._eth_type = flow.eth_type

        if self._eth_type == FlowEntry.EtherType.IPv4:
            self._ip_protocol = flow.ip_protocol
            self._ipv4_dst = flow.ipv4_dst

            if self._ip_protocol == FlowEntry.IpProtocol.UDP:
                self._udp_dst = flow.udp_dst
                self._udp_src = flow.udp_src

        return True
