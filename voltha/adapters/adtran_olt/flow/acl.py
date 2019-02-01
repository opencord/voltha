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
import xmltodict
import re
import structlog
from twisted.internet.defer import inlineCallbacks, returnValue, succeed

log = structlog.get_logger()

_acl_list = {}      # Key -> device-id -> Name: List of encoded EVCs

ACL_NAME_FORMAT = 'VOLTHA-ACL-{}-{}'  # format(flow_entry.flow_id, flow-entry-hash)
ACL_NAME_REGEX_ALL = 'VOLTHA-ACL-*'
ACE_NAME_FORMAT = 'VOLTHA-ACE-{}'  # format(flow_entry.flow_id)


class ACL(object):
    """
    Class to wrap Trap-to-Controller functionality
    """
    def __init__(self, flow_entry):
        self._installed = False
        self._status_message = None
        self._parent = flow_entry           # FlowEntry parent
        self._flow = flow_entry.flow
        self._handler = flow_entry.handler
        self._name = ACL.flow_to_name(flow_entry)
        self._rule_name = ACL.flow_to_ace_name(flow_entry)
        self._eth_type = flow_entry.eth_type
        self._ip_protocol = flow_entry.ip_protocol
        self._ipv4_dst = flow_entry.ipv4_dst
        self._src_port = flow_entry.udp_src
        self._dst_port = flow_entry.udp_dst
        self._exception = False
        self._enabled = True
        self._valid = self._decode()

    def __str__(self):
        return 'ACL: {}, Installed: {}, L2: {}, L3/4: {}'.\
            format(self.name, self._installed, self.is_l2_exception,
                   self.is_l3_l4_exception)

    @property
    def name(self):
        return self._name

    @property
    def installed(self):
        return self._installed

    @property
    def is_l2_exception(self):
        from flow_entry import FlowEntry
        return self._eth_type not in (None,
                                      FlowEntry.EtherType.IPv4,
                                      FlowEntry.EtherType.IPv6)

    @property
    def is_l3_l4_exception(self):
        return not self.is_l2_exception and self._ip_protocol is not None

    @staticmethod
    def _xml_header(operation=None):
        return '<access-lists xmlns="http://www.adtran.com/ns/yang/adtran-ietf-access-control-list"\
                xmlns:adtn-ietf-ns-acl="http://www.adtran.com/ns/yang/adtran-ietf-ns-access-control-list"><acl{}>'.\
            format('' if operation is None else ' xc:operation="{}"'.format(operation))

    @staticmethod
    def _xml_trailer():
        return '</acl></access-lists>'

    def _xml_action(self):
        xml = '<actions>'
        if self._exception:
            xml += '<adtn-ietf-ns-acl:exception-to-cpu/>'
        else:
            xml += '<permit/>'
        xml += '</actions>'
        return xml

    def _ace_l2(self):
        xml = '<ace>'
        xml += '<rule-name>{}</rule-name>'.format(self._rule_name)
        xml += '<matches><l2-acl><ether-type>{:04x}</ether-type></l2-acl></matches>'.format(self._eth_type)
        xml += self._xml_action()
        xml += '</ace>'
        return xml

    def _ace_l2_l3_ipv4(self):
        xml = '<ace>'
        xml += '<rule-name>{}</rule-name>'.format(self._rule_name)
        xml += '<matches><l2-l3-ipv4-acl>'
        xml += '<ether-type>{:04X}</ether-type>'.format(self._eth_type)

        if self._ip_protocol is not None:
            xml += '<protocol>{}</protocol>'.format(self._ip_protocol)
        if self._ipv4_dst is not None:
            xml += '<destination-ipv4-network>{}/32</destination-ipv4-network>'.format(self._ipv4_dst)
        if self._src_port is not None:
            xml += '<source-port-range><lower-port>{}</lower-port><operation>eq</operation></source-port-range>'.\
                format(self._src_port)
        if self._dst_port is not None:
            xml += '<destination-port-range><lower-port>' + \
                   '{}</lower-port><operations>eq</operations></destination-port-range>'.format(self._dst_port)

        xml += '</l2-l3-ipv4-acl></matches>'
        xml += self._xml_action()
        xml += '</ace>'
        return xml

    def _ace_any(self):
        xml = '<ace>'
        xml += '<rule-name>{}</rule-name>'.format(self._rule_name)
        xml += '<matches><any-acl/></matches>'
        xml += self._xml_action()
        xml += '</ace>'
        return xml

    def _acl_eth(self):
        xml = '<acl-type>eth-acl</acl-type>'
        xml += '<acl-name>{}</acl-name>'.format(self._name)
        return xml

    def _acl_l4(self):
        xml = '<acl-type>mixed-l2-l3-ipv4-acl</acl-type>'
        xml += '<acl-name>{}</acl-name>'.format(self._name)
        return xml

    def _acl_any(self):
        xml = '<acl-type>any-acl</acl-type>'
        xml += '<acl-name>{}</acl-name>'.format(self._name)
        return xml

    def _install_xml(self):
        xml = ACL._xml_header('create')
        if self.is_l2_exception:
            xml += self._acl_eth()
            xml += '<aces>{}</aces>'.format(self._ace_l2())
        elif self.is_l3_l4_exception:
            xml += self._acl_l4()
            xml += '<aces>{}</aces>'.format(self._ace_l2_l3_ipv4())
        else:
            xml += self._acl_any()
            xml += '<aces>{}</aces>'.format(self._ace_any())

        xml += ACL._xml_trailer()
        return xml

    def _remove_xml(self):
        xml = ACL._xml_header('delete')
        if self.is_l2_exception:
            xml += self._acl_eth()
        elif self.is_l3_l4_exception:
            xml += self._acl_l4()
        else:
            xml += self._acl_any()
        xml += ACL._xml_trailer()
        return xml

    def evc_map_ingress_xml(self):
        """ Individual ACL specific XML for the EVC MAP """

        xml = '<adtn-evc-map-acl:acl-type '
        fmt = 'xmlns:adtn-ietf-acl="http://www.adtran.com/ns/yang/adtran-ietf-access-control-list">adtn-ietf-acl:{}'\
              '</adtn-evc-map-acl:acl-type>'

        if self.is_l2_exception:
            xml += fmt.format('eth-acl')

        elif self.is_l3_l4_exception:
            xml += fmt.format('mixed-l2-l3-ipv4-acl')

        else:
            xml += fmt.format('any-acl')

        xml += '<adtn-evc-map-acl:acl-name>{}</adtn-evc-map-acl:acl-name>'.format(self.name)
        return xml

    @staticmethod
    def create(flow_entry):
        acl = ACL(flow_entry)

        # Already created and installed, return that one
        acls_installed = _acl_list.get(flow_entry.handler.device_id)
        if acls_installed is not None:
            entry = acls_installed.get(acl._name)
            if entry is not None:
                return entry

        return acl

    @staticmethod
    def flow_to_name(flow_entry):
        return ACL_NAME_FORMAT.format(flow_entry.flow_id, ACL.acl_hash(flow_entry))

    @staticmethod
    def flow_to_ace_name(flow_entry):
        return ACE_NAME_FORMAT.format(flow_entry.flow_id)

    @staticmethod
    def acl_hash(flow_entry):
        from hashlib import md5
        in_port = flow_entry.in_port or 0
        eth_type = flow_entry.eth_type or 0
        ip_protocol = flow_entry.ip_protocol or 0
        ipv4_dst = flow_entry.ipv4_dst or 0
        src_port = flow_entry.udp_src or 0
        dst_port = flow_entry.udp_dst or 0
        hex_string = md5('{},{},{},{},{},{}'.format(in_port, eth_type, ip_protocol,
                                                    ipv4_dst, src_port, dst_port)).hexdigest()
        return hex_string

    @property
    def valid(self):
        return self._valid

    @property
    def installed(self):
        return self._installed

    @property
    def status(self):
        return self._status_message

    @inlineCallbacks
    def install(self):
        log.debug('installing-acl', installed=self._installed)

        if not self._installed and self._enabled:
            if self._handler.device_id not in _acl_list:
                _acl_list[self._handler.device_id] = {}

            acls_installed = _acl_list[self._handler.device_id]
            if self._name in acls_installed:
                # Return OK
                returnValue(self._enabled)

            try:
                acl_xml = self._install_xml()
                log.debug('install-xml', xml=acl_xml, name=self._name)

                results = yield self._handler.netconf_client.edit_config(acl_xml)
                self._installed = results.ok
                self._status_message = '' if results.ok else results.error

                if self._installed:
                    acls_installed[self._name] = self

            except Exception as e:
                log.exception('install-failure', name=self._name, e=e)
                raise

        returnValue(self._installed and self._enabled)

    @inlineCallbacks
    def remove(self):
        log.debug('removing-acl', installed=self._installed)

        if self._installed:
            acl_xml = self._remove_xml()
            log.info('remove-xml', xml=acl_xml, name=self._name)

            results = yield self._handler.netconf_client.edit_config(acl_xml)
            self._installed = not results.ok
            self._status_message = '' if results.ok else results.error

            if not self._installed:
                acls_installed = _acl_list.get(self._handler.device_id)
                if acls_installed is not None and self._name in acls_installed:
                    del acls_installed[self._name]

        returnValue(not self._installed)

    def enable(self):
        if not self._enabled:
            self._enabled = False
            raise NotImplemented("TODO: Implement this")

    def disable(self):
        if self._enabled:
            self._enabled = True
            raise NotImplemented("TODO: Implement this")

    def _decode(self):
        """
        Examine the field settings and set ACL up for requested fields
        """
        # If EtherType is not None and not IP, this is an L2 exception
        self._exception = self.is_l2_exception or self.is_l3_l4_exception
        return True

    # BULK operations

    @staticmethod
    def enable_all():
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def disable_all():
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def clear_all(device_id):
        """
        Clear all acls for this device id from the list
        :param device_id: id of the device
        """
        if device_id in _acl_list:
            del _acl_list[device_id]

    @staticmethod
    def remove_all(client, regex_=ACL_NAME_REGEX_ALL):
        """
        Remove all matching ACLs from hardware
        :param client: (ncclient) NETCONF Client to use
        :param regex_: (String) Regular expression for name matching
        :return: (deferred)
        """
        # Do a 'get' on the evc config an you should get the names
        get_xml = """
        <filter>
          <access-lists xmlns="http://www.adtran.com/ns/yang/adtran-ietf-access-control-list">
            <acl><acl-type/><acl-name/></acl>
          </access-lists>
        </filter>
        """
        log.debug('query', xml=get_xml, regex=regex_)

        def request_failed(results, operation):
            log.error('{}-failed'.format(operation), results=results)

        def delete_complete(results):
            log.debug('delete-complete', results=results)

        def do_delete(rpc_reply, regexpr):
            log.debug('query-complete', rpc_reply=rpc_reply)

            if rpc_reply.ok:
                result_dict = xmltodict.parse(rpc_reply.data_xml)
                entries = result_dict['data'].get('access-lists') or {}

                if 'acl' in entries:
                    p = re.compile(regexpr)

                    pairs = []
                    if isinstance(entries['acl'], list):
                        pairs = {(entry['acl-type'], entry['acl-name']) for entry in entries['acl']
                                 if 'acl-name' in entry and 'acl-type' in entry and p.match(entry['acl-name'])}
                    else:
                        if 'acl' in entries:
                            entry = entries['acl']
                            if 'acl-name' in entry and 'acl-type' in entry and p.match(entry['acl-name']):
                                pairs = [(entry['acl-type'], entry['acl-name'])]

                    if len(pairs) > 0:
                        del_xml = '<access-lists xmlns="http://www.adtran.com/ns/yang/adtran-ietf-access-control-list">'
                        for pair in pairs:
                            del_xml += '<acl xc:operation = "delete">'
                            del_xml += '<acl-type>{}</acl-type>'.format(pair[0])
                            del_xml += '<acl-name>{}</acl-name>'.format(pair[1])
                            del_xml += '</acl>'
                        del_xml += '</access-lists>'
                        log.debug('removing', xml=del_xml)

                        return client.edit_config(del_xml)

            return succeed('no entries')

        d = client.get(get_xml)
        d.addCallbacks(do_delete, request_failed, callbackArgs=[regex_], errbackArgs=['get'])
        d.addCallbacks(delete_complete, request_failed, errbackArgs=['edit-config'])
        return d
