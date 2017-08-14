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

import xmltodict
import re
from enum import Enum
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
from voltha.core.flow_decomposer import *

log = structlog.get_logger()

EVC_NAME_FORMAT = 'VOLTHA-{}'                       # format(flow.id)
EVC_NAME_REGEX_ALL = EVC_NAME_FORMAT.format('*')
DEFAULT_STPID = 0x8100


class EVC(object):
    """
    Class to wrap EVC functionality
    """
    class SwitchingMethod(Enum):
        SINGLE_TAGGED = 1
        DOUBLE_TAGGED = 2
        MAC_SWITCHED = 3
        DOUBLE_TAGGED_MAC_SWITCHED = 4
        DEFAULT = SINGLE_TAGGED

        @staticmethod
        def xml(value):
            if value is None:
                value = EVC.SwitchingMethod.DEFAULT
            if value == EVC.SwitchingMethod.SINGLE_TAGGED:
                return '<single-tag-switched/>'
            elif value == EVC.SwitchingMethod.DOUBLE_TAGGED:
                return '<double-tag-switched/>'
            elif value == EVC.SwitchingMethod.MAC_SWITCHED:
                return '<mac-switched/>'
            elif value == EVC.SwitchingMethod.DOUBLE_TAGGED_MAC_SWITCHED:
                return '<double-tag-mac-switched/>'
            raise ValueError('Invalid SwitchingMethod enumeration')

    class Men2UniManipulation(Enum):
        SYMMETRIC = 1
        POP_OUT_TAG_ONLY = 2
        DEFAULT = SYMMETRIC

        @staticmethod
        def xml(value):
            if value is None:
                value = EVC.Men2UniManipulation.DEFAULT
            fmt = '<men-to-uni-tag-manipulation>{}</men-to-uni-tag-manipulation>'
            if value == EVC.Men2UniManipulation.SYMMETRIC:
                return fmt.format('<symmetric/>')
            elif value == EVC.Men2UniManipulation.POP_OUT_TAG_ONLY:
                return fmt.format('<pop-outer-tag-only/>')
            raise ValueError('Invalid Men2UniManipulation enumeration')

    class ElineFlowType(Enum):
        NNI_TO_UNI = 1
        UNI_TO_NNI = 2
        NNI_TO_NNI = 3
        UNI_TO_UNI = 4
        ACL_FILTER = 5
        UNKNOWN = 6
        UNSUPPORTED = 7    # Or Invalid

    def __init__(self, flow_entry):
        self._installed = False
        self._status_message = None
        self._flow = flow_entry
        self._name = self._create_name()
        self._evc_maps = {}               # Map Name -> evc-map
        self._install_deferred = None

        self._flow_type = EVC.ElineFlowType.UNKNOWN

        # EVC related properties
        self._enabled = True
        self._men_ports = []
        self._s_tag = None
        self._stpid = None
        self._switching_method = None

        self._ce_vlan_preservation = None
        self._men_to_uni_tag_manipulation = None

        try:
            self._valid = self._decode()

        except Exception as e:
            log.exception('Failure during EVC decode', e=e)
            self._valid = False

    def __str__(self):
        return "EVC-{}: MEN: {}, S-Tag: {}".format(self._name, self._men_ports, self._s_tag)

    def _create_name(self):
        #
        # TODO: Take into account selection criteria and output to make the name
        #
        return EVC_NAME_FORMAT.format(self._flow.flow_id)

    @property
    def name(self):
        return self._name

    @property
    def valid(self):
        return self._valid

    @property
    def installed(self):
        return self._installed

    @property
    def status(self):
        return self._status_message

    @status.setter
    def status(self, value):
        self._status_message = value

    @property
    def s_tag(self):
        return self._s_tag

    @property
    def stpid(self):
        return self._stpid

    @stpid.setter
    def stpid(self, value):
        assert self._stpid is None or self._stpid == value
        self._stpid = value

    @property
    def switching_method(self):
        return self._switching_method

    @switching_method.setter
    def switching_method(self, value):
        assert self._switching_method is None or self._switching_method == value
        self._switching_method = value

    @property
    def ce_vlan_preservation(self):
        return self._ce_vlan_preservation

    @ce_vlan_preservation.setter
    def ce_vlan_preservation(self, value):
        assert self._ce_vlan_preservation is None or self._ce_vlan_preservation == value
        self._ce_vlan_preservation = value

    @property
    def men_to_uni_tag_manipulation(self):
        return self._men_to_uni_tag_manipulation

    @men_to_uni_tag_manipulation.setter
    def men_to_uni_tag_manipulation(self, value):
        assert self._men_to_uni_tag_manipulation is None or self._men_to_uni_tag_manipulation == value
        self._men_to_uni_tag_manipulation = value

    @property
    def flow_entry(self):
        return self._flow

    @property
    def evc_maps(self):
        """
        Get all EVC Maps that reference this EVC
        :return: list of EVCMap
        """
        return self._evc_maps.values()

    def add_evc_map(self, evc_map):
        if self._evc_maps is not None:
            self._evc_maps[evc_map.name] = evc_map

    def remove_evc_map(self, evc_map):
        if self._evc_maps is not None and evc_map.name in self._evc_maps:
            del self._evc_maps[evc_map.name]

    def schedule_install(self):
        """
        Try to install EVC and all MAPs in a single operational sequence
        """
        if self._valid and self._install_deferred is None:
                self._install_deferred = reactor.callLater(0, self._do_install)

        return self._install_deferred

    @staticmethod
    def _xml_header(operation=None):
        return '<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs"><evc{}>'.\
            format('' if operation is None else ' operation="{}"'.format(operation))

    @staticmethod
    def _xml_trailer():
        return '</evc></evcs>'

    @inlineCallbacks
    def _do_install(self):
        self._install_deferred = None

        # Install the EVC if needed

        if self._valid and not self._installed:
            # TODO: Currently install EVC and then MAPs. Can do it all in a single edit-config operation

            xml = EVC._xml_header()
            xml += '<name>{}</name>'.format(self.name)
            xml += '<enabled>{}</enabled>'.format('true' if self._enabled else 'false')

            if self._ce_vlan_preservation is not None:
                xml += '<ce-vlan-preservation>{}</ce-vlan-preservation>'.\
                    format('true' if self._ce_vlan_preservation else 'false')

            if self._s_tag is not None:
                xml += '<stag>{}</stag>'.format(self._s_tag)
                xml += '<stag-tpid>{:#x}</stag-tpid>'.format(self._stpid or DEFAULT_STPID)
            else:
                xml += 'no-stag/'

            for port in self._men_ports:
                xml += '<men-ports>{}</men-ports>'.format(port)

            xml += EVC.Men2UniManipulation.xml(self._men_to_uni_tag_manipulation)
            xml += EVC.SwitchingMethod.xml(self._switching_method)
            xml += EVC._xml_trailer()

            log.debug("Creating EVC {}: '{}'".format(self.name, xml))

            try:
                # Set installed to true while request is in progress
                self._installed = True
                results = yield self._flow.handler.netconf_client.edit_config(xml, lock_timeout=30)
                self._installed = results.ok

                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error                    # TODO: Save off error status

            except Exception as e:
                log.exception('Failed to install EVC', name=self.name, e=e)
                raise

        # Install any associated EVC Maps

        if self._installed:
            for evc_map in self.evc_maps:
                try:
                    results = yield evc_map.install()
                    pass  # TODO: What to do on error?

                except Exception as e:
                    evc_map.status = 'Exception during EVC-MAP Install: {}'.format(e.message)
                    log.exception(evc_map.status, e=e)

        returnValue(self._installed and self._valid)

    @inlineCallbacks
    def remove(self):
        d, self._install_deferred = self._install_deferred, None
        if d is not None:
            d.cancel()

        if self._installed:
            xml = EVC._xml_header('delete') + '<name>{}</name>'.format(self.name) + EVC._xml_trailer()

            log.debug('removing', evc=self.name, xml=xml)

            try:
                results = yield self._flow.handler.netconf_client.edit_config(xml, lock_timeout=30)
                self._installed = not results.ok
                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error             # TODO: Save off error status

            except Exception as e:
                log.exception('removing', name=self.name, e=e)
                raise

            # TODO: Do we remove evc-maps as well reference here or maybe have a 'delete' function?
            pass

        returnValue(not self._installed)

    @inlineCallbacks
    def enable(self):
        if self.installed and not self._enabled:
            xml = EVC._xml_header() + '<name>{}</name>'.format(self.name)
            xml += '<enabled>true</enabled>' + EVC._xml_trailer()

            log.debug('enabling', evc=self.name, xml=xml)

            try:
                results = yield self._flow.handler.netconf_client.edit_config(xml, lock_timeout=30)
                self._enabled = results.ok
                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error       # TODO: Save off error status

            except Exception as e:
                log.exception('enabling', name=self.name, e=e)
                raise

        returnValue(self.installed and self._enabled)

    @inlineCallbacks
    def disable(self):
        if self.installed and self._enabled:
            xml = EVC._xml_header() + '<name>{}</name>'.format(self.name)
            xml += '<enabled>false</enabled>' + EVC._xml_trailer()

            log.debug('disabling', evc=self.name, xml=xml)

            try:
                results = yield self._flow.handler.netconf_client.edit_config(xml, lock_timeout=30)
                self._enabled = not results.ok
                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error      # TODO: Save off error status

            except Exception as e:
                log.exception('disabling', name=self.name, e=e)
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
            self._evc_maps = None

        returnValue(succeeded)

    def _decode(self):
        """
        Examine flow rules and extract appropriate settings for this EVC
        """
        if self._flow.handler.is_nni_port(self._flow.in_port):
            self._men_ports.append(self._flow.handler.get_port_name(self._flow.in_port))
        else:
            self._status_message = 'EVCs with UNI ports are not supported'
            return False    # UNI Ports handled in the EVC Maps

        self._s_tag = self._flow.vlan_id

        # if self._flow.inner_vid is not None:
        #    self._switching_method = EVC.SwitchingMethod.DOUBLE_TAGGED         TODO: Future support

        # Note: The following fields will get set when the first EVC-MAP
        #       is associated with this object. Once set, they cannot be changed to
        #       another value.
        #  self._stpid
        #  self._switching_method
        #  self._ce_vlan_preservation
        #  self._men_to_uni_tag_manipulation
        return True

    # BULK operations

    @staticmethod
    def remove_all(client, regex_=EVC_NAME_REGEX_ALL):
        """
        Remove all matching EVCs from hardware
        :param client: (ncclient) NETCONF Client to use
        :param regex_: (String) Regular expression for name matching
        :return: (deferred)
        """
        # Do a 'get' on the evc config an you should get the names
        get_xml = """
        <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
          <evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs">
            <evc><name/></evc>
          </evcs>
        </filter>
        """
        log.debug('query', xml=get_xml)

        def request_failed(results, operation):
            log.error('{}-failed'.format(operation), results=results)
            # No further actions. Periodic poll later on will scrub any old EVCs if needed

        def delete_complete(results):
            log.debug('delete-complete', results=results)

        def do_delete(rpc_reply, regexpr):
            log.debug('query-complete', rpc_reply=rpc_reply)

            if rpc_reply.ok:
                result_dict = xmltodict.parse(rpc_reply.data_xml)
                entries = result_dict['data']['evcs'] if 'evcs' in result_dict['data'] else {}

                if 'evc' in entries:
                    p = re.compile(regexpr)

                    if isinstance(entries['evc'], list):
                        names = {entry['name'] for entry in entries['evc'] if 'name' in entry
                                 and p.match(entry['name'])}
                    else:
                        names = set()
                        for item in entries['evc-map'].items():
                            if isinstance(item, tuple) and item[0] == 'name':
                                names.add(item[1])
                                break

                    if len(names) > 0:
                        del_xml = EVC._xml_header('delete')
                        for name in names:
                            del_xml += '<name>{}</name>'.format(name)
                            del_xml += EVC._xml_trailer()

                        log.debug('removing', xml=del_xml)
                        return client.edit_config(del_xml, lock_timeout=30)

            return succeed('no entries')

        d = client.get(get_xml)
        d.addCallbacks(do_delete, request_failed, callbackArgs=[regex_], errbackArgs=['get'])
        d.addCallbacks(delete_complete, request_failed, errbackArgs=['edit-config'])
        return d
