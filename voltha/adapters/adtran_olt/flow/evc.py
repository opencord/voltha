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
from enum import IntEnum
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
import structlog

log = structlog.get_logger()

EVC_NAME_FORMAT = 'VOLTHA-{}'                       # format(flow.id)
EVC_NAME_REGEX_ALL = EVC_NAME_FORMAT.format('*')
DEFAULT_STPID = 0x8100


class EVC(object):
    """
    Class to wrap EVC functionality
    """
    class SwitchingMethod(IntEnum):
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

    class Men2UniManipulation(IntEnum):
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

    class ElineFlowType(IntEnum):
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
        self._deferred = None
        self._evc_maps = {}               # Map Name -> evc-map

        self._flow_type = EVC.ElineFlowType.UNKNOWN

        # EVC related properties
        self._enabled = True
        self._men_ports = []
        self._s_tag = None
        self._stpid = None
        self._switching_method = None
        self.service_evc = False

        self._ce_vlan_preservation = None
        self._men_to_uni_tag_manipulation = None

        try:
            self._valid = self._decode()

        except Exception as e:
            log.exception('Failure during EVC decode', e=e)
            self._valid = False

    def __str__(self):
        return "EVC-{}: MEN: {}, S-Tag: {}".format(self.name, self._men_ports, self.s_tag)

    def _create_name(self):
        #
        # TODO: Take into account selection criteria and output to make the name
        #
        return EVC_NAME_FORMAT.format(self._flow.flow_id)

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None

        try:
            if d is not None and not d.called:
                d.cancel()

        except Exception as e:
            pass

    @property
    def name(self):
        return self._name

    @property
    def valid(self):
        return self._valid

    @property
    def installed(self):
        return self._installed

    @installed.setter
    def installed(self, value):
        assert not value, 'EVC Install can only be reset'
        self._installed = False

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
        assert self._stpid is None or self._stpid == value, 'STPID can only be set once'
        self._stpid = value

    @property
    def switching_method(self):
        return self._switching_method

    @switching_method.setter
    def switching_method(self, value):
        assert self._switching_method is None or self._switching_method == value,\
            'Switching Method can only be set once. EVC: {}'.format(self.name)
        self._switching_method = value

    @property
    def ce_vlan_preservation(self):
        return self._ce_vlan_preservation

    @ce_vlan_preservation.setter
    def ce_vlan_preservation(self, value):
        assert self._ce_vlan_preservation is None or self._ce_vlan_preservation == value,\
            'CE VLAN Preservation can only be set once'
        self._ce_vlan_preservation = value

    @property
    def men_to_uni_tag_manipulation(self):
        return self._men_to_uni_tag_manipulation

    @men_to_uni_tag_manipulation.setter
    def men_to_uni_tag_manipulation(self, value):
        assert self._men_to_uni_tag_manipulation is None or self._men_to_uni_tag_manipulation == value, \
            'MEN-to-UNI tag manipulation can only be set once'
        self._men_to_uni_tag_manipulation = value

    @property
    def flow_entry(self):
        # Note that the first flow used to create the EVC is saved and it may
        # eventually get deleted while others still use the EVC.  This should
        # be okay as the downstream flow/signature table is used to maintain
        # the lifetime on this EVC object.
        return self._flow

    @flow_entry.setter
    def flow_entry(self, value):
        self._flow = value

    @property
    def evc_maps(self):
        """
        Get all EVC Maps that reference this EVC
        :return: list of EVCMap
        """
        return list(self._evc_maps.values()) if self._evc_maps is not None else []

    @property
    def evc_map_names(self):
        """
        Get all EVC Map names that reference this EVC
        :return: list of EVCMap names
        """
        return list(self._evc_maps.keys()) if self._evc_maps is not None else []

    def add_evc_map(self, evc_map):
        if self._evc_maps is None:
            self._evc_maps = dict()

        if evc_map.name not in self._evc_maps:
            self._evc_maps[evc_map.name] = evc_map

    def remove_evc_map(self, evc_map):
        if self._evc_maps is not None and evc_map.name in self._evc_maps:
            del self._evc_maps[evc_map.name]

    def schedule_install(self, delay=0):
        """
        Try to install EVC and all MAPs in a single operational sequence.
        The delay parameter is used during recovery to allow multiple associated
        EVC maps to be updated/modified independently before the parent EVC
        is installed.

        :param delay: (int) Seconds to delay before install
        """
        self._cancel_deferred()

        self._deferred = reactor.callLater(delay, self._do_install) \
            if self.valid else succeed('Not VALID')

        return self._deferred

    @staticmethod
    def _xml_header(operation=None):
        return '<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs"{}><evc>'.\
            format('' if operation is None else ' xc:operation="{}"'.format(operation))

    @staticmethod
    def _xml_trailer():
        return '</evc></evcs>'

    @inlineCallbacks
    def _do_install(self):
        # Install the EVC if needed
        log.debug('do-install', valid=self.valid, installed=self.installed)

        if self.valid and not self.installed:
            # TODO: Currently install EVC and then MAPs. Can do it all in a single edit-config operation

            xml = EVC._xml_header()
            xml += '<name>{}</name>'.format(self.name)
            xml += '<enabled>{}</enabled>'.format('true' if self._enabled else 'false')

            if self._ce_vlan_preservation is not None:
                xml += '<ce-vlan-preservation>{}</ce-vlan-preservation>'.format('false')

            if self._s_tag is not None:
                xml += '<stag>{}</stag>'.format(self._s_tag)
                xml += '<stag-tpid>{}</stag-tpid>'.format(self.stpid or DEFAULT_STPID)
            else:
                xml += 'no-stag/'

            for port in self._men_ports:
                xml += '<men-ports>{}</men-ports>'.format(port)

            # xml += EVC.Men2UniManipulation.xml(self._men_to_uni_tag_manipulation)
            # xml += EVC.SwitchingMethod.xml(self._switching_method)
            xml += EVC._xml_trailer()

            log.debug('create-evc', name=self.name, xml=xml)
            try:
                # Set installed to true while request is in progress
                self._installed = True
                results = yield self._flow.handler.netconf_client.edit_config(xml)
                self._installed = results.ok
                self.status = '' if results.ok else results.error

            except Exception as e:
                log.exception('install-failed', name=self.name, e=e)
                raise

        # Install any associated EVC Maps

        if self.installed:
            for evc_map in self.evc_maps:
                try:
                    yield evc_map.install()

                except Exception as e:
                    evc_map.status = 'Exception during EVC-MAP Install: {}'.format(e.message)
                    log.exception('evc-map-install-failed', e=e)

        returnValue(self.installed and self.valid)

    def remove(self, remove_maps=True):
        """
        Remove EVC (and optional associated EVC-MAPs) from hardware
        :param remove_maps: (boolean)
        :return: (deferred)
        """
        if not self.installed:
            return succeed('Not installed')

        log.info('removing', evc=self, remove_maps=remove_maps)
        dl = []

        def _success(rpc_reply):
            log.debug('remove-success', rpc_reply=rpc_reply)
            self._installed = False

        def _failure(results):
            log.error('remove-failed', results=results)
            self._installed = False

        xml = EVC._xml_header('delete') + '<name>{}</name>'.format(self.name) + EVC._xml_trailer()
        d = self._flow.handler.netconf_client.edit_config(xml)
        d.addCallbacks(_success, _failure)
        dl.append(d)

        if remove_maps:
            for evc_map in self.evc_maps:
                dl.append(evc_map.remove())

        return defer.gatherResults(dl, consumeErrors=True)

    @inlineCallbacks
    def delete(self, delete_maps=True):
        """
        Remove from hardware and delete/clean-up EVC Object
        """
        log.info('deleting', evc=self, delete_maps=delete_maps)

        assert self._flow, 'Delete EVC must have flow reference'
        try:
            dl = [self.remove()]
            self._valid = False

            if delete_maps:
                for evc_map in self.evc_maps:
                    dl.append(evc_map.delete(None))   # TODO: implement bulk-flow procedures

            yield defer.gatherResults(dl, consumeErrors=True)

        except Exception as e:
            log.exception('removal', e=e)

        self._evc_maps = None
        f, self._flow = self._flow, None
        if f is not None and f.handler is not None:
            f.handler.remove_evc(self)

        returnValue('Done')

    def reflow(self, reflow_maps=True):
        """
        Attempt to install/re-install a flow
        :param reflow_maps: (boolean) Flag indication if EVC-MAPs should be reflowed as well
        :return: (deferred)
        """
        self._installed = False

        if reflow_maps:
            for evc_map in self.evc_maps:
                evc_map.installed = False

        return self.schedule_install()

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

        if self._flow.inner_vid is not None:
            self._switching_method = EVC.SwitchingMethod.DOUBLE_TAGGED

        # For the Utility VLAN, multiple ingress ACLs (different GEMs) will need to
        # be trapped on this EVC. Since these are usually untagged, we have to force
        # the EVC to preserve CE VLAN tags.

        if self.s_tag == self._flow.handler.utility_vlan:
            self._ce_vlan_preservation = True

        # Note: The following fields may get set when the first EVC-MAP
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
</filter>""".strip().replace('\n', '')
        log.debug('query', xml=get_xml, regex=regex_)

        def request_failed(results, operation):
            log.error('{}-failed'.format(operation), results=results)
            # No further actions. Periodic poll later on will scrub any old EVCs if needed

        def delete_complete(results):
            log.debug('delete-complete', results=results)

        def do_delete(rpc_reply, regexpr):
            log.debug('query-complete', rpc_reply=rpc_reply)

            if rpc_reply.ok:
                result_dict = xmltodict.parse(rpc_reply.data_xml)
                entries = result_dict['data'].get('evcs') or {}

                evcs = entries.get('evc') or None
                if evcs:
                    p = re.compile(regexpr)
                    if isinstance(evcs, dict):
                        evcs = [evcs]
                    names = {entry.get('name') for entry in evcs if p.match(entry.get('name', ''))}

                    if names:
                        del_xml = ('<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs" '
                                   'xc:operation="delete">')
                        for name in sorted(names):
                            del_xml += '<evc>'
                            del_xml += '<name>{}</name>'.format(name)
                            del_xml += '</evc>'
                        del_xml += '</evcs>'
                        log.debug('removing', xml=del_xml)

                        return client.edit_config(del_xml)

            return succeed('no entries')

        d = client.get(get_xml)
        d.addCallbacks(do_delete, request_failed, callbackArgs=[regex_], errbackArgs=['get'])
        d.addCallbacks(delete_complete, request_failed, errbackArgs=['edit-config'])
        return d
