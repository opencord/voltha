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

from enum import Enum
from twisted.internet.defer import inlineCallbacks, returnValue
from voltha.core.flow_decomposer import *

log = structlog.get_logger()

EVC_NAME_FORMAT = 'EVC-VOLTHA-{}-{}'
EVC_NAME_REGEX = 'EVC-VOLTHA-{}'.format('regex-here')
DEFAULT_STPID = 0x8100

_xml_header = '<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs"><evc>'
_xml_trailer = '</evc></evcs>'


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
        SYMETRIC = 1
        POP_OUT_TAG_ONLY = 2
        DEFAULT = SYMETRIC

        @staticmethod
        def xml(value):
            if value is None:
                value = EVC.Men2UniManipulation.DEFAULT
            fmt = '<men-to-uni-tag-manipulation>{}</men-to-uni-tag-manipulation>'
            if value == EVC.Men2UniManipulation.SYMETRIC:
                return fmt.format('<symetric/>')
            elif value == EVC.Men2UniManipulation.POP_OUT_TAG_ONLY:
                return fmt.format('<pop-outer-tag-only/>')
            raise ValueError('Invalid Men2UniManipulation enumeration')

    class ElineFlowType(Enum):
        NNI_TO_UNI = 1
        UNI_TO_NNI = 2
        NNI_TO_NNI = 3
        ACL_FILTER = 4
        UNKNOWN = 5
        UNSUPPORTED = 5    # Or Invalid

    def __init__(self, flow_entry):
        self._installed = False
        self._status_message = None
        self._flow = flow_entry
        self._name = self._create_name()
        self._evc_maps = {}             # Map Name -> evc-map

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

    def _create_name(self):
        #
        # TODO: Take into account selection criteria and output to make the name
        #
        return EVC_NAME_FORMAT.format(self._flow.device_id, self._flow.flow_id)

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
        self.ce_vlan_preservation = value

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

    @inlineCallbacks
    def install(self):
        if self._valid and not self._installed:
            xml = _xml_header
            xml += '<name>{}</name>'.format(self.name)
            xml += '<enabled>{}</enabled>'.format(self._enabled)
            xml += '<ce-vlan-preservation>{}</ce-vlan-preservation>'.\
                format(self._ce_vlan_preservation or True)

            if self._s_tag is not None:
                xml += '<stag>{}</stag>'.format(self._s_tag)
                xml += '<stag-tpid>{:#x}</stag-tpid>'.format(self._stpid or DEFAULT_STPID)
            else:
                xml += 'no-stag/'

            for port in self._men_ports:
                xml += '<men-ports>{}</men-ports>'.format(port)

            xml += EVC.Men2UniManipulation.xml(self._men_to_uni_tag_manipulation)
            xml += EVC.SwitchingMethod.xml(self._switching_method)
            xml += _xml_trailer

            log.debug("Creating EVC {}: '{}'".format(self.name, xml))

            try:
                results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                              default_operation='create',
                                                                              lock_timeout=30)
                self._installed = results.ok
                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error                    # TODO: Save off error status

            except Exception as e:
                log.exception('Failed to install EVC', name=self.name, e=e)
                raise

        returnValue(self._installed and self._valid)

    @inlineCallbacks
    def remove(self):
        if self._installed:
            xml = _xml_header + '<name>{}</name>'.format(self.name) + _xml_trailer

            log.debug("Deleting EVC {}: '{}'".format(self.name, xml))

            try:
                results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                              default_operation='delete',
                                                                              lock_timeout=30)
                self._installed = not results.ok
                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error             # TODO: Save off error status

            except Exception as e:
                log.exception('Failed to remove EVC', name=self.name, e=e)
                raise

            # TODO: Do we remove evc-maps as well reference here or maybe have a 'delete' function?
            pass

        returnValue(not self._installed)

    @inlineCallbacks
    def enable(self):
        if self.installed and not self._enabled:
            xml = _xml_header + '<name>{}</name>'.format(self.name)
            xml += '<enabled>true</enabled>' + _xml_trailer

            log.debug("Enabling EVC {}: '{}'".format(self.name, xml))

            try:
                results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                              default_operation='merge',
                                                                              lock_timeout=30)
                self._enabled = results.ok
                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error       # TODO: Save off error status

            except Exception as e:
                log.exception('Failed to enable EVC', name=self.name, e=e)
                raise

        returnValue(self.installed and self._enabled)

    @inlineCallbacks
    def disable(self):
        if self.installed and self._enabled:
            xml = _xml_header + '<name>{}</name>'.format(self.name)
            xml += '<enabled>false</enabled>' + _xml_trailer

            log.debug("Disabling EVC {}: '{}'".format(self.name, xml))

            try:
                results = yield self._flow.handler.netconf_client.edit_config(xml,
                                                                              default_operation='merge',
                                                                              lock_timeout=30)
                self._enabled = not results.ok
                if results.ok:
                    self.status = ''
                else:
                    self.status = results.error      # TODO: Save off error status

            except Exception as e:
                log.exception('Failed to disable EVC', name=self.name, e=e)
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

        if self._flow.inner_vid is not None:
            self._switching_method = EVC.SwitchingMethod.DOUBLE_TAGGED

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

