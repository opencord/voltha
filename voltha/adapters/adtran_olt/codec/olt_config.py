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

import pprint

import os
import structlog

log = structlog.get_logger()


class OltConfig(object):
    """
    Class to wrap decode of olt container (config) from the ADTRAN
    gpon-olt-hw.yang YANG model
    """
    def __init__(self, packet):
        self._packet = packet
        self._pons = None

    def __str__(self):
        return "OltConfig: {}".format(self.olt_id)

    @property
    def olt_id(self):
        """Unique OLT identifier"""
        return self._packet.get('olt-id', '')

    @property
    def debug_output(self):
        """least important level that will output everything"""
        return self._packet.get('debug-output', 'warning')

    @property
    def pons(self):
        if self._pons is None:
            self._pons = OltConfig.Pon.decode(self._packet.get('pon', None))
        return self._pons

    class Pon(object):
        """
        Provides decode of PON list from within
        """
        def __init__(self, packet):
            assert 'pon-id' in packet, 'pon-id not found'
            self._packet = packet
            self._onus = None

        def __str__(self):
            return "OltConfig.Pon: pon-id: {}".format(self.pon_id)

        @staticmethod
        def decode(pon_list):
            pons = {}

            if pon_list is not None:
                for pon_data in pon_list:
                    pon = OltConfig.Pon(pon_data)
                    assert pon.pon_id not in pons
                    pons[pon.pon_id] = pon

            return pons

        @property
        def pon_id(self):
            """PON identifier"""
            return self._packet['pon-id']

        @property
        def enabled(self):
            """The desired state of the interface"""
            return self._packet.get('enabled', False)

        @property
        def downstream_fec_enable(self):
            """Enables downstream Forward Error Correction"""
            return self._packet.get('downstream-fec-enable', False)

        @property
        def upstream_fec_enable(self):
            """Enables upstream Forward Error Correction"""
            return self._packet.get('upstream-fec-enable', False)

        @property
        def deployment_range(self):
            """Maximum deployment distance (meters)"""
            return self._packet.get('deployment-range', 25000)

        @property
        def onus(self):
            if self._onus is None:
                self._onus = OltConfig.Pon.Onu.decode(self._packet.get('onus', None))
            return self._onus

        class Onu(object):
            """
            Provides decode of onu list for a PON port
            """
            def __init__(self, packet):
                assert 'onu-id' in packet, 'onu-id not found'
                self._packet = packet
                self._tconts = None
                self._tconts_dict = None
                self._gem_ports = None
                self._gem_ports_dict = None

            def __str__(self):
                return "OltConfig.Pon.Onu: onu-id: {}".format(self.onu_id)

            @staticmethod
            def decode(onu_dict):
                onus = {}

                if onu_dict is not None:
                    if 'onu' in onu_dict:
                        for onu_data in onu_dict['onu']:
                            onu = OltConfig.Pon.Onu(onu_data)
                            assert onu.onu_id not in onus
                            onus[onu.onu_id] = onu
                    elif len(onu_dict) > 0 and 'onu-id' in onu_dict[0]:
                        onu = OltConfig.Pon.Onu(onu_dict[0])
                        assert onu.onu_id not in onus
                        onus[onu.onu_id] = onu

                return onus

            @property
            def onu_id(self):
                """The ID used to identify the ONU"""
                return self._packet['onu-id']

            @property
            def serial_number_64(self):
                """The serial number (base-64) is unique for each ONU"""
                return self._packet.get('serial-number', '')

            @property
            def password(self):
                """ONU Password"""
                return self._packet.get('password', bytes(0))

            @property
            def enable(self):
                """If true, places the ONU in service"""
                return self._packet.get('enable', False)

            @property
            def tconts(self):
                if self._tconts is None:
                    self._tconts = OltConfig.Pon.Onu.TCont.decode(self._packet.get('t-conts', None))
                return self._tconts

            @property
            def tconts_dict(self):               # TODO: Remove if not used
                if self._tconts_dict is None:
                    self._tconts_dict = {self.tconts[tcont].alloc_id: self.tconts[tcont] for tcont in self.tconts}
                return self._tconts_dict

            @property
            def gem_ports(self):
                if self._gem_ports is None:
                    self._gem_ports = OltConfig.Pon.Onu.GemPort.decode(self._packet.get('gem-ports', None))
                return self._gem_ports

            @property
            def gem_ports_dict(self):               # TODO: Remove if not used
                if self._gem_ports_dict is None:
                    self._gem_ports_dict = {self.gem_ports[gem].gem_id: self.gem_ports[gem] for gem in self.gem_ports}
                return self._gem_ports_dict

            class TCont(object):
                """
                Provides decode of onu list for the T-CONT container
                """
                def __init__(self, packet):
                    assert 'alloc-id' in packet, 'alloc-id not found'
                    self._packet = packet
                    self._traffic_descriptor = None
                    self._best_effort = None

                def __str__(self):
                    return "OltConfig.Pon.Onu.TCont: alloc-id: {}".format(self.alloc_id)

                @staticmethod
                def decode(tcont_container):
                    tconts = {}

                    if tcont_container is not None:
                        for tcont_data in tcont_container.get('t-cont', []):
                            tcont = OltConfig.Pon.Onu.TCont(tcont_data)
                            assert tcont.alloc_id not in tconts
                            tconts[tcont.alloc_id] = tcont

                    return tconts

                @property
                def alloc_id(self):
                    """The ID used to identify the T-CONT"""
                    return self._packet['alloc-id']

                @property
                def traffic_descriptor(self):
                    """
                    Each Alloc-ID is provisioned with a traffic descriptor that specifies
                    the three bandwidth component parameters: fixed bandwidth, assured
                    bandwidth, and maximum bandwidth, as well as the ternary eligibility
                    indicator for additional bandwidth assignment
                    """
                    if self._traffic_descriptor is None and 'traffic-descriptor' in self._packet:
                        self._traffic_descriptor = OltConfig.Pon.Onu.TCont.\
                            TrafficDescriptor(self._packet['traffic-descriptor'])
                    return self._traffic_descriptor

                class TrafficDescriptor(object):
                    def __init__(self, packet):
                        self._packet = packet

                    def __str__(self):
                        return "OltConfig.Pon.Onu.TCont.TrafficDescriptor: {}/{}/{}".\
                            format(self.fixed_bandwidth, self.assured_bandwidth,
                                   self.maximum_bandwidth)

                    @property
                    def fixed_bandwidth(self):
                        try:
                            return int(self._packet.get('fixed-bandwidth', 0))
                        except:
                            return 0

                    @property
                    def assured_bandwidth(self):
                        try:
                            return int(self._packet.get('assured-bandwidth', 0))
                        except:
                            return 0

                    @property
                    def maximum_bandwidth(self):
                        try:
                            return int(self._packet.get('maximum-bandwidth', 0))
                        except:
                            return 0

                    @property
                    def additional_bandwidth_eligibility(self):
                        return self._packet.get('additional-bandwidth-eligibility', 'none')

                @property
                def best_effort(self):
                    if self._best_effort is None:
                        self._best_effort = OltConfig.Pon.Onu.TCont.BestEffort.decode(
                            self._packet.get('best-effort', None))
                    return self._best_effort

                class BestEffort(object):
                    def __init__(self, packet):
                        self._packet = packet

                    def __str__(self):
                        return "OltConfig.Pon.Onu.TCont.BestEffort: {}".format(self.bandwidth)

                    @staticmethod
                    def decode(best_effort_container):
                        return OltConfig.Pon.Onu.TCont.BestEffort(best_effort_container)

                    @property
                    def bandwidth(self):
                        return self._packet['bandwidth']

                    @property
                    def priority(self):
                        return self._packet['priority']

                    @property
                    def weight(self):
                        return self._packet['weight']

            class GemPort(object):
                """
                Provides decode of onu list for the gem-ports container
                """
                def __init__(self, packet):
                    assert 'port-id' in packet, 'port-id not found'
                    self._packet = packet

                def __str__(self):
                    return "OltConfig.Pon.Onu.GemPort: port-id: {}/{}".\
                        format(self.port_id, self.alloc_id)

                @staticmethod
                def decode(gem_port_container):
                    gem_ports = {}

                    if gem_port_container is not None:
                        for gem_port_data in gem_port_container.get('gem-port', []):
                            gem_port = OltConfig.Pon.Onu.GemPort(gem_port_data)
                            assert gem_port.port_id not in gem_ports
                            gem_ports[gem_port.port_id] = gem_port

                    return gem_ports

                @property
                def port_id(self):
                    """The ID used to identify the GEM Port"""
                    return self._packet['port-id']

                @property
                def gem_id(self):
                    """The ID used to identify the GEM Port"""
                    return self.port_id

                @property
                def alloc_id(self):
                    """The Alloc-ID of the T-CONT to which this GEM port is mapped"""
                    return self._packet['alloc-id']

                @property
                def omci_transport(self):
                    """If true, this GEM port is used to transport the OMCI virtual connection"""
                    return self._packet.get('omci-transport', False)

                @property
                def encryption(self):
                    """If true, enable encryption using the advanced encryption standard(AES)"""
                    return self._packet.get('encryption', False)
