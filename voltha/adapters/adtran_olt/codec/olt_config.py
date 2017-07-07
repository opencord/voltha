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
            assert 'pon-id' in packet
            self._packet = packet
            self._onus = None

        def __str__(self):
            return "OltConfig.Pon: pon-id: {}".format(self.pon_id)

        @staticmethod
        def decode(pon_list):
            log.info('Decoding PON List:{}{}'.format(os.linesep,
                                                     pprint.PrettyPrinter().pformat(pon_list)))
            pons = {}
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
            return self._packet.get('enabled', True)

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
                self._onus = OltConfig.Pon.decode(self._packet.get('pon', None))
            return self._onus

        class Onu(object):
            """
            Provides decode of onu list for a PON port
            """

            def __init__(self, packet):
                assert 'onu-id' in packet
                self._packet = packet

            def __str__(self):
                return "OltConfig.Pon.Onu: onu-id: {}".format(self.onu_id)

            @staticmethod
            def decode(onu_list):
                log.debug('onus:{}{}'.format(os.linesep,
                                             pprint.PrettyPrinter().pformat(onu_list)))
                onus = {}
                for onu_data in onu_list:
                    onu = OltConfig.Pon.Onu(onu_data)
                    assert onu.onu_id not in onus
                    onus[onu.onu_id] = onu

                return onus

            @property
            def onu_id(self):
                """The ID used to identify the ONU"""
                return self._packet['onu-id']

            @property
            def serial_number(self):
                """The serial number is unique for each ONU"""
                return self._packet.get('serial-number', '')

            @property
            def password(self):
                """ONU Password"""
                return self._packet.get('password', bytes(0))

            @property
            def enable(self):
                """If true, places the ONU in service"""
                return self._packet.get('enable', False)

                # TODO: TCONT and GEM lists
