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


class OltState(object):
    """
    Class to wrap decode of olt-state container from the ADTRAN
    gpon-olt-hw.yang YANG model
    """

    def __init__(self, packet):
        self._packet = packet
        self._pons = None

    def __str__(self):
        return "OltState: {}".format(self.software_version)

    @property
    def software_version(self):
        """The software version of olt driver"""
        return self._packet.get('software-version', '')

    @property
    def pons(self):
        if self._pons is None:
            self._pons = OltState.Pon.decode(self._packet.get('pon', None))
        return self._pons

    #############################################################
    # Act like a container for simple access into PON list

    def __len__(self):
        return len(self.pons)

    def __getitem__(self, key):
        if not isinstance(key, int):
            raise TypeError('Key should be of type int')
        if key not in self.pons:
            raise KeyError("key '{}' not found".format(key))

        return self.pons[key]

    def __iter__(self):
        raise NotImplementedError('TODO: Not yet implemented')

    def __contains__(self, item):
        if not isinstance(item, int):
            raise TypeError('Item should be of type int')
        return item in self.pons

    # TODO: Look at generator support and if it is useful

    class Pon(object):
        """
        Provides decode of PON list from within
        """
        def __init__(self, packet):
            assert 'pon-id' in packet
            self._packet = packet
            self._onus = None
            self._gems = None

        def __str__(self):
            return "OltState.Pon: pon-id: {}".format(self.pon_id)

        @staticmethod
        def decode(pon_list):
            # log.debug('Decoding PON List:{}{}'.format(os.linesep,
            #                                           pprint.PrettyPrinter().pformat(pon_list)))
            pons = {}
            for pon_data in pon_list:
                pon = OltState.Pon(pon_data)
                assert pon.pon_id not in pons
                pons[pon.pon_id] = pon

            return pons

        @property
        def pon_id(self):
            """PON identifier"""
            return self._packet['pon-id']

        @property
        def downstream_wavelength(self):
            """The wavelength, in nanometers, being used in the downstream direction"""
            return self._packet.get('downstream-wavelength', 0)

        @property
        def upstream_wavelength(self):
            """The wavelength, in nanometers, being used in the upstream direction"""
            return self._packet.get('upstream-wavelength', 0)

        @property
        def downstream_channel_id(self):
            """Downstream wavelength channel identifier associated with this PON."""
            return self._packet.get('downstream-channel-id', 0)

        @property
        def rx_packets(self):
            """Sum all of the RX Packets of GEM ports that are not base TCONT's"""
            return int(self._packet.get('rx-packets', 0))

        @property
        def tx_packets(self):
            """Sum all of the TX Packets of GEM ports that are not base TCONT's"""
            return int(self._packet.get('tx-packets', 0))

        @property
        def rx_bytes(self):
            """Sum all of the RX Octets of GEM ports that are not base TCONT's"""
            return int(self._packet.get('rx-bytes', 0))

        @property
        def tx_bytes(self):
            """Sum all of the TX Octets of GEM ports that are not base TCONT's"""
            return int(self._packet.get('tx-bytes', 0))

        @property
        def tx_bip_errors(self):
            """Sum the TX ONU bip errors to get TX BIP's per PON"""
            return int(self._packet.get('tx-bip-errors', 0))

        @property
        def wm_tuned_out_onus(self):
            """
            bit array indicates the list of tuned out ONU's that are in wavelength
            mobility protecting state.
                onu-bit-octects:
                  type binary { length "4 .. 1024"; }
                  description  each bit position indicates corresponding ONU's status
                               (true or false) whether that ONU's is in
                               wavelength mobility protecting state or not
                               For 128 ONTs per PON, the size of this
                               array will be 16. onu-bit-octects[0] and MSB bit in that byte
                               represents ONU 0 etc.
            """
            return self._packet.get('wm-tuned-out-onus', bytes(0))

        @property
        def ont_los(self):
            """List of configured ONTs that have been previously discovered and are in a los of signal state"""
            return self._packet.get('ont-los', [])

        @property
        def discovered_onu(self):
            """
            Immutable Set of each Optical Network Unit(ONU) that has been activated via discovery
                key/value: serial-number (string)
            """
            return frozenset([sn['serial-number'] for sn in self._packet.get('discovered-onu', [])
                              if 'serial-number' in sn and sn['serial-number'] != 'AAAAAAAAAAA='])

        @property
        def gems(self):
            """This list is not in the proposed BBF model, the stats are part of ietf-interfaces"""
            if self._gems is None:
                self._gems = OltState.Pon.Gem.decode(self._packet.get('gem', []))
            return self._gems

        @property
        def onus(self):
            """
            The map of each Optical Network Unit(ONU).  Key: ONU ID (int)
            """
            if self._onus is None:
                self._onus = OltState.Pon.Onu.decode(self._packet.get('onu', []))
            return self._onus

        class Onu(object):
            """
            Provides decode of onu list for a PON port
            """
            def __init__(self, packet):
                assert 'onu-id' in packet, 'onu-id not found in packet'
                self._packet = packet

            def __str__(self):
                return "OltState.Pon.Onu: onu-id: {}".format(self.onu_id)

            @staticmethod
            def decode(onu_list):
                # log.debug('onus:{}{}'.format(os.linesep,
                #                              pprint.PrettyPrinter().pformat(onu_list)))
                onus = {}
                for onu_data in onu_list:
                    onu = OltState.Pon.Onu(onu_data)
                    assert onu.onu_id not in onus
                    onus[onu.onu_id] = onu

                return onus

            @property
            def onu_id(self):
                """The ID used to identify the ONU"""
                return self._packet['onu-id']

            @property
            def oper_status(self):
                """The operational state of each ONU"""
                return self._packet.get('oper-status', 'unknown')

            @property
            def reported_password(self):
                """The password reported by the ONU (binary)"""
                return self._packet.get('reported-password', bytes(0))

            @property
            def rssi(self):
                """The received signal strength indication of the ONU"""
                return self._packet.get('rssi', -9999)

            @property
            def equalization_delay(self):
                """Equalization delay (bits)"""
                return self._packet.get('equalization-delay', 0)

            @property
            def fiber_length(self):
                """Distance to ONU"""
                return self._packet.get('fiber-length', 0)

        class Gem(object):
            """
            Provides decode of onu list for a PON port
            """
            def __init__(self, packet):
                assert 'onu-id' in packet, 'onu-id not found in packet'
                assert 'port-id' in packet, 'port-id not found in packet'
                assert 'alloc-id' in packet, 'alloc-id not found in packet'
                self._packet = packet

            def __str__(self):
                return "OltState.Pon.Gem: onu-id: {}, gem-id: {}".\
                    format(self.onu_id, self.gem_id)

            @staticmethod
            def decode(gem_list):
                # log.debug('gems:{}{}'.format(os.linesep,
                #                              pprint.PrettyPrinter().pformat(gem_list)))
                gems = {}
                for gem_data in gem_list:
                    gem = OltState.Pon.Gem(gem_data)
                    assert gem.gem_id not in gems
                    gems[gem.gem_id] = gem

                return gems

            @property
            def onu_id(self):
                """The ID used to identify the ONU"""
                return self._packet['onu-id']

            @property
            def alloc_id(self):
                return self._packet['alloc-id']

            @property
            def gem_id(self):
                return self._packet['port-id']

            @property
            def tx_packets(self):
                return int(self._packet.get('tx-packets', 0))

            @property
            def tx_bytes(self):
                return int(self._packet.get('tx-bytes', 0))

            @property
            def rx_packets(self):
                return int(self._packet.get('rx-packets', 0))

            @property
            def rx_bytes(self):
                return int(self._packet.get('rx-bytes', 0))
