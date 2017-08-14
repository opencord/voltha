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

import base64
import binascii
import json
import structlog
from twisted.internet.defer import inlineCallbacks, returnValue, succeed

from adtran_olt_handler import AdtranOltHandler

# Following is only used in autoactivate/demo mode. Otherwise xPON
_VSSN_TO_VENDOR = {
    'ADTN': 'adtran_onu',
    'BCM?': 'broadcom_onu',   # TODO: Get actual VSSN for this vendor
    'DP??': 'dpoe_onu',       # TODO: Get actual VSSN for this vendor
    'PMC?': 'pmcs_onu',       # TODO: Get actual VSSN for this vendor
    'PSMO': 'ponsim_onu',
    'SIM?': 'simulated_onu',  # TODO: Get actual VSSN for this vendor
    'TBT?': 'tibit_onu',      # TODO: Get actual VSSN for this vendor
}


class Onu(object):
    """
    Wraps an ONU
    """
    MIN_ONU_ID = 0
    MAX_ONU_ID = 253            # G.984. 0..253, 254=reserved, 255=broadcast
    BROADCAST_ONU_ID = 255
    # MAX_ONU_ID = 1022           # G.987. 0..1022, 1023=broadcast
    # BROADCAST_ONU_ID = 1023
    DEFAULT_PASSWORD = ''

    def __init__(self, onu_info):
        # onu_info = {
        #     'serial-number': serial_number,
        #     'xpon-name': None,
        #     'pon-id': self.pon_id,
        #     'onu-id': None,  # Set later (mandatory)
        #     'enabled': True,
        #     'upstream-channel-speed': 0,
        #     't-cont': get_tconts(self.pon_id, serial_number),
        #     'gem-ports': get_gem_ports(self.pon_id, serial_number),
        # }
        self._onu_id = onu_info['onu-id']
        if self._onu_id is None:
            raise ValueError('No ONU ID available')

        self._serial_number_base64 = Onu.string_to_serial_number(onu_info['serial-number'])
        self._serial_number_string = onu_info['serial-number']
        self._password = onu_info['password']
        self._pon = onu_info['pon']
        self._name = '{}@{}'.format(self._pon.name, self._onu_id)
        self._xpon_name = onu_info['xpon-name']
        self._gem_ports = {}                           # gem-id -> GemPort
        self._tconts = {}                              # alloc-id -> TCont

        # TODO: enable and upstream-channel-speed not yet supported

        self.log = structlog.get_logger(pon_id=self._pon.pon_id, onu_id=self._onu_id)
        self._vendor_id = _VSSN_TO_VENDOR.get(self._serial_number_string.upper()[:4],
                                              'Unsupported_{}'.format(self._serial_number_string))

    def __del__(self):
        # self.stop()
        pass

    def __str__(self):
        return "Onu-{}-{}, PON: {}".format(self._onu_id, self._serial_number_string, self._pon)
    
    @staticmethod
    def serial_number_to_string(value):
        sval = base64.decodestring(value)
        unique = [elem.encode("hex") for elem in sval[4:8]]
        return '{}{}{}{}{}'.format(sval[:4], unique[0], unique[1], unique[2], unique[3]).upper()

    @staticmethod
    def string_to_serial_number(value):
        bvendor = [octet for octet in value[:4]]
        bunique = [binascii.a2b_hex(value[offset:offset + 2]) for offset in xrange(4, 12, 2)]
        bvalue = ''.join(bvendor + bunique)
        return base64.b64encode(bvalue)

    @property
    def pon(self):
        return self._pon

    @property
    def olt(self):
        return self.pon.olt

    @property
    def onu_id(self):
        return self._onu_id

    @property
    def name(self):
        return self._name

    @property
    def serial_number(self):
        return self._serial_number_base64

    @property
    def vendor_id(self):
        return self._vendor_id

    @inlineCallbacks
    def create(self, onu_info):
        """
        POST -> /restconf/data/gpon-olt-hw:olt/pon=<pon-id>/onus/onu ->
        """
        self.log.debug('create')

        pon_id = self.pon.pon_id
        data = json.dumps({'onu-id': self._onu_id,
                           'serial-number': self._serial_number_base64,
                           'enable': onu_info['enabled']})
        uri = AdtranOltHandler.GPON_ONU_CONFIG_LIST_URI.format(pon_id)
        name = 'onu-create-{}-{}-{}: {}'.format(pon_id, self._onu_id,
                                                self._serial_number_base64, onu_info['enabled'])

        try:
            results = yield self.olt.rest_client.request('POST', uri, data=data, name=name)

        except Exception as e:
            self.log.exception('onu-create', e=e)
            raise

        # Now set up all tconts & gem-ports

        for _, tcont in onu_info['t-conts'].items():
            try:
                results = yield self.add_tcont(tcont)

            except Exception as e:
                self.log.exception('add-tcont', tcont=tcont, e=e)

        for _, gem_port in onu_info['gem-ports'].items():
            try:
                if gem_port.multicast:
                    self.log.warning('multicast-not-yet-supported', gem_port=gem_port)  # TODO Support it
                    continue
                results = yield self.add_gem_port(gem_port)

            except Exception as e:
                self.log.exception('add-gem_port', gem_port=gem_port, e=e)

        returnValue(results)

    def set_config(self, leaf, value):
        self.log.debug('set-config', leaf=leaf, value=value)

        pon_id = self.pon.pon_id
        data = json.dumps({'onu-id': self._onu_id,
                           leaf: value})
        uri = AdtranOltHandler.GPON_ONU_CONFIG_LIST_URI.format(pon_id)
        name = 'onu-set-config-{}-{}-{}: {}'.format(pon_id, self._onu_id, leaf, value)
        return self.olt.rest_client.request('PATCH', uri, data=data, name=name)

    @property
    def alloc_ids(self):
        """
        Get alloc-id's of all T-CONTs
        """
        return frozenset(self._tconts.keys())

    @inlineCallbacks
    def add_tcont(self, tcont):
        """
        Creates/ a T-CONT with the given alloc-id

        :param tcont: (TCont) Object that maintains the TCONT properties
        """
        from tcont import TrafficDescriptor

        if tcont.alloc_id in self._tconts:
            returnValue(succeed('already created'))

        pon_id = self.pon.pon_id
        uri = AdtranOltHandler.GPON_TCONT_CONFIG_LIST_URI.format(pon_id, self.onu_id)
        data = json.dumps({'alloc-id': tcont.alloc_id})
        name = 'tcont-create-{}-{}: {}'.format(pon_id, self._onu_id, tcont.alloc_id)

        try:
            results = yield self.olt.rest_client.request('POST', uri, data=data, name=name)
            self._tconts[tcont.alloc_id] = tcont

        except Exception as e:
            self.log.exception('tcont', tcont=tcont, e=e)
            raise

        # TODO May want to pull this out and have it accessible elsewhere once xpon work supports TDs

        if tcont.traffic_descriptor is not None:
            uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(pon_id, self.onu_id, tcont.alloc_id)
            data = json.dumps({'traffic-descriptor': tcont.traffic_descriptor.to_dict()})
            name = 'tcont-td-{}-{}: {}'.format(pon_id, self._onu_id, tcont.alloc_id)
            try:
                results = yield self.olt.rest_client.request('PATCH', uri, data=data, name=name)

            except Exception as e:
                self.log.exception('traffic-descriptor', td=tcont.traffic_descriptor, e=e)

            if tcont.traffic_descriptor.additional_bandwidth_eligibility == \
               TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING:
                if tcont.best_effort is None:
                    raise ValueError('TCONT {} is best-effort but does not define best effort sharing'.
                                     format(tcont.name))

                data = json.dumps({'best-effort': tcont.best_effort.to_dict()})
                name = 'tcont-best-effort-{}-{}: {}'.format(pon_id, self._onu_id, tcont.alloc_id)
                try:
                    results = yield self.olt.rest_client.request('PATCH', uri, data=data, name=name)

                except Exception as e:
                    self.log.exception('best-effort', best_effort=tcont.best_effort, e=e)
                    raise

        returnValue(results)

    def remove_tcont(self, alloc_id):
        if alloc_id in self._tconts:
            del self._tconts[alloc_id]

        # Always remove from OLT hardware
        pon_id = self.pon.pon_id
        uri = AdtranOltHandler.GPON_TCONT_CONFIG_URI.format(pon_id, self.onu_id, alloc_id)
        name = 'tcont-delete-{}-{}: {}'.format(pon_id, self._onu_id, alloc_id)
        return self.olt.rest_client.request('DELETE', uri, name=name)

    #@property
    def gem_ids(self, exception_gems):
        """Get all GEM Port IDs used by this ONU"""
        return frozenset([gem_id for gem_id, gem in self._gem_ports.items()
                         if gem.exception == exception_gems])
        # return frozenset(self._gem_ports.keys())

    @inlineCallbacks
    def add_gem_port(self, gem_port):
        if gem_port.gem_id in self._gem_ports:
            returnValue(succeed('already created'))

        pon_id = self.pon.pon_id
        uri = AdtranOltHandler.GPON_GEM_CONFIG_LIST_URI.format(pon_id, self.onu_id)
        data = json.dumps(gem_port.to_dict())
        name = 'gem-port-create-{}-{}: {}/{}'.format(pon_id, self._onu_id,
                                                     gem_port.gem_id,
                                                     gem_port.alloc_id)
        try:
            results = yield self.olt.rest_client.request('POST', uri, data=data, name=name)
            self._gem_ports[gem_port.gem_id] = gem_port
            # TODO: May need to update flow tables/evc-maps

        except Exception as e:
            self.log.exception('gem-port', e=e)
            raise

        returnValue(results)

    def remove_gem_id(self, gem_id):
        if gem_id in self._gem_ports:
            del self._gem_ports[gem_id]
            # TODO: May need to update flow tables/evc-maps

        # Always remove from OLT hardware
        pon_id = self.pon.pon_id
        uri = AdtranOltHandler.GPON_GEM_CONFIG_URI.format(pon_id, self.onu_id, gem_id)
        name = 'gem-port-delete-{}-{}: {}'.format(pon_id, self._onu_id, gem_id)
        return self.olt.rest_client.request('DELETE', uri, name=name)

    @staticmethod
    def gem_id_to_gvid(gem_id):
        """Calculate GEM VID for a given GEM port id"""
        return gem_id - 2048
