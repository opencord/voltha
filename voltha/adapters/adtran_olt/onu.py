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

import base64
import json

import structlog

from adtran_olt_handler import AdtranOltHandler

log = structlog.get_logger()

_VSSN_TO_VENDOR = {
    'adtn': 'adtran_onu',
    'adtr': 'adtran_onu',
    'bcm?': 'broadcom_onu',  # TODO: Get actual VSSN for this vendor
    'dp??': 'dpoe_onu',  # TODO: Get actual VSSN for this vendor
    'pmc?': 'pmcs_onu',  # TODO: Get actual VSSN for this vendor
    'psm?': 'ponsim_onu',  # TODO: Get actual VSSN for this vendor
    'sim?': 'simulated_onu',  # TODO: Get actual VSSN for this vendor
    'tbt?': 'tibit_onu',  # TODO: Get actual VSSN for this vendor
}


class Onu(object):
    """
    Wraps an ONU
    """
    MIN_ONU_ID = 0
    MAX_ONU_ID = 254
    BROADCAST_ONU_ID = 255
    # MAX_ONU_ID = 1022
    # BROADCAST_ONU_ID = 1023
    DEFAULT_PASSWORD = ''

    def __init__(self, serial_number, pon, password=DEFAULT_PASSWORD):
        self._onu_id = pon.get_next_onu_id()

        if self._onu_id is None:
            raise ValueError('No ONU ID available')

        self._serial_number = serial_number
        self._password = password
        self._pon = pon
        self._name = 'xpon {}/{}'.format(pon.pon_id, self._onu_id)

        try:
            sn_ascii = base64.decodestring(serial_number).lower()[:4]
        except Exception:
            sn_ascii = 'Invalid_VSSN'

        self._vendor_device = _VSSN_TO_VENDOR.get(sn_ascii,
                                                  'Unsupported_{}'.format(sn_ascii))

    def __del__(self):
        # self.stop()
        pass

    def __str__(self):
        return "Onu-{}-{}/{} parent: {}".format(self._onu_id, self._serial_number,
                                                base64.decodestring(self._serial_number),
                                                self._pon)

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
    def vendor_device(self):
        return self._vendor_device

    def create(self, enabled):
        """
        POST -> /restconf/data/gpon-olt-hw:olt/pon=<pon-id>/onus/onu ->
        """
        pon_id = self.pon.pon_id
        data = json.dumps({'onu-id': self._onu_id,
                           'serial-number': self._serial_number,
                           'enable': enabled})
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(pon_id)
        name = 'onu-create-{}-{}-{}: {}'.format(pon_id, self._onu_id, self._serial_number, enabled)

        return self.olt.rest_client.request('POST', uri, data=data, name=name)

    def set_config(self, leaf, value):
        pon_id = self.pon.pon_id
        data = json.dumps({'onu-id': self._onu_id,
                           leaf: value})
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(pon_id)
        name = 'onu-set-config-{}-{}-{}: {}'.format(pon_id, self._onu_id, leaf, value)
        return self.olt.rest_client.request('PATCH', uri, data=data, name=name)
