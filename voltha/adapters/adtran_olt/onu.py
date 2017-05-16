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
import base64
import json

import structlog

from adtran_olt_handler import AdtranOltHandler

log = structlog.get_logger()

_VSSN_TO_VENDOR = {
    'adtn': 'adtran_onu',
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
    MAX_ONU_ID = 1022
    BROADCAST_ONU_ID = 1023
    DEFAULT_PASSWORD = ''

    def __init__(self, serial_number, parent, password=DEFAULT_PASSWORD):
        self.onu_id = parent.get_next_onu_id()
        self.serial_number = serial_number
        self.password = password
        self.parent = parent

        try:
            sn_ascii = base64.decodestring(serial_number).lower()[:4]
        except Exception:
            sn_ascii = 'Invalid_VSSN'

        self.vendor_device = _VSSN_TO_VENDOR.get(sn_ascii,
                                                 'Unsupported_{}'.format(sn_ascii))

    def __del__(self):
        # self.stop()
        pass

    def __str__(self):
        return "Onu-{}-{}/{} parent: {}".format(self.onu_id, self.serial_number,
                                                base64.decodestring(self.serial_number),
                                                self.parent)

    def create(self, enabled):
        """
        POST -> /restconf/data/gpon-olt-hw:olt/pon=<pon-id>/onus/onu ->
        """
        pon_id = self.parent.pon_id
        data = json.dumps({'onu-id': self.onu_id,
                           'serial-number': self.serial_number,
                           'enable': enabled})
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(pon_id)
        name = 'onu-create-{}-{}-{}: {}'.format(pon_id, self.onu_id, self.serial_number, enabled)
        return self.parent.parent.rest_client.request('POST', uri, data=data, name=name)

    def set_config(self, leaf, value):
        pon_id = self.parent.pon_id
        data = json.dumps({'onu-id': self.onu_id,
                           leaf: value})
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(pon_id)
        name = 'pon-set-config-{}-{}-{}'.format(self.pon_id, leaf, str(value))
        name = 'onu-set-config-{}-{}-{}: {}'.format(pon_id, self.onu_id, leaf, value)
        return self.parent.parent.rest_client.request('PATCH', uri, data=data, name=name)
