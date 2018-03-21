#
# Copyright 2017 the original author or authors.
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

from twisted.internet.defer import inlineCallbacks

"""
Asfvolt16 Device specific information handler
"""


class Asfvolt16DeviceTopology(object):
    def __init__(self, nnis=4, pons=16, mac_devs=8, mac_per_dev=2,
                 pon_sub_family="BAL_PON_SUB_FAMILY_XGPON"):
        self.num_of_nni_ports = nnis
        self.num_of_pon_ports = pons
        self.num_of_mac_devs = mac_devs
        self.num_of_pons_per_mac_dev = mac_per_dev
        self.pon_sub_family = pon_sub_family


class Asfvolt16DeviceSoftwareInfo(object):
    def __init__(self, ver_type="BAL_VERSION_TYPE_RELEASE", maj_ver=2,
                 min_ver=4, om_ver=1):
        self.version_type = ver_type
        self.major_version = maj_ver
        self.minor_version = min_ver
        self.om_version = om_ver


class Asfvolt16DeviceInfo(object):
    def __init__(self, bal, log, device_id):
        self.bal = bal
        self.log = log
        self.device_id = device_id
        self.asfvolt16_device_topology = Asfvolt16DeviceTopology()
        self.asfvolt16_device_sw_info = Asfvolt16DeviceSoftwareInfo()
        self.sfp_device_presence_map = dict()

    def update_device_topology(self, access_term_ind):
        try:
            self.asfvolt16_device_topology.num_of_nni_ports = \
                access_term_ind.data.topology.num_of_nni_ports
            self.asfvolt16_device_topology.num_of_pon_ports = \
                access_term_ind.data.topology.num_of_pon_ports
            self.asfvolt16_device_topology.num_of_mac_devs = \
                access_term_ind.data.topology.num_of_mac_devs
            self.asfvolt16_device_topology.num_of_pons_per_mac_dev = \
                access_term_ind.data.topology.num_of_pons_per_mac_dev
            self.asfvolt16_device_topology.pon_sub_family = \
                access_term_ind.data.topology.pon_sub_family
        except Exception as e:
            self.log.error("error-reading-topology", e=e)

    def update_device_software_info(self, access_term_ind):
        try:
            self.asfvolt16_device_sw_info.version_type = \
                access_term_ind.data.sw_version.version_type
            self.asfvolt16_device_sw_info.major_rev = \
                access_term_ind.data.sw_version.major_rev
            self.asfvolt16_device_sw_info.minor_rev = \
                access_term_ind.data.sw_version.minor_rev
            self.asfvolt16_device_sw_info.om_version = \
                access_term_ind.data.sw_version.om_version
        except Exception as e:
            self.log.error("error-reading-software-info", e=e)

    @inlineCallbacks
    def read_and_build_device_sfp_presence_map(self):
        try:
            sfp_presence_bitmap = \
                yield self.bal.get_asfvolt_sfp_presence_map(self.device_id)
            for i in range(self.asfvolt16_device_topology.num_of_pon_ports + \
                           self.asfvolt16_device_topology.num_of_nni_ports):
                if (1 << i) & int(sfp_presence_bitmap):
                    self.sfp_device_presence_map[i] = True
        except Exception as e:
            self.log.error("read_and_build_device_sfp_presence_map", e=e)
