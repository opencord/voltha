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

"""
systems
"""
from constants import Defaults, UriConst
import json


class Systems (object):
    def __init__(self, rest_client):
        self.sys_reset_uri = ''
        # GracefulRestart/PushPowerButton/NMI.
        self.reset_allow_values = ["GracefulRestart"]
        self.rest_client = rest_client
        self.log = rest_client.log
        self.system_reboot_uri_get()

    def reboot_olt(self, reset_type=Defaults.reset_type):
        """
        """
        try:
            if(reset_type in self.reset_allow_values):
                self.log.info("Rebooting-ASFVOLT16-OLT")
                self.rest_client.http_post(uri=self.sys_reset_uri,
                                           data=json.dumps({"ResetType":
                                                            str(reset_type)}))
            else:
                self.log.debug("Reset-Type-not-supported.")
        except Exception as e:
            self.log.debug("Exception-Occured-:", str(e))

    def system_get(self, sys_info_dict, uri=UriConst.systems_uri):
        """
        """
        uri = UriConst.base_uri + uri
        try:
            response = self.rest_client.http_get(uri)
            for member in json.loads(response.text)['Members']:
                response = self.rest_client.http_get(member['@odata.id'])
                sys_dict = json.loads(response.text)
                sys_info_dict["AssetTag"] = sys_dict["AssetTag"]
                sys_info_dict["Manufacturer"] = sys_dict["Manufacturer"]
                sys_info_dict["Model"] = sys_dict["Model"]
                sys_info_dict["SKU"] = sys_dict["SKU"]
                sys_info_dict["SerialNumber"] = sys_dict["SerialNumber"]
                sys_info_dict["PartNumber"] = sys_dict["PartNumber"]
                sys_info_dict["UUID"] = sys_dict["UUID"]
                sys_info_dict["BiosVersion"] = sys_dict["BiosVersion"]
                sys_info_dict["ProductName"] = sys_dict["ProductName"]
                sys_info_dict["MACAddress"] = sys_dict["MACAddress"]
                sys_info_dict["MACRange"] = sys_dict["MACRange"]
                sys_info_dict["ManufactureDate"] = sys_dict["ManufactureDate"]
                sys_info_dict["PlatformName"] = sys_dict["PlatformName"]
                sys_info_dict["LabelRevision"] = sys_dict["LabelRevision"]
                sys_info_dict["CountryCode"] = sys_dict["CountryCode"]
                sys_info_dict["DiagVersion"] = sys_dict["DiagVersion"]
                sys_info_dict["OnieVersion"] = sys_dict["OnieVersion"]
                self.log.info("System-Info-:", system_details=sys_info_dict)

        except Exception as e:
            self.log.debug("Exception-occurred-:", str(e))

    def system_reboot_uri_get(self, uri=UriConst.systems_uri):
        """
        """
        uri = UriConst.base_uri + uri
        try:
            response = self.rest_client.http_get(uri)
            for member in json.loads(response.text)['Members']:
                response = self.rest_client.http_get(member['@odata.id'])
                sys_dict = json.loads(response.text)
                if(sys_dict["Actions"]):
                    if(sys_dict["Actions"]["#ComputerSystem.Reset"]):
                        self.sys_reset_uri = sys_dict["Actions"]\
                        ["#ComputerSystem.Reset"]["target"]
                        self.reset_allow_values = sys_dict["Actions"]\
                        ["#ComputerSystem.Reset"]\
                        ["ResetType@Redfish.AllowableValues"]
        except Exception as e:
            self.log.debug("Exception-occurred-:", str(e))
