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
chassis
"""
import json
from twisted.internet import reactor, task
from constants import UriConst, Defaults


class Chassis(object):
    def __init__(self, rest_client):
        self.log = rest_client.log
        self.rest_client = rest_client
        self.chassis_list = []
        self.chassis_get()

    def chassis_get(self, uri=UriConst.chassis_uri):
        """
        Method to parse Uri for fans and psu.
        """
        uri = UriConst.base_uri + uri
        try:
            response = self.rest_client.http_get(uri)
            for member in json.loads(response.text)['Members']:
                response = self.rest_client.http_get(member['@odata.id'])
                chassis_dict = json.loads(response.text)
                if (chassis_dict['Status']['State'] == 'Enabled'):
                    self.chassis_list.append(chassis_dict)
                    return True
            return False
        except Exception as e:
            self.log.debug("Exception-occurred-:", str(e))
            return False

    def fans_get(self):
        """
        Method to get fan health status.
        """
        for chassis in self.chassis_list:
            thermal_uri = chassis['Links']['Thermal'][0]['@odata.id']
            try:
                response = self.rest_client.http_get(thermal_uri)
                fans_list = json.loads(response.text)['Fans']
                for fan in fans_list:
                    response = self.rest_client.http_get(fan['@odata.id'])
                    fan_dict = json.loads(response.text)['Fan']
                    self.log.info("Fan-Info-:", Id=fan_dict['Id'],
                                  rpm=fan_dict['Reading'],
                                  State=fan_dict['Status']['State'],
                                  Health=fan_dict['Status']['Health'])

                    if (fan_dict['Status']['Health'] != 'OK'):
                        # Raise Alarm
                        self.rest_client.generate_alarm(
                            status=True,
                            alarm={'Health-check-failed-for-Fan':
                                   str(fan_dict['Id'])},
                            alarm_severity=fan_dict['Status']['Health'])
                        self.log.info("Raising-alarm-for-fan",
                                      Id=fan_dict['Id'])
            except Exception as e:
                self.log.debug("Exception-occurred-:", str(e))

    def psu_get(self):
        """
        Method to get psu health status.
        """
        for chassis in self.chassis_list:
            power_uri = chassis['Links']['Power'][0]['@odata.id']
            try:
                response = self.rest_client.http_get(power_uri)
                psu_list = json.loads(response.text)['Power']
                for psu in psu_list:
                    response = self.rest_client.http_get(psu['@odata.id'])
                    psu_dict = json.loads(response.text)['PowerSupply']
                    self.log.info("Power-Supply-:",
                                  Id=psu_dict['MemberId'],
                                  Power=psu_dict['PowerConsumedWatts'],
                                  Temperature=psu_dict['PsuTemperature'],
                                  FanRpm=psu_dict['PsuFanRpm'],
                                  State=psu_dict['Status']['State'],
                                  Health=psu_dict['Status']['Health'])

                    if (psu_dict['Status']['Health'] != 'OK'):
                        # Raise Alarm
                        self.rest_client.generate_alarm(
                            status=True,
                            alarm={'Health-check-failed-for-Psu':
                                    str(psu_dict['MemberId'])},
                            alarm_severity=psu_dict['Status']['Health'])
                        self.log.info("Raising-alarm-for-PSU",
                                          Id=psu_dict['MemberId'])
            except Exception as e:
                self.log.debug("Exception-occurred-:", str(e))

    def get_chassis_health(self):
        self.fans_get()
        self.psu_get()
        self.health_thread = reactor.callLater(
            Defaults.health_check_interval,
            self.get_chassis_health)

    def stop_chassis_monitoring(self):
        try:
            h, self.health_thread = self.health_thread, None
            if(h is not None):
                h.cancel()
        except Exception as e:
            self.log.debug("Exception-occured-:", str(e))
