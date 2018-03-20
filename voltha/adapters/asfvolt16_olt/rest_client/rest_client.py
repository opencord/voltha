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
rest_client
"""
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import arrow
from chassis import Chassis
from systems import Systems
from ethernet import Ethernet
from constants import UriConst, RestConst, Defaults
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory


class RestClient(object):
    def __init__(self, host_and_port, adapter, log, device_id):
        self.log = log
        self.headers = {'Accept-Encoding': None}
        self.device_id = device_id
        self.adapter_agent = adapter.adapter_agent
        self.adapter_name = adapter.name
        self.host_and_port = host_and_port.split(':')[0] +\
        Defaults.redfish_port
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.chassis_obj = Chassis(self)
        self.systems_obj = Systems(self)
        self.ethernet_obj = Ethernet(self)
        self.sys_info = {}

    def get_system_details(self):
        """
        Method to fetch OLT info.
        This method is supposed to get invoked from NBI API get_device_details.
        Currently the get_device_details() is in NotImplemented stated
        """

        self.systems_obj.system_get(self.sys_info)
        return self.sys_info

    def start_health_monitoring(self):
        """
        Method to fetch health status of asfvolt16 olt hardware modules
        """
        self.chassis_obj.get_chassis_health()
        self.ethernet_obj.get_ethernet_health()

    def stop_health_monitoring(self):
        """
        Method to stop health monitoring of asfvolt16 olt modules
        are not controlled by bal
        """
        self.chassis_obj.stop_chassis_monitoring()
        self.ethernet_obj.stop_ether_monitoring()

    def reboot_device(self):
        """
        Reboot asfvolt16 olt through Redfish service
        """
        self.systems_obj.reboot_olt()

    def generate_alarm(self, status, alarm, alarm_severity):
        """
        Method to create and submit alarms.
        """
        if(alarm_severity == "Warning"):
            al_severity = AlarmEventSeverity.WARNING
        elif (alarm_severity == "Critical"):
            al_severity = AlarmEventSeverity.CRITICAL
        try:
            ts = arrow.utcnow().timestamp
            alarm_event = self.adapter_agent.create_alarm(
                id='voltha.{}.{}.olt'.format(self.adapter_name,
                                             self.device_id),
                resource_id='olt',
                type=AlarmEventType.EQUIPMENT,
                severity=al_severity,
                category=AlarmEventCategory.OLT,
                state=AlarmEventState.RAISED if status else
                AlarmEventState.CLEARED,
                description='OLT Alarm - Health Monitoring asfvolt16 olt - {}'
                .format('Raised'
                        if status
                        else 'Cleared'),
                context=alarm,
                raised_ts=ts)

            self.adapter_agent.submit_alarm(self.device_id, alarm_event)
        except Exception as e:
            self.log.exception('failed-to-submit-alarm', e=e)

    def http_get(self, uri=UriConst.base_uri):
        """
        Method to send http GET request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request(RestConst.GET, url=url,
                                   headers=self.headers,
                                   auth=None, verify=False)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug("Connection-timed-out.")
        except Exception as e:
            self.log.debug("Exception1-occurred-:", str(e))

    def http_put(self, uri=UriConst.base_uri, data=None):
        """
        Method to send http PUT request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request(RestConst.PUT, url=url,
                                   headers=self.headers, auth=None,
                                   verify=False, data=data)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug("Connection-timed-out.")
        except Exception as e:
            self.log.debug("Exception1-occurred-:", str(e))

    def http_post(self, uri=UriConst.base_uri, data=None):
        """
        Method to send http POST request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request(RestConst.POST, url=url,
                                   headers=self.headers, auth=None,
                                   verify=False, data=data)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug("Connection-timed-out.")
        except Exception as e:
            self.log.debug("Exception1-occurred-:", str(e))

    def http_patch(self, uri=UriConst.base_uri, data=None):
        """
        Method to send http Patch request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request(RestConst.PATCH,
                                   url=url, headers=self.headers,
                                   auth=None, verify=False,
                                   data=data)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug("Connection-timed-out.")
        except Exception as e:
            self.log.debug("Exception1-occurred-:", str(e))

    def chassis_get_state(self):
        """
        Method to get Refish chassis state
        """
        return self.chassis_obj.chassis_get()
