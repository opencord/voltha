import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import arrow
from chassis import chassis
from systems import systems
from ethernet import ethernet
from constants import UriConst, RestConst, Defaults
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory

class restClient (object):
    def __init__ (self, host_and_port, adapter, log, device_id):
        self.log           = log
        self.headers       = {'Accept-Encoding': None}
        self.device_id     = device_id
        self.adapter_agent = adapter.adapter_agent
        self.adapter_name  = adapter.name
        self.host_and_port = host_and_port.split (':')[0] + Defaults.redfishPort
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.chassisObj    = chassis (self)
        self.systemsObj    = systems (self)
        self.ethernetObj   = ethernet (self)
        self.sysInfo       = {}

    def getSystemDetails (self):
        """
        Method to fetch OLT info.
        This method is supposed to get invoked from NBI API get_device_details.
        Currently the get_device_details() is in NotImplemented stated
        """
        
        self.systemsObj.systemGet (self.sysInfo)
        return self.sysInfo
 
    def startHealthMonitoring (self):
        """
        Metod to fetch health status of asfvolt16 olt hardware modules
        """
        self.chassisObj.getChassisHealth ()
        self.ethernetObj.getEthernetHealth ()
        
    def stopHealthMonitoring (self):
        """
        Method to stop health monitoring of asfvolt16 olt modules
        are not controlled by bal
        """
        self.chassisObj.stopChassisMonitoring ()

    def rebootDevice (self):
        """
        Reboot asfvolt16 olt through Redfish service
        """
        self.systemsObj.rebootOlt ()

    def generateAlarm (self, status, alarm, alarmSeverity):
        """
        Method to create and submit alarms.
        """
        if (alarmSeverity == "Warning"):
            alSeverity = AlarmEventSeverity.WARNING
        elif (alarmSeverity == "Critical"):
            alSeverity = AlarmEventSeverity.CRITICAL
        try:
            ts = arrow.utcnow().timestamp
            alarm_event = self.adapter_agent.create_alarm(
                id = 'voltha.{}.{}.olt'.format(self.adapter_name, self.device_id),
                resource_id = 'olt',
                type = AlarmEventType.EQUIPMENT,
                severity = alSeverity, 
                category = AlarmEventCategory.OLT,
                state = AlarmEventState.RAISED if status else
                    AlarmEventState.CLEARED,
                description='OLT Alarm - Health  Monitoring asfvolt16 olt - {}'.format('Raised'
                                                                if status
                                                                else 'Cleared'),
                context=alarm,
                raised_ts = ts)

            self.adapter_agent.submit_alarm(self.device_id, alarm_event)
        except Exception as e:
               self.log.exception('failed-to-submit-alarm', e=e)

    def httpGet (self, uri=UriConst.baseUri):
        """
        Method to send http GET request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request (RestConst.GET, url=url, headers=self.headers, auth=None, verify=False)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug ("Connection timed out.")
        except Exception as e:
            self.log.debug ("Exception1 occurred : ", str(e))

    def httpPut (self, uri=UriConst.baseUri, data=None):
        """
        Method to send http PUT request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request (RestConst.PUT, url=url, headers=self.headers, auth=None, verify=False, data=data)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug ("Connection timed out.")
        except Exception as e:
            self.log.debug ("Exception1 occurred : ", str(e))

    def httpPost (self, uri=UriConst.baseUri, data=None):
        """
        Method to send http POST request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request (RestConst.POST, url=url, headers=self.headers, auth=None, verify=False, data=data)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug ("Connection timed out.")
        except Exception as e:
            self.log.debug ("Exception1 occurred : ", str(e))

    def httpPatch (self, uri=UriConst.baseUri, data=None):
        """
        Method to send http Patch request.
        """
        url = UriConst.HTTPS + self.host_and_port + uri
        try:
            ret = requests.request (RestConst.PATCH, url=url, headers=self.headers, auth=None, verify=False, data=data)
            return ret
        except requests.exceptions.ConnectTimeout:
            self.log.debug ("Connection timed out.")
        except Exception as e:
            self.log.debug ("Exception1 occurred : ", str(e))

