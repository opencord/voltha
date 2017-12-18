import json
from twisted.internet import reactor, task
from constants import UriConst, Defaults


class chassis (object):
    def __init__(self, restClient):
        self.log = restClient.log
        self.restClient = restClient
        self.chassisList = []
        self.chassisGet()

    def chassisGet(self, uri=UriConst.chassisUri):
        """
        Method to parse Uri for fans and psu.
        """
        uri = UriConst.baseUri + uri
        try:
            response = self.restClient.httpGet(uri)
            for member in json.loads(response.text)['Members']:
                response = self.restClient.httpGet(member['@odata.id'])
                chassisDict = json.loads(response.text)
                if (chassisDict['Status']['State'] == 'Enabled'):
                    self.chassisList.append(chassisDict)
        except Exception as e:
            self.log.debug("Exception-occurred-:", str(e))

    def fansGet(self):
        """
        Method to get fan health status.
        """
        for chassis in self.chassisList:
            thermalUri = chassis['Links']['Thermal'][0]['@odata.id']
            try:
                response = self.restClient.httpGet(thermalUri)
                fansList = json.loads(response.text)['Fans']
                for fan in fansList:
                    response = self.restClient.httpGet(fan['@odata.id'])
                    fanDict = json.loads(response.text)['Fan']
                    if (fanDict['Status']['State'] == 'Enabled'):
                        if (fanDict['Status']['Health'] != 'OK'):
                            # Raise Alarm
                            self.restClient.generateAlarm(
                                     status=True,
                                     alarm={'Health-check-failed-for-Fan':
                                            str(fanDict['Id'])},
                                     alarmSeverity=fanDict['Status']['Health'])
                            self.log.info("Raising-alarm-for-fan",
                                          fanDict['Id'])
                    else:
                        self.log.debug("Disabled-Fan-Info-:", fanDict)
            except Exception as e:
                self.log.debug("Exception-occurred-:", str(e))

    def psuGet(self):
        """
        Method to get psu health status.
        """
        for chassis in self.chassisList:
            powerUri = chassis['Links']['Power'][0]['@odata.id']
            try:
                response = self.restClient.httpGet(powerUri)
                psuList = json.loads(response.text)['Power']
                for psu in psuList:
                    response = self.restClient.httpGet(psu['@odata.id'])
                    psuDict = json.loads(response.text)['PowerSupply']
                    if (psuDict['Status']['State'] == 'Enabled'):
                        if (psuDict['Status']['Health'] != 'OK'):
                            # Raise Alarm
                            self.restClient.generateAlarm(
                                     status=True,
                                     alarm={'Health-check-failed-for-Psu':
                                            str(psuDict['MemberId'])},
                                     alarmSeverity=psuDict['Status']['Health'])
                            self.log.info("Raising-alarm-for-PSU",
                                          psuDict['MemberId'])
                    else:
                        self.log.debug("Power-supply-disabled",
                                       psuDict['MemberId'])
            except Exception as e:
                self.log.debug("Exception-occurred-:", str(e))

    def getChassisHealth(self):
        self.fansGet()
        self.psuGet()
        self.healthThread = reactor.callLater(
                                              Defaults.healthCheckInterval,
                                              self.getChassisHealth)

    def stopChassisMonitoring(self):
        try:
            h, self.healthThread = self.healthThread, None
            if(h is not None):
                h.cancel()
        except Exception as e:
            self.log.debug("Exception-occured-:", str(e))
