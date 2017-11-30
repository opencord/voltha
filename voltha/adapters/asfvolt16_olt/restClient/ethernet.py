import json
from twisted.internet import reactor, task
from constants import UriConst, Defaults

class ethernet (object):
    def __init__ (self, restClient):
        self.log = restClient.log
        self.restClient = restClient
        self.ethernetList = []
        self.ethernetGet ()

    def ethernetGet (self, uri=UriConst.ethernetUri):
        """
        Method to parse Uri for ethernet.
        """
        uri = UriConst.baseUri + uri
        try:
            response = self.restClient.httpGet (uri)
            for member in json.loads (response.text)['Members']:
                response = self.restClient.httpGet (member['@odata.id'])
                ethernetDict = json.loads(response.text)
                self.ethernetList.append (ethernetDict['Ports'])

        except Exception as e:
            self.log.debug ("Exception occurred : ", str(e))

    def PortsGet (self):
        """
        Method to get port health status.
        """
        for member in self.ethernetList:
            try:
                response = self.restClient.httpGet (member['@odata.id'])
                for port in json.loads (response.text)['Members']:
                    response = self.restClient.httpGet (port['@odata.id'])
                    portDict = json.loads(response.text)
                    if (portDict ['Status']['State'] == 'Enabled'):
                        if (portDict ['Status']['Health'] != 'OK'):
                            self.restClient.generateAlarm (status=True, 
                                        alarm={'Health check failed for module Ports': str(portDict['Id'])},
                                        alarmSeverity=portDict ['Status']['Health'])
                            self.log.debug ("Raising alarm for Ports ", portDict['Id'])
                                
                    else:
                        self.log.debug ("Disabled Port ", portDict)
            except Exception as e:
                self.log.debug ("Exception occurred : ", str(e))

    
    def getEthernetHealth (self):
        self.PortsGet ()
        self.healthThread = reactor.callLater (Defaults.healthCheckInterval, self.getEthernetHealth)

    def stopEtherMonitoring (self):
        try:
            h, self.healthThread = self.healthThread, None
            if (h is not None):
                h.cancel ()
        except Exception as e:
            self.log.debug ("Exception occured :", str(e))

