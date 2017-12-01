from constants import Defaults, UriConst
import json


class systems(object):
    def __init__(self, restClient):
        self.sysresetUri = ''
        self.resetAllowValues = []
        self.restClient = restClient
        self.log = restClient.log
        self.systemRebootUriGet()

    def rebootOlt(self, resetType=Defaults.resetType):
        """
        """
        try:
            if(resetType in self.resetAllowValues):
                self.log.debug("Rebooting-ASFVOLT16-OLT")
                self.restClient.httpPost(uri=self.sysresetUri,
                                         data=json.dumps({"ResetType":
                                                         str(resetType)}))
            else:
                self.log.debug("Reset-Type-not-supported.")
        except Exception as e:
            self.log.debug("Exception-Occured-:", str(e))

    def systemGet(self, sysInfoDict, uri=UriConst.systemsUri):
        """
        """
        uri = UriConst.baseUri + uri
        try:
            response = self.restClient.httpGet(uri)
            for member in json.loads(response.text)['Members']:
                response = self.restClient.httpGet(member['@odata.id'])
                self.log.debug("System-:", json.loads(response.text))
                sysDict = json.loads(response.text)
                sysInfoDict["AssetTag"] = sysDict["AssetTag"]
                sysInfoDict["Manufacturer"] = sysDict["Manufacturer"]
                sysInfoDict["Model"] = sysDict["Model"]
                sysInfoDict["SKU"] = sysDict["SKU"]
                sysInfoDict["SerialNumber"] = sysDict["SerialNumber"]
                sysInfoDict["PartNumber"] = sysDict["PartNumber"]
                sysInfoDict["UUID"] = sysDict["UUID"]
                sysInfoDict["BiosVersion"] = sysDict["BiosVersion"]
                sysInfoDict["ProductName"] = sysDict["ProductName"]
                sysInfoDict["MACAddress"] = sysDict["MACAddress"]
                sysInfoDict["MACRange"] = sysDict["MACRange"]
                sysInfoDict["ManufactureDate"] = sysDict["ManufactureDate"]
                sysInfoDict["PlatformName"] = sysDict["PlatformName"]
                sysInfoDict["LabelRevision"] = sysDict["LabelRevision"]
                sysInfoDict["CountryCode"] = sysDict["CountryCode"]
                sysInfoDict["DiagVersion"] = sysDict["DiagVersion"]
                sysInfoDict["OnieVersion"] = sysDict["OnieVersion"]

        except Exception as e:
            self.log.debug("Exception-occurred-:", str(e))

    def systemRebootUriGet(self, uri=UriConst.systemsUri):
        """
        """
        uri = UriConst.baseUri + uri
        try:
            response = self.restClient.httpGet(uri)
            for member in json.loads(response.text)['Members']:
                response = self.restClient.httpGet(member['@odata.id'])
                sysDict = json.loads(response.text)
                if(sysDict["Actions"]):
                    if(sysDict["Actions"]["#ComputerSystem.Reset"]):
                        self.sysresetUri = sysDict["Actions"]
                        ["#ComputerSystem.Reset"]
                        ["target"]
                        self.resetAllowValues = sysDict["Actions"]
                        ["#ComputerSystem.Reset"]
                        ["ResetType@Redfish.AllowableValues"]
        except Exception as e:
            self.log.debug("Exception-occurred-:", str(e))
