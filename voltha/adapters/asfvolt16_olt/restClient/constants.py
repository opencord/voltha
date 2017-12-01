class UriConst:
    baseUri = '/redfish/v1'
    chassisUri = '/Chassis/'
    systemsUri = '/Systems/'
    updateUri = '/UpdateService/'
    ethernetUri = '/EthernetSwitches/'
    HTTPS = 'https://'


class RestConst:
    GET = 'GET'
    PUT = 'PUT'
    PATCH = 'PATCH'
    POST = 'POST'
    DELETE = 'DELETE'


class Defaults:
    resetType = 'GracefulRestart'
    healthCheckInterval = 60
    redfishPort = ':8888'
