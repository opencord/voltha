from unittest import main
from time import time, sleep
import simplejson, jsonschema
from google.protobuf.json_format import MessageToDict, \
         MessageToJson
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul
from voltha.protos.device_pb2 import Device, OperationResp, \
        SoftwareUpdateReq, SoftwareDownloadReq, SoftwareDownloadStatus

LOCAL_CONSUL = "localhost:8500"

class VolthaDeviceManagementSoftwareUpdate(RestBase):
    # Retrieve details on the REST entry point
    rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'chameleon-rest')

    # Construct the base_url
    base_url = 'http://' + rest_endpoint

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    def setUp(self):
        # Make sure the Voltha REST interface is available
        self.verify_rest()
        # Create a new device
        device = self.add_device()
        # Activate the new device
        self.activate_device(device['id'])
        self.device_id = device['id']
        print("self.device_id {}".format(self.device_id))
        assert(self.device_id)

        # wait untill device moves to ACTIVE state
        self.wait_till(
            'admin state moves from ACTIVATING to ACTIVE',
            lambda: self.get('/api/v1/devices/{}'.format(self.device_id))\
                    ['oper_status'] in ('ACTIVE'),
            timeout=5.0)
        # wait until ONUs are detected
        sleep(2.0)

    def tearDown(self):
        # Disable device
        self.disable_device(self.device_id)
        # Delete device
        self.delete_device(self.device_id)
        self.device_id = None

    # test cases

    def test_1_voltha_request_software_download(self):
        # Request sofware download
        url='http://[user@](hostname)[:port]/\
                (upgrade-image-directory)/filename'
        request = SoftwareDownloadReq(id=self.device_id,
                                      url=url)
        path = '/api/v1/local/devices/{}/request_software_download' \
                .format(self.device_id)
        response = self.post(path, MessageToDict(request),
                   expected_code=200)
        print(response)
        response_schema = { \
            "code": {
                "type": "enum"
            },
            "addtional_info": {
                "type": "string"
            }
        }
        # Validate the schema
        self.validate_schema(response, response_schema)

    def test_2_voltha_get_software_download_status(self):
        # Get sofware download status
        path = '/api/v1/local/devices/{}/get_software_download_status' \
                .format(self.device_id)
        response = self.get(path)
        print(response)
        response_schema = { \
            "state": {
                "type": "enum"
            },
            "downloaded_version": {
                "type": "string"
            },
            "downloaded_bytes": {
                "type": "string"
            },
            "reason": {
                "type": "enum"
            },
            "addtional_info": {
                "type": "string"
            }
        }
        # Validate the schema
        self.validate_schema(response, response_schema)

    # test helpers

    def verify_rest(self):
        self.get('/api/v1')

    # Create a new simulated device
    def add_device(self):
        device = Device(
            type='simulated_olt',
        )
        device = self.post('/api/v1/local/devices', MessageToDict(device),
                           expected_code=200)
        return device

    # Active the simulated device.
    def activate_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    # Disable the simulated device.
    def disable_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.post(path + '/disable', expected_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'DISABLED')

    # Delete the simulated device
    def delete_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.delete(path + '/delete', expected_code=200)

    # Validate actual output with expected
    def validate_schema(self, actual, expected):
        try:
            jsonschema.validate(actual, expected)
        except Exception as e:
            self.assertTrue(
                False, 'Validation failed for: {}'.format(e.message))

if __name__ == '__main__':
    main()
