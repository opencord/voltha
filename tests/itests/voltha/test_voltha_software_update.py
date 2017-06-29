from unittest import main
from time import time, sleep
import simplejson, jsonschema
from google.protobuf.json_format import MessageToDict, \
         MessageToJson
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul
from voltha.protos.device_pb2 import Device, \
        ImageUpdateReq, ImageDownloadReq, ImageDownloadStatus
from voltha.protos.common_pb2 import OperationResp
from google.protobuf.empty_pb2 import Empty

LOCAL_CONSUL = "localhost:8500"

class VolthaImageUpdate(RestBase):
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
        #self.disable_device(self.device_id)
        # Delete device
        #self.delete_device(self.device_id)
        pass

    # test cases

    def test_1_voltha_local_download_image(self):
        path = '/api/v1/local/devices/{}/image_download' \
                .format(self.device_id)
        self.download_image(path)

    def test_2_voltha_local_get_download_image_status(self):
        path = '/api/v1/local/devices/{}/image_download' \
                .format(self.device_id)
        self.get_download_image_status(path)

    def test_3_voltha_local_cancel_download_image(self):
        path = '/api/v1/local/devices/{}/image_download_cancellation' \
                .format(self.device_id)
        self.cancel_download_image(path)

    def test_4_voltha_local_activate_image_update(self):
        path = '/api/v1/local/devices/{}/image_update' \
                .format(self.device_id)
        self.update_image(path)

    def test_5_voltha_local_deactivate_image_update(self):
        path = '/api/v1/local/devices/{}/image_update_reversion' \
                .format(self.device_id)
        self.update_image(path)

    def test_6_voltha_global_download_image(self):
        path = '/api/v1/devices/{}/image_download' \
                .format(self.device_id)
        self.download_image(path)

    def test_7_voltha_global_get_download_image_status(self):
        path = '/api/v1/devices/{}/image_download' \
                .format(self.device_id)
        self.get_download_image_status(path)

    def test_8_voltha_global_cancel_download_image(self):
        path = '/api/v1/devices/{}/image_download_cancellation' \
                .format(self.device_id)
        self.cancel_download_image(path)

    def test_9_voltha_global_activate_image_update(self):
        path = '/api/v1/devices/{}/image_update' \
                .format(self.device_id)
        self.update_image(path)

    def test_10_voltha_global_deactivate_image_update(self):
        path = '/api/v1/devices/{}/image_update_reversion' \
                .format(self.device_id)
        self.update_image(path)

    def download_image(self, path):
        # Request sofware download
        url='http://[user@](hostname)[:port]/\
                (upgrade-image-directory)/filename'
        request = ImageDownloadReq(id=self.device_id,
                                url=url)
        response = self.post(path, MessageToDict(request),
                   expected_code=200)
        print(response)
        response_schema = { \
            "code": {
                "type": "enum"
            },
            "additional_info": {
                "type": "string"
            }
        }
        # Validate the schema
        self.validate_schema(response, response_schema)

    def get_download_image_status(self, path):
        # Get sofware download status
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
            "additional_info": {
                "type": "string"
            }
        }
        # Validate the schema
        self.validate_schema(response, response_schema)

    def cancel_download_image(self, path):
        # Cancel sofware download
        response = self.post(path, MessageToDict(Empty()),
                             expected_code=200)
        print(response)
        response_schema = { \
            "code": {
                "type": "enum"
            },
            "additional_info": {
                "type": "string"
            }
        }
        # Validate the schema
        self.validate_schema(response, response_schema)

    def update_image(self, path):
        # Fill a request
        request = ImageUpdateReq(id=self.device_id,
                                 save_config=True,
                                 software_version='v1.1.1',
                                 local_dir='/md/images/v.1.1.run')
        response = self.post(path, MessageToDict(request),
                             expected_code=200)
        print(response)
        response_schema = { \
            "code": {
                "type": "enum"
            },
            "additional_info": {
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
