from unittest import main
from time import time, sleep
from common.utils.consulhelpers import get_endpoint_from_consul
from tests.itests.voltha.rest_base import RestBase
from google.protobuf.json_format import MessageToDict
from voltha.protos.device_pb2 import Device
import simplejson, jsonschema

# ~~~~~~~ Common variables ~~~~~~~

IMAGES_SCHEMA = {
    "properties": {
        "image": {
            "items": {
                "properties": {
                    "hash": {
                        "type": "string"
                    },
                    "install_datetime": {
                        "type": "string"
                    },
                    "is_active": {
                        "type": "boolean"
                    },
                    "is_committed": {
                        "type": "boolean"
                    },
                    "is_valid": {
                        "type": "boolean"
                    },
                    "name": {
                        "type": "string"
                    },
                    "version": {
                        "type": "string"
                    }
                },
                "type": "object"
            },
            "type": "array"
        }
    },
    "type": "object"
}

LOCAL_CONSUL = "localhost:8500"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################
# Requirements for the test:                         #
# Ensure voltha and chameleon are running fine and   #
# chameleon is available on port 8881 to listen for  #
# any REST requests                                  #
######################################################


class VolthaDeviceManagementRetrieveSoftwareInfo(RestBase):
    # Retrieve details on the REST entry point
    rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'chameleon-rest')

    # Construct the base_url
    base_url = 'https://' + rest_endpoint

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    # ~~~~~~~~~~~~ Tests ~~~~~~~~~~~~
    def test_01_voltha_device_management_retrieve_images(self):
        # Make sure the Voltha REST interface is available
        self.verify_rest()

        # Create a new device
        device = self.add_device()

        # Activate the new device
        self.activate_device(device['id'])

        # wait till device moves to ACTIVE state
        self.wait_till(
            'admin state moves from ACTIVATING to ACTIVE',
            lambda: self.get('/api/v1/devices/{}'.format(device['id']))['oper_status'] in ('ACTIVE'),
            timeout=5.0)

        # Give some time before ONUs are detected
        sleep(2.0)

        # Retrieve the images for the device
        images = self.get_images(device['id'])

        # Validate the schema for the software info
        self.validate_images_schema(images)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

    # Retrieve software info on the device
    def get_images(self, device_id):
        path = '/api/v1/local/devices/{}/images'.format(device_id)
        images = self.get(path)
        return images

    def validate_images_schema(self, images):
        try:
            jsonschema.validate(images, IMAGES_SCHEMA)
        except Exception as e:
            self.assertTrue(
                False, 'Validation failed for images: {}'.format(e.message))


if __name__ == '__main__':
    main()
