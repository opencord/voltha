# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from unittest import main
from time import time, sleep
import simplejson, jsonschema
from google.protobuf.json_format import MessageToDict, \
         MessageToJson
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul
from voltha.protos.device_pb2 import Device, ImageDownload
from voltha.protos.common_pb2 import AdminState
from google.protobuf.empty_pb2 import Empty

LOCAL_CONSUL = "localhost:8500"

class VolthaImageDownloadUpdate(RestBase):
    # Retrieve details on the REST entry point
    rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'envoy-8443')

    # Construct the base_url
    base_url = 'https://' + rest_endpoint

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

    def test_voltha_global_download_image(self):
        name = 'image-1'
        self.request_download_image(name)
        self.verify_request_download_image(name)
        self.cancel_download_image(name)
        self.verify_list_download_images(0)

        name = 'image-2'
        self.request_download_image(name)
        self.verify_request_download_image(name)
        self.get_download_image_status(name)
        self.verify_successful_download_image(name)
        self.activate_image(name)
        self.verify_activate_image(name)
        self.revert_image(name)
        self.verify_revert_image(name)

        name = 'image-3'
        self.request_download_image(name)
        self.verify_request_download_image(name)
        self.verify_list_download_images(2)
        
    def verify_list_download_images(self, num_of_images):
        path = '/api/v1/devices/{}/image_downloads' \
                .format(self.device_id)
        res = self.get(path)
        print(res['items'])
        self.assertEqual(len(res['items']), num_of_images)

    def get_download_image(self, name):
        path = '/api/v1/devices/{}/image_downloads/{}' \
                .format(self.device_id, name)
        response = self.get(path)
        print(response)
        return response

    def request_download_image(self, name):
        path = '/api/v1/devices/{}/image_downloads/{}' \
                .format(self.device_id, name)
        url='http://[user@](hostname)[:port]/(dir)/(filename)'
        request = ImageDownload(id=self.device_id,
                                name=name,
                                image_version="1.1.2",
                                url=url)
        self.post(path, MessageToDict(request),
                  expected_http_code=200)

    def verify_request_download_image(self, name):
        res = self.get_download_image(name)
        self.assertEqual(res['state'], 'DOWNLOAD_REQUESTED')
        self.assertEqual(res['image_state'], 'IMAGE_UNKNOWN')
        path = '/api/v1/devices/{}'.format(self.device_id)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'DOWNLOADING_IMAGE')

    def cancel_download_image(self, name):
        path = '/api/v1/devices/{}/image_downloads/{}' \
                .format(self.device_id, name)
        self.delete(path, expected_http_code=200)

    def get_download_image_status(self, name):
        path = '/api/v1/devices/{}/image_downloads/{}/status' \
                .format(self.device_id, name)
        response = self.get(path)
        while (response['state'] != 'DOWNLOAD_SUCCEEDED'):
            response = self.get(path)

    def verify_successful_download_image(self, name):
        res = self.get_download_image(name)
        self.assertEqual(res['state'], 'DOWNLOAD_SUCCEEDED')
        self.assertEqual(res['image_state'], 'IMAGE_UNKNOWN')
        path = '/api/v1/devices/{}'.format(self.device_id)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    def activate_image(self, name):
        path = '/api/v1/devices/{}/image_downloads/{}/image_update' \
                .format(self.device_id, name)
        request = ImageDownload(id=self.device_id,
                                name=name,
                                save_config=True,
                                local_dir='/local/images/v.1.1.run')
        self.post(path, MessageToDict(request),
                  expected_http_code=200)

    def verify_activate_image(self, name):
        res = self.get_download_image(name)
        self.assertEqual(res['image_state'], 'IMAGE_ACTIVE')

    def revert_image(self, name):
        path = '/api/v1/devices/{}/image_downloads/{}/image_revert' \
                .format(self.device_id, name)
        request = ImageDownload(id=self.device_id,
                                name=name,
                                save_config=True,
                                local_dir='/local/images/v.1.1.run')
        self.post(path, MessageToDict(request),
                  expected_http_code=200)

    def verify_revert_image(self, name):
        res = self.get_download_image(name)
        self.assertEqual(res['image_state'], 'IMAGE_INACTIVE')


    # test helpers

    def verify_rest(self):
        self.get('/api/v1')

    # Create a new simulated device
    def add_device(self):
        device = Device(
            type='simulated_olt',
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device

    # Active the simulated device.
    def activate_device(self, device_id):
        path = '/api/v1/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_http_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    # Disable the simulated device.
    def disable_device(self, device_id):
        path = '/api/v1/devices/{}'.format(device_id)
        self.post(path + '/disable', expected_http_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'DISABLED')

    # Delete the simulated device
    def delete_device(self, device_id):
        path = '/api/v1/devices/{}'.format(device_id)
        self.delete(path + '/delete', expected_http_code=200)

if __name__ == '__main__':
    main()
