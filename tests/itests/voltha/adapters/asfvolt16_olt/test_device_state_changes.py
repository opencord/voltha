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
from time import time, sleep

from google.protobuf.json_format import MessageToDict

from voltha.protos.device_pb2 import Device
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul

LOCAL_CONSUL = "localhost:8500"


class TestDeviceStateChangeSequence(RestBase):
    """
    The prerequisite for this test are:
     1. voltha ensemble is running
          docker-compose -f compose/docker-compose-system-test.yml up -d
     2. ponsim olt is running with 1 OLT and 4 ONUs using device_type 'bal'
          sudo -s
          . ./env.sh
          ./ponsim/main.py -v -o 4 -d bal
    """

    # Retrieve details of the REST entry point
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

    def test_device_state_changes_scenarios(self):

        self.verify_prerequisites()
        # Test basic scenario

        self.basic_scenario()

    def basic_scenario(self):
        """
        Test the enable -> disable -> enable -> disable -> delete for OLT
        """
        self.assert_no_device_present()
        olt_id = self.add_olt_device()
        self.verify_device_preprovisioned_state(olt_id)
        self.enable_device(olt_id)
        ldev_id = self.wait_for_logical_device(olt_id)
        self.verify_logical_ports(ldev_id, 1)
        olt_ids, _ = self.get_devices()
        self.disable_device(olt_ids[0])
        self.assert_no_logical_device()
        self.delete_device(olt_ids[0])
        self.assert_no_device_present()

    def verify_prerequisites(self):
        # all we care is that Voltha is available via REST using the base uri
        self.get('/api/v1')

    def get_devices(self):
        devices = self.get('/api/v1/devices')['items']
        olt_ids = []
        onu_ids = []
        for d in devices:
            if d['adapter'] == 'asfvolt16_olt':
                olt_ids.append(d['id'])
        return olt_ids, onu_ids

    def add_olt_device(self):
        device = Device(
            type='asfvolt16_olt',
            host_and_port='172.17.0.1:50060'
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device['id']

    def verify_device_preprovisioned_state(self, olt_id):
        # we also check that so far what we read back is same as what we get
        # back on create
        device = self.get('/api/v1/devices/{}'.format(olt_id))
        self.assertNotEqual(device['id'], '')
        self.assertEqual(device['adapter'], 'asfvolt16_olt')
        self.assertEqual(device['admin_state'], 'PREPROVISIONED')
        self.assertEqual(device['oper_status'], 'UNKNOWN')

    def enable_device(self, olt_id):
        path = '/api/v1/devices/{}'.format(olt_id)
        self.post(path + '/enable', expected_http_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

        self.wait_till(
            'admin state moves to ACTIVATING or ACTIVE',
            lambda: self.get(path)['oper_status'] in ('ACTIVATING', 'ACTIVE'),
            timeout=0.5)

        # eventually, it shall move to active state and by then we shall have
        # device details filled, connect_state set, and device ports created
        '''
        # The check for ACTIVE is suppressed since the indications
        # portion of the code is not yet ready.
        self.wait_till(
            'admin state ACTIVE',
            lambda: self.get(path)['oper_status'] == 'ACTIVE',
            timeout=0.5)
        device = self.get(path)
        '''
        self.assertEqual(device['connect_status'], 'REACHABLE')

        ports = self.get(path + '/ports')['items']
        #self.assertEqual(len(ports), 2)
        self.assertEqual(len(ports), 1)

    def wait_for_logical_device(self, olt_id):
        # we shall find the logical device id from the parent_id of the olt
        # (root) device
        device = self.get(
            '/api/v1/devices/{}'.format(olt_id))
        self.assertNotEqual(device['parent_id'], '')
        logical_device = self.get(
            '/api/v1/logical_devices/{}'.format(device['parent_id']))

        # the logical device shall be linked back to the hard device,
        # its ports too
        self.assertEqual(logical_device['root_device_id'], device['id'])

        logical_ports = self.get(
            '/api/v1/logical_devices/{}/ports'.format(
                logical_device['id'])
        )['items']
        self.assertGreaterEqual(len(logical_ports), 1)
        logical_port = logical_ports[0]
        self.assertEqual(logical_port['id'], 'nni')
        self.assertEqual(logical_port['ofp_port']['name'], 'nni')
        self.assertEqual(logical_port['ofp_port']['port_no'], 0)
        self.assertEqual(logical_port['device_id'], device['id'])
        self.assertEqual(logical_port['device_port_no'], 50)
        return logical_device['id']

    def verify_logical_ports(self, ldev_id, num_ports):

        # at this point we shall see num_ports logical ports on the
        # logical device
        logical_ports = self.get(
            '/api/v1/logical_devices/{}/ports'.format(ldev_id)
        )['items']
        self.assertGreaterEqual(len(logical_ports), num_ports)

        # verify that all logical ports are LIVE (state=4)
        for lport in logical_ports:
            self.assertEqual(lport['ofp_port']['state'], 4)

    def disable_device(self, id):
        path = '/api/v1/devices/{}'.format(id)
        self.post(path + '/disable', expected_http_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'DISABLED')

        self.wait_till(
            'operational state moves to UNKNOWN',
            lambda: self.get(path)['oper_status'] == 'UNKNOWN',
            timeout=0.5)

        # eventually, the connect_state should be UNREACHABLE
        self.wait_till(
            'connest status UNREACHABLE',
            lambda: self.get(path)['connect_status'] == 'UNREACHABLE',
            timeout=0.5)

        # Device's ports should be INACTIVE
        ports = self.get(path + '/ports')['items']
        #self.assertEqual(len(ports), 2)
        self.assertEqual(len(ports), 1)
        for p in ports:
            self.assertEqual(p['admin_state'], 'DISABLED')
            self.assertEqual(p['oper_status'], 'UNKNOWN')

    def delete_device(self, id):
        path = '/api/v1/devices/{}'.format(id)
        self.delete(path + '/delete', expected_http_code=200)
        device = self.get(path, expected_http_code=200, grpc_status=5)
        self.assertIsNone(device)

    def assert_no_device_present(self):
        path = '/api/v1/devices'
        devices = self.get(path)['items']
        self.assertEqual(devices, [])

    def assert_no_logical_device(self):
        path = '/api/v1/logical_devices'
        ld = self.get(path)['items']
        self.assertEqual(ld, [])
