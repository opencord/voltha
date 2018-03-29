#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import logging
import os
from time import time, sleep
import json

from google.protobuf.json_format import MessageToDict
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul
from voltha.protos.device_pb2 import Device
from unittest import skip

this_dir = os.path.abspath(os.path.dirname(__file__))

from tests.itests.test_utils import run_command_to_completion_with_raw_stdout

log = logging.getLogger(__name__)

DOCKER_COMPOSE_FILE = "compose/docker-compose-ofagent-test.yml"
LOCAL_CONSUL = "localhost:8500"

command_defs = dict(
    docker_stop="docker stop {}",
    docker_start="docker start {}",
    docker_compose_start_all="docker-compose -f {} up -d "
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_stop="docker-compose -f {} stop"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_rm_f="docker-compose -f {} rm -f"
        .format(DOCKER_COMPOSE_FILE),
    onos_form_cluster="./tests/itests/ofagent/onos-form-cluster",
    onos1_ip="docker inspect --format '{{ .NetworkSettings.Networks.compose_default.IPAddress }}' onos1",
    onos2_ip="docker inspect --format '{{ .NetworkSettings.Networks.compose_default.IPAddress }}' onos2",
    onos3_ip="docker inspect --format '{{ .NetworkSettings.Networks.compose_default.IPAddress }}' onos3",
    get_onos_devices="curl -u karaf:karaf  http://localhost:8181/onos/v1/devices")

@skip('Test case hangs at REST calls during execution. Refer to VOL-425 and VOL-427')
class OfagentRecoveryTest(RestBase):
    def setUp(self):
        # Run Voltha,OFAgent,3 ONOS and form ONOS cluster.
        print "Starting all containers ..."
        cmd = command_defs['docker_compose_start_all']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        print "Waiting for all containers to be ready ..."
        sleep(60)
        cmd = command_defs['onos1_ip']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        onos1_ip = out
        print "ONOS1 IP is {}".format(onos1_ip)
        cmd = command_defs['onos2_ip']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        onos2_ip = out
        print "ONOS2 IP is {}".format(onos2_ip)
        cmd = command_defs['onos3_ip']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        onos3_ip = out
        print "ONOS3 IP is {}".format(onos3_ip)
        cmd = command_defs['onos_form_cluster'] + ' {} {} {}'.format(onos1_ip.strip(),
                                                                     onos2_ip.strip(),
                                                                     onos3_ip.strip())
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        print "Cluster Output :{} ".format(out)

        self.get_rest_endpoint()

    def tearDown(self):
        # Stopping and Removing Voltha,OFAgent,3 ONOS.
        print "Stopping and removing all containers ..."
        cmd = command_defs['docker_compose_stop']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        print "Waiting for all containers to be stopped ..."
        sleep(1)
        cmd = command_defs['docker_compose_rm_f']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    def get_rest_endpoint(self):
        # Retrieve details on the REST entry point
        rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'envoy-8443')

        # Construct the base_url
        self.base_url = 'https://' + rest_endpoint

    def add_device(self):
        print "Adding device"

        device = Device(
            type='simulated_olt'
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)

        print "Added device - id:{}, type:{}".format(device['id'], device['type'])
        sleep(5)

        return device

    def enable_device(self, device_id):
        print "Enabling device - id:{}".format(device_id)

        path = '/api/v1/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_http_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

        self.wait_till(
            'admin state moves to ACTIVATING or ACTIVE',
            lambda: self.get(path)['oper_status'] in ('ACTIVATING', 'ACTIVE'),
            timeout=0.5)

        # eventually, it shall move to active state and by then we shall have
        # device details filled, connect_state set, and device ports created
        self.wait_till(
            'admin state ACTIVE',
            lambda: self.get(path)['oper_status'] == 'ACTIVE',
            timeout=0.5)
        device = self.get(path)
        images = device['images']
        image = images['image']
        image_1 = image[0]
        version = image_1['version']
        self.assertNotEqual(version, '')
        self.assertEqual(device['connect_status'], 'REACHABLE')

        ports = self.get(path + '/ports')['items']
        self.assertEqual(len(ports), 2)

        sleep(30)
        print "Enabled device - id:{}".format(device_id)

    def get_device(self, device_id, expected_code=200):
        print "Getting device - id:{}".format(device_id)

        device = self.get('/api/v1/devices/{}'.format(device_id),
                          expected_http_code=expected_code)

        if device is not None:
            print "Got device - id:{}, type:{}".format(device['id'], device['type'])
        else:
            print "Unable to get device - id:{}".format(device_id)

        return device

    def get_onos_devices(self):
        print "Getting ONOS devices ..."
        cmd = command_defs['get_onos_devices']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        if out is not None:
            onos_devices = json.loads(out)
            print "Got ONOS devices"
        else:
            onos_devices = None
            print "Unable to get ONOS devices"

        return onos_devices

    def stop_container(self, container):
        print "Stopping {} ...".format(container)

        cmd = command_defs['docker_stop'].format(container)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        sleep(10)
        print "Stopped {}".format(container)

    def start_container(self, container):
        print "Starting {} ...".format(container)

        cmd = command_defs['docker_start'].format(container)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        sleep(10)
        print "Started {}".format(container)

    def test_01_recovery_after_voltha_restart(self):
        # Add and enable a new OLT device
        device_1 = self.add_device()
        self.enable_device(device_1['id'])

        # Verify that the device was propagated in ONOS
        onos_devices = self.get_onos_devices()

        self.assertEqual(len(onos_devices['devices']), 1)

        # Restart voltha
        self.stop_container('compose_voltha_1')
        self.assertEqual(self.get_device(device_1['id'], 503), None)
        self.start_container('compose_voltha_1')

        # Get the device from VOLTHA after restart
        device_1_after = self.get_device(device_1['id'])
        self.assertEqual(device_1_after['id'], device_1['id'])

        # Get the device from ONOS after restart
        onos_devices = self.get_onos_devices()

        self.assertEqual(len(onos_devices['devices']), 1)

        # Add a new device
        device_2 = self.add_device()
        self.enable_device(device_2['id'])

        # Ensure that ONOS has picked up the new device
        onos_devices = self.get_onos_devices()

        self.assertEqual(len(onos_devices['devices']), 2)

    def test_02_recovery_after_ofagent_restart(self):
        # Add and enable a new OLT device
        device_1 = self.add_device()
        self.enable_device(device_1['id'])

        # Verify that the device was propagated in ONOS
        onos_devices = self.get_onos_devices()

        self.assertEqual(len(onos_devices['devices']), 1)

        # Restart ofagent
        self.stop_container('compose_ofagent_1')

        # Try to create a device while ofagent is down
        # this will succeed from a voltha point of view
        # but it will not be propagated to ONOS until ofagent is back up
        device_fail = self.add_device()
        self.enable_device(device_fail['id'])
        onos_devices = self.get_onos_devices()

        # Onos should only have 1 device
        self.assertNotEqual(len(onos_devices['devices']), 2)

        self.start_container('compose_ofagent_1')

        # Get the device from VOLTHA after restart
        device_1_after = self.get_device(device_1['id'])
        self.assertEqual(device_1_after['id'], device_1['id'])

        # Get the device from ONOS after restart
        onos_devices = self.get_onos_devices()
        self.assertEqual(len(onos_devices['devices']), 2)

        # Add a new device
        device_2 = self.add_device()
        self.enable_device(device_2['id'])

        # Ensure that ONOS has picked up the new device
        onos_devices = self.get_onos_devices()

        self.assertEqual(len(onos_devices['devices']), 3)
