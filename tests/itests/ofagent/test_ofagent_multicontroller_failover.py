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
from time import time, sleep
import logging
import os
import json
from unittest import TestCase,main

this_dir = os.path.abspath(os.path.dirname(__file__))

from tests.itests.test_utils import run_command_to_completion_with_raw_stdout
from voltha.protos.device_pb2 import Device
from google.protobuf.json_format import MessageToDict
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul

log = logging.getLogger(__name__)

DOCKER_COMPOSE_FILE = "compose/docker-compose-ofagent-test.yml"
LOCAL_CONSUL = "localhost:8500"

command_defs = dict(
    docker_images="docker images",
    docker_stop="docker stop",
    docker_rm="docker rm",
    docker_voltha_logs="docker logs -f compose_voltha_1",
    docker_compose_logs="docker-compose -f {} logs".format(
        DOCKER_COMPOSE_FILE),
    docker_stop_and_remove_all_containers="docker stop `docker ps -q` ; "
                                          "docker rm `docker ps -a -q`",
    docker_compose_start_all="docker-compose -f {} up -d "
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_stop="docker-compose -f {} stop"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_rm_f="docker-compose -f {} rm -f"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_ps="docker-compose -f {} ps".format(DOCKER_COMPOSE_FILE),
    docker_ps="docker ps",
    onos_form_cluster="./tests/itests/ofagent/onos-form-cluster",
    onos1_ip="docker inspect --format '{{ .NetworkSettings.Networks.compose_default.IPAddress }}' onos1",
    onos2_ip ="docker inspect --format '{{ .NetworkSettings.Networks.compose_default.IPAddress }}' onos2",
    onos3_ip="docker inspect --format '{{ .NetworkSettings.Networks.compose_default.IPAddress }}' onos3",
    onos1_devices="curl -u karaf:karaf  http://localhost:8181/onos/v1/devices",
    onos2_devices="curl -u karaf:karaf  http://localhost:8182/onos/v1/devices",
    onos3_devices="curl -u karaf:karaf  http://localhost:8183/onos/v1/devices")

class TestOFAGENT_MultiController(RestBase):
    # Test OFAgent Support for Multiple controller
    def setUp(self):
        # Run Voltha,OFAgent,3 ONOS and form ONOS cluster.
        print "Starting all containers ..."
        cmd = command_defs['docker_compose_start_all']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        print "Waiting for all containers to be ready ..."
        sleep(80)
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
        cmd = command_defs['onos_form_cluster'] + ' {} {} {}'.format(onos1_ip.strip(),onos2_ip.strip(),onos3_ip.strip())
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
        rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'voltha-envoy-8443')

        # Construct the base_url
        self.base_url = 'https://' + rest_endpoint

    def add_device(self):
        print "Adding device"

        device = Device(
            type='simulated_olt',
            mac_address='01:0c:e2:31:40:00'
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

    def test_ofagent_controller_failover(self):
        olt_device = self.add_device()
        print "Output of ADD OLT is {} {} {}".format(olt_device, type(olt_device), olt_device['id'])
        sleep(5)
        self.enable_device(olt_device['id'])
        print "Waiting for OLT device to be activated ..."
        sleep(80)
        cmd = command_defs['onos1_devices']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        onos1_devices = json.loads(out)
        onos1_role = onos1_devices['devices'][0]['role']
        print "Role of ONOS1 is {}".format(onos1_role)
        cmd = command_defs['onos2_devices']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        onos2_devices = json.loads(out)
        onos2_role = onos2_devices['devices'][0]['role']
        print "Role of ONOS2 is {}".format(onos2_role)
        cmd = command_defs['onos3_devices']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        onos3_devices = json.loads(out)
        onos3_role = onos3_devices['devices'][0]['role']
        print "Role of ONOS3 is {}".format(onos3_role)
        if onos1_role == "MASTER":
           cmd = command_defs['docker_stop']+ ' onos1'
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           print "Waiting for ONOS to Elect New Master"
           sleep(20)
           cmd = command_defs['onos2_devices']
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           onos2_devices = json.loads(out)
           onos2_role = onos2_devices['devices'][0]['role']
           print "Role of ONOS2 is {}".format(onos2_role)
           cmd = command_defs['onos3_devices']
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           onos3_devices = json.loads(out)
           onos3_role = onos3_devices['devices'][0]['role']
           print "Role of ONOS3 is {}".format(onos3_role)
           assert (onos3_role == "MASTER" or onos2_role == "MASTER"), "Exception,New Master Election Failed"
        elif onos2_role == "MASTER":
           cmd = command_defs['docker_stop']+ ' onos2'
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           print "Waiting for ONOS to Elect New Master"
           sleep(20)
           cmd = command_defs['onos1_devices']
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           onos1_devices = json.loads(out)
           onos1_role = onos1_devices['devices'][0]['role']
           print "Role of ONOS1 is {}".format(onos1_role)
           cmd = command_defs['onos3_devices']
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           onos3_devices = json.loads(out)
           onos3_role = onos3_devices['devices'][0]['role']
           print "Role of ONOS3 is {}".format(onos3_role)
           assert (onos3_role == "MASTER" or onos1_role == "MASTER"), "Exception,New Master Election Failed"
        elif onos3_role == "MASTER":
           cmd = command_defs['docker_stop']+ ' onos3'
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           print "Waiting for ONOS to Elect New Master"
           sleep(20)
           cmd = command_defs['onos1_devices']
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           onos1_devices = json.loads(out)
           onos1_role = onos1_devices['devices'][0]['role']
           print "Role of ONOS1 is {}".format(onos1_role)
           cmd = command_defs['onos2_devices']
           out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
           self.assertEqual(rc, 0)
           onos2_devices = json.loads(out)
           onos2_role = onos2_devices['devices'][0]['role']
           print "Role of ONOS2 is {}".format(onos2_role)
           assert (onos1_role == "MASTER" or onos2_role == "MASTER"), "Exception,New Master Election Failed"

