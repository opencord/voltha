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
import time
import logging
import os
import json
from unittest import TestCase,main

this_dir = os.path.abspath(os.path.dirname(__file__))

from tests.itests.docutests.test_utils import run_command_to_completion_with_raw_stdout

log = logging.getLogger(__name__)

DOCKER_COMPOSE_FILE = "compose/docker-compose-ofagent-test.yml"

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
    add_olt='''curl -s -X POST -d '{"type": "simulated_olt", "mac_address": "01:0c:e2:31:40:00"}' \
               http://localhost:8881/api/v1/local/devices''',
    enable_olt="curl -s -X POST http://localhost:8881/api/v1/local/devices/",
    onos1_devices="curl -u karaf:karaf  http://localhost:8181/onos/v1/devices",
    onos2_devices="curl -u karaf:karaf  http://localhost:8182/onos/v1/devices",
    onos3_devices="curl -u karaf:karaf  http://localhost:8183/onos/v1/devices")

class TestOFAGENT_MultiController(TestCase):
    # Test OFAgent Support for Multiple controller
    def setUp(self):
        # Run Voltha,OFAgent,3 ONOS and form ONOS cluster.
        print "Starting all containers ..."
        cmd = command_defs['docker_compose_start_all']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        print "Waiting for all containers to be ready ..."
        time.sleep(80)
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

    def tearDown(self):
        # Stopping and Removing Voltha,OFAgent,3 ONOS.
        print "Stopping and removing all containers ..."
        cmd = command_defs['docker_compose_stop']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        print "Waiting for all containers to be stopped ..."
        time.sleep(1)
        cmd = command_defs['docker_compose_rm_f']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

    def test_ofagent_controller_failover(self):
        cmd = command_defs['add_olt']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        olt_device = json.loads(out)
        print "Output of ADD OLT is {} {} {}".format(olt_device, type(olt_device), olt_device['id'])
        time.sleep(5)
        cmd = command_defs['enable_olt'] + '{}'.format(olt_device['id']) + '/enable'
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        print "output is {}".format(out)
        print "Waiting for OLT device to be activated ..."
        time.sleep(80)
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
           time.sleep(20)
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
           time.sleep(20)
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
           time.sleep(20)
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

