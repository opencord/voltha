#!/usr/bin/env python
#
# Copyright 2016 the original author or authors.
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
import subprocess
import select
import time
import logging
from common.utils.consulhelpers import verify_all_services_healthy, get_endpoint_from_consul
import os
import json
from unittest import TestCase
import re
import simplejson
import sys
import traceback

this_dir = os.path.abspath(os.path.dirname(__file__))

from test_utils import run_command_to_completion_with_raw_stdout, \
    is_open, \
    is_valid_ip, \
    run_long_running_command_with_timeout, \
    run_command_to_completion_with_stdout_in_list

log = logging.getLogger(__name__)

LOCAL_CONSUL = "localhost:8500"
LOCAL_CONSUL_URL = "http://%s" % LOCAL_CONSUL
LOCAL_CONSUL_DNS = "@localhost -p 8600"
DOCKER_COMPOSE_FILE = "compose/docker-compose-docutests.yml"
DOCKER_COMPOSE_FILE_SERVICES_COUNT = 7

command_defs = dict(
    makefile_fetch_images="grep \"docker pull\" Makefile",
    make="make",
    make_fetch="make fetch",
    remove_env_directory="rm -rf venv-linux",
    make_clean="make clean",
    docker_images="docker images",
    docker_stop="docker stop",
    docker_rm="docker rm",
    fluentd_logs="less /tmp/fluentd/data.log",
    docker_voltha_logs="docker logs -f compose_voltha_1",
    docker_compose_logs="docker-compose -f {} logs".format(
        DOCKER_COMPOSE_FILE),
    docker_stop_and_remove_all_containers="docker stop `docker ps -q` ; "
                                          "docker rm `docker ps -a -q`",
    docker_start_voltha="docker run -ti --rm cord/voltha",
    docker_start_voltha_with_consul_ip="docker run -ti --rm --net="
                                       "compose_default cord/voltha "
                                       "/voltha/voltha/main.py --consul=",
    docker_get_consul_ip="docker inspect "
                         "compose_consul_1 | jq -r "
                         "'.[0].NetworkSettings.Networks."
                         "compose_default.IPAddress'",
    docker_compose_start_consul="docker-compose -f {} up -d "
                                "consul".format(DOCKER_COMPOSE_FILE),
    docker_compose_start_all="docker-compose -f {} up -d "
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_stop="docker-compose -f {} stop"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_rm_f="docker-compose -f {} rm -f"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_ps="docker-compose -f {} ps".format(DOCKER_COMPOSE_FILE),
    docker_ps="docker ps",
    docker_ps_filtered="docker ps --format '{{{{.Names}}}}' | grep -v '^{}$' || true",
    docker_get_ids_filtered="docker ps --format '{{{{.Names}}}},{{{{.ID}}}}' | grep -v '^{},'",
    docker_swarm_manager_count="docker info --format '{{.Swarm.Managers}}'",
    docker_verify_swarm="test $(docker info --format '{{.Swarm.Managers}}') -ne 0",
    docker_ps_count="docker ps -q | wc -l",
    docker_compose_is_consul_up="docker-compose -f {} ps | grep consul"
        .format(DOCKER_COMPOSE_FILE),
    consul_get_leader_ip_port="curl -s {}/v1/status/leader | jq -r ."
        .format(LOCAL_CONSUL_URL),
    docker_compose_services_running="docker-compose -f {} ps -q"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_services_running_count="docker-compose -f {} ps -q | "
                                          "grep Up "
                                          "| wc -l".format(
        DOCKER_COMPOSE_FILE),
    docker_compose_services="docker-compose -f {} config --services"
        .format(DOCKER_COMPOSE_FILE),
    consul_get_services="curl -s {}/v1/catalog/services | jq -r ."
        .format(LOCAL_CONSUL_URL),
    consul_get_srv_voltha_health="curl -s {}/v1/catalog/service/voltha-health "
                                 "| jq -r .".format(LOCAL_CONSUL_URL),
    kafka_client_run="kafkacat -b {} -L",
    kafka_client_heart_check="kafkacat -o end -b {} -C -t voltha.heartbeat -c 1",
    consul_get_voltha_rest_a_record="dig {} voltha-health.service.consul"
        .format(LOCAL_CONSUL_DNS),
    consul_get_voltha_rest_ip="dig {} +short voltha-health.service.consul"
        .format(LOCAL_CONSUL_DNS),
    consul_get_voltha_service_port="dig {} +short "
                                   "voltha-health.service.consul SRV | "
                                   " awk \'{{print $3}}'"
        .format(LOCAL_CONSUL_DNS),
    docker_compose_scale_voltha_to_10="docker-compose -f {} scale "
                                      "voltha=10".format(DOCKER_COMPOSE_FILE),
    docker_compose_scaled_voltha_ps="docker-compose -f {} ps voltha | "
                                    "grep Up | wc -l"
        .format(DOCKER_COMPOSE_FILE),
    consul_verify_voltha_registration="curl -s {}"
                                      "/v1/kv/service/voltha/members?recurse |"
                                      " jq -r .".format(LOCAL_CONSUL_DNS)
)


class BuildMdTests(TestCase):

    def _start_all_containers(self, name):
        print "start_all_containers_Start:-----------------------"
        cmd = "./integrations/swarm/test/helpers/start_voltha.sh {}".format(name)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if rc != 0:
            print err
        self.assertEqual(rc, 0)
        print out
        print "start_all_containers_End:-------------------------"

    def _stop_all_containers(self):
        print "stop_all_containers_Start:------------------------"
        cmd = "./integrations/swarm/test/helpers/stop_and_remove_all_containers.sh"
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if rc != 0:
            print err
        self.assertEqual(rc, 0)
        print out
        print "stop_all_containers_End:--------------------------"

    def _wait_for_containers_stop(self):
        print "wait_for_containers_stop_Start:-------------------"
        cmd = "./integrations/helpers/wait_for.sh 'Waiting for containers to stop' 'test $(docker ps -q | wc -l) -eq 1' 'Unable to stop all containers' 3 20"
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if rc != 0:
            print err
        self.assertEqual(rc, 0)
        print out
        print "wait_for_containers_stop_End:----------------------"

    def _wait_for_voltha_start(self, name):
        print "wait_for_voltha_start_Start:-----------------------"
        cmd = "./integrations/swarm/test/helpers/wait_for_voltha.sh {}".format(name)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if rc != 0:
            print err
        self.assertEqual(rc, 0)
        print out
        print "wait_for_voltha_start_End:------------------------"

    def _exec_command_against_voltha(self, name, cmd):
        print "exec_command_against_voltha_Start:----------------"
        cmd = "./integrations/swarm/test/helpers/run_test.sh {} {}".format(name, cmd)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        if rc != 0:
            print err
        self.assertEqual(rc, 0)
        print "exec_command_against_voltha_End:------------------"
        return out

    def test_01_validation_tests(self):
        print "Test_01_validation_tests_Start:------------------ "
        t0 = time.time()

        try:
            self._stop_all_containers()
            self._wait_for_containers_stop()
            self._start_all_containers("validation")
            self._wait_for_voltha_start("validation")
            # Verify kafka client is receiving the messages
            print "Verify kafka client has heartbeat topic ..."
            expected_pattern = ['voltha.heartbeat']
            kafka_endpoint = 'kafka'
            cmd = command_defs['kafka_client_run'].format(kafka_endpoint)
            kafka_client_output = run_long_running_command_with_timeout(cmd, 20)

            # Verify the kafka client output
            # instance id
            found = False
            for out in kafka_client_output:
                if all(ep for ep in expected_pattern if ep in out):
                    found = True
                    break
            self.assertTrue(found)

            #                   'registrator_1', 'kafka_1', 'zookeeper_1',
            #                   'ofagent_1', 'netconf_1']
            #cmd = command_defs['docker_compose_logs']
            #docker_compose_logs = run_long_running_command_with_timeout(cmd, 5,
            #                                                            0)
            #intersected_logs = [l for l in expected_output if
            #                    l in docker_compose_logs]
            #self.assertEqual(len(intersected_logs), len(expected_output))

            # verify docker voltha logs are being produced - we will just verify
            # some
            # key messages in the logs
            #print "Verify docker voltha logs are produced ..."
            #expected_output = ['coordinator._renew_session', 'main.heartbeat']
            #cmd = command_defs['docker_voltha_logs']
            #docker_voltha_logs = run_long_running_command_with_timeout(cmd,
            #                                                           0.5, 3)
            #intersected_logs = [l for l in expected_output if
            #                    l in docker_voltha_logs]
            #self.assertEqual(len(intersected_logs), len(expected_output))

        finally:
            self._stop_all_containers()
            self._wait_for_containers_stop()
            print "Test_01_validation_tests_End:------------------ took {}" \
                  " secs \n\n".format(time.time() - t0)

    def test_02_dig_ip_resolution(self):
        print "Test_02_dig_ip_resolution_Start:------------------"
        t0 = time.time()

        try:
            self._stop_all_containers()
            self._wait_for_containers_stop()
            self._start_all_containers("ip_resolution")
            self._wait_for_voltha_start("ip_resolution")
            # Get the IP address(es) for voltha's REST interface
            print "  Get DNS record of Voltha REST interface..."
            out, err, rc = run_command_to_completion_with_raw_stdout("dig voltha")
            if rc != 0:
                print err
            self.assertEqual(rc, 0)

            # Get only the ip address
            print "  Get IP of Voltha REST interface ..."
            out, err, rc = run_command_to_completion_with_raw_stdout("dig +short voltha")
            if rc != 0:
                print err
            self.assertEqual(rc, 0)
            ip = out.strip()
            self.assertTrue(is_valid_ip(ip))
            port=8882

            # Verify that we can connect to the port using the previously
            # acquired ip
            print "  Verify connectivity with voltha ip and port..."
            self.assertTrue(is_open('{}:{}'.format(ip, port)))
        finally:
            self._stop_all_containers()
            self._wait_for_containers_stop()
            print "Test_02_dig_ip_resolution_End:------------------" \
                  "took {} secs \n\n".format(time.time() - t0)

    def test_03_scale_voltha(self):
        print "Test_03_scale_voltha_Start:------------------"
        t0 = time.time()

        try:
            prefix="scale"
            count=3
            self._stop_all_containers()
            self._wait_for_containers_stop()
            self._start_all_containers(prefix)
            self._wait_for_voltha_start(prefix)
            # Scale voltha to 3 instances
            print "Scale voltha to {} instances ...".format(count)
            cmd = "./integrations/swarm/test/helpers/scale_service.sh {} {} {}".format(prefix, "vcore", count)
            out, err, rc = run_command_to_completion_with_stdout_in_list(cmd)
            self.assertEqual(rc, 0)

            print "Verify {} instances are expected ...".format(count)
            cmd = "./integrations/swarm/test/helpers/get_instance_count.sh {} {}".format(prefix, "vcore")
            out, err, rc = run_command_to_completion_with_stdout_in_list(cmd)
            self.assertEqual(rc, 0)
            vals = out[0].strip().split("/")
            self.assertEqual(int(vals[1]), 3)

            # Verify that instances are running
            print "Verify {} instances of voltha are running ...".format(count)
            cmd = "./integrations/swarm/test/helpers/count_instances.sh {} {}".format(prefix, "vcore")
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            self.assertEqual(out.strip(), "{}".format(count))
        finally:
            self._stop_all_containers()
            self._wait_for_containers_stop()
            print "Test_03_scale_voltha_End:------------------took {} secs " \
                  "\n\n".format(time.time() - t0)
