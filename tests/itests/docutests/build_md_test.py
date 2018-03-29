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

from tests.itests.test_utils import run_command_to_completion_with_raw_stdout, \
    is_open, \
    is_valid_ip, \
    run_long_running_command_with_timeout, \
    run_command_to_completion_with_stdout_in_list

log = logging.getLogger(__name__)

LOCAL_CONSUL = "localhost:8500"
LOCAL_CONSUL_URL = "http://%s" % LOCAL_CONSUL
LOCAL_CONSUL_DNS = "@localhost -p 8600"
DOCKER_COMPOSE_PROJECT = "compose"
DOCKER_COMPOSE_FILE = "compose/docker-compose-docutests.yml"
DOCKER_COMPOSE_FILE_SERVICES_COUNT = 7

command_defs = dict(
    makefile_fetch_images="grep \"docker pull\" Makefile",
    make="make",
    make_clean_build="make -e DOCKER_CACHE_ARG=--no-cache build",
    make_fetch="make fetch",
    remove_env_directory="rm -rf venv-linux",
    make_clean="make clean",
    docker_images="docker images",
    docker_stop="docker stop",
    docker_rm="docker rm",
    fluentd_logs="less /tmp/fluentd/data.log",
    docker_voltha_logs="docker-compose -p {} -f {} logs voltha"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_logs="docker-compose -p {} -f {} logs"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_stop_and_remove_all_containers="docker stop `docker ps -q` ; "
                                          "docker rm `docker ps -a -q`",
    docker_start_voltha="docker run -ti --rm voltha/voltha",
    docker_start_voltha_with_consul_ip="docker run -ti --rm --net="
                                       "compose_default voltha/voltha "
                                       "/voltha/voltha/main.py --consul=",
    docker_get_consul_ip="docker inspect "
                         "compose_consul_1 | jq -r "
                         "'.[0].NetworkSettings.Networks."
                         "compose_default.IPAddress'",
    docker_compose_start_consul="docker-compose -p {} -f {} up -d "
                                "consul".format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_start_all="docker-compose -p {} -f {} up -d "
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_stop="docker-compose -p {} -f {} stop"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_rm_f="docker-compose -p {} -f {} rm -f"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_down="docker-compose -p {} -f {} down"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_ps="docker-compose -p {} -f {} ps"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_ps="docker ps",
    docker_ps_count="docker ps -q | wc -l",
    docker_compose_is_consul_up="docker-compose -p {} -f {} ps | grep consul"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    consul_get_leader_ip_port="curl -s {}/v1/status/leader | jq -r ."
        .format(LOCAL_CONSUL_URL),
    docker_compose_services_running="docker-compose -p {} -f {} ps -q"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_services_running_count="docker-compose -p {} -f {} ps -q | "
                                          "grep Up | wc -l"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_services="docker-compose -p {} -f {} config --services"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
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
    docker_compose_scale_voltha_to_10="docker-compose -p {} -f {} scale "
                                      "voltha=10"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    docker_compose_scaled_voltha_ps="docker-compose -p {} -f {} ps voltha | "
                                    "grep Up | wc -l"
        .format(DOCKER_COMPOSE_PROJECT, DOCKER_COMPOSE_FILE),
    consul_verify_voltha_registration="curl -s {}"
                                      "/v1/kv/service/voltha/members?recurse |"
                                      " jq -r .".format(LOCAL_CONSUL_DNS)
)


class BuildMdTests(TestCase):
    # docker_client = Client(base_url='unix://var/run/docker.sock')

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))


    def test_01_setup(self):
        print "Test_01_setup_Start:------------------"
        t0 = time.time()

        try:
            # remove the venv-linux directory
            print "Remove venv-linux ..."
            cmd = command_defs['remove_env_directory']
            rm_venv, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            # make clean
            print "Make clean ..."
            cmd = command_defs['make_clean']
            mk_clean, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            # source the env
            print "Source environment ..."
            self._source_env()

        finally:
            print "Test_01_setup_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)

    def test_02_make_fetch(self):
        print "Test_02_make_fetch_Start:------------------"
        t0 = time.time()

        try:
            # Get list of images to fetch from the Makefile
            print "Get list of images to fetch ..."
            cmd = command_defs['makefile_fetch_images']
            makefile_images_to_fetch, err, rc \
                = run_command_to_completion_with_stdout_in_list(cmd)
            self.assertEqual(rc, 0)

            images_to_fetch = []
            for image in makefile_images_to_fetch:
                tmp = ''.join(image.split())
                images_to_fetch.append(tmp[len('dockerpull'):])

            # make fetch
            print "Fetching images {} ...".format(images_to_fetch)
            cmd = command_defs['make_fetch']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            # verify that the images have been downloaded
            print "Verify images downloaded and present locally ..."
            cmd = command_defs['docker_images']
            local_images, err, rc = \
                run_command_to_completion_with_stdout_in_list(cmd)
            self.assertEqual(rc, 0)

            local_images_list = []
            for local_image in local_images:
                words = local_image.split()
                local_images_list.append('{}:{}'.format(words[0], words[1]))

            intersection_list = [i for i in images_to_fetch if
                                 i in local_images_list]
            assert len(intersection_list) == len(images_to_fetch)

        finally:
            print "Test_02_make_fetch_End:------------------ took {} " \
                  "secs \n\n".format(time.time() - t0)

    def test_03_make(self):
        print "Test_03_make_build_Start:------------------"
        t0 = time.time()
        try:
            cmd = command_defs['make_clean_build']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
        finally:
            print "Test_03_make_build_Start:------------------ took {} secs \n\n" \
                .format(time.time() - t0)

    def test_04_run_voltha_standalone_without_consul(self):
        print "Test_04_run_voltha_standalone_without_consul_Start:------------" \
              "------"
        t0 = time.time()

        try:
            # Run voltha for 10 secs and verity the following lines are displayed
            #  (a subset of output messages along with a flag when found)
            print "Start voltha ..."
            expected_output_subset = [
                'main.print_banner {event: (to stop: press Ctrl-C), '
                'instance_id:',
                'coordinator.__init__ {event: initializing-coordinator,',
                'grpc_server.start {event: started',
                'main.<lambda> {event: twisted-reactor-started',
                'main.startup_components {event: started-internal-services,',
                'kafka_proxy.start {event: started,',
                'coordinator._backoff {retry_in: 5, event: consul-not-up,'
            ]

            cmd = command_defs['docker_start_voltha']
            command_output = run_long_running_command_with_timeout(cmd, 10)

            # There should at least be 1 line in the output
            self.assertGreater(len(command_output), 0)

            # Verify that the output contained the expected_output_subset -
            # save the docker instance id
            print "Verify voltha started correctly ..."
            instance_id = None
            for ext_output in expected_output_subset:
                match_str = next(
                    (out for out in command_output if ext_output in out),
                    None)
                self.assertIsNotNone(match_str)
                if "instance_id" in ext_output:
                    instance_id = re.findall(r'[0-9a-f]+', match_str)[-1]

            # Now stop the voltha docker that was created
            print "Stop voltha ..."
            self._stop_docker_container_by_id(instance_id)


        finally:
            # Remove any created container
            self._stop_and_remove_all_containers()

            print "Test_04_run_voltha_standalone_without_consul_End" \
                  ":------------------ took {} secs \n\n".format(
                time.time() - t0)

    def test_05_run_consul_only(self):
        print "Test_05_run_consul_only_Start:------------------ "
        t0 = time.time()

        try:
            # run consul
            print "Start consul ..."
            self._run_consul()

            print "Waiting for consul to be ready ..."
            rc = self._wait_for_consul_to_be_ready()
            self.assertEqual(rc, 0)

            # Get the docker IP address and port number of the consul instance
            print "Get consul leader IP ..."
            cmd = command_defs['consul_get_leader_ip_port']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            # validate that the returned ip:port is valid and open
            print "Verify consul IP and port is reachable ..."
            self.assertTrue(is_open(out))

        finally:
            # clean up all created containers for this test
            print "Stop consul ..."
            self._stop_and_remove_all_containers()

            print "Test_05_run_consul_only_End:------------------ took {} secs" \
                  "\n\n".format(time.time() - t0)

    def test_06_run_voltha_standalone_with_consul_only(self):
        print "Test_06_run_voltha_standalone_with_consul_only_Start:----------" \
              "-------- "
        t0 = time.time()

        try:
            # run consul first
            print "Start consul ..."
            self._run_consul()

            # get consul ip
            print "Get consul IP ..."
            cmd = command_defs['docker_get_consul_ip']
            consul_ip, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            self.assertIsNotNone(consul_ip)

            # start voltha now for 15 secs and verify it can now connect to
            # consul - following message in the output
            print "Start voltha with consul IP ..."
            expected_pattern = ['coordinator', 'event: created-consul-session']
            cmd = command_defs['docker_start_voltha_with_consul_ip'] + \
                  '{}:8500'.format(consul_ip.strip())
            command_output = run_long_running_command_with_timeout(cmd, 10)

            # Verify the output of voltha and get the container instance id
            print "Verify voltha is registered with consul ..."
            instance_id = None
            for out in command_output:
                if all(ep for ep in expected_pattern if ep in out):
                    self.assertTrue(True)
                    instance_id = re.findall(r'[0-9a-f]+', out)[-1]
                    break

            self.assertIsNotNone(instance_id)

            # Verify Voltha's self-registration with consul
            expected_output = ['ModifyIndex', 'CreateIndex', 'Session',
                               'Value',
                               'Flags', 'Key', 'LockIndex']

            cmd = command_defs['consul_verify_voltha_registration']
            registration_info, err, rc = \
                run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            try:
                jr_info = json.loads(registration_info)
                intersect_elems = [e for e in jr_info[0] if
                                   e in expected_output]
                self.assertEqual(len(expected_output), len(intersect_elems))
            except Exception as e:
                self.assertRaises(e)

            # stop voltha
            print "Stop voltha ..."
            self._stop_docker_container_by_id(instance_id)

            # check the service has deregistered
            print "Verify voltha is no longer registered in consul..."
            cmd = command_defs['consul_verify_voltha_registration']
            registration_info, err, rc = \
                run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            self.assertEqual(registration_info, '')

        finally:
            # clean up all created containers for this test
            print "Stop consul ..."
            self._stop_and_remove_all_containers()

            print "Test_06_run_voltha_standalone_with_consul_only_End:--------" \
                  "---------- took {} " \
                  "secs \n\n".format(time.time() - t0)

    def test_07_start_all_containers(self):
        print "Test_07_start_all_containers_Start:------------------ "
        t0 = time.time()

        try:
            # Pre-test - clean up all running docker containers
            print "Pre-test: Removing all running containers ..."
            cmd = command_defs['docker_compose_stop']
            _, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            cmd = command_defs['docker_compose_rm_f']
            _, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            # get a list of services in the docker-compose file
            print "Getting list of services in docker compose file ..."
            cmd = command_defs['docker_compose_services']
            services, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            docker_service_list = services.split()
            self.assertGreaterEqual(len(docker_service_list),
                                    DOCKER_COMPOSE_FILE_SERVICES_COUNT)

            # start all the containers
            print "Starting all containers ..."
            cmd = command_defs['docker_compose_start_all']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            # Instead of using only a fixed timeout:
            #   1) wait until the services are ready (polling per second)
            #   2) bail out after a longer timeout.
            print "Waiting for all containers to be ready ..."
            self.wait_till('Not all services are up',
                           self._is_voltha_ensemble_ready,
                           interval=1,
                           timeout=30)

            # verify that all containers are running
            print "Verify all services are running using docker command ..."
            for service in docker_service_list:
                cmd = command_defs['docker_compose_ps'] + ' {} | wc -l'.format(
                    service)
                out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
                self.assertEqual(rc, 0)
                self.assertGreaterEqual(out, 3)  # 2 are for headers

            # Verify that 'docker ps' return the same number of running process
            cmd = command_defs['docker_ps_count']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            self.assertGreaterEqual(out, (len(docker_service_list)))

            # Retrieve the list of services from consul and validate against
            # the list obtained from docker composed
            print "Verify all services are registered in consul ..."
            expected_services = ['consul-rest', 'fluentd-intake',
                                 'voltha-grpc',
                                 'voltha-health',
                                 'consul-8600', 'zookeeper', 'consul',
                                 'kafka']

            cmd = command_defs['consul_get_services']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            try:
                consul_services = json.loads(out)
                intersected_services = [s for s in expected_services if
                                        s in consul_services]
                self.assertEqual(len(intersected_services),
                                 len(expected_services))
                # services_match = 0
                # for d_service in docker_service_list:
                #     for c_service in consul_services:
                #         if c_service.find(d_service) != -1:
                #             services_match += 1
                #             print d_service, c_service
                #             break
                # self.assertEqual(services_match, len(docker_service_list))
            except Exception as e:
                self.assertRaises(e)

            # Verify the service record of the voltha service
            print "Verify the service record of voltha in consul ..."
            expected_srv_elements = ['ModifyIndex', 'CreateIndex',
                                     'ServiceEnableTagOverride', 'Node',
                                     'Address', 'TaggedAddresses', 'ServiceID',
                                     'ServiceName', 'ServiceTags',
                                     'ServiceAddress', 'ServicePort']
            cmd = command_defs['consul_get_srv_voltha_health']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            try:
                srv = json.loads(out)
                intersect_elems = [e for e in srv[0] if
                                   e in expected_srv_elements]
                self.assertEqual(len(expected_srv_elements),
                                 len(intersect_elems))
            except Exception as e:
                self.assertRaises(e)

            # Verify kafka client is receiving the messages
            print "Verify kafka client has heartbeat topic ..."
            expected_pattern = ['voltha.heartbeat']
            kafka_endpoint = get_endpoint_from_consul(LOCAL_CONSUL,'kafka')
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

            # Commented the heartbeat messages from voltha as on Jenkins this
            # test fails more often than not.   On local or cluster environment
            # the kafka event bus works well.

            # verify docker-compose logs are being produced - just get the
            # first work of each line
            print "Verify docker compose logs has output from all the services " \
                  "..."
            expected_output = ['voltha_1', 'fluentd_1', 'vconsul_1',
                               'registrator_1', 'kafka_1', 'zookeeper_1',
                               'ofagent_1', 'netconf_1']
            cmd = command_defs['docker_compose_logs']
            docker_compose_logs = run_long_running_command_with_timeout(cmd, 5, 0)
            intersected_logs = [l for l in expected_output if
                                l in docker_compose_logs]
            self.assertEqual(len(intersected_logs), len(expected_output))

            # verify docker voltha logs are being produced - we will just verify
            # some
            # key messages in the logs
            print "Verify docker voltha logs are produced ..."
            self.wait_till('Basic voltha logs are absent',
                           self._is_basic_voltha_logs_produced,
                           interval=1,
                           timeout=30)

        finally:
            print "Stopping all containers ..."
            # clean up all created containers for this test
            #self._stop_and_remove_all_containers()
            cmd = command_defs['docker_compose_down']
            _, err, rc = run_command_to_completion_with_raw_stdout(cmd)

            print "Test_07_start_all_containers_End:------------------ took {}" \
                  " secs \n\n".format(time.time() - t0)

    def test_08_stop_all_containers_started_using_docker_compose(self):
        print "Test_08_stop_all_containers_started_using_docker_compose_Start:" \
              "------------------ "
        t0 = time.time()

        try:
            # commands to stop and clear the docker images
            cmds = [command_defs['docker_compose_stop'],
                    command_defs['docker_compose_rm_f']]

            print "Stopping all containers ..."
            for cmd in cmds:
                out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
                self.assertEqual(rc, 0)

            # Verify that no docker process is running
            print "Verify no containers is running..."
            cmd = command_defs['docker_compose_services_running']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

        finally:
            print "Test_08_stop_all_containers_started_using_docker_compose_:" \
                  "------------------ took {} secs \n\n".format(
                time.time() - t0)

    def test_09_dig_consul_command(self):
        print "Test_09_dig_consul_command_Start:------------------"
        t0 = time.time()

        try:
            # start all containers
            print "Start all containers..."
            self._start_all_containers()

            print "Waiting for all containers to be ready ..."
            time.sleep(10)
            rc = verify_all_services_healthy(LOCAL_CONSUL)
            if not  rc:
                print "Not all services are up"
            self.assertEqual(rc, True)

            # Get the IP address(es) for voltha's REST interface
            print "Get IP of Voltha REST interface..."
            cmd = command_defs['consul_get_voltha_rest_a_record']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            self.assertGreaterEqual(out.find("voltha-health.service.consul"),
                                    0)

            # Get only the ip address
            cmd = command_defs['consul_get_voltha_rest_ip']
            ip, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            self.assertTrue(is_valid_ip(ip))

            # Get the exposed service port
            print "Get Voltha exposed service port..."
            cmd = command_defs['consul_get_voltha_service_port']
            port, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            # Verify that we can connect to the port using the previously
            # acquired ip
            print "Verify connectivity with voltha ip and port..."
            self.assertTrue(is_open('{}:{}'.format(ip, port)))
        finally:
            print "Stopping all containers ..."
            # clean up all created containers for this test
            self._stop_and_remove_all_containers()

            print "Test_09_dig_consul_command_Start_End:------------------" \
                  "took {} secs \n\n".format(time.time() - t0)

    def test_10_scale_voltha(self):
        print "Test_10_scale_voltha_Start:------------------"
        t0 = time.time()

        try:
            # start all containers
            print "Start all containers..."
            self._start_all_containers()

            # Instead of using only a fixed timeout:
            #   1) wait until the services are ready (polling per second)
            #   2) bail out after a longer timeout.
            print "Waiting for all containers to be ready ..."
            self.wait_till('Not all services are up',
                           self._is_voltha_ensemble_ready,
                           interval=1,
                           timeout=30)

            # Scale voltha to 10 instances
            print "Scale voltha to 10 instances ..."
            cmd = command_defs['docker_compose_scale_voltha_to_10']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            # Verify that 10 instances are running
            print "Verify 10 instances of voltha are running ..."
            cmd = command_defs['docker_compose_scaled_voltha_ps']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)
            self.assertEqual(out.split(), ['10'])
        finally:
            print "Stopping all containers ..."
            # clean up all created containers for this test
            self._stop_and_remove_all_containers()

            print "Test_10_scale_voltha_End:------------------took {} secs " \
                  "\n\n".format(time.time() - t0)

    def _start_all_containers(self):
        cmd = command_defs['docker_compose_start_all']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

    def _is_voltha_ensemble_ready(self):
        res = verify_all_services_healthy(LOCAL_CONSUL)
        if not res:
            print "Not all consul services are ready ..."
        return res

    def _is_basic_voltha_logs_produced(self):
        expected_output = ['coordinator._renew_session', 'main.heartbeat']
        cmd = command_defs['docker_voltha_logs']
        docker_voltha_logs = run_long_running_command_with_timeout(cmd,
                                                                   10, 5)
        intersected_logs = [l for l in expected_output if
                            l in docker_voltha_logs]
        return  len(intersected_logs) == len(expected_output)

    def _run_consul(self):
        # run consul
        cmd = command_defs['docker_compose_start_consul']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        # verify consul is up
        cmd = command_defs['docker_compose_is_consul_up']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)
        self.assertIn('compose_consul_1', out)

    def _stop_and_remove_all_containers(self):
        # check if there are any running containers first
        cmd = command_defs['docker_ps']
        out, err, rc = run_command_to_completion_with_stdout_in_list(cmd)
        self.assertEqual(rc, 0)
        if len(out) > 1:  # not counting docker ps header
            cmd = command_defs['docker_stop_and_remove_all_containers']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

    def _stop_docker_container_by_id(self, instance_id):
        # stop
        cmd = command_defs['docker_stop'] + " {}".format(instance_id)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        # remove
        cmd = command_defs['docker_rm'] + " {}".format(instance_id)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

    def _source_env(self):
        # Go to voltha root directory
        res = os.system('cd {}'.format(this_dir))
        assert res == 0

        # set the env
        command = ['bash', '-c', '. env.sh']
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        if proc.wait() != 0:
            err_msg = "Failed to source the environment'"
            raise RuntimeError(err_msg)

        env = os.environ.copy()
        return env

    def _wait_for_consul_to_be_ready(self):
        # Consul is ready when it's leader ip and port is set.  The maximum
        # time to wait of 60 secs as consul should be ready by then
        max_wait_time = 60
        t0 = time.time()

        while True:
            # Get the docker IP address and port number of the consul instance
            print "waiting for consul to be ready ..."
            cmd = command_defs['consul_get_leader_ip_port']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            out = out.strip()
            if rc != 0:
                # Something is wrong, return
                return -1  # error
            elif out is not None and out != '':
                return 0  # found something
            elif time.time() - t0 > max_wait_time:
                return -1  # consul should have come up by this time
            else:
                time.sleep(2)  # constant sleep for testing
