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
from unittest import main, TestCase
from nose.tools import *
from requests import get
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul
from common.utils.consulhelpers import verify_all_services_healthy
from tests.itests.test_utils import \
    run_command_to_completion_with_raw_stdout, \
    run_command_to_completion_with_stdout_in_list

LOCAL_CONSUL = "localhost:8500"
DOCKER_COMPOSE_FILE = "compose/docker-compose-system-test.yml"

command_defs = dict(
    docker_ps="docker ps",
    docker_compose_start_all="docker-compose -f {} up -d "
        .format(DOCKER_COMPOSE_FILE),
    docker_stop_and_remove_all_containers="docker-compose -f {} down"
        .format(DOCKER_COMPOSE_FILE),
)


class SelfSignedSSLCertAuthFail(RestBase):

    t0 = [time()]

    def pt(self, msg=''):
        t1 = time()
        print '%20.8f ms - %s' % (1000 * (t1 - SelfSignedSSLCertAuthFail.t0[0]),
                                  msg)
        SelfSignedSSLCertAuthFail.t0[0] = t1


    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))


    def test_01_self_signed_ssl_cert_auth_failure(self):
        # Start the voltha ensemble with a single voltha instance
        self._stop_and_remove_all_containers()
        sleep(5)  # A small wait for the system to settle down
        self.start_all_containers()
        self.set_rest_endpoint()

        self._get_health()

    def _stop_and_remove_all_containers(self):
        # check if there are any running containers first
        cmd = command_defs['docker_ps']
        out, err, rc = run_command_to_completion_with_stdout_in_list(cmd)
        self.assertEqual(rc, 0)
        if len(out) > 1:  # not counting docker ps header
            cmd = command_defs['docker_stop_and_remove_all_containers']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

    def start_all_containers(self):
        t0 = time()

        # start all the containers
        self.pt("Starting all containers ...")
        cmd = command_defs['docker_compose_start_all']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        self.pt("Waiting for voltha container to be ready ...")
        self.wait_till('voltha services HEALTHY',
                       lambda: verify_all_services_healthy(
                           LOCAL_CONSUL, service_name='voltha-grpc') == True,
                       timeout=10)

        sleep(10)

    def set_rest_endpoint(self):
        self.rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL,
                                                      'envoy-8443')
        self.base_url = 'https://' + self.rest_endpoint

    @raises(Exception)
    def _get_health(self):
        # Raises SSLError exception because "verify" set to true and
        # we use self-signed certificates
        res = self.get('/health', verify=True)


if __name__ == '__main__':
    main()
