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

import simplejson
from google.protobuf.json_format import MessageToDict

from common.utils.consulhelpers import get_endpoint_from_consul
from tests.itests.test_utils import get_pod_ip, \
    run_long_running_command_with_timeout
from tests.itests.voltha.rest_base import RestBase
from voltha.protos.device_pb2 import Device
from voltha.protos.voltha_pb2 import AlarmFilter
from testconfig import config

# ~~~~~~~ Common variables ~~~~~~~

LOCAL_CONSUL = "localhost:8500"
ENV_DOCKER_COMPOSE = 'docker-compose'
ENV_K8S_SINGLE_NODE = 'k8s-single-node'

orch_env = ENV_DOCKER_COMPOSE
if 'test_parameters' in config and 'orch_env' in config['test_parameters']:
    orch_env = config['test_parameters']['orch_env']
print 'orchestration-environment: %s' % orch_env

COMMANDS = dict(
    kafka_client_run="kafkacat -b {} -L",
    kafka_client_send_msg='echo hello | kafkacat -b {} -P -t voltha.alarms -c 1',
    kafka_client_alarm_check="kafkacat -o end -b {} -C -t voltha.alarms -c 2",
)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


class VolthaAlarmFilterTests(RestBase):
    # Get endpoint info
    if orch_env == ENV_K8S_SINGLE_NODE:
        rest_endpoint = get_pod_ip('voltha') + ':8443'
        kafka_endpoint = get_pod_ip('kafka')
    else:
        rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'voltha-envoy-8443')
        kafka_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'kafka')

    # Construct the base_url
    base_url = 'https://' + rest_endpoint

    # ~~~~~~~~~~~~ Tests ~~~~~~~~~~~~

    def test_1_alarm_topic_exists(self):
        # Produce a message to ensure that the topic exists
        cmd = COMMANDS['kafka_client_send_msg'].format(self.kafka_endpoint)
        run_long_running_command_with_timeout(cmd, 5)

        # We want to make sure that the topic is available on the system
        expected_pattern = ['voltha.alarms']

        # Start the kafka client to retrieve details on topics
        cmd = COMMANDS['kafka_client_run'].format(self.kafka_endpoint)
        kafka_client_output = run_long_running_command_with_timeout(cmd, 20)

        # Loop through the kafka client output to find the topic
        found = False
        for out in kafka_client_output:
            if all(ep in out for ep in expected_pattern):
                found = True
                break

        self.assertTrue(found,
                        'Failed to find topic {}'.format(expected_pattern))

    def test_2_alarm_generated_by_adapter(self):
        # Verify that REST calls can be made
        self.verify_rest()

        # Create a new device
        device_not_filtered = self.add_device('00:00:00:00:00:01')
        device_filtered = self.add_device('00:00:00:00:00:02')

        self.add_device_id_filter(device_filtered['id'])

        # Activate the new device
        self.activate_device(device_not_filtered['id'])
        self.activate_device(device_filtered['id'])

        # The simulated olt devices should start generating alarms periodically

        # We should see alarms generated for the non filtered device
        self.get_alarm_event(device_not_filtered['id'])

        # We should not see any alarms from the filtered device
        self.get_alarm_event(device_filtered['id'], True)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    # Make sure the Voltha REST interface is available
    def verify_rest(self):
        self.get('/api/v1')

    # Create a new simulated device
    def add_device(self, mac_address):
        device = Device(
            type='simulated_olt',
            mac_address=mac_address
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device

    # Create a filter against a specific device id
    def add_device_id_filter(self, device_id):
        rules = list()
        rule = dict()

        # Create a filter with a single rule
        rule['key'] = 'device_id'
        rule['value'] = device_id
        rules.append(rule)

        alarm_filter = AlarmFilter(rules=rules)
        alarm_filter = self.post('/api/v1/alarm_filters', MessageToDict(alarm_filter),
                                 expected_http_code=200)

        return alarm_filter

    # Active the simulated device.
    # This will trigger the simulation of random alarms
    def activate_device(self, device_id):
        path = '/api/v1/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_http_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    # Retrieve a sample alarm for a specific device
    def get_alarm_event(self, device_id, expect_failure=False):
        cmd = COMMANDS['kafka_client_alarm_check'].format(self.kafka_endpoint)
        kafka_client_output = run_long_running_command_with_timeout(cmd, 30)

        # Verify the kafka client output
        found = False
        alarm_data = None

        for out in kafka_client_output:
            # Catch any error that might occur while reading the kafka messages
            try:
                alarm_data = simplejson.loads(out)
                print alarm_data

                if not alarm_data or 'resource_id' not in alarm_data:
                    continue
                elif alarm_data['resource_id'] == device_id:
                    found = True
                    break

            except Exception as e:
                continue

        if not expect_failure:
            self.assertTrue(
                found,
                'Failed to find kafka alarm with device id:{}'.format(device_id))
        else:
            self.assertFalse(
                found,
                'Found a kafka alarm with device id:{}.  It should have been filtered'.format(
                    device_id))

        return alarm_data


if __name__ == '__main__':
    main()
