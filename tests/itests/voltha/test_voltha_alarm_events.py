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
from common.utils.consulhelpers import get_endpoint_from_consul
from tests.itests.test_utils import get_pod_ip, \
    run_long_running_command_with_timeout
from tests.itests.voltha.rest_base import RestBase
from google.protobuf.json_format import MessageToDict
from voltha.protos.device_pb2 import Device
import simplejson, jsonschema
import re
from tests.itests.orch_environment import get_orch_environment
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

ALARM_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "type": {"type": "string"},
        "category": {"type": "string"},
        "state": {"type": "string"},
        "severity": {"type": "string"},
        "resource_id": {"type": "string"},
        "raised_ts": {"type": "number"},
        "reported_ts": {"type": "number"},
        "changed_ts": {"type": "number"},
        "description": {"type": "string"},
        "context": {
            "type": "object",
            "additionalProperties": {"type": "string"}
        }
    }
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


class VolthaAlarmEventTests(RestBase):
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
        device = self.add_device()

        # Activate the new device
        self.activate_device(device['id'])

        # The simulated olt device should start generating alarms periodically
        alarm = self.get_alarm_event(device['id'])

        # Make sure that the schema is valid
        self.validate_alarm_event_schema(alarm)

        # Validate the constructed alarm id
        self.verify_alarm_event_id(device['id'], alarm['id'])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    # Make sure the Voltha REST interface is available
    def verify_rest(self):
        self.get('/api/v1')

    # Create a new simulated device
    def add_device(self):
        device = Device(
            type='simulated_olt',
            mac_address='00:00:00:00:00:01'
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device

    # Active the simulated device.
    # This will trigger the simulation of random alarms
    def activate_device(self, device_id):
        path = '/api/v1/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_http_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    # Retrieve a sample alarm for a specific device
    def get_alarm_event(self, device_id):
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

        self.assertTrue(
            found,
            'Failed to find kafka alarm with device id:{}'.format(device_id))

        return alarm_data

    # Verify that the alarm follows the proper schema structure
    def validate_alarm_event_schema(self, alarm):
        try:
            jsonschema.validate(alarm, ALARM_SCHEMA)
        except Exception as e:
            self.assertTrue(
                False, 'Validation failed for alarm : {}'.format(e.message))

    # Verify that alarm identifier based on the format generated by default.
    def verify_alarm_event_id(self, device_id, alarm_id):
        prefix = re.findall(r"(voltha)\.(\w+)\.(\w+)", alarm_id)

        self.assertEqual(
            len(prefix), 1,
            'Failed to parse the alarm id: {}'.format(alarm_id))
        self.assertEqual(
            len(prefix[0]), 3,
            'Expected id format: voltha.<adapter name>.<device id>')
        self.assertEqual(
            prefix[0][0], 'voltha',
            'Expected id format: voltha.<adapter name>.<device id>')
        self.assertEqual(
            prefix[0][1], 'simulated_olt',
            'Expected id format: voltha.<adapter name>.<device id>')
        self.assertEqual(
            prefix[0][2], device_id,
            'Expected id format: voltha.<adapter name>.<device id>')


if __name__ == '__main__':
    main()
