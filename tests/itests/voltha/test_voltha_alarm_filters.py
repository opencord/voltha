from unittest import main

import simplejson
from google.protobuf.json_format import MessageToDict

from common.utils.consulhelpers import get_endpoint_from_consul
from tests.itests.docutests.test_utils import \
    run_long_running_command_with_timeout
from tests.itests.voltha.rest_base import RestBase
from voltha.protos.device_pb2 import Device
from voltha.protos.voltha_pb2 import AlarmFilter

# ~~~~~~~ Common variables ~~~~~~~

LOCAL_CONSUL = "localhost:8500"

COMMANDS = dict(
    kafka_client_run="kafkacat -b {} -L",
    kafka_client_alarm_check="kafkacat -o -5 -b {} -C -t voltha.alarms -c 10",
)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


class VolthaAlarmFilterTests(RestBase):
    # Retrieve details on the REST entry point
    rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'chameleon-rest')

    # Construct the base_url
    base_url = 'http://' + rest_endpoint

    # Start by querying consul to get the endpoint details
    kafka_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'kafka')

    # ~~~~~~~~~~~~ Tests ~~~~~~~~~~~~

    def test_alarm_topic_exists(self):
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

    def test_alarm_generated_by_adapter(self):
        # Verify that REST calls can be made
        self.verify_rest()

        # Create a new device
        device_not_filtered = self.add_device()
        device_filtered = self.add_device()

        self.add_device_id_filter(device_filtered['id'])

        # Activate the new device
        self.activate_device(device_not_filtered['id'])
        self.activate_device(device_filtered['id'])

        # The simulated olt devices should start generating alarms periodically

        # We should see alarms generated for the non filtered device
        alarm_not_filtered = self.get_alarm_event(device_not_filtered['id'])

        # We should not see any alarms from the filtered device
        alarm_filtered = self.get_alarm_event(device_filtered['id'], True)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    # Make sure the Voltha REST interface is available
    def verify_rest(self):
        self.get('/api/v1')

    # Create a new simulated device
    def add_device(self):
        device = Device(
            type='simulated_olt',
        )
        device = self.post('/api/v1/local/devices', MessageToDict(device),
                           expected_code=200)
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
        alarm_filter = self.post('/api/v1/local/alarm_filters', MessageToDict(alarm_filter),
                                 expected_code=200)

        return alarm_filter

    # Active the simulated device.
    # This will trigger the simulation of random alarms
    def activate_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    # Retrieve a sample alarm for a specific device
    def get_alarm_event(self, device_id, expect_failure=False):
        cmd = COMMANDS['kafka_client_alarm_check'].format(self.kafka_endpoint)
        kafka_client_output = run_long_running_command_with_timeout(cmd, 30)

        # Verify the kafka client output
        found = False
        self.alarm_data = None

        for out in kafka_client_output:
            self.alarm_data = simplejson.loads(out)

            print self.alarm_data

            if 'resource_id' not in self.alarm_data:
                continue
            elif self.alarm_data['resource_id'] == device_id:
                found = True
                break

        if not expect_failure:
            self.assertTrue(
                found,
                'Failed to find kafka alarm with device id:{}'.format(device_id))
        else:
            self.assertFalse(
                found,
                'Found a kafka alarm with device id:{}.  It should have been filtered'.format(
                    device_id))

        return self.alarm_data


if __name__ == '__main__':
    main()
