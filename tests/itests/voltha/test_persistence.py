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
from google.protobuf.json_format import MessageToDict
from time import time, sleep
from voltha.core.flow_decomposer import *
from voltha.protos import openflow_13_pb2 as ofp
import simplejson, jsonschema
import os
import subprocess
import select

from tests.itests.test_utils import \
    run_command_to_completion_with_raw_stdout, \
    run_command_to_completion_with_stdout_in_list
from unittest import skip

from common.utils.consulhelpers import verify_all_services_healthy

from voltha.protos.device_pb2 import Device
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul
from voltha.protos.voltha_pb2 import AlarmFilter

LOCAL_CONSUL = "localhost:8500"
DOCKER_COMPOSE_FILE = "compose/docker-compose-system-test-persistence.yml"

command_defs = dict(
    docker_ps="docker ps",
    docker_compose_start_all="docker-compose -f {} up -d "
        .format(DOCKER_COMPOSE_FILE),
    docker_stop_and_remove_all_containers="docker-compose -f {} down"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_start_voltha="docker-compose -f {} up -d voltha "
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_stop_voltha="docker-compose -f {} stop voltha"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_remove_voltha="docker-compose -f {} rm -f voltha"
        .format(DOCKER_COMPOSE_FILE),
    kafka_topics="kafkacat -b {} -L",
    kafka_alarms="kafkacat -o end -b {} -C -t voltha.alarms -c 2",
    kafka_kpis="kafkacat -o end -b {} -C -t voltha.kpis -c 5"
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


class TestConsulPersistence(RestBase):
    t0 = [time()]

    def pt(self, msg=''):
        t1 = time()
        print '%20.8f ms - %s' % (1000 * (t1 - TestConsulPersistence.t0[0]),
                                  msg)
        TestConsulPersistence.t0[0] = t1

    # @skip('Test case hangs during execution. Investigation required. Refer to VOL-425 and VOL-427')
    def test_all_scenarios(self):
        self.basic_scenario()
        self.data_integrity()

    def basic_scenario(self):
        # 1. Setup the test
        #       A. Stop and restart all containers (to start from clean)
        #       B. Setup the REST endpoint
        self.pt('Test setup - starts')
        self._stop_and_remove_all_containers()
        sleep(5)  # A small wait for the system to settle down
        self.start_all_containers()
        self.set_rest_endpoint()
        self.set_kafka_endpoint()
        self.pt('Test setup - ends')

        # 2. Test 1 - Verify no data is present in voltha
        self.pt('Test 1 - starts')
        self.verify_instance_has_no_data()
        self.pt('Test 1 - ends')

        # 3. Test 2 - Verify voltha data is preserved after a restart
        #       A. Add data to voltha
        #       B. Stop voltha instance only (data is in consul)
        #       C. Start a new voltha instance
        #       D. Verify the data is previoulsy set data is in the new voltha
        #           instance
        self.pt('Test 2 - starts')
        self.add_data_to_voltha_instance()
        instance_data_before = self.get_voltha_instance_data()
        self.stop_remove_start_voltha()
        instance_data_after = self.get_voltha_instance_data()
        self.assertEqual(instance_data_before, instance_data_after)
        self.pt('Test 2 - ends')

    def data_integrity(self):
        """
        This test goes through several voltha restarts along with variations 
        of configurations in between to ensure data integrity is preserved.
        
        During this test, the user will be prompted to start ponsim.  Use 
        these commands to run ponsim with 1 OLT and 4 ONUs. THis will also 
        enable alarm at a frequency of 5 seconds:
            sudo -s
            . ./env.sh
            ./ponsim/main.py -v -o 4 -a -f 5

         The user will also be prompted to enable port forwarding on ponmgmt 
         bridge. Use these commands:
            sudo -s
            echo 8 > /sys/class/net/ponmgmt/bridge/group_fwd_mask            
         """

        def prompt(input_func, text):
            val = input_func(text)
            return val

        def prompt_for_return(text):
            return raw_input(text)

        # 1. Setup the test
        #       A. Stop and restart all containers (to start from clean)
        #       B. Setup the REST endpoint
        self.pt('Test setup - starts')
        self._stop_and_remove_all_containers()
        sleep(5)  # A small wait for the system to settle down
        self.start_all_containers()
        self.consume_kafka_message_starting_at = time()
        self.set_rest_endpoint()
        self.set_kafka_endpoint()
        self.pt('Test setup - ends')

        # Get the user to start PONSIM as root
        prompt(prompt_for_return,
               '\nStart PONSIM as root with alarms enabled in another window ...')

        prompt(prompt_for_return,
               '\nEnsure port forwarding is set on ponmgnt ...')

        # 2. Configure some data on the volthainstance
        self.assert_no_device_present()
        host = '172.17.0.1'
        olt = self.add_olt_device(host)
        olt_id = olt['id']
        self.pt(olt_id)
        self.verify_device_preprovisioned_state(olt_id)
        self.enable_device(olt_id)
        ldev_id = self.wait_for_logical_device(olt_id)
        onu_ids = self.wait_for_onu_discovery(olt_id)
        self.verify_logical_ports(ldev_id, 5)
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        self.assert_kpis_event(olt_id)
        self.assert_alarm_generation(olt_id)
        alarm_filter = self.create_device_filter(olt_id)
        self.consume_kafka_message_starting_at = time()
        self.assert_alarm_generation(olt_id, event_present=False)

        # 3. Kill and restart the voltha instance
        self.assert_restart_voltha_successful()
        self.assert_kpis_event(olt_id)
        self.remove_device_filter(alarm_filter['id'])
        self.assert_alarm_generation(olt_id)

        self.pt('Voltha restart with initial set of data - successful')

        # 4. Ensure we can keep doing operation on the new voltha instance
        # as if nothing happened
        olt_ids, onu_ids = self.get_olt_onu_devices()
        self.disable_device(onu_ids[0])
        self.verify_logical_ports(ldev_id, 4)

        # 5. Kill and restart the voltha instance
        self.assert_restart_voltha_successful()
        self.assert_kpis_event(olt_id)
        alarm_filter = self.create_device_filter(olt_id)
        self.consume_kafka_message_starting_at = time()
        self.assert_alarm_generation(olt_id, event_present=False)
        self.remove_device_filter(alarm_filter['id'])
        self.assert_alarm_generation(olt_id)

        self.pt('Voltha restart with disabled ONU - successful')

        # 6. Do some more operations
        self.enable_device(onu_ids[0])
        self.verify_logical_ports(ldev_id, 5)
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        self.disable_device(olt_ids[0])
        self.assert_all_onus_state(olt_ids[0], 'DISABLED', 'UNKNOWN')
        self.assert_no_logical_device()

        # 6. Kill and restart the voltha instance
        self.assert_restart_voltha_successful()
        self.assert_kpis_event(olt_id, event_present=False)
        self.assert_alarm_generation(olt_id, event_present=False)

        self.pt('Voltha restart with disabled OLT - successful')

        # 7. Enable OLT and very states of ONUs
        self.enable_device(olt_ids[0])
        self.assert_all_onus_state(olt_ids[0], 'ENABLED', 'ACTIVE')
        self.wait_for_logical_device(olt_ids[0])

        # 8. Kill and restart the voltha instance
        self.assert_restart_voltha_successful()
        self.assert_kpis_event(olt_id)
        self.assert_alarm_generation(olt_id)

        self.pt('Voltha restart with re-enabled OLT - successful')

        # 9. Install EAPOL and disable ONU
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        self.disable_device(onu_ids[0])

        # 10. Kill and restart the voltha instance
        self.assert_restart_voltha_successful()
        self.assert_kpis_event(olt_id)
        self.assert_alarm_generation(olt_id)

        self.pt('Voltha restart with EAPOL and disabled ONU - successful')

        # 11. Delete the OLT and ONU
        self.delete_device(onu_ids[0])
        self.verify_logical_ports(ldev_id, 4)
        self.disable_device(olt_ids[0])
        self.delete_device(olt_ids[0])
        self.assert_no_device_present()

        # 13. Kill and restart the voltha instance
        self.assert_restart_voltha_successful()
        self.assert_kpis_event(olt_id, event_present=False)
        self.assert_alarm_generation(olt_id, event_present=False)

        self.pt('Voltha restart with no data - successful')

        # 14.  Verify no device present
        self.assert_no_device_present()

    def set_rest_endpoint(self):
        self.rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL,
                                                      'voltha-envoy-8443')
        self.base_url = 'https://' + self.rest_endpoint

    def set_kafka_endpoint(self):
        self.kafka_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'kafka')

    def assert_restart_voltha_successful(self):
        self.maxDiff = None
        instance_data_before = self.get_voltha_instance_data()
        self.stop_remove_start_voltha()
        instance_data_after = self.get_voltha_instance_data()
        self.assertEqual(instance_data_before, instance_data_after)

    def stop_remove_start_voltha(self):
        self.stop_voltha(remove=True)
        self.consume_kafka_message_starting_at = time()
        self.start_voltha()
        # REST endpoint may have changed after a voltha restart
        # Send a basic command to trigger the REST endpoint to refresh itself
        try:
            self.get_devices()
        except Exception as e:
            self.pt('get-devices-fail expected')
        # Wait for everything to settle
        sleep(10)
        # Update the REST endpoint info
        self.set_rest_endpoint()

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

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
                       lambda: verify_all_services_healthy(LOCAL_CONSUL,
                                                           service_name='vcore-grpc') == True,
                       timeout=10)
        sleep(10)

    def start_voltha(self):
        t0 = time()
        self.pt("Starting voltha ...")
        cmd = command_defs['docker_compose_start_voltha']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        self.pt("Waiting for voltha to be ready ...")
        self.wait_till('voltha service HEALTHY',
                       lambda: verify_all_services_healthy(LOCAL_CONSUL,
                                                           service_name='vcore-grpc') == True,
                       timeout=30)
        self.pt("Voltha is ready ...")

    def stop_voltha(self, remove=False):
        t0 = time()
        self.pt("Stopping voltha ...")
        cmd = command_defs['docker_compose_stop_voltha']
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        if remove:
            cmd = command_defs['docker_compose_remove_voltha']
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

    def get_devices(self):
        devices = self.get('/api/v1/devices')['items']
        return devices

    def get_logical_devices(self):
        ldevices = self.get('/api/v1/logical_devices')['items']
        return ldevices

    def get_adapters(self):
        adapters = self.get('/api/v1/adapters')['items']
        return adapters

    def verify_instance_has_no_data(self):
        data = self.get_voltha_instance_data()
        self.assertEqual(data['logical_devices']['items'], None or [])
        self.assertEqual(data['devices']['items'], None or [])

    def add_data_to_voltha_instance(self):
        # Preprovision a bunch of ponsim devices
        self.n_olts = 100
        self.olt_devices = {}
        for i in xrange(self.n_olts):
            host = '172.17.1.{}'.format(i)
            d = self.add_olt_device(host)
            self.olt_devices[d['id']] = d

    def get_voltha_instance_data(self):
        data = {}
        data['devices'] = self.get('/api/v1/devices')
        data['logical_devices'] = self.get('/api/v1/logical_devices')
        return data

    def add_olt_device(self, host):
        device = Device(
            type='ponsim_olt',
            host_and_port='{}:50060'.format(host)
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device

    def get_olt_onu_devices(self):
        devices = self.get('/api/v1/devices')['items']
        olt_ids = []
        onu_ids = []
        for d in devices:
            if d['adapter'] == 'ponsim_olt':
                olt_ids.append(d['id'])
            elif d['adapter'] == 'ponsim_onu':
                onu_ids.append(d['id'])
            else:
                onu_ids.append(d['id'])
        return olt_ids, onu_ids

    def verify_device_preprovisioned_state(self, olt_id):
        # we also check that so far what we read back is same as what we get
        # back on create
        device = self.get('/api/v1/devices/{}'.format(olt_id))
        self.assertNotEqual(device['id'], '')
        self.assertEqual(device['adapter'], 'ponsim_olt')
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
        self.wait_till(
            'admin state ACTIVE',
            lambda: self.get(path)['oper_status'] == 'ACTIVE',
            timeout=0.5)
        device = self.get(path)
        self.assertEqual(device['connect_status'], 'REACHABLE')

        ports = self.get(path + '/ports')['items']
        self.assertEqual(len(ports), 2)

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
        self.assertEqual(logical_port['device_port_no'], 2)
        return logical_device['id']

    def find_onus(self, olt_id):
        devices = self.get('/api/v1/devices')['items']
        return [
            d for d in devices
            if d['parent_id'] == olt_id
        ]

    def wait_for_onu_discovery(self, olt_id):
        # shortly after we shall see the discovery of four new onus, linked to
        # the olt device
        self.wait_till(
            'find four ONUs linked to the olt device',
            lambda: len(self.find_onus(olt_id)) >= 4,
            2
        )
        # verify that they are properly set
        onus = self.find_onus(olt_id)
        for onu in onus:
            self.assertEqual(onu['admin_state'], 'ENABLED')
            self.assertEqual(onu['oper_status'], 'ACTIVE')

        return [onu['id'] for onu in onus]

    def assert_all_onus_state(self, olt_id, admin_state, oper_state):
        # verify all onus are in a given state
        onus = self.find_onus(olt_id)
        for onu in onus:
            self.assertEqual(onu['admin_state'], admin_state)
            self.assertEqual(onu['oper_status'], oper_state)

        return [onu['id'] for onu in onus]

    def assert_onu_state(self, onu_id, admin_state, oper_state):
        # Verify the onu states are correctly set
        onu = self.get('/api/v1/devices/{}'.format(onu_id))
        self.assertEqual(onu['admin_state'], admin_state)
        self.assertEqual(onu['oper_status'], oper_state)

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

    def simulate_eapol_flow_install(self, ldev_id, olt_id, onu_ids):

        # emulate the flow mod requests that shall arrive from the SDN
        # controller, one for each ONU
        lports = self.get(
            '/api/v1/logical_devices/{}/ports'.format(ldev_id)
        )['items']

        # device_id -> logical port map, which we will use to construct
        # our flows
        lport_map = dict((lp['device_id'], lp) for lp in lports)
        for onu_id in onu_ids:
            # if eth_type == 0x888e => send to controller
            _in_port = lport_map[onu_id]['ofp_port']['port_no']
            req = ofp.FlowTableUpdate(
                id=ldev_id,
                flow_mod=mk_simple_flow_mod(
                    match_fields=[
                        in_port(_in_port),
                        vlan_vid(ofp.OFPVID_PRESENT | 0),
                        eth_type(0x888e)],
                    actions=[
                        output(ofp.OFPP_CONTROLLER)
                    ],
                    priority=1000
                )
            )
            res = self.post('/api/v1/logical_devices/{}/flows'.format(ldev_id),
                            MessageToDict(req,
                                          preserving_proto_field_name=True),
                            expected_http_code=200)

        # for sanity, verify that flows are in flow table of logical device
        flows = self.get(
            '/api/v1/logical_devices/{}/flows'.format(ldev_id))['items']
        self.assertGreaterEqual(len(flows), 4)

    def verify_olt_eapol_flow(self, olt_id):
        # olt shall have two flow rules, one is the default and the
        # second is the result of eapol forwarding with rule:
        # if eth_type == 0x888e => push vlan(1000); out_port=nni_port
        flows = self.get('/api/v1/devices/{}/flows'.format(olt_id))['items']
        self.assertEqual(len(flows), 8)
        flow = flows[1]
        self.assertEqual(flow['table_id'], 0)
        self.assertEqual(flow['priority'], 1000)

        # TODO refine this
        # self.assertEqual(flow['match'], {})
        # self.assertEqual(flow['instructions'], [])

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
        self.assertEqual(len(ports), 2)
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

    def delete_device_incorrect_state(self, id):
        path = '/api/v1/devices/{}'.format(id)
        self.delete(path + '/delete', expected_http_code=200, grpc_status=3)

    def enable_unknown_device(self, id):
        path = '/api/v1/devices/{}'.format(id)
        self.post(path + '/enable', expected_http_code=200, grpc_status=5)

    def disable_unknown_device(self, id):
        path = '/api/v1/devices/{}'.format(id)
        self.post(path + '/disable', expected_http_code=200, grpc_status=5)

    def delete_unknown_device(self, id):
        path = '/api/v1/devices/{}'.format(id)
        self.delete(path + '/delete', expected_http_code=200, grpc_status=5)

    def assert_alarm_generation(self, device_id, event_present=True):
        # The olt device should start generating alarms periodically
        alarm = self.assert_alarm_event(device_id, event_present)

        if event_present:
            self.assertIsNotNone(alarm)
            # Make sure that the schema is valid
            self.assert_alarm_event_schema(alarm)

    # Validate a sample alarm for a specific device
    def assert_alarm_event(self, device_id, event_present=True):
        self.alarm_data = None

        def validate_output(data):
            alarm = simplejson.loads(data)

            if not alarm or \
                            'resource_id' not in alarm or \
                            'reported_ts' not in alarm:
                return False

            # Check for new alarms only
            if alarm['reported_ts'] > self.consume_kafka_message_starting_at:
                if alarm['resource_id'] == device_id:
                    self.alarm_data = alarm
                    return True

        cmd = command_defs['kafka_alarms'].format(self.kafka_endpoint)

        self.run_command_and_wait_until(cmd, validate_output, 30, 'alarms',
                                        expected_predicate_result=event_present)

        return self.alarm_data

    # Validate a sample kpi for a specific device
    def assert_kpis_event(self, device_id, event_present=True):

        def validate_output(data):
            kpis_data = simplejson.loads(data)

            if not kpis_data or \
                            'ts' not in kpis_data or \
                            'prefixes' not in kpis_data:
                return False

            # Check only new kpis
            if kpis_data['ts'] > self.consume_kafka_message_starting_at:
                for key, value in kpis_data['prefixes'].items():
                    if device_id in key:
                        return True
            return False

        cmd = command_defs['kafka_kpis'].format(self.kafka_endpoint)

        self.run_command_and_wait_until(cmd, validate_output, 60, 'kpis',
                                        expected_predicate_result=event_present)

    # Verify that the alarm follows the proper schema structure
    def assert_alarm_event_schema(self, alarm):
        try:
            jsonschema.validate(alarm, ALARM_SCHEMA)
        except Exception as e:
            self.assertTrue(
                False, 'Validation failed for alarm : {}'.format(e.message))

    def create_device_filter(self, device_id):
        rules = list()
        rule = dict()

        # Create a filter with a single rule
        rule['key'] = 'device_id'
        rule['value'] = device_id
        rules.append(rule)

        alarm_filter = AlarmFilter(rules=rules)
        alarm_filter = self.post('/api/v1/alarm_filters',
                                 MessageToDict(alarm_filter),
                                 expected_http_code=200)
        self.assertIsNotNone(alarm_filter)
        return alarm_filter

    def remove_device_filter(self, alarm_filter_id):
        path = '/api/v1/alarm_filters/{}'.format(alarm_filter_id)
        self.delete(path, expected_http_code=200)
        alarm_filter = self.get(path, expected_http_code=200, grpc_status=5)
        self.assertIsNone(alarm_filter)

    def run_command_and_wait_until(self, cmd, predicate, timeout, msg,
                                   expected_predicate_result=True):
        # Run until the predicate is True or timeout
        try:
            deadline = time() + timeout
            env = os.environ.copy()
            proc = subprocess.Popen(
                cmd,
                env=env,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1
            )
            poll_obj = select.poll()
            poll_obj.register(proc.stdout, select.POLLIN)
            while time() < deadline:
                poll_result = poll_obj.poll(0)
                if poll_result:
                    line = proc.stdout.readline()
                    if predicate(line):
                        try:
                            proc.terminate()
                            proc.wait()
                            subprocess.Popen(['reset']).wait()
                        except Exception as e:
                            print "Received exception {} when killing process " \
                                  "started with {}".format(repr(e), cmd)
                        if not expected_predicate_result:
                            self.fail(
                                'Predicate is True but is should be false:{}'.
                                    format(msg))
                        else:
                            return
            try:
                proc.terminate()
                proc.wait()
                subprocess.Popen(['reset']).wait()
            except Exception as e:
                print "Received exception {} when killing process " \
                      "started with {}".format(repr(e), cmd)

            if expected_predicate_result:
                self.fail(
                    'Timed out while waiting for condition: {}'.format(msg))

        except Exception as e:
            print 'Exception {} when running command:{}'.format(repr(e), cmd)
        return
