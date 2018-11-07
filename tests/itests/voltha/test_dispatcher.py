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
from random import randint
from time import time, sleep

from google.protobuf.json_format import MessageToDict, ParseDict
from unittest import main, skip
from voltha.protos.device_pb2 import Device
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul, \
    get_all_instances_of_service
from common.utils.consulhelpers import verify_all_services_healthy
from tests.itests.test_utils import \
    run_command_to_completion_with_raw_stdout, \
    run_command_to_completion_with_stdout_in_list
from voltha.protos.voltha_pb2 import AlarmFilter
from google.protobuf.empty_pb2 import Empty
import grpc
from voltha.protos import third_party
from voltha.protos import voltha_pb2, voltha_pb2_grpc
from voltha.core.flow_decomposer import *
from voltha.protos.openflow_13_pb2 import FlowTableUpdate
from voltha.protos import bbf_fiber_base_pb2 as fb
from tests.itests.voltha.xpon_scenario import scenario as xpon_scenario
from tests.itests.test_utils import get_pod_ip
from tests.itests.orch_environment import get_orch_environment
from testconfig import config

LOCAL_CONSUL = "localhost:8500"
DOCKER_COMPOSE_FILE = "compose/docker-compose-system-test-dispatcher.yml"
ENV_DOCKER_COMPOSE = 'docker-compose'
ENV_K8S_SINGLE_NODE = 'k8s-single-node'

orch_env = ENV_DOCKER_COMPOSE
if 'test_parameters' in config and 'orch_env' in config['test_parameters']:
    orch_env = config['test_parameters']['orch_env']
print 'orchestration-environment: %s' % orch_env
orch = get_orch_environment(orch_env)

command_defs = dict(
    docker_ps="docker ps",
    docker_compose_start_all="docker-compose -f {} up -d "
        .format(DOCKER_COMPOSE_FILE),
    docker_stop_and_remove_all_containers="docker-compose -f {} down"
        .format(DOCKER_COMPOSE_FILE),
    docker_compose_scale_voltha="docker-compose -f {} scale "
                                "voltha=".format(DOCKER_COMPOSE_FILE)
)

command_k8s = dict(
    docker_ps = "kubectl -n voltha get pods",
    docker_compose_start_all = "./tests/itests/env/voltha-ponsim-k8s-start.sh",
    docker_stop_and_remove_all_containers = "./tests/itests/env/voltha-ponsim-k8s-stop.sh",
    docker_compose_scale_voltha = "kubectl -n voltha scale deployment vcore --replicas="
)

commands = {
    ENV_DOCKER_COMPOSE: command_defs,
    ENV_K8S_SINGLE_NODE: command_k8s
}
vcore_svc_name = {
    ENV_DOCKER_COMPOSE: 'vcore-grpc',
    ENV_K8S_SINGLE_NODE: 'vcore'
}
envoy_svc_name = {
    ENV_DOCKER_COMPOSE: 'voltha-grpc',
    ENV_K8S_SINGLE_NODE: 'voltha'
}
obj_type_config = {
    'cg':     {'type':'channel_groups',
               'config':'channelgroup_config'},
    'cpart':  {'type':'channel_partitions',
               'config':'channelpartition_config'},
    'cpair':  {'type':'channel_pairs',
               'config':'channelpair_config'},
    'cterm':  {'type':'channel_terminations',
               'config':'channeltermination_config'},
    'vontani':{'type':'v_ont_anis',
               'config':'v_ontani_config'},
    'ontani': {'type':'ont_anis',
               'config':'ontani_config'},
    'venet':  {'type':'v_enets',
               'config':'v_enet_config'},
    'gemport':{'type':'gemports',
               'config':'gemports_config'},
    'tcont':  {'type':'tconts',
               'config':'tconts_config'},
    'tdp':    {'type':'traffic_descriptor_profiles',
               'config':'traffic_descriptor_profiles'}
}

def get_command(cmd):
    if orch_env == ENV_K8S_SINGLE_NODE and cmd in commands[ENV_K8S_SINGLE_NODE]:
        return commands[ENV_K8S_SINGLE_NODE][cmd]
    else:
        return commands[ENV_DOCKER_COMPOSE][cmd]

class DispatcherTest(RestBase):
    def setUp(self):
        self.grpc_channels = dict()

    t0 = [time()]

    def pt(self, msg=''):
        t1 = time()
        print '%20.8f ms - %s' % (1000 * (t1 - DispatcherTest.t0[0]),
                                  msg)
        DispatcherTest.t0[0] = t1

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    def get_channel(self, voltha_grpc):
        if voltha_grpc not in self.grpc_channels:
            self.grpc_channels[voltha_grpc] = grpc.insecure_channel(
                voltha_grpc)
        return self.grpc_channels[voltha_grpc]

    def test_01_global_rest_apis(self):
        # Start the voltha ensemble with a single voltha instance
        self._stop_and_remove_all_containers()
        sleep(5)  # A small wait for the system to settle down
        self.start_all_containers()
        self.set_rest_endpoint()

        # self._get_root_rest()
        self._get_schema_rest()
        self._get_health_rest()
        self._get_voltha_rest()
        self._list_voltha_instances_rest()
        self._get_voltha_instance_rest()
        olt_id = self._add_olt_device_rest()
        self._verify_device_preprovisioned_state_rest(olt_id)
        self._activate_device_rest(olt_id)
        ldev_id = self._wait_for_logical_device_rest(olt_id)
        ldevices = self._list_logical_devices_rest()
        logical_device_id = ldevices['items'][0]['id']
        self._get_logical_device_rest(logical_device_id)
        self._list_logical_device_ports_rest(logical_device_id)
        self._list_and_update_logical_device_flows_rest(logical_device_id)
        self._list_and_update_logical_device_flow_groups_rest(
            logical_device_id)
        devices = self._list_devices_rest()
        device_id = devices['items'][0]['id']
        self._get_device_rest(device_id)
        self._list_device_ports_rest(device_id)
# TODO: Figure out why this test fails
#        self._list_device_flows_rest(device_id)
        self._list_device_flow_groups_rest(device_id)
        self._get_images_rest(device_id)
        self._self_test_rest(device_id)
        dtypes = self._list_device_types_rest()
        self._get_device_type_rest(dtypes['items'][0]['id'])
        alarm_filter = self._create_device_filter_rest(olt_id)
        self._remove_device_filter_rest(alarm_filter['id'])
        #for xPON objects
        for item in xpon_scenario:
            for key,value in item.items():
                try:
                    _device_id = None
                    _obj_action = [val for val in key.split('-')]
                    _type_config = obj_type_config[_obj_action[0]]
                    if _obj_action[0] == "cterm":
                        _device_id = olt_id
                    if _obj_action[1] == "mod":
                        continue
                    elif _obj_action[1] == "add":
                        _xpon_obj = self._create_xpon_object_rest(_type_config,
                                                                  value,
                                                                  _device_id)
                    elif _obj_action[1] == "del":
                        self._delete_xpon_object_rest(_type_config,
                                                      value,
                                                      _device_id)
                except Exception, e:
                    print 'An error occurred', e
                    continue

        # TODO: PM APIs test

    # @skip('Test fails due to environment configuration.  Need to investigate.  Refer to VOL-427')
    def test_02_cross_instances_dispatch(self):

        def prompt(input_func, text):
            val = input_func(text)
            return val

        def prompt_for_return(text):
            return raw_input(text)

        # Start the voltha ensemble with a single voltha instance
        self._stop_and_remove_all_containers()
        sleep(5)  # A small wait for the system to settle down
        self.start_all_containers()
        self.set_rest_endpoint()

        # Scale voltha to 3 instances and setup the voltha grpc assigments
        self._scale_voltha(3)
        sleep(20)  # A small wait for the system to settle down
        voltha_instances = orch.get_all_instances_of_service(vcore_svc_name[orch_env], port_name='grpc')
        self.assertEqual(len(voltha_instances), 3)
        self.ponsim_voltha_stub_local = voltha_pb2_grpc.VolthaLocalServiceStub(
            self.get_channel(self._get_grpc_address(voltha_instances[2])))
        self.ponsim_voltha_stub_global = voltha_pb2_grpc.VolthaGlobalServiceStub(
            self.get_channel(self._get_grpc_address(voltha_instances[2])))

        self.simulated_voltha_stub_local = voltha_pb2_grpc.VolthaLocalServiceStub(
            self.get_channel(self._get_grpc_address(voltha_instances[1])))
        self.simulated_voltha_stub_global = voltha_pb2_grpc.VolthaGlobalServiceStub(
            self.get_channel(self._get_grpc_address(voltha_instances[1])))

        self.empty_voltha_stub_local = voltha_pb2_grpc.VolthaLocalServiceStub(
            self.get_channel(self._get_grpc_address(voltha_instances[0])))
        self.empty_voltha_stub_global = voltha_pb2_grpc.VolthaGlobalServiceStub(
            self.get_channel(self._get_grpc_address(voltha_instances[0])))

        if orch_env == ENV_DOCKER_COMPOSE:
            # Prompt the user to start ponsim
            # Get the user to start PONSIM as root
            prompt(prompt_for_return,
                   '\nStart PONSIM as root in another window ...')

            prompt(prompt_for_return,
                   '\nEnsure port forwarding is set on ponmgnt ...')

        # Test 1:
        # A. Get the list of adapters using a global stub
        # B. Get the list of adapters using a local stub
        # C. Verify that the two lists are the same
        adapters_g = self._get_adapters_grpc(self.ponsim_voltha_stub_global)
        adapters_l =  self._get_adapters_grpc(self.empty_voltha_stub_local)
        assert adapters_g == adapters_l

        # Test 2:
        # A. Provision a pomsim olt using the ponsim_voltha_stub
        # B. Enable the posim olt using the simulated_voltha_stub
        # C. Wait for onu discovery using the empty_voltha_stub
        ponsim_olt = self._provision_ponsim_olt_grpc(
            self.ponsim_voltha_stub_local)
        ponsim_logical_device_id = self._enable_device_grpc(
            self.simulated_voltha_stub_global,
            ponsim_olt.id)
        self._wait_for_onu_discovery_grpc(self.empty_voltha_stub_global,
                                          ponsim_olt.id,
                                          count=4)
        # Test 3:
        # A. Provision a simulated olt using the simulated_voltha_stub
        # B. Enable the simulated olt using the ponsim_voltha_stub
        # C. Wait for onu discovery using the empty_voltha_stub
        simulated_olt = self._provision_simulated_olt_grpc(
            self.simulated_voltha_stub_local)
        simulated_logical_device_id = self._enable_device_grpc(
            self.ponsim_voltha_stub_global, simulated_olt.id)
        self._wait_for_onu_discovery_grpc(self.empty_voltha_stub_global,
                                          simulated_olt.id, count=4)

        # Test 4:
        # Verify that we have at least 8 devices created using the global
        # REST and also via direct grpc in the empty stub
        devices_via_rest = self._list_devices_rest(8)['items']
        devices_via_global_grpc = self._get_devices_grpc(
            self.empty_voltha_stub_global)
        assert len(devices_via_rest) == len(devices_via_global_grpc)

        # Test 5:
        # A. Create 2 Alarms filters using REST
        # B. Ensure it is present across all instances
        # C. Ensure when requesting the alarm filters we do not get
        # duplicate results
        alarm_filter1 = self._create_device_filter_rest(ponsim_olt.id)
        alarm_filter2 = self._create_device_filter_rest(simulated_olt.id)
        global_filters = self._get_alarm_filters_rest()
        filter = self._get_alarm_filters_grpc(self.simulated_voltha_stub_local)
        assert global_filters == MessageToDict(filter)
        filter = self._get_alarm_filters_grpc(self.ponsim_voltha_stub_local)
        assert global_filters == MessageToDict(filter)
        filter = self._get_alarm_filters_grpc(self.empty_voltha_stub_local)
        assert global_filters == MessageToDict(filter)
        filter = self._get_alarm_filters_grpc(self.empty_voltha_stub_global)
        assert global_filters == MessageToDict(filter)

        # Test 6:
        # A. Delete an alarm filter
        # B. Ensure that filter is deleted from all instances
        self._remove_device_filter_rest(alarm_filter1['id'])
        previous_filters = global_filters
        global_filters = self._get_alarm_filters_rest()
        assert global_filters != previous_filters
        filter = self._get_alarm_filters_grpc(self.simulated_voltha_stub_local)
        assert global_filters == MessageToDict(filter)
        filter = self._get_alarm_filters_grpc(self.ponsim_voltha_stub_local)
        assert global_filters == MessageToDict(filter)
        filter = self._get_alarm_filters_grpc(self.empty_voltha_stub_local)
        assert global_filters == MessageToDict(filter)
        filter = self._get_alarm_filters_grpc(self.empty_voltha_stub_global)
        assert global_filters == MessageToDict(filter)

        # Test 7:
        # A. Simulate EAPOL install on ponsim instance using grpc
        # B. Validate the flows using global REST
        # C. Retrieve the flows from global grpc using empty voltha instance
        self._install_eapol_flow_grpc(self.ponsim_voltha_stub_local,
                                      ponsim_logical_device_id)
        self._verify_olt_eapol_flow_rest(ponsim_olt.id)
        res = self._get_olt_flows_grpc(self.empty_voltha_stub_global,
                                       ponsim_logical_device_id)

        # Test 8:
        # A. Create xPON objects instance using REST
        # B. Ensuring that Channeltermination is present on specific instances
        # C. Ensuring that other xPON objects are present in all instances
        for item in xpon_scenario:
            for key,value in item.items():
                _obj_action = [val for val in key.split('-')]
                _type_config = obj_type_config[_obj_action[0]]
                if _obj_action[1] == "mod":
                    continue
                if _obj_action[0] == "cterm":
                    if _obj_action[1] == "add":
                        #Ponsim OLT
                        self._create_xpon_object_rest(_type_config,
                                                      value,
                                                      ponsim_olt.id)
                        self._verify_xpon_object_on_device(
                            _type_config,
                            self.ponsim_voltha_stub_global,
                            ponsim_olt.id)
                        self._delete_xpon_object_rest(_type_config,
                                                      value,
                                                      ponsim_olt.id)
                        #Simulated OLT
                        self._create_xpon_object_rest(_type_config,
                                                      value,
                                                      simulated_olt.id)
                        self._verify_xpon_object_on_device(
                            _type_config,
                            self.simulated_voltha_stub_global,
                            simulated_olt.id)
                        self._delete_xpon_object_rest(_type_config,
                                                      value,
                                                      simulated_olt.id)
                    elif _obj_action[1] == "del":
                        continue
                else:
                    if _obj_action[1] == "add":
                        self._create_xpon_object_rest(_type_config, value)
                        #Checking with Ponsim OLT
                        self._verify_xpon_object_on_device(
                            _type_config,
                            self.ponsim_voltha_stub_global)
                        #Checking with empty instance
                        self._verify_xpon_object_on_device(
                            _type_config,
                            self.empty_voltha_stub_global)
                        #Checking with Simulated OLT
                        self._verify_xpon_object_on_device(
                            _type_config,
                            self.simulated_voltha_stub_global)
                    elif _obj_action[1] == "del":
                        self._delete_xpon_object_rest(_type_config, value)

        #TODO:  More tests to be added as new features are added


    def _get_grpc_address(self, voltha_instance):
        address = '{}:{}'.format(voltha_instance['ServiceAddress'],
                                 voltha_instance['ServicePort'])
        return address

    def _stop_and_remove_all_containers(self):
        # check if there are any running containers first
        cmd = get_command('docker_ps')
        out, err, rc = run_command_to_completion_with_stdout_in_list(cmd)
        self.assertEqual(rc, 0)
        if len(out) > 1:  # not counting docker ps header
            cmd = get_command('docker_stop_and_remove_all_containers')
            out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

    def start_all_containers(self):
        t0 = time()

        # start all the containers
        self.pt("Starting all containers ...")
        cmd = get_command('docker_compose_start_all')
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

        self.pt("Waiting for voltha container to be ready ...")
        self.wait_till('voltha services HEALTHY',
                       lambda: orch.verify_all_services_healthy(
                           service_name=envoy_svc_name[orch_env]) == True,
                       timeout=10)
        sleep(10)

    def set_rest_endpoint(self):
        if orch_env == ENV_K8S_SINGLE_NODE:
            self.rest_endpoint = get_pod_ip('voltha') + ':8443'
        else:
            self.rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL,
                                                          'voltha-envoy-8443')
        self.base_url = 'https://' + self.rest_endpoint

    def set_kafka_endpoint(self):
        self.kafka_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'kafka')

    def _scale_voltha(self, scale=2):
        self.pt("Scaling voltha ...")
        cmd = get_command('docker_compose_scale_voltha') + str(scale)
        out, err, rc = run_command_to_completion_with_raw_stdout(cmd)
        self.assertEqual(rc, 0)

    def _get_root_rest(self):
        res = self.get('/', expected_content_type='text/html')
        self.assertGreaterEqual(res.find('swagger'), 0)

    def _get_schema_rest(self):
        res = self.get('/schema')
        self.assertEqual(set(res.keys()),
                         {'protos', 'yang_from', 'swagger_from'})

    def _get_health_rest(self):
        res = self.get('/health')
        self.assertEqual(res['state'], 'HEALTHY')

    # ~~~~~~~~~~~~~~~~~~~~~ TOP LEVEL VOLTHA OPERATIONS ~~~~~~~~~~~~~~~~~~~~~~~

    def _get_voltha_rest(self):
        res = self.get('/api/v1')
        self.assertEqual(res['version'], '0.9.0')

    def _list_voltha_instances_rest(self):
        res = self.get('/api/v1/instances')
        self.assertEqual(len(res['items']), 1)

    def _get_voltha_instance_rest(self):
        res = self.get('/api/v1/instances')
        voltha_id = res['items'][0]
        res = self.get('/api/v1/instances/{}'.format(voltha_id))
        self.assertEqual(res['version'], '0.9.0')

    def _add_olt_device_rest(self, grpc=None):
        device = Device(
            type='simulated_olt',
            mac_address='00:00:00:00:00:01'
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device['id']

    def _provision_simulated_olt_grpc(self, stub):
        device = Device(
            type='simulated_olt',
            mac_address='00:00:00:00:00:01'
        )
        device = stub.CreateDevice(device)
        return device

    def _provision_ponsim_olt_grpc(self, stub):
        if orch_env == ENV_K8S_SINGLE_NODE:
            host_and_port = get_pod_ip('olt') + ':50060'
        else:
            host_and_port = '172.17.0.1:50060'
        device = Device(
            type='ponsim_olt',
            host_and_port=host_and_port
        )
        device = stub.CreateDevice(device)
        return device

    def _enable_device_grpc(self, stub, device_id):
        logical_device_id = None
        try:
            stub.EnableDevice(voltha_pb2.ID(id=device_id))
            while True:
                device = stub.GetDevice(voltha_pb2.ID(id=device_id))
                # If this is an OLT then acquire logical device id
                if device.oper_status == voltha_pb2.OperStatus.ACTIVE:
                    if device.type.endswith('_olt'):
                        assert device.parent_id
                        logical_device_id = device.parent_id
                        self.pt('success (logical device id = {})'.format(
                            logical_device_id))
                    else:
                        self.pt('success (device id = {})'.format(device.id))
                    break
                self.pt('waiting for device to be enabled...')
                sleep(.5)
        except Exception, e:
            self.pt('Error enabling {}.  Error:{}'.format(device_id, e))
        return logical_device_id

    def _delete_device_grpc(self, stub, device_id):
        try:
            stub.DeleteDevice(voltha_pb2.ID(id=device_id))
            while True:
                device = stub.GetDevice(voltha_pb2.ID(id=device_id))
                assert not device
        except Exception, e:
            self.pt('deleting device {}.  Error:{}'.format(device_id, e))

    def _get_devices_grpc(self, stub):
        res = stub.ListDevices(Empty())
        return res.items

    def _get_adapters_grpc(self, stub):
        res = stub.ListAdapters(Empty())
        return res.items

    def _find_onus_grpc(self, stub, olt_id):
        devices = self._get_devices_grpc(stub)
        return [
            d for d in devices
            if d.parent_id == olt_id
        ]

    def _wait_for_onu_discovery_grpc(self, stub, olt_id, count=4):
        # shortly after we shall see the discovery of four new onus, linked to
        # the olt device
        #
        # NOTE: The success of the wait_till invocation below appears to be very
        # sensitive to the values of the interval and timeout parameters.
        #
        self.wait_till(
            'find ONUs linked to the olt device',
            lambda: len(self._find_onus_grpc(stub, olt_id)) >= count,
            interval=2, timeout=10
        )
        # verify that they are properly set
        onus = self._find_onus_grpc(stub, olt_id)
        for onu in onus:
            self.assertEqual(onu.admin_state, 3)  # ENABLED
            self.assertEqual(onu.oper_status, 4)  # ACTIVE

        return [onu.id for onu in onus]

    def _verify_device_preprovisioned_state_rest(self, olt_id):
        # we also check that so far what we read back is same as what we get
        # back on create
        device = self.get('/api/v1/devices/{}'.format(olt_id))
        self.assertNotEqual(device['id'], '')
        self.assertEqual(device['adapter'], 'simulated_olt')
        self.assertEqual(device['admin_state'], 'PREPROVISIONED')
        self.assertEqual(device['oper_status'], 'UNKNOWN')

    def _activate_device_rest(self, olt_id):
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
        images = device['images']
        image = images['image']
        image_1 = image[0]
        version = image_1['version']
        self.assertNotEqual(version, '')
        self.assertEqual(device['connect_status'], 'REACHABLE')

        ports = self.get(path + '/ports')['items']
        self.assertEqual(len(ports), 2)

    def _wait_for_logical_device_rest(self, olt_id):
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
        self.assertEqual(logical_port['ofp_port']['port_no'], 129)
        self.assertEqual(logical_port['device_id'], device['id'])
        self.assertEqual(logical_port['device_port_no'], 2)
        return logical_device['id']

    def _list_logical_devices_rest(self):
        res = self.get('/api/v1/logical_devices')
        self.assertGreaterEqual(len(res['items']), 1)
        return res

    def _get_logical_device_rest(self, id):
        res = self.get('/api/v1/logical_devices/{}'.format(id))
        self.assertIsNotNone(res['datapath_id'])

    def _list_logical_device_ports_rest(self, id):
        res = self.get('/api/v1/logical_devices/{}/ports'.format(id))
        self.assertGreaterEqual(len(res['items']), 1)

    def _list_and_update_logical_device_flows_rest(self, id):

        # retrieve flow list
        res = self.get('/api/v1/logical_devices/{}/flows'.format(id))
        len_before = len(res['items'])

        # add some flows
        req = ofp.FlowTableUpdate(
            id=id,
            flow_mod=mk_simple_flow_mod(
                cookie=randint(1, 10000000000),
                priority=len_before,
                match_fields=[
                    in_port(129)
                ],
                actions=[
                    output(1)
                ]
            )
        )
        res = self.post('/api/v1/logical_devices/{}/flows'.format(id),
                        MessageToDict(req, preserving_proto_field_name=True),
                        expected_http_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/logical_devices/{}/flows'.format(id))
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def _list_and_update_logical_device_flow_groups_rest(self, id):

        # retrieve flow list
        res = self.get('/api/v1/logical_devices/{}/flow_groups'.format(id))
        len_before = len(res['items'])

        # add some flows
        req = ofp.FlowGroupTableUpdate(
            id=id,
            group_mod=ofp.ofp_group_mod(
                command=ofp.OFPGC_ADD,
                type=ofp.OFPGT_ALL,
                group_id=len_before + 1,
                buckets=[
                    ofp.ofp_bucket(
                        actions=[
                            ofp.ofp_action(
                                type=ofp.OFPAT_OUTPUT,
                                output=ofp.ofp_action_output(
                                    port=1
                                )
                            )
                        ]
                    )
                ]
            )
        )
        res = self.post('/api/v1/logical_devices/{}/flow_groups'.format(id),
                        MessageToDict(req, preserving_proto_field_name=True),
                        expected_http_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/logical_devices/{}/flow_groups'.format(id))
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def _list_devices_rest(self, count=2):
        res = self.get('/api/v1/devices')
        self.assertGreaterEqual(len(res['items']), count)
        return res

    def _get_device_rest(self, id):
        res = self.get('/api/v1/devices/{}'.format(id))
        # TODO test result

    def _list_device_ports_rest(self, id, count=2):
        res = self.get('/api/v1/devices/{}/ports'.format(id))
        self.assertGreaterEqual(len(res['items']), count)

    def _list_device_flows_rest(self, id, count=1):
        # pump some flows into the logical device
        res = self.get('/api/v1/devices/{}/flows'.format(id))
        self.assertGreaterEqual(len(res['items']), count)

    def _list_device_flow_groups_rest(self, id, count=0):
        res = self.get('/api/v1/devices/{}/flow_groups'.format(id))
        self.assertGreaterEqual(len(res['items']), count)

    def _list_device_types_rest(self, count=2):
        res = self.get('/api/v1/device_types')
        self.assertGreaterEqual(len(res['items']), count)
        return res

    def _get_device_type_rest(self, dtype):
        res = self.get('/api/v1/device_types/{}'.format(dtype))
        self.assertIsNotNone(res)
        # TODO test the result

    def _list_device_groups(self):
        pass
        # res = self.get('/api/v1/device_groups')
        # self.assertGreaterEqual(len(res['items']), 1)

    def _get_device_group(self):
        pass
        # res = self.get('/api/v1/device_groups/1')
        # # TODO test the result

    def _get_images_rest(self, id):
        res = self.get('/api/v1/devices/{}/images'.format(id))
        self.assertIsNotNone(res)

    def _self_test_rest(self, id):
        res = self.post('/api/v1/devices/{}/self_test'.format(id),
                        expected_http_code=200)
        self.assertIsNotNone(res)

    def _create_device_filter_rest(self, device_id):
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

    def _remove_device_filter_rest(self, alarm_filter_id):
        path = '/api/v1/alarm_filters/{}'.format(alarm_filter_id)
        self.delete(path, expected_http_code=200)
        alarm_filter = self.get(path, expected_http_code=200, grpc_status=5)
        self.assertIsNone(alarm_filter)

    def _get_alarm_filter_grpc(self, stub, alarm_filter_id):
        res = stub.GetAlarmFilter(voltha_pb2.ID(id=alarm_filter_id))
        return res

    def _get_alarm_filters_grpc(self, stub):
        res = stub.ListAlarmFilters(Empty())
        return res

    def _get_alarm_filters_rest(self):
        res = self.get('/api/v1/alarm_filters')
        return res

    def _install_eapol_flow_grpc(self, stub, logical_device_id):
        """
        Install an EAPOL flow on the given logical device. If device is not
        given, it will be applied to logical device of the last pre-provisioned
        OLT device.
        """

        # gather NNI and UNI port IDs
        nni_port_no, unis = self._get_logical_ports(stub, logical_device_id)

        # construct and push flow rule
        for uni_port_no, _ in unis:
            update = FlowTableUpdate(
                id=logical_device_id,
                flow_mod=mk_simple_flow_mod(
                    priority=2000,
                    match_fields=[in_port(uni_port_no), eth_type(0x888e)],
                    actions=[
                        # push_vlan(0x8100),
                        # set_field(vlan_vid(4096 + 4000)),
                        output(ofp.OFPP_CONTROLLER)
                    ]
                )
            )
            res = stub.UpdateLogicalDeviceFlowTable(update)
            self.pt('success for uni {} ({})'.format(uni_port_no, res))

    def _get_logical_ports(self, stub, logical_device_id):
        """
        Return the NNI port number and the first usable UNI port of logical
        device, and the vlan associated with the latter.
        """
        ports = stub.ListLogicalDevicePorts(
            voltha_pb2.ID(id=logical_device_id)).items
        nni = None
        unis = []
        for port in ports:
            if port.root_port:
                assert nni is None, "There shall be only one root port"
                nni = port.ofp_port.port_no
            else:
                uni = port.ofp_port.port_no
                uni_device = self._get_device_grpc(stub, port.device_id)
                vlan = uni_device.vlan
                unis.append((uni, vlan))

        assert nni is not None, "No NNI port found"
        assert unis, "Not a single UNI?"

        return nni, unis

    def _get_device_grpc(self, stub, device_id, depth=0):
        res = stub.GetDevice(voltha_pb2.ID(id=device_id),
                             metadata=(('get-depth', str(depth)),))
        return res

    def _verify_olt_eapol_flow_rest(self, logical_device_id):
        flows = self.get('/api/v1/devices/{}/flows'.format(logical_device_id))[
            'items']
        self.assertEqual(len(flows), 8)
        flow = flows[1]
        self.assertEqual(flow['table_id'], 0)
        self.assertEqual(flow['priority'], 2000)


    def _get_olt_flows_grpc(self, stub, logical_device_id):
        res = stub.ListLogicalDeviceFlows(voltha_pb2.ID(id=logical_device_id))
        return res

    #For xPON objects
    def _get_path(self, type, name, operation, device_id=None):
        if(type == 'channel_terminations'):
            return '/api/v1/devices/{}/{}/{}{}'.format(device_id, type, name,
                                                       operation)
        return '/api/v1/{}/{}{}'.format(type, name, operation)

    def _get_xpon_object_rest(self, obj_type, device_id=None):
        if obj_type["type"] == "channel_terminations":
            res = self.get('/api/v1/devices/{}/{}'.format(device_id,
                                                          obj_type["type"]))
        else:
            res = self.get('/api/v1/{}'.format(obj_type["type"]))
        return res

    def _get_xpon_object_grpc(self, stub, obj_type, device_id=None):
        if obj_type["type"] == "channel_groups":
            res = stub.GetAllChannelgroupConfig(Empty())
        elif obj_type["type"] == "channel_partitions":
            res = stub.GetAllChannelpartitionConfig(Empty())
        elif obj_type["type"] == "channel_pairs":
            res = stub.GetAllChannelpairConfig(Empty())
        elif obj_type["type"] == "channel_terminations":
            res = stub.GetAllChannelterminationConfig(
                voltha_pb2.ID(id=device_id))
        elif obj_type["type"] == "v_ont_anis":
            res = stub.GetAllVOntaniConfig(Empty())
        elif obj_type["type"] == "ont_anis":
            res = stub.GetAllOntaniConfig(Empty())
        elif obj_type["type"] == "v_enets":
            res = stub.GetAllVEnetConfig(Empty())
        elif obj_type["type"] == "gemports":
            res = stub.GetAllGemportsConfigData(Empty())
        elif obj_type["type"] == "tconts":
            res = stub.GetAllTcontsConfigData(Empty())
        elif obj_type["type"] == "traffic_descriptor_profiles":
            res = stub.GetAllTrafficDescriptorProfileData(Empty())
        return res

    def _create_xpon_object_rest(self, obj_type, value, device_id=None):
        ParseDict(value['rpc'], value['pb2'])
        request = value['pb2']
        self.post(self._get_path(obj_type["type"], value['rpc']['name'], "",
                                 device_id),
                  MessageToDict(request, preserving_proto_field_name = True),
                  expected_http_code = 200)
        return request

    def _delete_xpon_object_rest(self, obj_type, value, device_id=None):
        self.delete(self._get_path(obj_type["type"], value['rpc']['name'],
                                   "/delete", device_id), expected_http_code = 200)

    def _verify_xpon_object_on_device(self, type_config, stub, device_id=None):
        global_xpon_obj = self._get_xpon_object_rest(type_config, device_id)
        xpon_obj = self._get_xpon_object_grpc(stub, type_config, device_id)
        assert global_xpon_obj == MessageToDict(xpon_obj,
            including_default_value_fields = True,
            preserving_proto_field_name = True)

if __name__ == '__main__':
    main()
