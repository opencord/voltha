from random import randint
from time import time, sleep

from google.protobuf.json_format import MessageToDict
from unittest import main, TestCase
from voltha.protos.device_pb2 import Device
from tests.itests.voltha.rest_base import RestBase
from voltha.core.flow_decomposer import mk_simple_flow_mod, in_port, output
from voltha.protos import openflow_13_pb2 as ofp
from common.utils.consulhelpers import get_endpoint_from_consul
from common.utils.consulhelpers import verify_all_services_healthy
from tests.itests.docutests.test_utils import \
    run_command_to_completion_with_raw_stdout, \
    run_command_to_completion_with_stdout_in_list
from voltha.protos.voltha_pb2 import AlarmFilter

LOCAL_CONSUL = "localhost:8500"
DOCKER_COMPOSE_FILE = "compose/docker-compose-system-test.yml"

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

class DispatcherTest(RestBase):

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


    def test_01_global_rest_apis(self):
        # Start the voltha ensemble with a single voltha instance
        self._stop_and_remove_all_containers()
        sleep(5)  # A small wait for the system to settle down
        self.start_all_containers()
        self.set_rest_endpoint()
        self.set_kafka_endpoint()

        self._get_root()
        self._get_schema()
        self._get_health()
        self._get_voltha()
        self._list_voltha_instances()
        self._get_voltha_instance()
        olt_id = self._add_olt_device()
        self._verify_device_preprovisioned_state(olt_id)
        self._activate_device(olt_id)
        ldev_id = self._wait_for_logical_device(olt_id)
        ldevices = self._list_logical_devices()
        logical_device_id = ldevices['items'][0]['id']
        self._get_logical_device(logical_device_id)
        self._list_logical_device_ports(logical_device_id)
        self._list_and_update_logical_device_flows(logical_device_id)
        self._list_and_update_logical_device_flow_groups(logical_device_id)
        devices = self._list_devices()
        device_id = devices['items'][0]['id']
        self._get_device(device_id)
        self._list_device_ports(device_id)
        self._list_device_flows(device_id)
        self._list_device_flow_groups(device_id)
        self._get_images(device_id)
        self._self_test(device_id)
        dtypes = self._list_device_types()
        self._get_device_type(dtypes['items'][0]['id'])
        alarm_filter = self._create_device_filter(olt_id)
        self._remove_device_filter(alarm_filter['id'])
        # TODO: PM APIs test

    def test_02_cross_instances_dispatch(self):
        """ TODO: So far manual tests done.  Needs to be automated. """
        pass

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

        self.pt("Waiting for voltha and chameleon containers to be ready ...")
        self.wait_till('voltha services HEALTHY',
                       lambda: verify_all_services_healthy(
                           LOCAL_CONSUL, service_name='voltha-grpc') == True,
                       timeout=10)
        self.wait_till('chameleon services HEALTHY',
                       lambda: verify_all_services_healthy(
                           LOCAL_CONSUL,service_name='chameleon-rest') == True,
                       timeout=10)

        # Chameleon takes some time to compile the protos and make them
        # available.  So let's wait 10 seconds
        sleep(10)

    def set_rest_endpoint(self):
        self.rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL,
                                                      'chameleon-rest')
        self.base_url = 'http://' + self.rest_endpoint

    def set_kafka_endpoint(self):
        self.kafka_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'kafka')


    def _get_root(self):
        res = self.get('/', expected_content_type='text/html')
        self.assertGreaterEqual(res.find('swagger'), 0)

    def _get_schema(self):
        res = self.get('/schema')
        self.assertEqual(set(res.keys()), {'protos', 'yang_from','swagger_from'})

    def _get_health(self):
        res = self.get('/health')
        self.assertEqual(res['state'], 'HEALTHY')

    # ~~~~~~~~~~~~~~~~~~~~~ TOP LEVEL VOLTHA OPERATIONS ~~~~~~~~~~~~~~~~~~~~~~~

    def _get_voltha(self):
        res = self.get('/api/v1')
        self.assertEqual(res['version'], '0.9.0')

    def _list_voltha_instances(self):
        res = self.get('/api/v1/instances')
        self.assertEqual(len(res['items']), 1)

    def _get_voltha_instance(self):
        res = self.get('/api/v1/instances')
        voltha_id=res['items'][0]
        res = self.get('/api/v1/instances/{}'.format(voltha_id))
        self.assertEqual(res['version'], '0.9.0')

    def _add_olt_device(self):
        device = Device(
            type='simulated_olt',
            mac_address='00:00:00:00:00:01'
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_code=200)
        return device['id']

    def _verify_device_preprovisioned_state(self, olt_id):
        # we also check that so far what we read back is same as what we get
        # back on create
        device = self.get('/api/v1/devices/{}'.format(olt_id))
        self.assertNotEqual(device['id'], '')
        self.assertEqual(device['adapter'], 'simulated_olt')
        self.assertEqual(device['admin_state'], 'PREPROVISIONED')
        self.assertEqual(device['oper_status'], 'UNKNOWN')

    def _activate_device(self, olt_id):
        path = '/api/v1/devices/{}'.format(olt_id)
        self.post(path + '/enable', expected_code=200)
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

    def _wait_for_logical_device(self, olt_id):
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

    def _list_logical_devices(self):
        res = self.get('/api/v1/logical_devices')
        self.assertGreaterEqual(len(res['items']), 1)
        return res

    def _get_logical_device(self, id):
        res = self.get('/api/v1/logical_devices/{}'.format(id))
        self.assertIsNotNone(res['datapath_id'])

    def _list_logical_device_ports(self, id):
        res = self.get('/api/v1/logical_devices/{}/ports'.format(id))
        self.assertGreaterEqual(len(res['items']), 1)

    def _list_and_update_logical_device_flows(self, id):

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
                        expected_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/logical_devices/{}/flows'.format(id))
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def _list_and_update_logical_device_flow_groups(self, id):

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
                        expected_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/logical_devices/{}/flow_groups'.format(id))
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def _list_devices(self):
        res = self.get('/api/v1/devices')
        self.assertGreaterEqual(len(res['items']), 2)
        return res

    def _get_device(self, id):
        res = self.get('/api/v1/devices/{}'.format(id))
        # TODO test result

    def _list_device_ports(self, id):
        res = self.get('/api/v1/devices/{}/ports'.format(id))
        self.assertGreaterEqual(len(res['items']), 2)

    def _list_device_flows(self, id):
        # pump some flows into the logical device
        res = self.get('/api/v1/devices/{}/flows'.format(id))
        self.assertGreaterEqual(len(res['items']), 1)

    def _list_device_flow_groups(self,id):
        res = self.get('/api/v1/devices/{}/flow_groups'.format(id))
        self.assertGreaterEqual(len(res['items']), 0)

    def _list_device_types(self):
        res = self.get('/api/v1/device_types')
        self.assertGreaterEqual(len(res['items']), 2)
        return res

    def _get_device_type(self, dtype):
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

    def _get_images(self, id):
        res = self.get('/api/v1/devices/{}/images'.format(id))
        self.assertIsNotNone(res)

    def _self_test(self, id):
        res = self.post('/api/v1/devices/{}/self_test'.format(id),
                        expected_code=200)
        self.assertIsNotNone(res)

    def _create_device_filter(self, device_id):
        rules = list()
        rule = dict()

        # Create a filter with a single rule
        rule['key'] = 'device_id'
        rule['value'] = device_id
        rules.append(rule)

        alarm_filter = AlarmFilter(rules=rules)
        alarm_filter = self.post('/api/v1/alarm_filters',
                                 MessageToDict(alarm_filter),
                                 expected_code=200)
        self.assertIsNotNone(alarm_filter)
        return alarm_filter

    def _remove_device_filter(self, alarm_filter_id):
        path = '/api/v1/alarm_filters/{}'.format(alarm_filter_id)
        self.delete(path, expected_code=200)
        alarm_filter = self.get(path, expected_code=404)
        self.assertIsNone(alarm_filter)


if __name__ == '__main__':
    main()
