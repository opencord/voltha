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

from google.protobuf.json_format import MessageToDict
from unittest import main, TestCase, skip
from voltha.protos.device_pb2 import Device
from tests.itests.voltha.rest_base import RestBase
from voltha.core.flow_decomposer import mk_simple_flow_mod, in_port, output
from voltha.protos import openflow_13_pb2 as ofp
from common.utils.consulhelpers import get_endpoint_from_consul
from structlog import get_logger
from tests.itests.test_utils import get_pod_ip
from testconfig import config

LOCAL_CONSUL = "localhost:8500"

log = get_logger()

orch_env = 'docker-compose'
if 'test_parameters' in config and 'orch_env' in config['test_parameters']:
    orch_env = config['test_parameters']['orch_env']
log.debug('orchestration-environment', orch_env=orch_env)

# Retrieve details of the REST entry point
if orch_env == 'k8s-single-node':
    rest_endpoint = get_pod_ip('voltha') + ':8443'
elif orch_env == 'swarm-single-node':
    rest_endpoint = 'localhost:8443'
else:
    rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'voltha-envoy-8443')

class GlobalRestCalls(RestBase):

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    # Construct the base_url
    base_url = 'https://' + rest_endpoint
    log.debug('global-rest-calls', base_url=base_url)
    
    def test_01_global_rest_apis(self):
        # ~~~~~~~~~~~~~~~~~~~ GLOBAL TOP-LEVEL SERVICES~ ~~~~~~~~~~~~~~~~~~~~~~
        # self._get_root()
        self._get_schema()
        self._get_health()
        # ~~~~~~~~~~~~~~~~~~~ TOP LEVEL VOLTHA OPERATIONS ~~~~~~~~~~~~~~~~~~~~~
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
# TODO: Figure out why this test fails
#        self._list_device_flows(device_id)
        self._list_device_flow_groups(device_id)
        dtypes = self._list_device_types()
        self._get_device_type(dtypes['items'][0]['id'])


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
                           expected_http_code=200)
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
                        expected_http_code=200)
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
                        expected_http_code=200)
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


@skip("Use of local rest calls is deprecated.")
class TestLocalRestCalls(RestBase):

    # Construct the base_url
    base_url = 'https://' + rest_endpoint

    def test_02_local_rest_apis(self):
        # ~~~~~~~~~~~~~~~~ VOLTHA INSTANCE LEVEL OPERATIONS ~~~~~~~~~~~~~~~~~~~
        self._get_local()
        self._get_local_health()
        self._list_local_adapters()
        ldevices = self._list_local_logical_devices()
        logical_device_id = ldevices[0]['id']
        self._get_local_logical_device(logical_device_id)
        self._list_local_logical_device_ports(logical_device_id)
        self._list_and_update_local_logical_device_flows(logical_device_id)
        self._list_and_update_local_logical_device_flow_groups(logical_device_id)
        devices = self._list_local_devices()
        device_id = devices['items'][0]['id']
        self._get_local_device(device_id)
        self._list_local_device_ports(device_id)
        self._list_local_device_flows(device_id)
        self._list_local_device_flow_groups(device_id)
        dtypes = self._list_local_device_types()
        self._get_local_device_type(dtypes['items'][0]['id'])

    def _get_local(self):
        self.assertEqual(self.get('/api/v1/local')['version'], '0.9.0')

    def _get_local_health(self):
        d = self.get('/api/v1/local/health')
        self.assertEqual(d['state'], 'HEALTHY')

    def _list_local_adapters(self):
        self.assertGreaterEqual(
            len(self.get('/api/v1/local/adapters')['items']), 1)

    def _list_local_logical_devices(self):
        res = self.get('/api/v1/local/logical_devices')['items']
        self.assertGreaterEqual(res, 1)
        return res

    def _get_local_logical_device(self, id):
        res = self.get('/api/v1/local/logical_devices/{}'.format(id))
        self.assertIsNotNone(res['datapath_id'])

    def _list_local_logical_device_ports(self, id):
        res = self.get('/api/v1/local/logical_devices/{}/ports'.format(id))
        self.assertGreaterEqual(len(res['items']), 1)

    def _list_and_update_local_logical_device_flows(self, id):

        # retrieve flow list
        res = self.get('/api/v1/local/logical_devices/{}/flows'.format(id))
        len_before = len(res['items'])

        t0 = time()
        # add some flows
        for _ in xrange(10):
            req = ofp.FlowTableUpdate(
                id=id,
                flow_mod=mk_simple_flow_mod(
                    cookie=randint(1, 10000000000),
                    priority=randint(1, 10000),  # to make it unique
                    match_fields=[
                        in_port(129)
                    ],
                    actions=[
                        output(1)
                    ]
                )
            )
            self.post('/api/v1/local/logical_devices/{}/flows'.format(id),
                      MessageToDict(req, preserving_proto_field_name=True),
                      expected_http_code=200)
        print time() - t0

        res = self.get('/api/v1/local/logical_devices/{}/flows'.format(id))
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def _list_and_update_local_logical_device_flow_groups(self, id):

        # retrieve flow list
        res = self.get('/api/v1/local/logical_devices/{'
                       '}/flow_groups'.format(id))
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

        res = self.post('/api/v1/local/logical_devices/{'
                        '}/flow_groups'.format(id),
                        MessageToDict(req, preserving_proto_field_name=True),
                        expected_http_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/local/logical_devices/{'
                       '}/flow_groups'.format(id))
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def _list_local_devices(self):
        res = self.get('/api/v1/local/devices')
        self.assertGreaterEqual(len(res['items']), 2)
        return res

    def _get_local_device(self, id):
        res = self.get('/api/v1/local/devices/{}'.format(id))
        self.assertIsNotNone(res)

    def _list_local_device_ports(self, id):
        res = self.get('/api/v1/local/devices/{}/ports'.format(id))
        self.assertGreaterEqual(len(res['items']), 2)

    def _list_local_device_flows(self, id):
        res = self.get('/api/v1/local/devices/{}/flows'.format(id))
        self.assertGreaterEqual(len(res['items']), 0)

    def _list_local_device_flow_groups(self, id):
        res = self.get('/api/v1/local/devices/{}/flow_groups'.format(id))
        self.assertGreaterEqual(len(res['items']), 0)

    def _list_local_device_types(self):
        res = self.get('/api/v1/local/device_types')
        self.assertGreaterEqual(len(res['items']), 2)
        return res

    def _get_local_device_type(self, type):
        res = self.get('/api/v1/local/device_types/{}'.format(type))
        self.assertIsNotNone(res)

    def _list_local_device_groups(self):
        pass
        # res = self.get('/api/v1/local/device_groups')
        # self.assertGreaterEqual(len(res['items']), 1)

    def _get_local_device_group(self):
        pass
        # res = self.get('/api/v1/local/device_groups/1')
        # # TODO test the result

class TestGlobalNegativeCases(RestBase):

    # Construct the base_url
    base_url = 'https://' + rest_endpoint
    log.debug('global-negative-tests', base_url=base_url)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~ NEGATIVE TEST CASES ~~~~~~~~~~~~~~~~~~~~~~~~~~

    def test_03_negative_behavior(self):
        self._invalid_url()
        self._instance_not_found()
        self._logical_device_not_found()
        self._device_not_found()

    def _invalid_url(self):
        self.get('/some_invalid_url', expected_http_code=404)

    def _instance_not_found(self):
        self.get('/api/v1/instances/nay', expected_http_code=200, grpc_status=5)

    def _logical_device_not_found(self):
        self.get('/api/v1/logical_devices/nay', expected_http_code=200, grpc_status=5)

    def _device_not_found(self):
        self.get('/api/v1/devices/nay', expected_http_code=200, grpc_status=5)

    # TODO add more negative cases


if __name__ == '__main__':
    main()
