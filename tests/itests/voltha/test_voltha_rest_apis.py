from random import randint
from time import time, sleep

from google.protobuf.json_format import MessageToDict
from unittest import main

from tests.itests.voltha.rest_base import RestBase
from voltha.core.flow_decomposer import mk_simple_flow_mod, in_port, output
from voltha.protos import openflow_13_pb2 as ofp


class GlobalRestCalls(RestBase):

    # ~~~~~~~~~~~~~~~~~~~~~ GLOBAL TOP-LEVEL SERVICES~ ~~~~~~~~~~~~~~~~~~~~~~~~

    def test_get_root(self):
        res = self.get('/', expected_content_type='text/html')
        self.assertGreaterEqual(res.find('swagger'), 0)

    def test_get_schema(self):
        res = self.get('/schema')
        self.assertEqual(set(res.keys()), {'protos', 'swagger_from'})

    def test_get_health(self):
        res = self.get('/health')
        self.assertEqual(res['state'], 'HEALTHY')

    # ~~~~~~~~~~~~~~~~~~~~~ TOP LEVEL VOLTHA OPERATIONS ~~~~~~~~~~~~~~~~~~~~~~~

    def test_get_voltha(self):
        res = self.get('/api/v1')
        self.assertEqual(res['version'], '0.9.0')

    def test_list_voltha_instances(self):
        res = self.get('/api/v1/instances')
        self.assertEqual(len(res['items']), 1)

    def test_get_voltha_instance(self):
        res = self.get('/api/v1/instances/1')
        self.assertEqual(res['version'], '0.9.0')

    def test_list_logical_devices(self):
        res = self.get('/api/v1/logical_devices')
        self.assertGreaterEqual(len(res['items']), 1)

    def test_get_logical_device(self):
        res = self.get('/api/v1/logical_devices/simulated1')
        self.assertEqual(res['datapath_id'], '1')

    def test_list_logical_device_ports(self):
        res = self.get('/api/v1/logical_devices/simulated1/ports')
        self.assertGreaterEqual(len(res['items']), 3)

    def test_list_and_update_logical_device_flows(self):

        # retrieve flow list
        res = self.get('/api/v1/logical_devices/simulated1/flows')
        len_before = len(res['items'])

        # add some flows
        req = ofp.FlowTableUpdate(
            id='simulated1',
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
        res = self.post('/api/v1/logical_devices/simulated1/flows',
                        MessageToDict(req, preserving_proto_field_name=True),
                        expected_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/logical_devices/simulated1/flows')
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def test_list_and_update_logical_device_flow_groups(self):

        # retrieve flow list
        res = self.get('/api/v1/logical_devices/simulated1/flow_groups')
        len_before = len(res['items'])

        # add some flows
        req = ofp.FlowGroupTableUpdate(
            id='simulated1',
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
        res = self.post('/api/v1/logical_devices/simulated1/flow_groups',
                        MessageToDict(req, preserving_proto_field_name=True),
                        expected_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/logical_devices/simulated1/flow_groups')
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def test_list_devices(self):
        res = self.get('/api/v1/devices')
        self.assertGreaterEqual(len(res['items']), 2)

    def test_get_device(self):
        res = self.get('/api/v1/devices/simulated_olt_1')
        # TODO test result

    def test_list_device_ports(self):
        res = self.get('/api/v1/devices/simulated_olt_1/ports')
        self.assertGreaterEqual(len(res['items']), 2)

    def test_list_device_flows(self):
        # pump some flows into the logical device
        self.test_list_and_update_logical_device_flows()
        res = self.get('/api/v1/devices/simulated_olt_1/flows')
        self.assertGreaterEqual(len(res['items']), 1)

    def test_list_device_flow_groups(self):
        res = self.get('/api/v1/devices/simulated_olt_1/flow_groups')
        self.assertGreaterEqual(len(res['items']), 0)

    def test_list_device_types(self):
        res = self.get('/api/v1/device_types')
        self.assertGreaterEqual(len(res['items']), 2)

    def test_get_device_type(self):
        res = self.get('/api/v1/device_types/simulated_olt')
        # TODO test the result

    def test_list_device_groups(self):
        res = self.get('/api/v1/device_groups')
        self.assertGreaterEqual(len(res['items']), 1)

    def test_get_device_group(self):
        res = self.get('/api/v1/device_groups/1')
        # TODO test the result


class TestLocalRestCalls(RestBase):

    # ~~~~~~~~~~~~~~~~~~ VOLTHA INSTANCE LEVEL OPERATIONS ~~~~~~~~~~~~~~~~~~~~~

    def test_get_local(self):
        self.assertEqual(self.get('/api/v1/local')['version'], '0.9.0')

    def test_get_local_health(self):
        d = self.get('/api/v1/local/health')
        self.assertEqual(d['state'], 'HEALTHY')

    def test_list_local_adapters(self):
        self.assertGreaterEqual(
            len(self.get('/api/v1/local/adapters')['items']), 1)

    def test_list_local_logical_devices(self):
        self.assertGreaterEqual(
            len(self.get('/api/v1/local/logical_devices')['items']), 1)

    def test_get_local_logical_device(self):
        res = self.get('/api/v1/local/logical_devices/simulated1')
        self.assertEqual(res['datapath_id'], '1')

    def test_list_local_logical_device_ports(self):
        res = self.get('/api/v1/local/logical_devices/simulated1/ports')
        self.assertGreaterEqual(len(res['items']), 3)

    def test_list_and_update_local_logical_device_flows(self):

        # retrieve flow list
        res = self.get('/api/v1/local/logical_devices/simulated1/flows')
        len_before = len(res['items'])

        t0 = time()
        # add some flows
        for _ in xrange(10):
            req = ofp.FlowTableUpdate(
                id='simulated1',
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
            self.post('/api/v1/local/logical_devices/simulated1/flows',
                      MessageToDict(req, preserving_proto_field_name=True),
                      expected_code=200)
        print time() - t0

        res = self.get('/api/v1/local/logical_devices/simulated1/flows')
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def test_list_and_update_local_logical_device_flow_groups(self):

        # retrieve flow list
        res = self.get('/api/v1/local/logical_devices/simulated1/flow_groups')
        len_before = len(res['items'])

        # add some flows
        req = ofp.FlowGroupTableUpdate(
            id='simulated1',
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

        res = self.post('/api/v1/local/logical_devices/simulated1/flow_groups',
                        MessageToDict(req, preserving_proto_field_name=True),
                        expected_code=200)
        # TODO check some stuff on res

        res = self.get('/api/v1/local/logical_devices/simulated1/flow_groups')
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def test_list_local_devices(self):
        res = self.get('/api/v1/local/devices')
        self.assertGreaterEqual(len(res['items']), 2)

    def test_get_local_device(self):
        res = self.get('/api/v1/local/devices/simulated_olt_1')
        # TODO test result

    def test_list_local_device_ports(self):
        res = self.get('/api/v1/local/devices/simulated_olt_1/ports')
        self.assertGreaterEqual(len(res['items']), 2)

    def test_list_local_device_flows(self):
        res = self.get('/api/v1/local/devices/simulated_olt_1/flows')
        self.assertGreaterEqual(len(res['items']), 0)

    def test_list_local_device_flow_groups(self):
        res = self.get('/api/v1/local/devices/simulated_olt_1/flow_groups')
        self.assertGreaterEqual(len(res['items']), 0)

    def test_list_local_device_types(self):
        res = self.get('/api/v1/local/device_types')
        self.assertGreaterEqual(len(res['items']), 2)

    def test_get_local_device_type(self):
        res = self.get('/api/v1/local/device_types/simulated_olt')
        # TODO test the result

    def test_list_local_device_groups(self):
        res = self.get('/api/v1/local/device_groups')
        self.assertGreaterEqual(len(res['items']), 1)

    def test_get_local_device_group(self):
        res = self.get('/api/v1/local/device_groups/1')
        # TODO test the result


class TestGlobalNegativeCases(RestBase):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~ NEGATIVE TEST CASES ~~~~~~~~~~~~~~~~~~~~~~~~~~

    def test_invalid_url(self):
        self.get('/some_invalid_url', expected_code=404)

    def test_instance_not_found(self):
        self.get('/api/v1/instances/nay', expected_code=404)

    def test_logical_device_not_found(self):
        self.get('/api/v1/logical_devices/nay', expected_code=404)

    def test_device_not_found(self):
        self.get('/api/v1/devices/nay', expected_code=404)

    # TODO add more negative cases


if __name__ == '__main__':
    main()
