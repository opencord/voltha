from google.protobuf.json_format import MessageToDict
from requests import get, post, put, patch, delete
from unittest import TestCase, main

from voltha.protos.openflow_13_pb2 import FlowTableUpdate, ofp_flow_mod, \
    OFPFC_ADD, ofp_instruction, OFPIT_APPLY_ACTIONS, ofp_instruction_actions, \
    ofp_action, OFPAT_OUTPUT, ofp_action_output, FlowGroupTableUpdate, \
    ofp_group_mod, OFPGC_ADD, OFPGT_ALL, ofp_bucket


class TestRestCases(TestCase):

    base_url = 'http://localhost:8881'

    def url(self, path):
        while path.startswith('/'):
            path = path[1:]
        return self.base_url + '/' + path

    def verify_content_type_and_return(self, response, expected_content_type):
        if 200 <= response.status_code < 300:
            self.assertEqual(
                response.headers['Content-Type'],
                expected_content_type,
                msg='Content-Type %s != %s; msg:%s' % (
                     response.headers['Content-Type'],
                     expected_content_type,
                     response.content))
            if expected_content_type == 'application/json':
                return response.json()
            else:
                return response.content

    def get(self, path, expected_code=200,
            expected_content_type='application/json'):
        r = get(self.url(path))
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))
        return self.verify_content_type_and_return(r, expected_content_type)

    def post(self, path, json_dict, expected_code=201):
        r = post(self.url(path), json=json_dict)
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))
        return self.verify_content_type_and_return(r, 'application/json')

    def put(self, path, json_dict, expected_code=200):
        r = put(self.url(path), json=json_dict)
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))
        return self.verify_content_type_and_return(r, 'application/json')

    def delete(self, path, expected_code=209):
        r = delete(self.url(path))
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))

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
        self.assertEqual(res['datapath_id'], '1')  # TODO should be int

    def test_list_logical_device_ports(self):
        res = self.get('/api/v1/logical_devices/simulated1/ports')
        self.assertGreaterEqual(len(res['items']), 3)

    def test_list_and_update_logical_device_flows(self):

        # retrieve flow list
        res = self.get('/api/v1/logical_devices/simulated1/flows')
        len_before = len(res['items'])

        # add some flows
        req = FlowTableUpdate(
            id='simulated1',
            flow_mod=ofp_flow_mod(
                command=OFPFC_ADD,
                instructions=[
                    ofp_instruction(
                        type=OFPIT_APPLY_ACTIONS,
                        actions=ofp_instruction_actions(
                            actions=[
                                ofp_action(
                                    type=OFPAT_OUTPUT,
                                    output=ofp_action_output(
                                        port=1
                                    )
                                )
                            ]
                        )
                    )
                ]
            )
        )

        res = self.post('/api/v1/logical_devices/simulated1/flows',
                        MessageToDict(req, preserving_proto_field_name=True))
        # TODO check some stuff on res

        res = self.get('/api/v1/logical_devices/simulated1/flows')
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def test_list_and_update_logical_device_flow_groups(self):

        # retrieve flow list
        res = self.get('/api/v1/logical_devices/simulated1/flow_groups')
        len_before = len(res['items'])

        # add some flows
        req = FlowGroupTableUpdate(
            id='simulated1',
            group_mod=ofp_group_mod(
                command=OFPGC_ADD,
                type=OFPGT_ALL,
                group_id=1,
                buckets=[
                    ofp_bucket(
                        actions=[
                            ofp_action(
                                type=OFPAT_OUTPUT,
                                output=ofp_action_output(
                                    port=1
                                )
                            )
                        ]
                    )
                ]
            )
        )

        res = self.post('/api/v1/logical_devices/simulated1/flow_groups',
                        MessageToDict(req, preserving_proto_field_name=True))
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
        res = self.get('/api/v1/devices/simulated_olt_1/flows')
        self.assertGreaterEqual(len(res['items']), 0)

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
        self.assertEqual(res['datapath_id'], '1')  # TODO this should be a long int

    def test_list_local_logical_device_ports(self):
        res = self.get('/api/v1/local/logical_devices/simulated1/ports')
        self.assertGreaterEqual(len(res['items']), 3)

    def test_list_and_update_local_logical_device_flows(self):

        # retrieve flow list
        res = self.get('/api/v1/local/logical_devices/simulated1/flows')
        len_before = len(res['items'])

        # add some flows
        req = FlowTableUpdate(
            id='simulated1',
            flow_mod=ofp_flow_mod(
                command=OFPFC_ADD,
                instructions=[
                    ofp_instruction(
                        type=OFPIT_APPLY_ACTIONS,
                        actions=ofp_instruction_actions(
                            actions=[
                                ofp_action(
                                    type=OFPAT_OUTPUT,
                                    output=ofp_action_output(
                                        port=1
                                    )
                                )
                            ]
                        )
                    )
                ]
            )
        )

        res = self.post('/api/v1/local/logical_devices/simulated1/flows',
                        MessageToDict(req, preserving_proto_field_name=True))
        # TODO check some stuff on res

        res = self.get('/api/v1/local/logical_devices/simulated1/flows')
        len_after = len(res['items'])
        self.assertGreater(len_after, len_before)

    def test_list_and_update_local_logical_device_flow_groups(self):

        # retrieve flow list
        res = self.get('/api/v1/local/logical_devices/simulated1/flow_groups')
        len_before = len(res['items'])

        # add some flows
        req = FlowGroupTableUpdate(
            id='simulated1',
            group_mod=ofp_group_mod(
                command=OFPGC_ADD,
                type=OFPGT_ALL,
                group_id=1,
                buckets=[
                    ofp_bucket(
                        actions=[
                            ofp_action(
                                type=OFPAT_OUTPUT,
                                output=ofp_action_output(
                                    port=1
                                )
                            )
                        ]
                    )
                ]
            )
        )

        res = self.post('/api/v1/local/logical_devices/simulated1/flow_groups',
                        MessageToDict(req, preserving_proto_field_name=True))
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


if __name__ == '__main__':
    main()
