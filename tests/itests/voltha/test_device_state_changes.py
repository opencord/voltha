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

from google.protobuf.json_format import MessageToDict

from voltha.core.flow_decomposer import *
from voltha.protos.device_pb2 import Device
from voltha.protos.common_pb2 import AdminState, OperStatus
from voltha.protos import openflow_13_pb2 as ofp
from tests.itests.voltha.rest_base import RestBase
from common.utils.consulhelpers import get_endpoint_from_consul
from testconfig import config
from tests.itests.test_utils import get_pod_ip

LOCAL_CONSUL = "localhost:8500"

orch_env = 'docker-compose'
if 'test_parameters' in config and 'orch_env' in config['test_parameters']:
    orch_env = config['test_parameters']['orch_env']
print('orchestration-environment: {}'.format(orch_env))

class TestDeviceStateChangeSequence(RestBase):
    """
    The prerequisite for this test are:
     1. voltha ensemble is running
          docker-compose -f compose/docker-compose-system-test.yml up -d
     2. ponsim olt is running with 1 OLT and 4 ONUs
          sudo -s
          . ./env.sh
          ./ponsim/main.py -v -o 4
    """

    # Retrieve details of the REST entry point
    if orch_env == 'k8s-single-node':
        rest_endpoint = get_pod_ip('voltha') + ':8443'
        olt_host_and_port = get_pod_ip('olt') + ':50060'
    elif orch_env == 'swarm-single-node':
        rest_endpoint = 'localhost:8443'
        olt_host_and_port = 'localhost:50060'
    else:
        rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'voltha-envoy-8443')
        olt_host_and_port = '172.17.0.1:50060'

    # Construct the base_url
    base_url = 'https://' + rest_endpoint

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    def test_device_state_changes_scenarios(self):

        self.verify_prerequisites()
        # Test basic scenario

        self.basic_scenario()
        self.failure_scenario()

    def basic_scenario(self):
        """
        Test the enable -> disable -> enable -> disable -> delete for OLT
        and ONU.
        """
        self.assert_no_device_present()
        olt_id = self.add_olt_device()
        self.verify_device_preprovisioned_state(olt_id)
        self.enable_device(olt_id)
        ldev_id = self.wait_for_logical_device(olt_id)
        onu_ids = self.wait_for_onu_discovery(olt_id)
        self.verify_logical_ports(ldev_id, 5)
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        olt_ids, onu_ids = self.get_devices()
        self.disable_device(onu_ids[0])
        self.verify_logical_ports(ldev_id, 4)
        self.enable_device(onu_ids[0])
        self.verify_logical_ports(ldev_id, 5)
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        self.disable_device(olt_ids[0])
        self.assert_all_onus_state(olt_ids[0], 'DISABLED', 'UNKNOWN')
        self.assert_no_logical_device()
        self.enable_device(olt_ids[0])
        self.assert_all_onus_state(olt_ids[0], 'ENABLED', 'ACTIVE')
        self.wait_for_logical_device(olt_ids[0])
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        self.disable_device(onu_ids[0])
        # self.delete_device(onu_ids[0])
        self.verify_logical_ports(ldev_id, 4)
        self.disable_device(olt_ids[0])
        self.delete_device(olt_ids[0])
        self.assert_no_device_present()

    def failure_scenario(self):
        self.assert_no_device_present()
        olt_id = self.add_olt_device()
        self.verify_device_preprovisioned_state(olt_id)
        self.enable_device(olt_id)
        ldev_id = self.wait_for_logical_device(olt_id)
        onu_ids = self.wait_for_onu_discovery(olt_id)
        self.verify_logical_ports(ldev_id, 5)
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        self.delete_device_incorrect_state(olt_id)
        self.delete_device_incorrect_state(onu_ids[0])
        unknown_id = '9999999999'
        self.enable_unknown_device(unknown_id)
        self.disable_unknown_device(unknown_id)
        self.delete_unknown_device(unknown_id)
        latest_olt_ids, latest_onu_ids = self.get_devices()
        self.assertEqual(len(latest_olt_ids), 1)
        self.assertEqual(len(latest_onu_ids), 4)
        self.verify_logical_ports(ldev_id, 5)
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        # Cleanup
        self.disable_device(olt_id)
        self.delete_device(olt_id)
        self.assert_no_device_present()

    def verify_prerequisites(self):
        # all we care is that Voltha is available via REST using the base uri
        self.get('/api/v1')

    def get_devices(self):
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

    def add_olt_device(self):
        device = Device(
            type='ponsim_olt',
            host_and_port=self.olt_host_and_port
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device['id']

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
            lambda: self.get(path)['oper_status'] in ('ACTIVATING', 'ACTIVE'))

        # eventually, it shall move to active state and by then we shall have
        # device details filled, connect_state set, and device ports created
        self.wait_till(
            'admin state ACTIVE',
            lambda: self.get(path)['oper_status'] == 'ACTIVE')
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
            lambda: len(self.find_onus(olt_id)) >= 4
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
            lambda: self.get(path)['oper_status'] == 'UNKNOWN')

        # eventually, the connect_state should be UNREACHABLE
        self.wait_till(
            'connect status UNREACHABLE',
            lambda: self.get(path)['connect_status'] == 'UNREACHABLE')

        # Device's ports should be INACTIVE
        ports = self.get(path + '/ports')['items']
        self.assertEqual(len(ports), 2)
        for p in ports:
            self.assertEqual(p['admin_state'], 'DISABLED')
            self.assertEqual(p['oper_status'], 'UNKNOWN')

    def delete_device(self, id):
        path = '/api/v1/devices/{}'.format(id)
        self.delete(path + '/delete', expected_http_code=200, grpc_status=0)
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
