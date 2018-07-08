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
from structlog import get_logger
from tests.itests.test_utils import get_pod_ip
from testconfig import config

LOCAL_CONSUL = "localhost:8500"

log = get_logger()

orch_env = 'docker-compose'
if 'test_parameters' in config and 'orch_env' in config['test_parameters']:
    orch_env = config['test_parameters']['orch_env']
log.debug('orchestration-environment', orch_env=orch_env)

class TestColdActivationSequence(RestBase):

    # Retrieve details of the REST entry point
    if orch_env == 'k8s-single-node':
        rest_endpoint = get_pod_ip('voltha') + ':8443'
    elif orch_env == 'swarm-single-node':
        rest_endpoint = 'localhost:8443'
    else:
        rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'voltha-envoy-8443')

    # Construct the base_url
    base_url = 'https://' + rest_endpoint
    log.debug('cold-activation-test', base_url=base_url)

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    def test_cold_activation_sequence(self):
        """Complex test-case to cover device activation sequence"""

        self.verify_prerequisites()
        olt_id = self.add_olt_device()
        self.verify_device_preprovisioned_state(olt_id)
        self.activate_device(olt_id)
        ldev_id = self.wait_for_logical_device(olt_id)
        onu_ids = self.wait_for_onu_discovery(olt_id)
        self.verify_logical_ports(ldev_id)
        self.simulate_eapol_flow_install(ldev_id, olt_id, onu_ids)
        self.verify_olt_eapol_flow(olt_id)
        self.verify_onu_forwarding_flows(onu_ids)
        self.simulate_eapol_start()
        self.simulate_eapol_request_identity()
        self.simulate_eapol_response_identity()
        self.simulate_eapol_request()
        self.simulate_eapol_response()
        self.simulate_eapol_success()
        self.install_and_verify_dhcp_flows()
        self.install_and_verify_igmp_flows()
        self.install_and_verifyunicast_flows()

    def verify_prerequisites(self):
        # all we care is that Voltha is available via REST using the base uri
        self.get('/api/v1')

    def add_olt_device(self):
        device = Device(
            type='simulated_olt',
            mac_address='00:00:00:00:00:01'
        )
        device = self.post('/api/v1/devices', MessageToDict(device),
                           expected_http_code=200)
        return device['id']

    def verify_device_preprovisioned_state(self, olt_id):
        # we also check that so far what we read back is same as what we get
        # back on create
        device = self.get('/api/v1/devices/{}'.format(olt_id))
        self.assertNotEqual(device['id'], '')
        self.assertEqual(device['adapter'], 'simulated_olt')
        self.assertEqual(device['admin_state'], 'PREPROVISIONED')
        self.assertEqual(device['oper_status'], 'UNKNOWN')

    def activate_device(self, olt_id):
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
        self.assertEqual(logical_port['ofp_port']['port_no'], 129)
        self.assertEqual(logical_port['device_id'], device['id'])
        self.assertEqual(logical_port['device_port_no'], 2)
        return logical_device['id']

    def wait_for_onu_discovery(self, olt_id):
        # shortly after we shall see the discovery of four new onus, linked to
        # the olt device
        def find_our_onus():
            devices = self.get('/api/v1/devices')['items']
            return [
                d for d in devices
                if d['parent_id'] == olt_id
            ]
        self.wait_till(
            'find ONUs linked to the olt device',
            lambda: len(find_our_onus()) >= 1,
            2
        )

        # verify that they are properly set
        onus = find_our_onus()
        for onu in onus:
            self.assertEqual(onu['admin_state'], 'ENABLED')
            self.assertEqual(onu['oper_status'], 'ACTIVE')

        return [onu['id'] for onu in onus]

    def verify_logical_ports(self, ldev_id):

        # at this point we shall see at least 5 logical ports on the
        # logical device
        logical_ports = self.get(
            '/api/v1/logical_devices/{}/ports'.format(ldev_id)
        )['items']
        self.assertGreaterEqual(len(logical_ports), 5)

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

    def verify_onu_forwarding_flows(self, onu_ids):
        pass

    def simulate_eapol_start(self):
        pass

    def simulate_eapol_request_identity(self):
        pass

    def simulate_eapol_response_identity(self):
        pass

    def simulate_eapol_request(self):
        pass

    def simulate_eapol_response(self):
        pass

    def simulate_eapol_success(self):
        pass

    def install_and_verify_dhcp_flows(self):
        pass

    def install_and_verify_igmp_flows(self):
        pass

    def install_and_verifyunicast_flows(self):
        pass

