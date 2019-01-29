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
from unittest import TestCase, main
from of_protocol_handler import OpenFlowProtocolHandler
import loxi.of13 as ofp

class TestOF_Protocol_handler(TestCase):

    def gen_packet_in(self):
        packet_in = 1
        return packet_in

    def gen_device(self):
        device =lambda: None
        device.id = "1"
        device.datapath_id = 1
        device.desc = '{mfr_desc: "cord porject" hw_desc: "simualted pon" sw_desc: "simualted pon"\
                       serial_num: "2f150d56afa2405eba3ba24e33ce8df9"  dp_desc: "n/a"}'
        device.switch_features = '{ n_buffers: 256 n_tables: 2 capabilities: 15 }'
        device.root_device_id = "a245bd8bb8b8"
        return device

    def gen_generic_obj(self):
        generic_obj = lambda: None
        return generic_obj

    def gen_role_req(self):
        req = self.gen_generic_obj()
        req.role = ofp.OFPCR_ROLE_MASTER
        return req

    def test_handle_flow_mod_request_role_slave(self):
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.role = ofp.OFPCR_ROLE_SLAVE
        with self.assertRaises(Exception) as context:
            of_proto_handler.handle_flow_mod_request(generic_obj)
        print context.exception
        self.assertTrue('\'function\' object has no attribute \'send\'' in str(context.exception))

    def test_handle_flow_mod_request_role_master(self):
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.role = ofp.OFPCR_ROLE_MASTER
        of_proto_handler.handle_flow_mod_request(generic_obj)

    def test_handle_meter_mod_request_role_slave(self):
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.role = ofp.OFPCR_ROLE_SLAVE
        with self.assertRaises(Exception) as context:
            of_proto_handler.handle_meter_mod_request(generic_obj)
        print context.exception
        self.assertTrue('\'function\' object has no attribute \'send\'' in str(context.exception))

    def test_handle_meter_mod_request_role_master(self):
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.role = ofp.OFPCR_ROLE_MASTER
        of_proto_handler.handle_meter_mod_request(generic_obj)

    def test_handle_role_request(self):
        generic_obj = self.gen_generic_obj()
        req = self.gen_role_req()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        with self.assertRaises(Exception) as context:
            of_proto_handler.handle_role_request(req)
            self.assertEqual(of_proto_handler.role,req.role)
        print context.exception
        self.assertTrue('\'function\' object has no attribute \'generation_is_defined\'' in str(context.exception))

    def test_forward_packet_in_role_none(self):
        packet_in = self.gen_packet_in()
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.forward_packet_in(packet_in)

    def test_forward_packet_in_role_master(self):
        packet_in = self.gen_packet_in()
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.role = ofp.OFPCR_ROLE_MASTER
        with self.assertRaises(Exception) as context:
            of_proto_handler.forward_packet_in(packet_in)
        print context.exception
        self.assertTrue('\'function\' object has no attribute \'send\'' in str(context.exception))

    def test_handle_meter_features_request_in_role_master(self):
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.role = ofp.OFPCR_ROLE_MASTER
        with self.assertRaises(Exception) as context:
            of_proto_handler.handle_meter_features_request(generic_obj)
        print context.exception
        self.assertTrue('\'function\' object has no attribute \'send\'' in str(context.exception))

    def test_handle_meter_features_request_in_role_slave(self):
        generic_obj = self.gen_generic_obj()
        device = self.gen_device()
        of_proto_handler = OpenFlowProtocolHandler(device.datapath_id, device.id, generic_obj, generic_obj, generic_obj)
        of_proto_handler.role = ofp.OFPCR_ROLE_SLAVE
        with self.assertRaises(Exception) as context:
            of_proto_handler.handle_meter_features_request(generic_obj)
        print
        context.exception
        self.assertTrue('\'function\' object has no attribute \'send\'' in str(context.exception))


if __name__ == '__main__':
    main()
