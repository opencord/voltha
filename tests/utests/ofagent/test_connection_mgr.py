from unittest import TestCase, main
from connection_mgr import ConnectionManager

class TestConection_mgr(TestCase):

    def gen_endpoints(self):
        consul_endpoint = "localhost:8500"
        voltha_endpoint= "localhost:8880"
        controller_endpoints = ["localhost:6633","localhost:6644","localhost:6655"]
        return (consul_endpoint,voltha_endpoint,controller_endpoints)

    def gen_devices(self):
        device =lambda: None
        device.id = "1"
        device.datapath_id = 1
        device.desc = '{mfr_desc: "cord porject" hw_desc: "simualted pon" sw_desc: "simualted pon"\
                       serial_num: "2f150d56afa2405eba3ba24e33ce8df9"  dp_desc: "n/a"}'
        device.switch_features = '{ n_buffers: 256 n_tables: 2 capabilities: 15 }'
        device.root_device_id = "a245bd8bb8b8"
        devices = [device]
        return devices,device

    def gen_packet_in(self):
        packet_in = 1
        return packet_in

    def test_connection_mgr_init(self):
        consul_endpoint,voltha_endpoint,controller_endpoints  = self.gen_endpoints()
        test_connection_init = ConnectionManager(consul_endpoint, voltha_endpoint, controller_endpoints)
        self.assertEqual(test_connection_init.consul_endpoint,consul_endpoint)
        self.assertEqual(test_connection_init.vcore_endpoint, voltha_endpoint)
        self.assertEqual(test_connection_init.controller_endpoints, controller_endpoints)

    def test_resolve_endpoint(self):
        consul_endpoint, voltha_endpoint, controller_endpoints = self.gen_endpoints()
        test_connection_init = ConnectionManager(consul_endpoint, voltha_endpoint, controller_endpoints)
        host,port = test_connection_init.resolve_endpoint(endpoint=consul_endpoint)
        assert isinstance(port, int)
        assert isinstance(host, basestring)

    def test_refresh_agent_connections(self):
        consul_endpoint, voltha_endpoint, controller_endpoints = self.gen_endpoints()
        devices,device = self.gen_devices()
        test_connection_init = ConnectionManager(consul_endpoint, voltha_endpoint, controller_endpoints)
        test_connection_init.refresh_agent_connections(devices)

    def test_create_agent(self):
        consul_endpoint, voltha_endpoint, controller_endpoints = self.gen_endpoints()
        devices,device = self.gen_devices()
        test_connection_init = ConnectionManager(consul_endpoint, voltha_endpoint, controller_endpoints)
        test_connection_init.create_agent(device)

    def test_delete_agent(self):
        consul_endpoint, voltha_endpoint, controller_endpoints = self.gen_endpoints()
        devices,device = self.gen_devices()
        test_connection_init = ConnectionManager(consul_endpoint, voltha_endpoint, controller_endpoints)
        test_connection_init.create_agent(device)
        with self.assertRaises(Exception) as context:
            test_connection_init.delete_agent(device.datapath_id)
        print context.exception
        self.assertTrue('\'NoneType\' object has no attribute \'disconnect\'' in str(context.exception))

    def test_forward_packet_in(self):
        consul_endpoint, voltha_endpoint, controller_endpoints = self.gen_endpoints()
        devices,device = self.gen_devices()
        packet_in = self.gen_packet_in()
        test_connection_init = ConnectionManager(consul_endpoint, voltha_endpoint, controller_endpoints)
        test_connection_init.create_agent(device)
        test_connection_init.forward_packet_in(device.id, packet_in)

if __name__ == '__main__':
    main()
