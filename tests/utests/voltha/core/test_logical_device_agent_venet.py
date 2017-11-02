from unittest import main
from mock import Mock

from tests.utests.voltha.core.test_logical_device_agent import \
    test_logical_device_agent
from voltha.protos.device_pb2 import Port

class test_logical_device_agent_venet(test_logical_device_agent):
    def setUp(self):
        #calling the parent class setUp
        test_logical_device_agent.setUp(self)
        #re-initializing ports to VENET topology
        self.ports = {
            'olt': [
                Port(port_no=0, type=Port.ETHERNET_NNI, device_id='olt'),
                Port(port_no=1, type=Port.VENET_OLT, device_id='olt',
                     peers=[
                         Port.PeerPort(device_id='onu1', port_no=1),
                         Port.PeerPort(device_id='onu2', port_no=1)
                     ]
                )
            ],
            'onu1': [
                Port(port_no=0, type=Port.ETHERNET_UNI, device_id='onu1'),
                Port(port_no=1, type=Port.VENET_ONU, device_id='onu1',
                     peers=[
                         Port.PeerPort(device_id='olt', port_no=1),
                     ]
                )
            ],
            'onu2': [
                Port(port_no=0, type=Port.ETHERNET_UNI, device_id='onu2'),
                Port(port_no=1, type=Port.VENET_ONU, device_id='onu2',
                     peers=[
                         Port.PeerPort(device_id='olt', port_no=1),
                     ]
                )
            ],
        }
        #resetting root_proxy for VENET topology
        self.root_proxy = Mock()
        def get_devices(path):
            if path == '':
                return self.devices.values()
            if path.endswith('/ports'):
                return self.ports[path[:-len('/ports')]]
            elif path.find('/') == -1:
                return self.devices[path]
            else:
                raise Exception(
                    'Nothing to yield for path /devices/{}'.format(path))
        def update_devices(path, data):
            if path.endswith('/flows'):
                self.device_flows[path[:-len('/flows')]] = data
            elif path.endswith('/flow_groups'):
                self.device_groups[path[:-len('/flow_groups')]] = data
            else:
                raise NotImplementedError(
                    'not handling path /devices/{}'.format(path))
        self.root_proxy.get = lambda p: \
            get_devices(p[len('/devices/'):]) if p.startswith('/devices') \
                else None
        self.root_proxy.update = lambda p, d: \
            update_devices(p[len('/devices/'):], d) \
                if p.startswith('/devices') \
                else None

if __name__ == '__main__':
    main()
