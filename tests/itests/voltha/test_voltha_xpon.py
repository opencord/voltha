from tests.itests.voltha.rest_base import RestBase

from google.protobuf.json_format import MessageToDict, ParseDict
import unittest

from voltha.protos import bbf_fiber_base_pb2 as fb
from voltha.protos.device_pb2 import Device
from common.utils.consulhelpers import get_endpoint_from_consul

'''
These tests uses the ponsim OLT to verfiy addition, modification and deletion
of channelgroups, channelpartition, channelpair, channeltermination, vOntAni,
OntAni and VEnets for xpon
The prerequisite for this test are:
 1. voltha ensemble is running
      docker-compose -f compose/docker-compose-system-test.yml up -d
 2. ponsim olt is running with PONSIM-OLT
      sudo -s
      . ./env.sh
      ./ponsim/main.py -v
'''

device_type = 'ponsim_olt'
host_and_port = '172.17.0.1:50060'
scenario = [
        {'cg-add': {
            'pb2': fb.ChannelgroupConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "Manhattan",
                    "description": "Channel Group for Manhattan.."
                    },
                "data": {
                    "polling_period": 100,
                    "system_id": "000000",
                    "raman_mitigation": "RAMAN_NONE"
                    },
                "name": "Manhattan"
                }
            }
        },
        {'cpart-add': {
            'pb2': fb.ChannelpartitionConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "WTC",
                    "description": "Channel Partition for World Trade \
Center in Manhattan"
                    },
                "data": {
                    "differential_fiber_distance": 20,
                    "closest_ont_distance": 0,
                    "fec_downstream": False,
                    "multicast_aes_indicator": False,
                    "authentication_method": "SERIAL_NUMBER",
                    "channelgroup_ref": "Manhattan"
                    },
                "name": "WTC"
                }
            }
        },
        {'cpair-add': {
            'pb2': fb.ChannelpairConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "PON port",
                    "description": "Channel Pair for Freedom Tower in WTC"
                    },
                "data": {
                    "channelpair_linerate": "down_10_up_10",
                    "channelpair_type": "channelpair",
                    "channelgroup_ref": "Manhattan",
                    "gpon_ponid_interval": 0,
                    "channelpartition_ref": "WTC",
                    "gpon_ponid_odn_class": "CLASS_A"
                    },
                "name": "PON port"
                }
            }
        },
        {'cterm-add': {
            'pb2': fb.ChannelterminationConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "PON port",
                    "description": "Channel Termination for Freedom Tower"
                    },
                "data": {
                    "channelpair_ref": "PON port",
                    "location": "AT&T WTC OLT"
                    },
                "name": "PON port"
                }
            }
        },
        {'vontani-add': {
            'pb2': fb.VOntaniConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "ATT Golden User",
                    "description": "ATT Golden User in Freedom Tower"
                    },
                "data": {
                    "preferred_chanpair": "PON port",
                    "expected_serial_number": "ALCL00000000",
                    "parent_ref": "WTC",
                    "onu_id": 1
                    },
                "name": "ATT Golden User"
                }
            }
        },
        {'ontani-add': {
            'pb2': fb.OntaniConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "ATT Golden User",
                    "description": "ATT Golden User in Freedom Tower"
                    },
                "data": {
                    "upstream_fec_indicator": True,
                    "mgnt_gemport_aes_indicator": False
                    },
                "name": "ATT Golden User"
                }
            }
        },
        {'venet-add': {
            'pb2': fb.VEnetConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "ATT SU Enet UNI-1-1",
                    "description": "Ethernet port - 1"
                    },
                "data": {
                    "v_ontani_ref": "ATT Golden User"
                    },
                "name": "ATT SU Enet UNI-1-1"
                }
            }
        },
        {'cg-mod': {
            'pb2': fb.ChannelgroupConfig(),
            'rpc': {
                "interface": {
                    "enabled": True,
                    "name": "Manhattan",
                    "description": "Channel Group for Manhattan"
                    },
                "data": {
                    "polling_period": 100,
                    "system_id": "000000",
                    "raman_mitigation": "RAMAN_NONE"
                    },
                "name": "Manhattan"
                }
            }
        },
        {'venet-del': {
            'pb2': fb.VEnetConfig(),
            'rpc': {"name": "ATT SU Enet UNI-1-1"}}
        },
        {'ontani-del': {
            'pb2': fb.OntaniConfig(),
            'rpc': {"name": "ATT Golden User"}}
        },
        {'vontani-del': {
            'pb2': fb.VOntaniConfig(),
            'rpc': {"name": "ATT Golden User"}}
        },
        {'cterm-del': {
            'pb2': fb.ChannelterminationConfig(),
            'rpc': {"name": "PON port"}}
        },
        {'cpair-del': {
            'pb2': fb.ChannelpairConfig(),
            'rpc': {"name": "PON port"}}
        },
        {'cpart-del': {
            'pb2': fb.ChannelpartitionConfig(),
            'rpc': {"name": "WTC"}}
        },
        {'cg-del': {
            'pb2': fb.ChannelgroupConfig(),
            'rpc': {"name": "Manhattan"}}
        }
    ]

#for ordering the test cases
id = 3
LOCAL_CONSUL = "localhost:8500"
# Retrieve details of the REST entry point
rest_endpoint = get_endpoint_from_consul(LOCAL_CONSUL, 'chameleon-rest')
# Construct the base_url
base_url = 'https://' + rest_endpoint

class GlobalPreChecks(RestBase):
    def test_000_get_root(self):
        res = self.get('/#!/', expected_content_type='text/html')
        self.assertGreaterEqual(res.find('swagger'), 0)

    def test_001_get_health(self):
        res = self.get('/health')
        self.assertEqual(res['state'], 'HEALTHY')

class TestXPon(RestBase):
    def test_002_setup_device(self):
        global device
        device = self.add_device()
        self.verify_device_preprovisioned_state(device['id'])
        self.activate_device(device['id'])

    def test_999_remove_device(self):
        self.deactivate_device(device['id'])
        self.delete_device(device['id'])

    #~~~~~~~~~~~~~~~~~~~~~~ Helper Functions ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Create a new simulated device
    def add_device(self):
        return self.post('/api/v1/local/devices',
                           MessageToDict(Device(
                                type=device_type,
                                host_and_port=host_and_port
                            )),
                           expected_code=200)

    def verify_device_preprovisioned_state(self, olt_id):
        # we also check that so far what we read back is same as what we get
        # back on create
        device = self.get('/api/v1/local/devices/{}'.format(olt_id))
        self.assertNotEqual(device['id'], '')
        self.assertEqual(device['adapter'], 'ponsim_olt')
        self.assertEqual(device['admin_state'], 'PREPROVISIONED')
        self.assertEqual(device['oper_status'], 'UNKNOWN')

    # Active the simulated device.
    # This will trigger the simulation of random alarms
    def activate_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    def deactivate_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.post(path + '/disable', expected_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'DISABLED')

    def delete_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.delete(path + '/delete', expected_code=200)
        device = self.get(path, expected_code=404)
        self.assertIsNone(device)

    # Add cg, cpair, cpart
    def add(self, type, config, req, name):
        res = self.verify(type)
        prev_len = len(res[config])
        self.post(self.get_path(type, name, ''),
                  MessageToDict(req, preserving_proto_field_name = True),
                  expected_code = 200)
        return self.verify(type), prev_len

    # Modify the existing cg, cpair, cpart
    def modify(self, type, req, name):
        self.post(self.get_path(type, name, '/modify'),
                  MessageToDict(req, preserving_proto_field_name = True),
                  expected_code = 200)
        return self.verify(type)

    # Delete cg, cpair, cpart
    def remove(self, type, config, name):
        res = self.verify(type)
        prev_len = len(res[config])
        self.delete(self.get_path(type, name, '/delete'),
                  expected_code = 200)
        return self.verify(type), prev_len

    # Retrieve the desired item upon Post message
    def verify(self, type):
        if(type == 'channel_terminations'):
            return self.get('/api/v1/devices/{}/{}'.format(device['id'], type))
        return self.get('/api/v1/local/{}'.format(type))

    def get_path(self, type, name, operation):
        if(type == 'channel_terminations'):
            return 'api/v1/devices/{}/{}/{}{}'.format(device['id'],
                type, name, operation)
        return 'api/v1/local/{}/{}{}'.format(type, name, operation)

    # Method to check if the result is same as the change requested
    def search(self, req, result):
        dict1 = MessageToDict(req, preserving_proto_field_name = True)
        for item in result:
            if(isinstance(item, dict)):
                for k,v in item.items():
                    if(v == dict1['name']):
                        dict2 = item
                        break
        itfDiff = [k for k in dict1['interface'] if dict1['interface'][k] \
                   != dict2['interface'][k]]
        dataDiff = [k for k in dict1['data'] if dict1['data'][k] \
                    != dict2['data'][k]]
        if(len(itfDiff) == 0 and len(dataDiff) == 0):
            return True
        return False

#~~~~~~~~~~~~~~ Function to create test cases on the fly ~~~~~~~~~~~~~~~~
def create_dynamic_method(key, value):
    obj_type_config = {
        'cg':{'type':'channel_groups','config':'channelgroup_config'},
        'cpart':{'type':'channel_partitions',
                 'config':'channelpartition_config'},
        'cpair':{'type':'channel_pairs','config':'channelpair_config'},
        'cterm':{'type':'channel_terminations',
                 'config':'channeltermination_config'},
        'vontani':{'type':'v_ont_anis','config':'v_ontani_config'},
        'ontani':{'type':'ont_anis','config':'ontani_config'},
        'venet':{'type':'v_enets','config':'v_enet_config'}
    }

    def _add(self, type, config, req, name):
        result, prev_len = self.add(type, config, req, name)
        self.assertEqual(result[config][prev_len]['name'], name)
        self.assertEqual(len(result[config]), prev_len+1)
        self.assertEqual(self.search(req, result[config]), True)

    def _mod(self, type, config, req, name):
        result = self.modify(type, req, name)
        self.assertEqual(self.search(req, result[config]), True)

    def _del(self, type, config, req, name):
        result, prev_len = self.remove(type, config, name)
        self.assertEqual(len(result[config]), prev_len-1)

    def _operate(self, obj_action, type_config, req, name):
        if obj_action == 'add':
            _add(self, type_config['type'], type_config['config'], req, name)
        elif obj_action == 'mod':
            _mod(self, type_config['type'], type_config['config'], req, name)
        elif obj_action == 'del':
            _del(self, type_config['type'], type_config['config'], req, name)
    
    def _config(self):
        ParseDict(value['rpc'], value['pb2'])
        return value['pb2']

    def dynamic_test_method(self):
        _obj_action = [val for val in key.split('-')]
        _type_config = obj_type_config[_obj_action[0]]
        _req = _config(self)
        _operate(self, _obj_action[1], _type_config, _req, value['rpc']['name'])

    return dynamic_test_method

#read the set instructions for tests and dynamically create test cases in desired sequence
for item in scenario:
    id = id + 1
    if(isinstance(item, dict)):
        for k,v in item.items():
            dynamic_method = create_dynamic_method(k, v)
            dynamic_method.__name__ = 'test_{:3d}_{}'.format(id, k).replace(' ', '0')
            setattr(TestXPon, dynamic_method.__name__, dynamic_method)
            del dynamic_method

if __name__ == '__main__':
    unittest.main()
