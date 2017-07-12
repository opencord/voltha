from tests.itests.voltha.rest_base import RestBase

from google.protobuf.json_format import MessageToDict
import unittest

from voltha.protos import bbf_fiber_base_pb2 as fb
from voltha.protos import bbf_fiber_channelgroup_body_pb2 as cg
from voltha.protos import bbf_fiber_channelpair_body_pb2 as cpair
from voltha.protos import bbf_fiber_channelpartition_body_pb2 as cpart
from voltha.protos import bbf_fiber_channeltermination_body_pb2 as cterm
from voltha.protos import ietf_interfaces_pb2 as itf
from voltha.protos import bbf_fiber_types_pb2 as fbtypes
from voltha.protos.device_pb2 import Device
from common.utils.consulhelpers import get_endpoint_from_consul

device_type = 'ponsim_olt'
host_and_port = '172.17.0.1:50060'
scenario = [
        {'cg-add': {"interface": {
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
                    },
        {'cpart-add': {"interface": {
                            "enabled": True,
                            "name": "WTC",
                            "description": "Channel Partition for World Trade Center in Manhattan"
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
                    },
        {'cpair-add': {"interface": {
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
                    },
        {'cterm-add': {"interface": {
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
                    },
        {'cterm-del': {"name": "PON port"}},
        {'cpair-del': {"name": "PON port"}},
        {'cpart-del': {"name": "WTC"}},
        {'cg-del': {"name": "Manhattan"}}
    ]
EMPTY_STRING=''
DEFAULT_INT=0
id = 3      #for ordering the test cases
ref = dict([])
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
    """
    The prerequisite for this test are:
     1. voltha ensemble is running
          docker-compose -f compose/docker-compose-system-test.yml up -d
     2. ponsim olt is running with PONSIM-OLT
          sudo -s
          . ./env.sh
          ./ponsim/main.py -v
    """
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
            return self.get('/api/v1/local/devices/{}/{}'.format(device['id'], type))
        return self.get('/api/v1/local/{}'.format(type))

    def get_path(self, type, name, operation):
        if(type == 'channel_terminations'):
            return 'api/v1/local/devices/{}/{}/{}{}'.format(device['id'], type, name, operation)
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
        itfDiff = [k for k in dict1['interface'] if dict1['interface'][k] != dict2['interface'][k]]
        dataDiff = [k for k in dict1['data'] if dict1['data'][k] != dict2['data'][k]]
        if(len(itfDiff) == 0 and len(dataDiff) == 0):
            return True
        return False

#~~~~~~~~~~~~~~~~~~~~~~~~ Config Classes ~~~~~~~~~~~~~~~~~~~~~~~~~~
class ChannelGroupConfig:
    #Class Variables
    name=EMPTY_STRING
    description=EMPTY_STRING
    type=EMPTY_STRING
    enabled=True
    link_up_down_trap_enable=itf.Interface.LinkUpDownTrapEnableType.Name(0)
    #channelgroup data
    system_id='0000000'
    polling_period=DEFAULT_INT
    raman_mitigation=fbtypes.RamanMitigationType.Name(0)

    def mk_config(self):
        #returns the default values if not intialized by the caller
        return fb.ChannelgroupConfig(
                name=self.name,
                interface=itf.Interface(
                    name=self.name,
                    description=self.description,
                    type=self.type,
                    enabled=self.enabled,
                    link_up_down_trap_enable=self.link_up_down_trap_enable
                ),
                data=cg.ChannelgroupConfigData(
                    polling_period=self.polling_period,
                    system_id=self.system_id,
                    raman_mitigation=self.raman_mitigation
                )
            )

class ChannelPartitionConfig:
    #Class Variables
    name=EMPTY_STRING
    description=EMPTY_STRING
    type=EMPTY_STRING
    enabled=True
    link_up_down_trap_enable=itf.Interface.LinkUpDownTrapEnableType.Name(0)
    #channelpartition config data
    channelgroup_ref=EMPTY_STRING
    fec_downstream=True
    closest_ont_distance=DEFAULT_INT
    differential_fiber_distance=DEFAULT_INT
    authentication_method=fbtypes.AuthMethodType.Name(0)
    multicast_aes_indicator=True

    def mk_config(self):
        #returns the default values if not intialized by the caller
        return fb.ChannelpartitionConfig(
                name=self.name,
                interface=itf.Interface(
                    name=self.name,
                    description=self.description,
                    type=self.type,
                    enabled=self.enabled,
                    link_up_down_trap_enable=self.link_up_down_trap_enable
                ),
                data=cpart.ChannelpartitionConfigData(
                    channelgroup_ref=self.channelgroup_ref,
                    fec_downstream=self.fec_downstream,
                    closest_ont_distance=self.closest_ont_distance,
                    differential_fiber_distance=self.differential_fiber_distance,
                    authentication_method=self.authentication_method,
                    multicast_aes_indicator=self.multicast_aes_indicator
                )
            )

class ChannelPairConfig:
    #Class Variables
    name=EMPTY_STRING
    description=EMPTY_STRING
    type=EMPTY_STRING
    enabled=True
    link_up_down_trap_enable=itf.Interface.LinkUpDownTrapEnableType.Name(0)
    #channel pair config data
    channelgroup_ref=EMPTY_STRING
    channelpartition_ref=EMPTY_STRING
    channelpair_type=fbtypes.ChannelpairType.Name(0)
    channelpair_linerate=fbtypes.ChannelpairSpeedType.Name(0)
    gpon_ponid_interval=DEFAULT_INT
    gpon_ponid_odn_class=fbtypes.PonIdOdnClassType.Name(0)

    def mk_config(self):
        #returns the default values if not intialized by the caller
        return fb.ChannelpairConfig(
                name=self.name,
                interface=itf.Interface(
                    name=self.name,
                    description=self.description,
                    type=self.type,
                    enabled=self.enabled,
                    link_up_down_trap_enable=self.link_up_down_trap_enable
                ),
                data=cpair.ChannelpairConfigData(
                    channelgroup_ref=self.channelgroup_ref,
                    channelpartition_ref=self.channelpartition_ref,
                    channelpair_type=self.channelpair_type,
                    channelpair_linerate=self.channelpair_linerate,
                    gpon_ponid_interval=self.gpon_ponid_interval,
                    gpon_ponid_odn_class=self.gpon_ponid_odn_class
                )
            )

class ChannelTerminationConfig:
    #Class Variables
    name=EMPTY_STRING
    description=EMPTY_STRING
    type=EMPTY_STRING
    enabled=True
    link_up_down_trap_enable=itf.Interface.LinkUpDownTrapEnableType.Name(0)
    #channel termination config data
    channelpair_ref=EMPTY_STRING
    meant_for_type_b_primary_role=True
    ngpon2_twdm_admin_label=DEFAULT_INT
    ngpon2_ptp_admin_label=DEFAULT_INT
    xgs_ponid=DEFAULT_INT
    xgpon_ponid=DEFAULT_INT
    gpon_ponid=EMPTY_STRING
    pon_tag=EMPTY_STRING
    ber_calc_period=DEFAULT_INT
    location=EMPTY_STRING
    url_to_reach=EMPTY_STRING

    def mk_config(self):
        #returns the default values if not intialized by the caller
        return fb.ChannelterminationConfig(
                name=self.name,
                interface=itf.Interface(
                    name=self.name,
                    description=self.description,
                    type=self.type,
                    enabled=self.enabled,
                    link_up_down_trap_enable=self.link_up_down_trap_enable
                ),
                data=cterm.ChannelterminationConfigData(
                    channelpair_ref=self.channelpair_ref,
                    meant_for_type_b_primary_role=self.meant_for_type_b_primary_role,
                    ngpon2_twdm_admin_label=self.ngpon2_twdm_admin_label,
                    ngpon2_ptp_admin_label=self.ngpon2_ptp_admin_label,
                    xgs_ponid=self.xgs_ponid,
                    xgpon_ponid=self.xgpon_ponid,
                    gpon_ponid=self.gpon_ponid,
                    pon_tag=self.pon_tag,
                    ber_calc_period=self.ber_calc_period,
                    location=self.location,
                    url_to_reach=self.url_to_reach
                )
            )

#~~~~~~~~~~~~~~ Function to create test cases on the fly ~~~~~~~~~~~~~~~~
def create_dynamic_method(key, value):
    obj_type_config = {
            'cg': { 'type': 'channel_groups', 'config' : 'channelgroup_config', 'class' : ChannelGroupConfig() },
            'cpart': { 'type': 'channel_partitions', 'config' : 'channelpartition_config', 'class' : ChannelPartitionConfig() },
            'cpair': { 'type': 'channel_pairs', 'config' : 'channelpair_config', 'class' : ChannelPairConfig() },
            'cterm': { 'type': 'channel_terminations', 'config' : 'channeltermination_config', 'class' : ChannelTerminationConfig() }
        }

    def _add(self, type, config, req, name):
        result, prev_len = self.add(type, config, req, name)
        self.assertEqual(result[config][prev_len]['name'], name)
        self.assertEqual(len(result[config]), prev_len+1)

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

    def dynamic_test_method(self):
        for k,v in value.items():   #this should be a dictionary
            _obj_action = [val for val in key.split('-')]
            _type_config = obj_type_config[_obj_action[0]]
            name = '{}-{}'.format(_obj_action[0], value['name'])
            if(name not in ref):
                ref.update({name: _type_config['class']})
            if(isinstance(v, dict)):
                for nk, nv in v.items():
                    setattr(ref[name], nk, nv)
            else:
                setattr(ref[name], k, v)
        req = ref[name].mk_config()
        _operate(self, _obj_action[1], _type_config, req, name.replace('{}-'.format(_obj_action[0]), ''))

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