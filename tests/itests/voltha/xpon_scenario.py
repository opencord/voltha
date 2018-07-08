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
from voltha.protos import bbf_fiber_base_pb2 as fb
from voltha.protos import bbf_fiber_gemport_body_pb2 as gemport
from voltha.protos import bbf_fiber_tcont_body_pb2 as tcont
from voltha.protos import bbf_fiber_traffic_descriptor_profile_body_pb2 as tdp

'''
These tests use the Ponsim OLT to verify create, update, and delete
functionalities of ChannelgroupConfig, ChannelpartitionConfig,
ChannelpairConfig, ChannelterminationConfig, VOntAni, OntAni, and VEnets
for xPON
The prerequisite for this test are:
 1. voltha ensemble is running
      docker-compose -f compose/docker-compose-system-test.yml up -d
 2. ponsim olt is running with PONSIM-OLT
      sudo -s
      . ./env.sh
      ./ponsim/main.py -v
'''

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
                "name": "Freedom Tower",
                "description":"Channel Partition for Freedom Tower in Manhattan"
                },
            "data": {
                "differential_fiber_distance": 20,
                "closest_ont_distance": 0,
                "fec_downstream": False,
                "multicast_aes_indicator": False,
                "authentication_method": "SERIAL_NUMBER",
                "channelgroup_ref": "Manhattan"
                },
            "name": "Freedom Tower"
            }
        }
    },
    {'cpair-add': {
        'pb2': fb.ChannelpairConfig(),
        'rpc': {
            "interface": {
                "enabled": True,
                "name": "PON port",
                "description": "Channel Pair for Freedom Tower"
                },
            "data": {
                "channelpair_linerate": "down_10_up_10",
                "channelpair_type": "channelpair",
                "channelgroup_ref": "Manhattan",
                "gpon_ponid_interval": 0,
                "channelpartition_ref": "Freedom Tower",
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
                "location": "Freedom Tower OLT"
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
                "name": "Golden User",
                "description": "Golden User in Freedom Tower"
                },
            "data": {
                "preferred_chanpair": "PON port",
                "expected_serial_number": "PSMO00000001",
                "parent_ref": "Freedom Tower",
                "onu_id": 1
                },
            "name": "Golden User"
            }
        }
    },
    {'ontani-add': {
        'pb2': fb.OntaniConfig(),
        'rpc': {
            "interface": {
                "enabled": True,
                "name": "Golden User",
                "description": "Golden User in Freedom Tower"
                },
            "data": {
                "upstream_fec_indicator": True,
                "mgnt_gemport_aes_indicator": False
                },
            "name": "Golden User"
            }
        }
    },
    {'venet-add': {
        'pb2': fb.VEnetConfig(),
        'rpc': {
            "interface": {
                "enabled": True,
                "name": "Enet UNI 1",
                "description": "Ethernet port - 1"
                },
            "data": {
                "v_ontani_ref": "Golden User"
                },
            "name": "Enet UNI 1"
            }
        }
    },
    {'tdp-add': {
        'pb2': tdp.TrafficDescriptorProfileData(),
        'rpc': {
            "name": "TDP 1",
            "assured_bandwidth": "500000",
            "additional_bw_eligibility_indicator": \
"ADDITIONAL_BW_ELIGIBILITY_INDICATOR_NONE",
            "fixed_bandwidth": "100000",
            "maximum_bandwidth": "1000000",
            }
        }
    },
    {'tcont-add': {
        'pb2': tcont.TcontsConfigData(),
        'rpc': {
            "interface_reference": "Golden User",
            "traffic_descriptor_profile_ref": "TDP 1",
            "name": "TCont 1"
            }
        }
    },
    {'tcont-add-with-alloc-id': {
        'pb2': tcont.TcontsConfigData(),
        'rpc': {
            "interface_reference": "Golden User",
            "traffic_descriptor_profile_ref": "TDP 1",
            "name": "TCont 2",
            "alloc_id": 1234
            }
        }
    },
    {'tcont-add-with-alloc-id-zero': {
        'pb2': tcont.TcontsConfigData(),
        'rpc': {
            "interface_reference": "Golden User",
            "traffic_descriptor_profile_ref": "TDP 1",
            "name": "TCont 3",
            "alloc_id": 0
            }
        }
    },
    {'gemport-add': {
        'pb2': gemport.GemportsConfigData(),
        'rpc': {
            "aes_indicator": True,
            "name": "GEMPORT 1",
            "traffic_class": 0,
            "itf_ref": "Enet UNI 1",
            "tcont_ref": "TCont 1",
            }
        }
    },
    {'gemport-add-with-gemport-id': {
        'pb2': gemport.GemportsConfigData(),
        'rpc': {
            "aes_indicator": True,
            "name": "GEMPORT 2",
            "traffic_class": 0,
            "itf_ref": "Enet UNI 1",
            "tcont_ref": "TCont 2",
            "gemport_id": 2345
            }
        }
    },
    {'gemport-add-with-gemport-id-zero': {
        'pb2': gemport.GemportsConfigData(),
        'rpc': {
            "aes_indicator": True,
            "name": "GEMPORT 3",
            "traffic_class": 0,
            "itf_ref": "Enet UNI 1",
            "tcont_ref": "TCont 3",
            "gemport_id": 0
            }
        }
    }
]

