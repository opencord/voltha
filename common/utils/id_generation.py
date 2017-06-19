#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# """ ID generation utils """

from uuid import uuid4

def create_cluster_logical_device_ids(core_id, switch_id):
    """
    Creates a logical device id and an OpenFlow datapath id that is unique 
    across the Voltha cluster. Both ids represents a 64 bits integer where 
    the lower 48 bits represents the switch id and the upper 16 bits  
    represents the core id.  
    :param core_id: string
    :return: cluster logical device id and OpenFlow datapath id
    """
    switch_id = format(switch_id, '012x')
    id = '{}{}'.format(format(int(core_id), '04x'), switch_id)
    hex_int=int(id,16)
    return id, hex_int


def create_cluster_device_id(core_id):
    """
    Creates a device id that is unique across the Voltha cluster.
    The device id is a str of 64 bits.  The lower 48 bits refers to the 
    device id while the upper 16 bits refers to the core id.
    :param core_id: string
    :return: cluster device id
    """
    return '{}{}'.format(format(int(core_id), '04x'), uuid4().hex[:12])

def get_core_id_from_device_id(device_id):
    # Device id is a string and the first 4 characters represent the core_id
    assert device_id and device_id.len() == 16
    return device_id[:4]


def get_core_id_from_logical_device_id(logical_device_id):
    """ 
    Logical Device id is a string and the first 4 characters represent the 
    core_id
    :param logical_device_id: 
    :return: core_id string
    """
    assert logical_device_id and logical_device_id.len() == 16
    return logical_device_id[:4]

def get_core_id_from_datapath_id(datapath_id):
    """
    datapath id is a uint64 where:
        - low 48 bits -> switch_id
        - high 16 bits -> core id
    :param datapath_id: 
    :return: core_id string
    """
    assert datapath_id
    # Get the hex string and remove the '0x' prefix
    id_in_hex_str=hex(datapath_id)[2:]
    assert id_in_hex_str.len() > 12
    return id_in_hex_str[:-12]
