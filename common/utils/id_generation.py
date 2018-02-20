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


BROADCAST_CORE_ID=hex(0xFFFF)[2:]

def get_next_core_id(current_id_in_hex_str):
    """
    :param current_id_in_hex_str: a hex string of the maximum core id 
    assigned without the leading 0x characters
    :return: current_id_in_hex_str + 1 in hex string 
    """
    if not current_id_in_hex_str or current_id_in_hex_str == '':
        return '0001'
    else:
        return format(int(current_id_in_hex_str, 16) + 1, '04x')


def create_cluster_logical_device_ids(core_id, switch_id):
    """
    Creates a logical device id and an OpenFlow datapath id that is unique 
    across the Voltha cluster.
    The returned logical device id  represents a 64 bits integer where the
    lower 48 bits is the switch id and the upper 16 bits is the core id.   For
    the datapath id the core id is set to '0000' as it is not used for voltha
    core routing
    :param core_id: string
    :param switch_id:int
    :return: cluster logical device id and OpenFlow datapath id
    """
    switch_id = format(switch_id, '012x')
    core_in_hex=format(int(core_id, 16), '04x')
    ld_id = '{}{}'.format(core_in_hex[-4:], switch_id[-12:])
    dpid_id = '{}{}'.format('0000', switch_id[-12:])
    return ld_id, int(dpid_id, 16)

def is_broadcast_core_id(id):
    assert id and len(id) == 16
    return id[:4] == BROADCAST_CORE_ID

def create_empty_broadcast_id():
    """
    Returns an empty broadcast id (ffff000000000000). The id is used to
    dispatch xPON objects across all the Voltha instances.
    :return: An empty broadcast id
    """
    return '{}{}'.format(BROADCAST_CORE_ID, '0'*12)

def create_cluster_id():
    """
    Returns an id that is common across all voltha instances.  The id  
    is a str of 64 bits.  The lower 48 bits refers to an id specific to that 
    object while the upper 16 bits refers a broadcast core_id
    :return: An common id across all Voltha instances
    """
    return '{}{}'.format(BROADCAST_CORE_ID, uuid4().hex[:12])

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
    assert device_id and len(device_id) == 16
    # Get the leading 4 hexs and remove leading 0's
    return device_id[:4]


def get_core_id_from_logical_device_id(logical_device_id):
    """ 
    Logical Device id is a string and the first 4 characters represent the 
    core_id
    :param logical_device_id: 
    :return: core_id string
    """
    assert logical_device_id and len(logical_device_id) == 16
    # Get the leading 4 hexs and remove leading 0's
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
    id_in_hex_str = hex(datapath_id)[2:]
    assert len(id_in_hex_str) > 12
    return id_in_hex_str[:-12]
