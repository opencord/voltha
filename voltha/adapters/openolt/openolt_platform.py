#
# Copyright 2018 the original author or authors.
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
#

from voltha.protos.device_pb2 import Port
import voltha.protos.device_pb2 as dev_pb2

"""
Encoding of identifiers
=======================

GEM port ID

    GEM port id is unique per PON port

     10              3      0
    +--+--------------+------+
    |1 |     onu id   | GEM  |
    |  |              | idx  |
    +--+--------------+------+

    GEM port id range (0, 1023) is reserved
    onu id = 7 bits = 128 ONUs per PON
    GEM index = 3 bits = 8 GEM ports per ONU

Alloc ID

    Uniquely identifies a T-CONT
    Ranges from 0 to 4095
    Unique per PON interface

     12         6            0
    +------------+------------+
    |   onu id   | Alloc idx  |
    +------------+------------+

    onu id = 7 bits = 128 ONUs per PON
    Alloc index = 6 bits = 64 GEM ports per ONU

Flow id

    Identifies a flow within a single OLT
    Flow Id is unique per OLT
    Multiple GEM ports can map to same flow id

     13    11              4      0
    +--------+--------------+------+
    | pon id |    onu id    | Flow |
    |        |              | idx  |
    +--------+--------------+------+

    14 bits = 16384 flows (per OLT).

    pon id = 4 bits = 16 PON ports
    onu id = 7 bits = 128 ONUss per PON port
    Flow index = 3 bits = 4 bi-directional flows per ONU
                        = 8 uni-directional flows per ONU


Logical (OF) UNI port number

    OpenFlow port number corresponding to PON UNI

     15       11              4      0
    +--+--------+--------------+------+
    |0 | pon id |    onu id    |   0  |
    +--+--------+--------------+------+

    pon id = 4 bits = 16 PON ports
    onu id = 7 bits = 128 ONUs per PON port


PON OLT (OF) port number

    OpenFlow port number corresponding to PON OLT ports

     31    28                                 0
    +--------+------------------------~~~------+
    |  0x2   |          pon intf id            |
    +--------+------------------------~~~------+

"""

MAX_ONUS_PER_PON = 112

def mk_uni_port_num(intf_id, onu_id):
    return intf_id << 11 | onu_id << 4


def mk_alloc_id(intf_id, onu_id, idx=0):
    # FIXME - driver should do prefixing 1 << 10 as it is Maple specific
    # return 1<<10 | onu_id<<6 | idx
    return 1023 + intf_id * MAX_ONUS_PER_PON + onu_id  # FIXME


def mk_gemport_id(intf_id, onu_id, idx=0):
    return 1024 + (((MAX_ONUS_PER_PON * intf_id + onu_id - 1) * 7) + idx)

def onu_id_from_gemport_id(gemport_id):
    return (((gemport_id - 1024) // 7) % MAX_ONUS_PER_PON) + 1


def mk_flow_id(intf_id, onu_id, idx):
    return intf_id << 11 | onu_id << 4 | idx


def onu_id_from_port_num(port_num):
    return (port_num >> 4) & 0x7F


def intf_id_from_uni_port_num(port_num):
    return (port_num >> 11) & 0xF


def intf_id_from_pon_port_no(port_no):
    return port_no & 0xF


def intf_id_to_port_no(intf_id, intf_type):
    if intf_type is Port.ETHERNET_NNI:
        # FIXME - Remove hardcoded '128'
        return intf_id + 128
    elif intf_type is Port.PON_OLT:
        return 0x2 << 28 | intf_id
    else:
        raise Exception('Invalid port type')


def intf_id_from_nni_port_num(port_num):
    return port_num - 128

def intf_id_to_intf_type(intf_id):

    if (2 << 28 ^ intf_id) < 16:
        return Port.PON_OLT
    elif  128 <= intf_id <= 132:
        return Port.ETHERNET_NNI
    else:
        raise Exception('Invalid intf_id value')

def intf_id_to_port_type_name(intf_id):
    try:
        return  port_type_name_by_port_index(intf_id_to_intf_type(intf_id))
    except Exception as err:
        raise Exception(err)

def port_type_name_by_port_index(port_index):
    try:
        return dev_pb2._PORT_PORTTYPE.values_by_number[port_index].name
    except Exception as err:
        raise Exception(err)

def extract_access_from_flow(in_port, out_port):
    if is_upstream(in_port, out_port):
        return (intf_id_from_uni_port_num(in_port), onu_id_from_port_num(
            in_port))
    else:
        return (intf_id_from_uni_port_num(out_port), onu_id_from_port_num(
            out_port))

def is_upstream(in_port, out_port):
    #FIXME
    if out_port in [128, 129, 130, 131, 0xfffd, 0xfffffffd]:
        return True
    # if in_port not in [128, 129, 130, 131]:
    #     return True

    return False

def is_downstream(in_port, out_port):
    return not is_upstream(in_port, out_port)