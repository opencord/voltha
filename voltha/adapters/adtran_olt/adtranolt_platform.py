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

#######################################################################
##
##  This is a copy of the OpenOLT file of a similar name and is used
##  when running in non-xPON (OpenOLT/SEBA) mode.  We need to closely
##  watch for changes in the OpenOLT and eventually work together to
##  have a better way to do things (and more ONUs than 112)
##
##  TODO: These duplicate some methods in the OLT Handler.  Clean up
##        and use a separate file and include it into OLT Handler object
##        as something it derives from.
##
#######################################################################
"""
Encoding of identifiers
=======================

GEM port ID

    GEM port id is unique per PON port and ranges 

     9            3 2    0
    +--------------+------+
    |     onu id   | GEM  |
    |              | idx  |
    +--------------+------+

    GEM port id range (0..1023) is reserved, by standard
    Minimum GEM Port on Adtran OLT is 2176 (0x880)
    onu id = 7 bits = 128 ONUs per PON
    GEM index = 3 bits = 8 GEM ports per ONU

Alloc ID

    Uniquely identifies a T-CONT
    Ranges from 1024..16383 per ITU Standard
    For Adtran, 1024..1919
    Unique per PON interface

     9   7 6          0
    +-----+------------+
    | idx |   onu id   | + (Min Alloc ID)
    +-----+------------+

    onu id = 7 bits = 128 ONUs per PON
    Alloc index = 3 bits = 64 GEM ports per ONU

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

MIN_TCONT_ALLOC_ID = 1024                   # 1024..16383
MAX_TCONT_ALLOC_ID = 16383

# MIN_GEM_PORT_ID = 1023                    # 1023..65534
# MAX_GEM_PORT_ID = 65534

MIN_GEM_PORT_ID = 2176                      # 2176..4222
MAX_GEM_PORT_ID = MIN_GEM_PORT_ID + 2046

MAX_ONUS_PER_PON = 128
MAX_TCONTS_PER_ONU = 7


def mk_uni_port_num(intf_id, onu_id):
    """
    Create a unique virtual UNI port number based up on PON and ONU ID
    :param intf_id:
    :param onu_id: (int) ONU ID (0..max)
    :return: (int) UNI Port number
    """
    return intf_id << 11 | onu_id << 4


# def onu_id_from_uni_port_num(port_num):
#     """
#     Extract the ONU ID from a virtual UNI Port Number
#     :param port_num: (int) virtual UNI / vENET port number on OLT PON
#     :return: (int) onu ID
#     """
#     return (port_num >> 4) & 0x7F


def intf_id_from_uni_port_num(port_num):
    """
    Extract the PON device port number from a virtual UNI Port number

    :param port_num: (int) virtual UNI / vENET port number on OLT PON
    :return: (int) PON Port number (note, this is not the PON ID)
    """
    return (port_num >> 11) & 0xF


def mk_alloc_id(_, onu_id, idx=0):
    """
    Allocate a TCONT Alloc-ID.    This is only called by the OLT

    :param _: (int)         PON ID (not used)
    :param onu_id: (int)    ONU ID (0..MAX_ONUS_PER_PON-1)
    :param idx: (int)       TCONT Index (0..7)
    """
    assert 0 <= onu_id < MAX_ONUS_PER_PON, 'Invalid ONU ID. Expect 0..{}'.format(MAX_ONUS_PER_PON-1)
    assert 0 <= idx <= MAX_TCONTS_PER_ONU, 'Invalid TCONT instance. Expect 0..{}'.format(MAX_TCONTS_PER_ONU)
    alloc_id = MIN_TCONT_ALLOC_ID + (onu_id << 3) + idx
    return alloc_id


def mk_gemport_id(_, onu_id, idx=0):
    """
    Allocate a GEM-PORT ID.    This is only called by the OLT

    A 4-bit mask was used since we need a gvid for untagged-EAPOL
    traffic and then up to 8 more for user-user data priority
    levels.

    :param _: (int)         PON ID (0..n) - not used
    :param onu_id: (int)    ONU ID (0..MAX_ONUS_PER_PON-1)
    :param idx: (int)       GEM_PORT Index (0..15)
    """
    return MIN_GEM_PORT_ID + (onu_id << 4) + idx


# def onu_id_from_gemport_id(gemport_id):
#     """
#     Determine ONU ID from a GEM PORT ID.    This is only called by the OLT
#
#     :param gemport_id: (int)  GEM Port ID
#     """
#     return (gemport_id - MIN_GEM_PORT_ID) >> 4


# def mk_flow_id(intf_id, onu_id, idx):
#     return intf_id << 11 | onu_id << 4 | idx


# def intf_id_from_pon_id(port_no):
#     return port_no - 5


def intf_id_to_port_no(intf_id, intf_type):
    if intf_type is Port.ETHERNET_NNI:
        # OpenOLT starts at 128.  We start at 1 (one-to-one mapping)
        return intf_id
    elif intf_type is Port.PON_OLT:
        # OpenOLT sets bit 29 + intf_id. We start at 5 for now for PON 0
        # return 0x2 << 28 | intf_id
        return intf_id + 5              # see _pon_id_to_port_number
    else:
        raise Exception('Invalid port type')


def intf_id_from_nni_port_num(port_num):
    # OpenOLT starts at 128.  We start at 1 (one-to-one mapping)
    # return port_num - 128
    return port_num


def intf_id_to_intf_type(intf_id):
    # if (2 << 28 ^ intf_id) < 16:
    #     return Port.PON_OLT
    # elif  128 <= intf_id <= 132:
    #     return Port.ETHERNET_NNI
    if 5 <= intf_id <= 20:
        return Port.PON_OLT
    elif 1 <= intf_id <= 4:
        return Port.ETHERNET_NNI
    else:
        raise Exception('Invalid intf_id value')


# def intf_id_to_port_type_name(intf_id):
#     try:
#         return  port_type_name_by_port_index(intf_id_to_intf_type(intf_id))
#     except Exception as err:
#         raise Exception(err)


# def port_type_name_by_port_index(port_index):
#     try:
#         return dev_pb2._PORT_PORTTYPE.values_by_number[port_index].name
#     except Exception as err:
#         raise Exception(err)


# def extract_access_from_flow(in_port, out_port):
#     if is_upstream(in_port, out_port):
#         return (intf_id_from_uni_port_num(in_port), onu_id_from_uni_port_num(
#             in_port))
#     else:
#         return (intf_id_from_uni_port_num(out_port), onu_id_from_uni_port_num(
#             out_port))


def is_upstream(in_port, out_port):
    # FIXME
    # if out_port in [128, 129, 130, 131, 0xfffd, 0xfffffffd]:
    # Not sure what fffd and the other is
    return out_port in [1, 2, 3, 4, 0xfffd, 0xfffffffd]


def is_downstream(in_port, out_port):
    return not is_upstream(in_port, out_port)
