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
#
#  This is a copy of the OpenOLT file of a similar name and is used
#  when running in non-xPON (OpenOLT/SEBA) mode.  We need to closely
#  watch for changes in the OpenOLT and eventually work together to
#  have a better way to do things (and more ONUs than 112)
#
#  TODO: These duplicate some methods in the OLT Handler.  Clean up
#        and use a separate file and include it into OLT Handler object
#        as something it derives from.
#
#######################################################################
"""
Encoding of identifiers
=======================

Alloc ID

    Uniquely identifies a T-CONT
    Ranges from 1024..16383 per ITU Standard
    For Adtran, 1024..1919
    Unique per PON interface

     9   8 7        0
    +-----+----------+
    | idx |  onu_id  | + (Min Alloc ID)
    +-----+----------+

    onu id = 8 bit
    Alloc index = 2 bits (max 4 TCONTs/ONU)

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

MIN_GEM_PORT_ID = 2176                      # 2176..4222
MAX_GEM_PORT_ID = MIN_GEM_PORT_ID + 2046

MAX_ONUS_PER_PON = 128
MAX_TCONTS_PER_ONU = 4
MAX_GEM_PORTS_PER_ONU = 16          # Hardware can handle more


class adtran_platform(object):
    def __init__(self):
        pass

    def mk_uni_port_num(self, intf_id, onu_id, uni_id=0):
        return intf_id << 11 | onu_id << 4 | uni_id

    def uni_id_from_uni_port(self, uni_port):
        return uni_port & 0xF


def mk_uni_port_num(intf_id, onu_id, uni_id=0):
    """
    Create a unique virtual UNI port number based up on PON and ONU ID
    :param intf_id:
    :param onu_id: (int) ONU ID (0..max)
    :return: (int) UNI Port number
    """
    return intf_id << 11 | onu_id << 4 | uni_id


def uni_id_from_uni_port(uni_port):
    return uni_port & 0xF


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
    alloc_id = MIN_TCONT_ALLOC_ID + (idx << 8) + onu_id
    return alloc_id


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


def is_upstream(in_port, out_port):
    # FIXME
    # if out_port in [128, 129, 130, 131, 0xfffd, 0xfffffffd]:
    # Not sure what fffd and the other is
    return out_port in [1, 2, 3, 4, 0xfffd, 0xfffffffd]


def is_downstream(in_port, out_port):
    return not is_upstream(in_port, out_port)
