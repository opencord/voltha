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

Logical (OF) NNI port number

    OpenFlow port number corresponding to PON UNI

     16                             0
    +--+----------------------------+
    |1 |                    intf_id |
    +--+----------------------------+

    No overlap with UNI port number space


PON OLT (OF) port number

    OpenFlow port number corresponding to PON OLT ports

     31    28                                 0
    +--------+------------------------~~~------+
    |  0x2   |          pon intf id            |
    +--------+------------------------~~~------+

"""

# MAX_ONUS_PER_PON = 112
MAX_ONUS_PER_PON = 32

class OpenOltPlatform(object):

    def __init__(self, log, device_info):
        self.log = log
        self.device_info = device_info

    def mk_uni_port_num(self, intf_id, onu_id):
        return intf_id << 11 | onu_id << 4

    def mk_flow_id(self, intf_id, onu_id, idx):
        return intf_id << 9 | onu_id << 4 | idx


    def onu_id_from_port_num(self, port_num):
        return (port_num >> 4) & 0x7F


    def intf_id_from_uni_port_num(self, port_num):
        return (port_num >> 11) & 0xF


    def intf_id_from_pon_port_no(self, port_no):
        return port_no & 0xF


    def intf_id_to_port_no(self, intf_id, intf_type):
        if intf_type is Port.ETHERNET_NNI:
            return (0x1 << 16) | intf_id
        elif intf_type is Port.PON_OLT:
            return 0x2 << 28 | intf_id
        else:
            raise Exception('Invalid port type')


    def intf_id_from_nni_port_num(self, port_num):
        return port_num & 0xFFFF


    def intf_id_to_port_type_name(self, intf_id):
        if (2 << 28 ^ intf_id) < 16:
            return Port.PON_OLT
        elif intf_id & (0x1 << 16) == (0x1 << 16):
            return Port.ETHERNET_NNI
        else:
            return None

    def port_type_name_by_port_index(self, port_index):
        try:
            return dev_pb2._PORT_PORTTYPE.values_by_number[port_index].name
        except Exception as err:
            raise Exception(err)

    def extract_access_from_flow(self, in_port, out_port):
        if self.is_upstream(out_port):
            return (self.intf_id_from_uni_port_num(in_port),
                    self.onu_id_from_port_num(in_port))
        else:
            return (self.intf_id_from_uni_port_num(out_port),
                    self.onu_id_from_port_num(out_port))

    def is_upstream(self, out_port):

        if out_port in [0xfffd, 0xfffffffd]:
            # To Controller
            return True
        if (out_port & (0x1 << 16)) == (0x1 << 16):
            # NNI interface
            return True

        return False

    def max_onus_per_pon(self):
        return MAX_ONUS_PER_PON
