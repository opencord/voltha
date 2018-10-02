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


MAX_ONUS_PER_PON = 2

class AcmePlatform(object):

    def __init__(self, log, device_info):
        self.log = log
        self.device_info = device_info

    def mk_alloc_id(self, intf_id, onu_id, idx=0):
        # FIXME - driver should do prefixing 1 << 10 as it is Maple specific
        # return 1<<10 | onu_id<<6 | idx
        return 1023 + intf_id * MAX_ONUS_PER_PON + onu_id  # FIXME


    def mk_gemport_id(self, intf_id, onu_id, idx=0):
        return 1024 + (((MAX_ONUS_PER_PON * intf_id + onu_id - 1) * 7) + idx)

    def onu_id_from_gemport_id(self, gemport_id):
        return (((gemport_id - 1024) // 7) % MAX_ONUS_PER_PON) + 1

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
