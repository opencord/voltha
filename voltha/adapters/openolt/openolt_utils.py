#
# Copyright 2019 the original author or authors.
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
import binascii
import re
from voltha.adapters.openolt.protos import openolt_pb2
from voltha.protos.device_pb2 import Port


class OpenoltUtils(object):

    @classmethod
    def ip_hex(cls, ip):
        octets = ip.split(".")
        hex_ip = []
        for octet in octets:
            octet_hex = hex(int(octet))
            octet_hex = octet_hex.split('0x')[1]
            octet_hex = octet_hex.rjust(2, '0')
            hex_ip.append(octet_hex)
        return ":".join(hex_ip)

    @classmethod
    def str_to_mac(cls, uri):
        regex = re.compile('[^a-zA-Z]')
        uri = regex.sub('', uri)

        length = len(uri)
        if length > 6:
            uri = uri[0:6]
        else:
            uri = uri + uri[0:6 - length]

        print uri

        return ":".join([hex(ord(x))[-2:] for x in uri])

    @classmethod
    def stringify_vendor_specific(cls, vendor_specific):
        return ''.join(str(i) for i in [
            hex(ord(vendor_specific[0]) >> 4 & 0x0f)[2:],
            hex(ord(vendor_specific[0]) & 0x0f)[2:],
            hex(ord(vendor_specific[1]) >> 4 & 0x0f)[2:],
            hex(ord(vendor_specific[1]) & 0x0f)[2:],
            hex(ord(vendor_specific[2]) >> 4 & 0x0f)[2:],
            hex(ord(vendor_specific[2]) & 0x0f)[2:],
            hex(ord(vendor_specific[3]) >> 4 & 0x0f)[2:],
            hex(ord(vendor_specific[3]) & 0x0f)[2:]])

    @classmethod
    def stringify_serial_number(cls, serial_number):
        return ''.join([serial_number.vendor_id,
                        cls.stringify_vendor_specific(
                            serial_number.vendor_specific)])

    @classmethod
    def destringify_serial_number(cls, serial_number_str):
        serial_number = openolt_pb2.SerialNumber(
            vendor_id=serial_number_str[:4].encode('utf-8'),
            vendor_specific=binascii.unhexlify(serial_number_str[4:]))
        return serial_number

    @classmethod
    def make_mac_from_port_no(cls, port_no):
        mac = ''
        for i in range(4):
            mac = ':%02x' % ((port_no >> (i * 8)) & 0xff) + mac
        return '00:00' + mac

    @classmethod
    def port_name(cls, port_no, port_type, intf_id=None, serial_number=None):
        if port_type is Port.ETHERNET_NNI:
            return "nni-" + str(port_no)
        elif port_type is Port.PON_OLT:
            return "pon" + str(intf_id)
        elif port_type is Port.ETHERNET_UNI:
            assert False, 'local UNI management not supported'
