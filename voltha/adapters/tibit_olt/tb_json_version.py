#! /usr/bin/env python
""" JSON layer for scapy """

# Set log level to benefit from Scapy warnings
import logging
import json
import argparse
logging.getLogger("scapy").setLevel(1)

from scapy.packet import Packet, bind_layers
from scapy.fields import StrField
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.sendrecv import srp1
# from scapy.main import interact

from uuid import getnode as get_srcmac


class TBJSON(Packet):
    """ TBJSON 'packet' layer. """
    name = "TBJSON"
    fields_desc = [StrField("data", default="")]


def tb_json_packet_from_dict(json_operation_dict, dst_macid):
    """ Given an command matrix operation dictionary, return a packet """
    json_op_string = json.dumps(json_operation_dict, dst_macid)
    return tb_json_packet_from_str(json_op_string, dst_macid)


def tb_json_packet_from_str(json_operation_str, dst_macid):
    """ Given an command matrix operation as json string, return a packet """
    base_packet = Ether()/TBJSON(data='json %s' % json_operation_str)
    base_packet.type = int("9001", 16)
    mac = '%012x' % get_srcmac()
    base_packet.src = ':'.join(s.encode('hex') for s in mac.decode('hex'))
    base_packet.dst = dst_macid
    bind_layers(Ether, TBJSON, type=0x9001)
    return base_packet


def tb_macid_to_scapy(macid):
    """ convert a tibit macid (xxxxxxxxxxxx) to scapy (xx:xx:xx:xx:xx:xx) """
    if len(macid) != 12:
        print('tb_macid_to_scapy: unexpected macid length (%s)' % macid)
        return '00:00:00:00:00:00'
    new_macid = ''
    for i in [0, 2, 4, 6, 8]:
        new_macid += macid[i:i+2] + ':'
    new_macid += macid[10:12]
    return new_macid


def scapy_to_tb_macid(macid):
    """ convert a scapy macid (xx:xx:xx:xx:xx:xx) to tibit (xxxxxxxxxxxx) """
    if len(macid) != 17:
        print('tb_macid_to_scapy: unexpected macid length (%s)' % macid)
        return '000000000000'
    new_macid = ''
    for i in [0, 3, 6, 9, 12, 15]:
        new_macid += macid[i:i+2]
    return new_macid


def tb_json_packet(json_operation_dict):
    """ Given an command matrix operation dictionary, return a packet """
    json_op_string = json.dumps(json_operation_dict)
    base_packet = Ether()/TBJSON(data='json %s' % json_op_string)

    base_packet.type = int("9001", 16)
    mac = '%012x' % get_srcmac()
    base_packet.src = ':'.join(s.encode('hex') for s in mac.decode('hex'))
    base_packet.dst = args.dstAddress

    bind_layers(Ether, TBJSON, type=0x9001)

    return base_packet

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--dst', dest='dstAddress', action='store',
                        help='MAC address to use as destination.')

    args = parser.parse_args()

    if (args.dstAddress == None):
        args.dstAddress = '00:0c:e2:31:10:00'

    # Create a json packet
    PACKET = tb_json_packet_from_dict({"operation":"version"}, args.dstAddress)

    # Send the packet
    PACKET.show()
    p = srp1(PACKET, iface="eth0")
    if p:
        print "============================================================================="
        p.show()

    print "============================================================================="
    print "Stripping off the \"json\" and quotes yields...\n%s" % p.data[5:]
    print "============================================================================="
    print "Load the JSON..."
    print json.loads(p.data[5:])
    print "============================================================================="

    # interact(mydict=globals(), mybanner="===( TBJSON MODE )===")
