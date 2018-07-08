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
"""
Mock backend for testing purposes
"""

import logging
import os
import sys
from threading import Thread

from hexdump import hexdump
from scapy.all import Ether, IP, UDP, Dot1Q, sendp, sniff

# VERY IMPORTANT:
# Without the below hack, scapy will not properly receive VLAN
# header (see http://stackoverflow.com/questions/18994242/why-isnt-scapy-capturing-vlan-tag-information).
#
from scapy.all import conf, ETH_P_ALL
import pcap
conf.use_pcap = True
import scapy.arch.pcapdnet
assert conf.L2listen.__name__=='L2pcapListenSocket'

sys.path.insert(1, os.path.join(sys.path[0], '..'))

import loxi.of13 as ofp
from ofagent.utils import mac_str_to_tuple


class MockBackend(object):

    mfr_desc = "Ciena Corp."
    hw_desc = "mock"

    def __init__(self, store, in_out_iface=None, in_out_stag=None):
        self.store = store
        self.add_some_ports()
        self.in_out_iface = in_out_iface
        self.in_out_stag = in_out_stag
        self.agent = None
        self.in_out_receiver = None

    def set_agent(self, agent):
        self.agent = agent
        if self.in_out_iface is not None:
            self.in_out_receiver = InOutReceiver(self.in_out_iface, agent, self.in_out_stag)
            self.in_out_receiver.start()

    def stop(self):
        if self.in_out_receiver is not None:
            self.in_out_receiver.stop()

    def get_serial_num(self):
        return "DFG-4567-RTYU-789"

    def get_dp_desc(self):
        return "mock device"

    def add_some_ports(self):
        cap = ofp.OFPPF_1GB_FD | ofp.OFPPF_FIBER
        for pno, mac, nam, cur, adv, sup, spe in (
                (  1, '00:00:00:00:00:01', 'onu1', cap, cap, cap, ofp.OFPPF_1GB_FD),
                (  2, '00:00:00:00:00:02', 'onu2', cap, cap, cap, ofp.OFPPF_1GB_FD),
                (129, '00:00:00:00:00:81', 'olt',  cap, cap, cap, ofp.OFPPF_1GB_FD)
            ):
            port = ofp.common.port_desc(pno, mac_str_to_tuple(mac), nam,
                                        curr=cur, advertised=adv, supported=sup,
                                        curr_speed=spe, max_speed=spe)
            self.store.port_add(port)

    def packet_out(self, in_port, out_port, data):
        in_port = "CONTROLLER" if in_port == ofp.OFPP_CONTROLLER else in_port
        print "PACKET OUT (%s => %s): " % (in_port, out_port)
        hexdump(data)

        if self.in_out_iface is not None:

            try:
                # disect the packet
                pkt = Ether(data)

                # remove payload from Ether frame
                payload = pkt.payload
                payload_type = pkt.type
                pkt.remove_payload()

                # insert Dot1Q shim with vlan_id = out_port

                if self.in_out_stag is None:
                    ## WARNING -- This was changed from 0x88a8 to 0x8100 when
                    ## testing with the Intel XL710 quad 10GE boards.  The
                    ## XL710 does not support the TPID for the STAG.
                    ##
                    ## Long term, it should be changed back to 0x88a8!
                    ##
                    pkt.type = 0x8100
                    new_pkt = pkt / Dot1Q(vlan=out_port, type=payload_type) / payload

                else:
                    pkt.type = 0x8100
                    new_pkt = (
                            pkt /
                            Dot1Q(vlan=self.in_out_stag, type=0x8100) /
                            Dot1Q(vlan=out_port, type=payload_type) /
                            payload)

                # send out the packet
                sendp(new_pkt, iface=self.in_out_iface)

            except Exception, e:
                logging.exception("Could not parse packet-out data as scapy.Ether:\n")
                logging.error(hexdump(data, 'return'))


class InOutReceiver(Thread):

    def __init__(self, iface, agent, in_out_stag=None):
        Thread.__init__(self)
        self.iface = iface
        self.finished = False
        self.agent = agent
        self.in_out_stag = in_out_stag

    def run(self):
        # TODO this loop could be reconciled with the ofp Connection to become a
        # single select loop.
        self.sock = s = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.iface,
            filter='inbound'
        )
        while not self.finished:
            try:
                sniffed = sniff(1, iface=self.iface, timeout=1, opened_socket=s)
                print 'Sniffer received %d packet(s)' % len(sniffed)
                for pkt in sniffed:
                    self.forward_packet(pkt)

            except Exception, e:
                logging.error("scapy.sniff error: %s" % e)

    def stop(self):
        """
        Signal the thread to exit and wait for it
        """
        assert not self.finished
        logging.debug("Stop sniffing on in-out channel")
        self.finished = True
        self.sock.close()
        self.join()

    def forward_packet(self, pkt):
        print "Received packet:"
        hexdump(str(pkt))
        pkt.show()

        try:
            assert isinstance(pkt, Ether)
            assert isinstance(pkt.getlayer(1), Dot1Q)
            dot1q = pkt.getlayer(1)
            assert isinstance(dot1q, Dot1Q)

            if self.in_out_stag is None:
                payload = dot1q.payload
                payload_type = dot1q.type
                pkt.remove_payload()

                pkt.type = payload_type
                new_pkt = pkt / payload
                in_port = dot1q.vlan

            else:
                if dot1q.vlan != self.in_out_stag:
                    print 'Dropping packet because outer tag %d does not match %d' % (
                        dot1q.vlan, self.in_out_stag)
                    return
                dot1q_inner = dot1q.getlayer(1)
                assert isinstance(dot1q_inner, Dot1Q)
                payload = dot1q_inner.payload
                payload_type = dot1q_inner.type
                pkt.remove_payload()

                pkt.type = payload_type
                new_pkt = pkt / payload
                in_port = dot1q_inner.vlan

            if self.agent is not None:
                self.agent.send_packet_in(str(new_pkt), in_port=in_port)
                print 'new packet forwarded to controller (with in_port=%d):' % in_port
                new_pkt.show()

        except Exception, e:
            logging.exception("Unexpected packet format received by InOutReceiver: %s" % e)
            logging.error(hexdump(str(pkt), 'return'))


