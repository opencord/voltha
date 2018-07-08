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
import logging
from oftest.testutils import *
import oftest.base_tests as base_tests
import ofp
from scapy.all import Ether
from hexdump import hexdump


in_out_port = test_param_get("in_out_port", "ep1")


class PacketOutTest(base_tests.SimpleDataPlane):
    """
    Test that a packet sent out by the controller is forwarded to the in-out
    test port with the out_port encoded as a Dot1Q shim vlan_id
    """

    def runTest(self):
        logging.info("Running %s" % self.__class__.__name__)

        # These cleanups are not really needed. We do it to verify connection
        # to the agent.
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        # Send packet out and capture it at the in-out port
        pktlen = 60
        pkt_kws = dict(
            eth_src='de:ad:be:ef:00:01',
            eth_dst='de:ad:be:ef:00:02',
            ip_src='192.168.0.1',
            ip_dst='192.168.0.2'
        )

        pkt = simple_udp_packet(pktlen=pktlen, **pkt_kws)
        expected_pkt = simple_udp_packet(pktlen + 4, dl_vlan_enable=True,
                                         vlan_vid=1, **pkt_kws)

        msg = ofp.message.packet_out(
            in_port=ofp.OFPP_CONTROLLER,
            actions=[ofp.action.output(port=in_out_port)],
            buffer_id=ofp.OFP_NO_BUFFER,
            data=str(pkt)
        )
        self.controller.message_send(msg)
        verify_no_errors(self.controller)

        # now verify that we received the correct packet with proper vlan tag
        verify_packet(self, str(expected_pkt), in_out_port)


class PacketInTest(base_tests.SimpleDataPlane):
    """
    Test that a packet arriving at the in-out test port is forwarded to
    the controller as a packet-in message with in_port being the vlan_id
    of the outer Dot1Q shim (which is popped before the packet is sent in)
    """

    def runTest(self):
        logging.info("Running %s" % self.__class__.__name__)

        # These cleanups are not really needed. We do it to verify connection
        # to the agent.
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        # Send packet out and capture it at the in-out port
        pktlen = 60
        pkt_kws = dict(
            eth_src='de:ad:be:ef:00:01',
            eth_dst='de:ad:be:ef:00:02',
            ip_src='192.168.0.1',
            ip_dst='192.168.0.2'
        )

        pkt = simple_udp_packet(pktlen + 4, dl_vlan_enable=True,
                                vlan_vid=1, **pkt_kws)
        expected_pkt = simple_udp_packet(pktlen=pktlen, **pkt_kws)

        # send a test packet into the in_out_port
        self.dataplane.send(in_out_port, str(pkt))

        # expect it to become a packet_in
        verify_packet_in(self, str(expected_pkt), 1, ofp.OFPR_ACTION)
