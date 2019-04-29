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

import threading
from google.protobuf.json_format import Parse
from simplejson import loads
import structlog
from scapy.layers.l2 import Ether, Dot1Q
import binascii
from scapy.layers.l2 import Packet

from common.frameio.frameio import hexify
from voltha.protos.openflow_13_pb2 import PacketOut
from voltha.adapters.openolt.openolt_kafka_consumer import KConsumer
from voltha.core.flow_decomposer import OUTPUT
from voltha.protos.device_pb2 import Port
from voltha.adapters.openolt.protos import openolt_pb2
from voltha.adapters.openolt.openolt_kafka_admin import KAdmin


class OpenoltPacket(object):
    def __init__(self, device):
        self.log = structlog.get_logger()
        self.device = device

        self._kadmin = KAdmin()

        self.packet_out_thread_handle = threading.Thread(
            target=self.packet_out_thread)
        self.packet_out_thread_handle.setDaemon(True)

        self.packet_in_thread_handle = threading.Thread(
            target=self.packet_in_thread)
        self.packet_in_thread_handle.setDaemon(True)

        self._kadmin.delete_topics([
            'voltha.pktout-{}'.format(
                self.device.data_model.logical_device_id)])
        self._kadmin.delete_topics(['openolt.pktin-{}'.format(
            self.device.host_and_port.split(':')[0])])

    def start(self):
        self.packet_out_thread_handle.start()
        self.packet_in_thread_handle.start()

    def stop(self):
        self._kadmin.delete_topics([
            'voltha.pktout-{}'.format(self.data_model.logical_device_id)])
        self._kadmin.delete_topics(['openolt.pktin-{}'.format(
            self.host_and_port.split(':')[0])])

        # FIXME - kill threads

    def packet_out_thread(self):
        self.log.debug('openolt packet-out thread starting')
        KConsumer(self.packet_out_process,
                  'voltha.pktout-{}'.format(
                      self.device.data_model.logical_device_id))

    def packet_in_thread(self):
        self.log.debug('openolt packet-in thread starting')
        topic = 'openolt.pktin-{}'.format(
            self.device.host_and_port.split(':')[0])
        KConsumer(self.packet_in_process, topic)

    def packet_out_process(self, topic, msg):

        def get_port_out(opo):
            for action in opo.actions:
                if action.type == OUTPUT:
                    return action.output.port

        pb = Parse(loads(msg), PacketOut(), ignore_unknown_fields=True)

        logical_device_id = pb.id
        ofp_packet_out = pb.packet_out

        self.log.debug("received packet-out form kafka",
                       logical_device_id=logical_device_id,
                       ofp_packet_out=ofp_packet_out)

        egress_port = get_port_out(ofp_packet_out)
        msg = ofp_packet_out.data

        self.log.debug('rcv-packet-out', logical_device_id=logical_device_id,
                       egress_port=egress_port,
                       # adapter_name=self.adapter_name,
                       data=hexify(msg))

        pkt = Ether(msg)
        self.log.debug('packet out', egress_port=egress_port,
                       packet=str(pkt).encode("HEX"))

        # Find port type
        egress_port_type = self.device.platform \
            .intf_id_to_port_type_name(egress_port)

        if egress_port_type == Port.ETHERNET_UNI:

            if pkt.haslayer(Dot1Q):
                outer_shim = pkt.getlayer(Dot1Q)
                if isinstance(outer_shim.payload, Dot1Q):
                    # If double tag, remove the outer tag
                    payload = (
                            Ether(src=pkt.src, dst=pkt.dst,
                                  type=outer_shim.type) /
                            outer_shim.payload
                    )
                else:
                    payload = pkt
            else:
                payload = pkt

            send_pkt = binascii.unhexlify(str(payload).encode("HEX"))

            self.log.debug(
                'sending-packet-to-ONU', egress_port=egress_port,
                intf_id=self.device.platform.intf_id_from_uni_port_num(
                    egress_port),
                onu_id=self.device.platform.onu_id_from_port_num(egress_port),
                uni_id=self.device.platform.uni_id_from_port_num(egress_port),
                port_no=egress_port,
                packet=str(payload).encode("HEX"))

            onu_pkt = openolt_pb2.OnuPacket(
                intf_id=self.device.platform.intf_id_from_uni_port_num(
                    egress_port),
                onu_id=self.device.platform.onu_id_from_port_num(egress_port),
                port_no=egress_port,
                pkt=send_pkt)

            self.device.stub.OnuPacketOut(onu_pkt)

        elif egress_port_type == Port.ETHERNET_NNI:
            self.log.debug('sending-packet-to-uplink', egress_port=egress_port,
                           packet=str(pkt).encode("HEX"))

            send_pkt = binascii.unhexlify(str(pkt).encode("HEX"))

            uplink_pkt = openolt_pb2.UplinkPacket(
                intf_id=self.device.platform.intf_id_from_nni_port_num(
                    egress_port),
                pkt=send_pkt)

            self.device.stub.UplinkPacketOut(uplink_pkt)

        else:
            self.log.warn('Packet-out-to-this-interface-type-not-implemented',
                          egress_port=egress_port,
                          port_type=egress_port_type)

    def packet_in_process(self, topic, msg):

        ind = Parse(loads(msg), openolt_pb2.Indication(),
                    ignore_unknown_fields=True)
        assert(ind.HasField('pkt_ind'))
        pkt_ind = ind.pkt_ind

        self.log.debug("packet indication",
                       intf_type=pkt_ind.intf_type,
                       intf_id=pkt_ind.intf_id,
                       port_no=pkt_ind.port_no,
                       cookie=pkt_ind.cookie,
                       gemport_id=pkt_ind.gemport_id,
                       flow_id=pkt_ind.flow_id)
        try:
            logical_port_num = self.device.data_model.logical_port_num(
                pkt_ind.intf_type,
                pkt_ind.intf_id,
                pkt_ind.port_no,
                pkt_ind.gemport_id)
        except ValueError:
            self.log.error('No logical port found',
                           intf_type=pkt_ind.intf_type,
                           intf_id=pkt_ind.intf_id,
                           port_no=pkt_ind.port_no,
                           gemport_id=pkt_ind.gemport_id)
            return

        ether_pkt = Ether(pkt_ind.pkt)

        if isinstance(ether_pkt, Packet):
            ether_pkt = str(ether_pkt)

        logical_device_id = self.device.data_model.logical_device_id
        topic = 'packet-in:' + logical_device_id

        self.log.debug('send-packet-in', logical_device_id=logical_device_id,
                       logical_port_num=logical_port_num,
                       packet=hexify(ether_pkt))

        self.device.data_model.adapter_agent.event_bus.publish(
            topic, (logical_port_num, str(ether_pkt)))
