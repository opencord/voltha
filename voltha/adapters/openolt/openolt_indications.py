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
from twisted.internet import reactor
import structlog
from scapy.layers.l2 import Ether, Packet
from common.frameio.frameio import hexify

from voltha.adapters.openolt.protos import openolt_pb2
from voltha.adapters.openolt.openolt_kafka_consumer import KConsumer


class OpenoltIndications(object):
    def __init__(self, device):
        self.log = structlog.get_logger()
        self.device = device
        self.indications_thread_handle = threading.Thread(
            target=self.indications_thread)
        self.indications_thread_handle.setDaemon(True)

    def start(self):
        self.indications_thread_handle.start()

    def stop(self):
        pass

    def indications_thread(self):
        self.log.debug('openolt indications thread starting')
        KConsumer(self.indications_process, "openolt.ind")

    def indications_process(self, topic, msg):

        ind = Parse(loads(msg), openolt_pb2.Indication(),
                    ignore_unknown_fields=True)

        self.log.debug("received openolt indication", ind=ind)

        # indication handlers run in the main event loop
        if ind.HasField('olt_ind'):
            reactor.callFromThread(self.device.olt_indication, ind.olt_ind)
        elif ind.HasField('intf_ind'):
            reactor.callFromThread(self.device.intf_indication, ind.intf_ind)
        elif ind.HasField('intf_oper_ind'):
            reactor.callFromThread(self.device.intf_oper_indication,
                                   ind.intf_oper_ind)
        elif ind.HasField('onu_disc_ind'):
            reactor.callFromThread(self.device.onu_discovery_indication,
                                   ind.onu_disc_ind)
        elif ind.HasField('onu_ind'):
            reactor.callFromThread(self.device.onu_indication, ind.onu_ind)
        elif ind.HasField('omci_ind'):
            reactor.callFromThread(self.device.omci_indication, ind.omci_ind)
        elif ind.HasField('pkt_ind'):
            self.send_packet_in(ind.pkt_ind)
        elif ind.HasField('port_stats'):
            reactor.callFromThread(
                self.device.stats_mgr.port_statistics_indication,
                ind.port_stats)
        elif ind.HasField('flow_stats'):
            reactor.callFromThread(
                self.device.stats_mgr.flow_statistics_indication,
                ind.flow_stats)
        elif ind.HasField('alarm_ind'):
            reactor.callFromThread(
                self.device.alarm_mgr.process_alarms, ind.alarm_ind)
        else:
            self.log.warn('unknown indication type')

    def send_packet_in(self, pkt_indication):
        self.log.debug("packet indication",
                       intf_type=pkt_indication.intf_type,
                       intf_id=pkt_indication.intf_id,
                       port_no=pkt_indication.port_no,
                       cookie=pkt_indication.cookie,
                       gemport_id=pkt_indication.gemport_id,
                       flow_id=pkt_indication.flow_id)
        try:
            logical_port_num = self.device.data_model.logical_port_num(
                pkt_indication.intf_type,
                pkt_indication.intf_id,
                pkt_indication.port_no,
                pkt_indication.gemport_id)
        except ValueError:
            self.log.error('No logical port found',
                           intf_type=pkt_indication.intf_type,
                           intf_id=pkt_indication.intf_id,
                           port_no=pkt_indication.port_no,
                           gemport_id=pkt_indication.gemport_id)
            return

        ether_pkt = Ether(pkt_indication.pkt)

        if isinstance(ether_pkt, Packet):
            ether_pkt = str(ether_pkt)

        logical_device_id = self.device.data_model.logical_device_id
        topic = 'packet-in:' + logical_device_id

        self.log.debug('send-packet-in', logical_device_id=logical_device_id,
                       logical_port_num=logical_port_num,
                       packet=hexify(ether_pkt))

        self.device.data_model.adapter_agent.event_bus.publish(
            topic, (logical_port_num, str(ether_pkt)))
