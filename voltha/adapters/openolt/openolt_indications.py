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
        KConsumer(self.indications_process,
                  "openolt.ind.olt",
                  "openolt.ind.intf",
                  'openolt.ind.intfoper',
                  'openolt.ind.onudisc',
                  'openolt.ind.onu',
                  "openolt.ind.pkt")

    def indications_process(self, topic, msg):
        self.log.debug("received openolt indication", topic=topic, msg=msg)

        if topic == "openolt.ind.olt":
            pb = Parse(loads(msg), openolt_pb2.OltIndication(),
                       ignore_unknown_fields=True)
            reactor.callFromThread(self.device.olt_indication, pb)
        if topic == "openolt.ind.intf":
            pb = Parse(loads(msg), openolt_pb2.IntfIndication(),
                       ignore_unknown_fields=True)
            reactor.callFromThread(self.device.intf_indication, pb)
        if topic == "openolt.ind.intfoper":
            pb = Parse(loads(msg), openolt_pb2.IntfOperIndication(),
                       ignore_unknown_fields=True)
            reactor.callFromThread(self.device.intf_oper_indication, pb)
        if topic == "openolt.ind.onudisc":
            pb = Parse(loads(msg), openolt_pb2.OnuDiscIndication(),
                       ignore_unknown_fields=True)
            reactor.callFromThread(
                self.device.onu_discovery_indication, pb)
        if topic == "openolt.ind.onu":
            pb = Parse(loads(msg), openolt_pb2.OnuIndication(),
                       ignore_unknown_fields=True)
            reactor.callFromThread(self.device.onu_indication, pb)
        elif topic == "openolt.ind.pkt":
            pb = Parse(loads(msg), openolt_pb2.PacketIndication(),
                       ignore_unknown_fields=True)
            reactor.callFromThread(self.device.packet_indication, pb)
