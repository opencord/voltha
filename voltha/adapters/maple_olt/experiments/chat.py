#!/usr/bin/env python
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

import sys
from time import sleep

from scapy.packet import Packet
from twisted.spread import pb
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue
from twisted.python import util

from common.frameio.frameio import hexify
from common.utils.asleep import asleep
from voltha.extensions.omci.omci import *


class OmciProxy(pb.Root):

    def __init__(self):
        reactor.listenTCP(24497, pb.PBServerFactory(self))
        self.remote = None
        self.response_queue = DeferredQueue()

    @inlineCallbacks
    def connect(self):
        factory = pb.PBClientFactory()
        reactor.connectTCP("10.111.101.206", 24498, factory)
        self.remote = yield factory.getRootObject()
        print 'connected'
        yield self.remote.callRemote("setRemote", port=24496)

    def remote_echo(self, pkt_type, pon, onu, port, crc, size, data):
        print "Packet Type:", pkt_type
        print "PON:", pon
        print "ONU ID:", onu
        print "Port:", port
        print "CRC OK:", crc
        print "Packet Size:", size
        print "received:", hexify(data)
        self.response_queue.put(data)

    @inlineCallbacks
    def send_omci(self, msg):
        if isinstance(msg, Packet):
            msg = str(msg)
        try:
            print ' sending:', msg
            yield self.remote.callRemote("send_omci", 0, 0, 1, msg)
            print 'msg sent'

        except Exception, e:
            print >> sys.stderr, 'Blew up:', str(e)

    def receive(self):
        return self.response_queue.get()


@inlineCallbacks
def chat():
    proxy = OmciProxy()
    yield proxy.connect()

    tx_id = [0]
    def get_tx_id():
        tx_id[0] += 1
        return tx_id[0]

    if 0:
        # MIB RESET
        frame = OmciFrame(
            transaction_id=get_tx_id(),
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=OntData.class_id
            )
        )
        yield proxy.send_omci(hexify(str(frame)))

        # MIB RESET RESPONSE
        response = yield proxy.receive()
        resp = OmciFrame(response)
        resp.show()

    if 0:
        # GET ALL ALARMS
        frame = OmciFrame(
            transaction_id=get_tx_id(),
            message_type=OmciGetAllAlarms.message_id,
            omci_message=OmciGetAllAlarms(
                entity_class=OntData.class_id,
                entity_id=0
            )
        )
        yield proxy.send_omci(hexify(str(frame)))

        # MIB UPLOAD RESPONSE
        response = yield proxy.receive()
        resp = OmciFrame(response)
        resp.show()

    if 0:
        # MIB UPLOAD
        frame = OmciFrame(
            transaction_id=get_tx_id(),
            message_type=OmciMibUpload.message_id,
            omci_message=OmciMibUpload(
                entity_class=OntData.class_id
            )
        )
        yield proxy.send_omci(hexify(str(frame)))

        # MIB UPLOAD RESPONSE
        response = yield proxy.receive()
        resp = OmciFrame(response)
        resp.show()

        n_commands = resp.omci_message.number_of_commands
        for seq_num in range(n_commands):
            print 'seq_num', seq_num
            frame = OmciFrame(
                transaction_id=get_tx_id(),
                message_type=OmciMibUploadNext.message_id,
                omci_message=OmciMibUploadNext(
                    entity_class=OntData.class_id,
                    command_sequence_number=seq_num
                )
            )
            yield proxy.send_omci(hexify(str(frame)))

            response = yield proxy.receive()
            print hexify(response)
            # resp = OmciFrame(response)
            # resp.show()


    if 1:
        # GET CIRCUIT PACK
        frame = OmciFrame(
            transaction_id=get_tx_id(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=CircuitPack.class_id,
                entity_id=0x101,
                attributes_mask=CircuitPack.mask_for('vendor_id')
            )
        )
        yield proxy.send_omci(hexify(str(frame)))

        # MIB UPLOAD RESPONSE
        response = yield proxy.receive()
        resp = OmciFrame(response)
        resp.show()

    yield asleep(1)
    reactor.stop()


if __name__ == '__main__':
    reactor.callLater(0, chat)
    reactor.run()
