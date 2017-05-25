#
# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import binascii
import struct

import structlog
from txzmq import ZmqEndpoint, ZmqFactory
from txzmq.connection import ZmqConnection
from zmq import constants

log = structlog.get_logger()
zmq_factory = ZmqFactory()

# An OMCI message minimally has a 32-bit PON index and 32-bit ONU ID.

_OLT_TASK_ZEROMQ_OMCI_TCP_PORT = 25656


class AdtranZmqClient(object):
    """
    Adtran ZeroMQ Client for PON Agent packet in/out service
    
    PON Agent expects and external PAIR socket with 
    """

    def __init__(self, ip_address, rx_callback=None,
                 port=_OLT_TASK_ZEROMQ_OMCI_TCP_PORT):
        self.external_conn = 'tcp://{}:{}'.format(ip_address, port)

        self.zmq_endpoint = ZmqEndpoint('connect', self.external_conn)
        self.socket = ZmqPairConnection(zmq_factory,
                                        self.zmq_endpoint)

        self.socket.onReceive = rx_callback or AdtranZmqClient.rx_nop

    def send(self, data):
        try:
            self.socket.send(data)

        except Exception as e:
            log.exception(e.message)

    @staticmethod
    def rx_nop(message):
        log.debug('Discarding ZMQ message, no receiver specified')

    @staticmethod
    def encode_omci_message(msg, pon_index, onu_id):
        """
        Create an OMCI Tx Packet for the specified ONU
        
        :param msg: (str) OMCI message to send 
        :param pon_index: (unsigned int) PON Port index
        :param onu_id: (unsigned int) ONU ID
        
        :return: (bytes) octet string to send
        """
        assert msg
        # log.debug("Encoding OMCI: PON: {}, ONU: {}, Message: '{}'".
        #           format(pon_index, onu_id, msg))
        s = struct.Struct('!II')

        return s.pack(pon_index, onu_id) + binascii.unhexlify(msg)

    @staticmethod
    def decode_packet(packet):
        """
        Decode the packet provided by the ZMQ client
        
        :param packet: (bytes) Packet 
        :return: (long, long, bytes, boolean) PON Index, ONU ID, Frame Contents (OMCI or Ethernet),\
                                              and a flag indicating if it is OMCI
        """
        # TODO: For now, only OMCI supported
        if isinstance(packet, list):
            if len(packet) > 1:
                pass  # TODO: Can we get multiple packets?

            return AdtranZmqClient._decode_omci_message(packet[0])
        return -1, -1, None, False

    @staticmethod
    def _decode_omci_message(packet):
        """
        Decode the packet provided by the ZMQ client
        
        :param packet: (bytes) Packet 
        :return: (long, long, bytes) PON Index, ONU ID, OMCI Frame Contents
        """
        (pon_index, onu_id) = struct.unpack_from('!II', packet)
        omci_msg = packet[8:]

        return pon_index, onu_id, omci_msg, True

    @staticmethod
    def _decode_packet_in_message(packet):
        # TODO: This is not yet supported
        (pon_index, onu_id) = struct.unpack_from('!II', packet)
        msg = binascii.hexlify(packet[8:])

        return pon_index, onu_id, msg, False


class ZmqPairConnection(ZmqConnection):
    """
    Bidirectional messages to/from the socket.

    Wrapper around ZeroMQ PUSH socket.
    """
    socketType = constants.PAIR

    def messageReceived(self, message):
        """
        Called on incoming message from ZeroMQ.

        :param message: message data
        """
        self.onReceive(message)

    def onReceive(self, message):
        """
        Called on incoming message received from other end of the pair.

        :param message: message data
        """
        raise NotImplementedError(self)
