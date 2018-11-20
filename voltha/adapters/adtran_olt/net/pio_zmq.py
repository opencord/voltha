# Copyright 2017-present Adtran, Inc.
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

import json
import random
from adtran_zmq import AdtranZmqClient
from enum import IntEnum

DEFAULT_PIO_TCP_PORT = 5555
#DEFAULT_PIO_TCP_PORT = 5657


class PioClient(AdtranZmqClient):
    """
    Adtran ZeroMQ Client for packet in/out service
    """
    def __init__(self, ip_address, rx_callback, port):
        super(PioClient, self).__init__(ip_address, rx_callback, port)
        self._seq_number = random.randint(1, 2**32)

    class UrlType(IntEnum):
        PACKET_IN = 0         # Packet In
        PACKET_OUT = 1        # Packet Out
        EVCMAPS_REQUEST = 2   # EVC-MAPs request
        EVCMAPS_RESPONSE = 3  # EVC-MAPs response
        UNKNOWN = 4           # UNKNOWN URL

    def get_url_type(self, packet):
        url_type = PioClient.UrlType.UNKNOWN
        message = json.loads(packet)
        if 'url' in message:
            if message['url'] == 'adtran-olt-of-control/packet-in':
                url_type = PioClient.UrlType.PACKET_IN
            elif message['url'] == 'adtran-olt-of-control/packet-out':
                url_type = PioClient.UrlType.PACKET_OUT
            elif message['url'] == 'adtran-olt-of-control/evc-map-response':
                url_type = PioClient.UrlType.EVCMAPS_RESPONSE
            elif message['url'] == 'adtran-olt-of-control/evc-map-request':
                url_type = PioClient.UrlType.EVCMAPS_REQUEST
        return url_type

    def decode_packet(self, packet):
        from scapy.layers.l2 import Ether
        try:
            message = json.loads(packet)
            self.log.debug('message', message=message)

            for field in ['url', 'evc-map-name', 'total-len', 'port-number', 'message-contents']:
                assert field in message, "Missing field '{}' in received packet".format(field)

            decoded = message['message-contents'].decode('base64')

            assert len(decoded.encode('hex'))/2 == message['total-len'], \
                'Decoded length ({}) != Message Encoded length ({})'.\
                format(len(decoded.encode('hex')), message['total-len'])

            return int(message['port-number']), message['evc-map-name'], Ether(decoded)

        except Exception as e:
            self.log.exception('decode', e=e)
            raise

    @property
    def sequence_number(self):
        if self._seq_number >= 2**32:
            self._seq_number = 0
        else:
            self._seq_number += 1

        return self._seq_number

    def encode_packet(self, egress_port, packet, map_name='TODO', exception_type=''):
        """
        Encode a message for transmission as a Packet Out
        :param egress_port: (int) egress physical port number
        :param packet: (str) actual message
        :param map_name: (str) EVC-MAP Name
        :param exception_type: (str) Type of exception
        """
        return json.dumps({
            'url': 'adtran-olt-of-control/packet-out',
            'buffer-id': self.sequence_number,
            'total-len': len(packet),
            'evc-map-name': map_name,
            'exception-type': exception_type,
            'port-number': egress_port,
            'message-contents': packet.encode('base64')
        })

    def query_request_packet(self):
        """
        Create query-request to get all installed exceptions
        :return: Request string
        """
        return json.dumps({
            'url': 'adtran-olt-of-control/evc-map-request'
        })

    def decode_query_response_packet(self, packet, map_name=None):
        """
        Create query-request to get all installed exceptions
        :param map_name: (str) EVC-MAP Name (None=all)
        :param packet: returned query response packet
        :return: list of evcmaps and associated exceptions
        """
        from scapy.layers.l2 import Ether
        message = json.loads(packet)
        self.log.debug('message', message=message)

        if 'url' in message and message['url'] == 'adtran-olt-of-control/evc-map-response':
            maps=message['evc-map-list']
            if maps is not None:
                self.log.debug('evc-maps-query-response', maps=maps)
                return maps
        return []
