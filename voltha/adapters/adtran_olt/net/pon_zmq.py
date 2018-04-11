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
import struct
import binascii
from adtran_zmq import AdtranZmqClient

DEFAULT_PON_AGENT_TCP_PORT = 5656


class PonClient(AdtranZmqClient):
    """
    Adtran ZeroMQ Client for PON Agent service
    """
    def __init__(self, ip_address, rx_callback, port):
        super(PonClient, self).__init__(ip_address, rx_callback, port)

    def encode_omci_packet(self, msg, pon_index, onu_id):
        """
        Create an OMCI Tx Packet for the specified ONU

        :param msg: (str) OMCI message to send
        :param pon_index: (unsigned int) PON Port index
        :param onu_id: (unsigned int) ONU ID

        :return: (bytes) octet string to send
        """
        return json.dumps({"operation": "NOTIFY",
                           "url": "adtran-olt-pon-control/omci-message",
                           "pon-id": pon_index,
                           "onu-id": onu_id,
                           "message-contents": msg.decode("hex").encode("base64")
                           })

    def decode_packet(self, packet):
        """
        Decode the PON-Agent packet provided by the ZMQ client

        :param packet: (bytes) Packet
        :return: (long, long, bytes, boolean) PON Index, ONU ID, Frame Contents (OMCI or Ethernet),\
                                              and a flag indicating if it is OMCI
        """
        msg = json.loads(packet)
        pon_id = msg['pon-id']
        onu_id = msg['onu-id']
        msg_data = msg['message-contents'].decode("base64")
        is_omci = msg['operation'] == "NOTIFY" and 'omci-message' in msg['url']

        return pon_id, onu_id, msg_data, is_omci
