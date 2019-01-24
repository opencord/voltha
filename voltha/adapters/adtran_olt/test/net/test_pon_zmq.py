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

from unittest import TestCase
from mock import patch
from voltha.adapters.adtran_olt.net.pon_zmq import PonClient
import json


# Mock PonClient's __init__ constructor method
def adtran_zmq_client_init(self, ip_address, rx_callback, port):
    # Create instance vars that otherwise would have been created by the super() constructor call
    self.log = None
    self.zmq_endpoint = None
    self._socket = None
    self.auth = None


class TestPonZmq(TestCase):
    """
    This class contains all methods to unit test pon_zmq.py
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.AdtranZmqClient.__init__', adtran_zmq_client_init):
            # Create PonClient instance for test
            self.pon_client = PonClient(None, None, None)

    def test_create_pon_client_instance(self):
        self.assertIsNone(self.pon_client.log)
        self.assertIsNone(self.pon_client.zmq_endpoint)
        self.assertIsNone(self.pon_client._socket)
        self.assertIsNone(self.pon_client.auth)

    def test_encode_sample_omci_packet_pon0_onu0(self):
        packet = self.pon_client.encode_omci_packet('01234567', 0, 0)
        self.assertIs(type(packet), str)
        msg = json.loads(packet)
        self.assertEqual(msg['operation'], 'NOTIFY')
        self.assertEqual(msg['pon-id'], 0)
        self.assertEqual(msg['onu-id'], 0)

    def test_encode_sample_omci_packet_pon15_onu127(self):
        packet = self.pon_client.encode_omci_packet('76543210', 15, 127)
        self.assertIs(type(packet), str)
        msg = json.loads(packet)
        self.assertEqual(msg['operation'], 'NOTIFY')
        self.assertEqual(msg['pon-id'], 15)
        self.assertEqual(msg['onu-id'], 127)

    def test_decode_sample_omci_packet_pon0_onu0(self):
        msg = '01234567'
        test_packet = json.dumps({"operation": "NOTIFY",
                                  "url": "adtran-olt-pon-control/omci-message",
                                  "pon-id": 0,
                                  "onu-id": 0,
                                  "message-contents": msg.decode("hex").encode("base64")})
        pon_id, onu_id, msg_data, is_omci = self.pon_client.decode_packet(test_packet)
        self.assertEqual(pon_id, 0)
        self.assertEqual(onu_id, 0)
        self.assertEqual(msg_data.encode("hex"), '01234567')

    def test_decode_sample_omci_packet_pon15_onu127(self):
        msg = '76543210'
        test_packet = json.dumps({"operation": "NOTIFY",
                                  "url": "adtran-olt-pon-control/omci-message",
                                  "pon-id": 15,
                                  "onu-id": 127,
                                  "message-contents": msg.decode("hex").encode("base64")})
        pon_id, onu_id, msg_data, is_omci = self.pon_client.decode_packet(test_packet)
        self.assertEqual(pon_id, 15)
        self.assertEqual(onu_id, 127)
        self.assertEqual(msg_data.encode("hex"), '76543210')
