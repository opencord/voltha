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
from mock import MagicMock, patch
import pytest
from voltha.adapters.adtran_olt.net.pio_zmq import PioClient


@patch('json.loads', autospec=True, spec_set=True)
class TestPioZmqGetUrlType(TestCase):
    """
    This class contains all methods to unit test get_url_type()
    """
    # Helper method to run the test and do the checks for each test method
    def assert_url_type(self, packet, expected_url_type, mock_json_loads):
        url_type = self.pio_client.get_url_type(packet)
        mock_json_loads.assert_called_once_with(packet)
        self.assertEqual(url_type, expected_url_type)

    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.AdtranZmqClient.__init__', autospec=True):
            # Create PioClient instance for test
            self.pio_client = PioClient(None, None, None)

    # Test the creation of the PioClient instance
    def test_create_pio_client_instance(self, mock_json_loads):
        self.assertGreaterEqual(self.pio_client._seq_number, 1)
        self.assertLessEqual(self.pio_client._seq_number, 2**32)

    # Test get_url_type() for valid PACKET_IN url
    def test_get_url_type_packet_in(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/packet-in", "buffer-id": 1, "total-len": 4, \
                   "evc-map-name": "evc-map-name", "exception-type": "", "port-number": 1, \
                   "message-contents": "ASNFZw==n"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/packet-in',
                                        'buffer-id': 1,
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'exception-type': '',
                                        'port-number': 1,
                                        'message-contents': 'ASNFZw==n'}
        self.assert_url_type(packet, PioClient.UrlType.PACKET_IN, mock_json_loads)

    # Test get_url_type() for valid PACKET_OUT url
    def test_get_url_type_packet_out(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/packet-out", "buffer-id": 1, "total-len": 4, \
                   "evc-map-name": "evc-map-name", "exception-type": "", "port-number": 1, \
                   "message-contents": "ASNFZw==n"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/packet-out',
                                        'buffer-id': 1,
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'exception-type': '',
                                        'port-number': 1,
                                        'message-contents': 'ASNFZw==n'}
        self.assert_url_type(packet, PioClient.UrlType.PACKET_OUT, mock_json_loads)

    # Test get_url_type() for valid EVCMAPS_RESPONSE url
    def test_get_url_type_evc_map_response(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/evc-map-response", "buffer-id": 1, "total-len": 4, \
                   "evc-map-name": "evc-map-name", "exception-type": "", "port-number": 1, \
                   "message-contents": "ASNFZw==n"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/evc-map-response',
                                        'buffer-id': 1,
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'exception-type': '',
                                        'port-number': 1,
                                        'message-contents': 'ASNFZw==n'}
        self.assert_url_type(packet, PioClient.UrlType.EVCMAPS_RESPONSE, mock_json_loads)

    # Test get_url_type() for valid EVCMAPS_REQUEST url
    def test_get_url_type_evc_map_request(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/evc-map-request", "buffer-id": 1, "total-len": 4, \
                   "evc-map-name": "evc-map-name", "exception-type": "", "port-number": 1, \
                   "message-contents": "ASNFZw==n"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/evc-map-request',
                                        'buffer-id': 1,
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'exception-type': '',
                                        'port-number': 1,
                                        'message-contents': 'ASNFZw==n'}
        self.assert_url_type(packet, PioClient.UrlType.EVCMAPS_REQUEST, mock_json_loads)

    # Test get_url_type() for unknown url type
    def test_get_url_type_unknown_url_type(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/unknown", "buffer-id": 1, "total-len": 4, \
                   "evc-map-name": "evc-map-name", "exception-type": "", "port-number": 1, \
                   "message-contents": "ASNFZw==n"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/unknown',
                                        'buffer-id': 1,
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'exception-type': '',
                                        'port-number': 1,
                                        'message-contents': 'ASNFZw==n'}
        self.assert_url_type(packet, PioClient.UrlType.UNKNOWN, mock_json_loads)

    # Test get_url_type() for invalid json message (url field missing)
    def test_get_url_type_invalid_json(self, mock_json_loads):
        # Create serialized json string
        packet = '{"invalid": "meaningless"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'invalid': 'meaningless'}
        self.assert_url_type(packet, PioClient.UrlType.UNKNOWN, mock_json_loads)


@patch('scapy.layers.l2.Ether', autospec=True, spec_set=True)
@patch('json.loads', autospec=True, spec_set=True)
class TestPioZmqDecodePacket(TestCase):
    """
    This class contains all methods to unit test decode_packet()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.AdtranZmqClient.__init__', autospec=True) as mock_init:
            # Create PonClient instance for test
            self.pio_client = PioClient(None, None, None)
            # Probably shouldn't be doing a test in setUp(), but it seemed like the thing to do
            mock_init.assert_called_once_with(self.pio_client, None, None, None)
        self.pio_client.log = MagicMock()

    # Test decode_packet() for good decode with valid json message
    def test_decode_packet_valid_decode(self, mock_json_loads, mock_ether_class):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/packet-in", "total-len": 4, "evc-map-name": "evc-map-name", \
                   "port-number": 1, "message-contents": "ASNFZw==n"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/packet-in',
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'port-number': 1,
                                        'message-contents': 'ASNFZw==n'}
        port_num, evc_map_name, _ = self.pio_client.decode_packet(packet)
        mock_json_loads.assert_called_once_with(packet)
        self.assertTrue(self.pio_client.log.debug.called)
        self.assertFalse(self.pio_client.log.exception.called)
        self.assertEqual(port_num, 1)
        self.assertEqual(evc_map_name, 'evc-map-name')

    # Test decode_packet() for missing json field
    def test_decode_packet_json_field_missing(self, mock_json_loads, mock_ether_class):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/packet-in", "total-len": 4, "evc-map-name": "evc-map-name", \
                   "port-number": 1}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/packet-in',
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'port-number': 1}
        with pytest.raises(AssertionError, message="Expecting AssertionError"):
            _, _, _ = self.pio_client.decode_packet(packet)
        # All checks must be outside of the context manager scope in order to be executed
        self.assertTrue(self.pio_client.log.exception.called)

    # Test decode_packet() for 'total-len' value not matching actual length of 'message-contents'
    def test_decode_packet_json_message_length_mismatch(self, mock_json_loads, mock_ether_class):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/packet-in", "total-len": 4, "evc-map-name": "evc-map-name", \
                   "port-number": 1, "message-contents": ""}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/packet-in',
                                        'total-len': 4,
                                        'evc-map-name': 'evc-map-name',
                                        'port-number': 1,
                                        'message-contents': ''}
        with pytest.raises(AssertionError, message="Expecting AssertionError"):
            _, _, _ = self.pio_client.decode_packet(packet)
        # All checks must be outside of the context manager scope in order to be executed
        self.assertTrue(self.pio_client.log.exception.called)


class TestPioZmqSequenceNumber(TestCase):
    """
    This class contains all methods to unit test sequence_number()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.AdtranZmqClient.__init__', autospec=True) as mock_init:
            # Create PonClient instance for test
            self.pio_client = PioClient(None, None, None)
            # Probably shouldn't be doing a test in setUp(), but it seemed like the thing to do
            mock_init.assert_called_once_with(self.pio_client, None, None, None)

    # Test sequence_number() for normal +1 increment
    def test_sequence_number_normal_increment(self):
        self.pio_client._seq_number = 1
        seq_num = self.pio_client.sequence_number
        self.assertEqual(seq_num, 2)

    # Test sequence_number() for 2^32 overflow back to 0
    def test_sequence_number_overflow_reset(self):
        self.pio_client._seq_number = 2**32
        seq_num = self.pio_client.sequence_number
        self.assertEqual(seq_num, 0)


@patch('json.dumps', autospec=True, spec_set=True)
class TestPioZmqEncodePacket(TestCase):
    """
    This class contains all methods to unit test encode_packet()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.AdtranZmqClient.__init__', autospec=True) as mock_init:
            # Create PonClient instance for test
            self.pio_client = PioClient(None, None, None)
            # Probably shouldn't be doing a test in setUp(), but it seemed like the thing to do
            mock_init.assert_called_once_with(self.pio_client, None, None, None)

    # Test encode_packet() -- nothing to test, just gaining code coverage
    def test_encode_packet(self, mock_json_dumps):
        self.pio_client.encode_packet(1, '01234567', "evc-map-name")


@patch('json.dumps', autospec=True, spec_set=True)
class TestPioZmqQueryRequestPacket(TestCase):
    """
    This class contains all methods to unit test query_request_packet()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.AdtranZmqClient.__init__', autospec=True) as mock_init:
            # Create PonClient instance for test
            self.pio_client = PioClient(None, None, None)
            # Probably shouldn't be doing a test in setUp(), but it seemed like the thing to do
            mock_init.assert_called_once_with(self.pio_client, None, None, None)

    # Test query_request_packet() -- nothing to test, just gaining code coverage
    def test_query_request_packet(self, mock_json_dumps):
        self.pio_client.query_request_packet()


@patch('json.loads', autospec=True, spec_set=True)
class TestPioZmqDecodeQueryResponsePacket(TestCase):
    """
    This class contains all methods to unit test decode_query_response_packet()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.AdtranZmqClient.__init__', autospec=True) as mock_init:
            # Create PonClient instance for test
            self.pio_client = PioClient(None, None, None)
            # Probably shouldn't be doing a test in setUp(), but it seemed like the thing to do
            mock_init.assert_called_once_with(self.pio_client, None, None, None)
        self.pio_client.log = MagicMock()

    # Test decode_query_response_packet() for decoding a json message with valid evc-map list
    def test_decode_query_response_packet_valid_decode(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/evc-map-response"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/evc-map-response',
                                        'evc-map-list': ['evc-map-0123456789.0.0.2176']}
        maps = self.pio_client.decode_query_response_packet(packet)
        mock_json_loads.assert_called_once_with(packet)
        self.assertTrue(self.pio_client.log.debug.called)
        self.assertEqual(maps[0], 'evc-map-0123456789.0.0.2176')

    # Test decode_query_response_packet() for decoding a json message with wrong url type
    def test_decode_query_response_packet_wrong_url_type(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/packet-in"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/packet-in',
                                        'evc-map-list': ['evc-map-0123456789.0.0.2176']}
        maps = self.pio_client.decode_query_response_packet(packet)
        mock_json_loads.assert_called_once_with(packet)
        self.assertTrue(self.pio_client.log.debug.called)
        self.assertEqual(maps, [])

    # Test decode_query_response_packet() for decoding a json message with empty evc-map list
    def test_decode_query_response_packet_no_evc_maps(self, mock_json_loads):
        # Create serialized json string
        packet = '{"url": "adtran-olt-of-control/evc-map-response"}'
        # Create dict that would be returned by json.loads(packet)
        mock_json_loads.return_value = {'url': 'adtran-olt-of-control/evc-map-response',
                                        'evc-map-list': None}
        maps = self.pio_client.decode_query_response_packet(packet)
        mock_json_loads.assert_called_once_with(packet)
        self.assertTrue(self.pio_client.log.debug.called)
        self.assertEqual(maps, [])
