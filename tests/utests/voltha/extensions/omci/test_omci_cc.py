#
# Copyright 2017 the original author or authors.
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
from unittest import TestCase, main
from mock.mock_adapter_agent import MockAdapterAgent
from mock.mock_onu_handler import MockOnuHandler
from mock.mock_olt_handler import MockOltHandler
from mock.mock_onu import MockOnu
from voltha.extensions.omci.omci_defs import *
from voltha.extensions.omci.omci_frame import *
from voltha.extensions.omci.omci_cc import UNKNOWN_CLASS_ATTRIBUTE_KEY

DEFAULT_OLT_DEVICE_ID = 'default_olt_mock'
DEFAULT_ONU_DEVICE_ID = 'default_onu_mock'
DEFAULT_PON_ID = 0
DEFAULT_ONU_ID = 0
DEFAULT_ONU_SN = 'TEST00000001'

OP = EntityOperations
RC = ReasonCodes


def chunk(indexable, chunk_size):
    for i in range(0, len(indexable), chunk_size):
        yield indexable[i:i + chunk_size]


def hex2raw(hex_string):
    return ''.join(chr(int(byte, 16)) for byte in chunk(hex_string, 2))


class TestOmciCc(TestCase):
    """
    Test the Open OMCI Communication channels

    Note also added some testing of MockOnu behaviour since its behaviour during more
    complicated unit/integration tests may be performed in the future.
    """
    def setUp(self):
        self.adapter_agent = MockAdapterAgent()

    def tearDown(self):
        if self.adapter_agent is not None:
            self.adapter_agent.tearDown()

    def setup_mock_olt(self, device_id=DEFAULT_OLT_DEVICE_ID):
        handler = MockOltHandler(self.adapter_agent, device_id)
        self.adapter_agent.add_device(handler.device)
        return handler

    def setup_mock_onu(self, parent_id=DEFAULT_OLT_DEVICE_ID,
                       device_id=DEFAULT_ONU_DEVICE_ID,
                       pon_id=DEFAULT_PON_ID,
                       onu_id=DEFAULT_ONU_ID,
                       serial_no=DEFAULT_ONU_SN):
        handler = MockOnuHandler(self.adapter_agent, parent_id, device_id, pon_id, onu_id)
        handler.serial_number = serial_no
        onu = MockOnu(serial_no, self.adapter_agent, handler.device_id) \
            if serial_no is not None else None
        handler.onu_mock = onu
        return handler

    def setup_one_of_each(self):
        # Most tests will use at lease one or more OLT and ONU
        self.olt_handler = self.setup_mock_olt()
        self.onu_handler = self.setup_mock_onu(parent_id=self.olt_handler.device_id)
        self.onu_device = self.onu_handler.onu_mock

        self.adapter_agent.add_child_device(self.olt_handler.device,
                                            self.onu_handler.device)

    def _is_omci_frame(self, results):
        assert isinstance(results, OmciFrame), 'Not OMCI Frame'
        return results

    def _check_status(self, results, value):
        status = results.fields['omci_message'].fields['success_code']
        assert status == value,\
            'Unexpected Status Code. Got {}, Expected: {}'.format(status, value)
        return results

    def _check_mib_sync(self, results, value):
        assert self.onu_device.mib_data_sync == value, \
            'Unexpected MIB DATA Sync value. Got {}, Expected: {}'.format(
                self.onu_device.mib_data_sync, value)
        return results

    def _check_stats(self, results, snapshot, stat, expected):
        assert snapshot[stat] == expected, \
            'Invalid statistic "{}". Got {}, Expected: {}'.format(stat,
                                                                  snapshot[stat],
                                                                  expected)
        return results

    def _check_value_equal(self, results, name, value, expected):
        assert value == expected, \
            'Value "{}" not equal. Got {}, Expected: {}'.format(name, value,
                                                                expected)
        return results

    def _default_errback(self, failure):
        from twisted.internet.defer import TimeoutError
        assert isinstance(failure.type, type(TimeoutError))
        return None

    def _snapshot_stats(self):
        omci_cc = self.onu_handler.omci_cc
        return {
            'tx_frames': omci_cc.tx_frames,
            'rx_frames': omci_cc.rx_frames,
            'rx_unknown_tid': omci_cc.rx_unknown_tid,
            'rx_onu_frames': omci_cc.rx_onu_frames,
            'rx_onu_discards': omci_cc.rx_onu_discards,
            'rx_timeouts': omci_cc.rx_timeouts,
            'rx_unknown_me': omci_cc.rx_unknown_me,
            'tx_errors': omci_cc.tx_errors,
            'consecutive_errors': omci_cc.consecutive_errors,
            'reply_min': omci_cc.reply_min,
            'reply_max': omci_cc.reply_max,
            'reply_average': omci_cc.reply_average
        }

    def test_default_init(self):
        self.setup_one_of_each()
        # Test default construction of OMCI_CC as well as
        # various other parameter settings
        omci_cc = self.onu_handler.omci_cc

        # No device directly associated
        self.assertIsNotNone(omci_cc._adapter_agent)
        self.assertIsNone(omci_cc._proxy_address)

        # No outstanding requests
        self.assertEqual(len(omci_cc._requests), 0)

        # Flags/properties
        self.assertFalse(omci_cc.enabled)

        # Statistics
        self.assertEqual(omci_cc.tx_frames, 0)
        self.assertEqual(omci_cc.rx_frames, 0)
        self.assertEqual(omci_cc.rx_unknown_tid, 0)
        self.assertEqual(omci_cc.rx_onu_frames, 0)
        self.assertEqual(omci_cc.rx_onu_discards, 0)
        self.assertEqual(omci_cc.rx_unknown_me, 0)
        self.assertEqual(omci_cc.rx_timeouts, 0)
        self.assertEqual(omci_cc.tx_errors, 0)
        self.assertEqual(omci_cc.consecutive_errors, 0)
        self.assertNotEquals(omci_cc.reply_min, 0.0)
        self.assertEqual(omci_cc.reply_max, 0.0)
        self.assertEqual(omci_cc.reply_average, 0.0)

    def test_enable_disable(self):
        self.setup_one_of_each()

        # Test enable property
        omci_cc = self.onu_handler.omci_cc

        # Initially disabled
        self.assertFalse(omci_cc.enabled)
        omci_cc.enabled = False
        self.assertFalse(omci_cc.enabled)

        omci_cc.enabled = True
        self.assertTrue(omci_cc.enabled)
        self.assertIsNotNone(omci_cc._proxy_address)
        self.assertEqual(len(omci_cc._requests), 0)

        omci_cc.enabled = True      # Should be a NOP
        self.assertTrue(omci_cc.enabled)
        self.assertIsNotNone(omci_cc._proxy_address)
        self.assertEqual(len(omci_cc._requests), 0)

        omci_cc.enabled = False
        self.assertFalse(omci_cc.enabled)
        self.assertIsNone(omci_cc._proxy_address)

    def test_rx_discard_if_disabled(self):
        # ME without a known decoder
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = False
        snapshot = self._snapshot_stats()

        msg = '00fc2e0a00020000ff780000e00000010000000c' \
              '0000000000000000000000000000000000000000' \
              '00000028105a86ef'

        omci_cc.receive_message(hex2raw(msg))

        # Note: No counter increments
        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'])
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])

    def test_message_send_get(self):
        # Various tests of sending an OMCI message and it either
        # getting a response or send catching some errors of
        # importance
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()
        mib_data_sync = self.onu_device.mib_data_sync

        # GET
        # d = omci_cc.send()  # TODO: Implement
        #
        # d.addCallbacks(self._is_omci_frame, self._default_errback)
        # d.addCallback(self._check_status, RC.Success.value)
        # d.addCallback(self._check_mib_sync, mib_data_sync)
        #
        # d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        # d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        # d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        # d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)

        # return d

    def test_message_send_set(self):
        # Various tests of sending an OMCI message and it either
        # getting a response or send catching some errors of
        # importance
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()
        mib_data_sync = self.onu_device.mib_data_sync

        # SET
        # d = omci_cc.send()  # TODO: Implement
        #
        # d.addCallbacks(self._is_omci_frame, self._default_errback)
        # d.addCallback(self._check_status, RC.Success.value)
        # d.addCallback(self._check_mib_sync, mib_data_sync + 1 if mib_data_sync < 255 else 1)
        #
        # d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        # d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        # d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        # d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)

        # return d
        #
        # # Also test mib_data_sync rollover.  255 -> 1  (zero reserved)
        #
        # self.onu_device.mib_data_sync = 255
        # # SET
        # self.assertTrue(True)  # TODO: Implement (copy previous one here)
        # self.assertEqual(1, self.onu_device.mib_data_sync)

    def test_message_send_create(self):
        # Various tests of sending an OMCI message and it either
        # getting a response or send catching some errors of
        # importance
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()
        mib_data_sync = self.onu_device.mib_data_sync

        # Create
        # d = omci_cc.send()  # TODO: Implement
        #
        # d.addCallbacks(self._is_omci_frame, self._default_errback)
        # d.addCallback(self._check_status, RC.Success.value)
        # d.addCallback(self._check_mib_sync, mib_data_sync + 1 if mib_data_sync < 255 else 1)
        #
        # d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        # d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        # d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        # d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)

        # return d

    def test_message_send_delete(self):
        # Various tests of sending an OMCI message and it either
        # getting a response or send catching some errors of
        # importance
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()
        mib_data_sync = self.onu_device.mib_data_sync

        # Delete
        # d = omci_cc.send()  # TODO: Implement
        #
        # d.addCallbacks(self._is_omci_frame, self._default_errback)
        # d.addCallback(self._check_status, RC.Success.value)
        # d.addCallback(self._check_mib_sync, mib_data_sync + 1 if mib_data_sync < 255 else 1)
        #
        # d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        # d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        # d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        # d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)

        # return d

    def test_message_send_mib_reset(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        self.onu_device.mib_data_sync = 10
        snapshot = self._snapshot_stats()

        # Successful MIB Reset
        d = omci_cc.send_mib_reset(timeout=1.0)

        d.addCallbacks(self._is_omci_frame, self._default_errback)
        d.addCallback(self._check_status, RC.Success)
        d.addCallback(self._check_mib_sync, 0)

        d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)
        return d

    def test_message_send_mib_upload(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()
        mib_data_sync = self.onu_device.mib_data_sync

        # MIB Upload
        d = omci_cc.send_mib_upload(timeout=1.0)

        d.addCallbacks(self._is_omci_frame, self._default_errback)
        d.addCallback(self._check_status, RC.Success)
        d.addCallback(self._check_mib_sync, mib_data_sync)

        # TODO: MIB Upload Results specific tests here

        d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)
        return d

    def test_message_send_mib_upload_next(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()
        mib_data_sync = self.onu_device.mib_data_sync

        # # MIB Upload Next
        # d = omci_cc.send_mib_upload_next(0, timeout=1.0)
        #
        # d.addCallbacks(self._is_omci_frame, self._default_errback)
        # d.addCallback(self._check_status, RC.Success)
        # d.addCallback(self._check_mib_sync, mib_data_sync)
        #
        # # TODO: MIB Upload Next Results specific tests here
        #
        # d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        # d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        # d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        # d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        # d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        # d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)
        # return d

    def test_message_send_reboot(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # ONU Reboot
        d = omci_cc.send_reboot(timeout=1.0)

        d.addCallbacks(self._is_omci_frame, self._default_errback)
        d.addCallback(self._check_status, RC.Success)

        d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 1)
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'])
        d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)
        return d

    def test_message_send_with_omci_disabled(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        self.assertFalse(omci_cc.enabled)

        # Successful MIB Reset
        d = omci_cc.send_mib_reset(timeout=1.0)

        def success_is_bad(_results):
            assert False, 'This test should throw a failure/error'

        def fail_fast(_failure):
            pass
            return None

        d.addCallbacks(success_is_bad, fail_fast)
        return d

    def test_message_send_get_with_latency(self):
        # Various tests of sending an OMCI message and it either
        # getting a response or send catching some errors of
        # importance
        self.setup_one_of_each()
        self.olt_handler.latency = 0.500    # 1/2 second

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True

        # Successful MIB Reset
        d = omci_cc.send_mib_reset(timeout=1.0)

        d.addCallbacks(self._is_omci_frame, self._default_errback)
        d.addCallback(self._check_status, RC.Success)

        def check_latency_values(_):
            self.assertGreaterEqual(omci_cc.reply_min, self.olt_handler.latency)
            self.assertGreaterEqual(omci_cc.reply_max, self.olt_handler.latency)
            self.assertGreaterEqual(omci_cc.reply_average, self.olt_handler.latency)

        d.addCallback(check_latency_values)
        return d

    def test_message_failures(self):
        # Various tests of sending an OMCI message and it fails
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        self.assertEqual(omci_cc.tx_frames, 0)
        self.assertEqual(omci_cc.rx_frames, 0)
        self.assertEqual(omci_cc.rx_unknown_tid, 0)
        self.assertEqual(omci_cc.rx_timeouts, 0)
        self.assertEqual(omci_cc.tx_errors, 0)

        # # Class ID not found
        # d = omci_cc.send_mib_reset(timeout=1.0)
        # self.assertTrue(True)  # TODO: Implement
        # todo: Test non-zero consecutive errors
        #
        # # Instance ID not found
        # d = omci_cc.send_mib_reset(timeout=1.0)
        # self.assertTrue(True)  # TODO: Implement
        # todo: Test non-zero consecutive errors
        #
        # # PON is disabled
        # d = omci_cc.send_mib_reset(timeout=1.0)
        # self.assertTrue(True)  # TODO: Implement
        # todo: Test non-zero consecutive errors
        #
        # # ONU is disabled
        # d = omci_cc.send_mib_reset(timeout=1.0)
        # self.assertTrue(True)  # TODO: Implement
        # todo: Test non-zero consecutive errors
        #
        # # ONU is not activated
        # d = omci_cc.send_mib_reset(timeout=1.0)
        # self.assertTrue(True)  # TODO: Implement
        # todo: Test non-zero consecutive errors

        # TODO: make OLT send back an unknown TID (

        # todo: Test non-zero consecutive errors
        # todo: Send a good frame
        # todo: Test zero consecutive errors
        # d.addCallback(self._check_value_equal, 'consecutive_errors', 0, omci_cc.consecutive_errors)

    def test_rx_unknown_me(self):
        # ME without a known decoder
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # This is the ID ------+
        #                      v
        msg = '00fc2e0a00020000ff780000e00000010000000c' \
              '0000000000000000000000000000000000000000' \
              '00000028'

        omci_cc.receive_message(hex2raw(msg))

        # Note: After successful frame decode, a lookup of the corresponding request by
        #       TID is performed. None should be found, so we should see the Rx Unknown TID
        #       increment.
        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'])
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'] + 1)
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'] + 1)
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'])
        self.assertEqual(omci_cc.consecutive_errors, 0)

    def test_rx_decode_unknown_me(self):
        # ME without a known decoder
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # This is a MIB Upload Next Response. Where we would probably first see an
        # unknown Class ID
        #
        # This is the ID ------+
        #                      v
        msg = '00fc2e0a00020000ff780001e000'
        blob = '00010000000c0000000000000000000000000000000000000000'
        msg += blob + '00000028'

        # Dig into the internal method so we can get the returned frame
        frame = omci_cc._decode_unknown_me(hex2raw(msg))

        self.assertEqual(frame.fields['transaction_id'], 0x00fc)
        self.assertEqual(frame.fields['message_type'], 0x2e)

        omci_fields = frame.fields['omci_message'].fields

        self.assertEqual(omci_fields['entity_class'], 0x0002)
        self.assertEqual(omci_fields['entity_id'], 0x00)
        self.assertEqual(omci_fields['object_entity_class'], 0x0ff78)
        self.assertEqual(omci_fields['object_entity_id'], 0x01)
        self.assertEqual(omci_fields['object_attributes_mask'], 0xe000)

        data_fields = omci_fields['object_data']

        decoded_blob = data_fields.get(UNKNOWN_CLASS_ATTRIBUTE_KEY)
        self.assertIsNotNone(decoded_blob)
        self.assertEqual(decoded_blob, blob)

    def test_flush(self):
        # Test flush of autonomous ONU queues
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # TODO: add more
        self.assertTrue(True)  # TODO: Implement

    def test_avc_rx(self):
        # Test flush of autonomous ONU queues
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # TODO: add more
        self.assertTrue(True)  # TODO: Implement


    def test_rx_discard_if_disabled(self):
        # ME without a known decoder
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = False
        snapshot = self._snapshot_stats()

        msg = '00fc2e0a00020000ff780000e00000010000000c' \
              '0000000000000000000000000000000000000000' \
              '00000028105a86ef'

        omci_cc.receive_message(hex2raw(msg))

        # Note: No counter increments
        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'])
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])

    def test_omci_alarm_decode(self):
        """
        This test covers an issue discovered in Sept 2018 (JIRA-1213).  It was
        an exception during frame decode.
        """
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True

        # Frame from the JIRA issue
        msg = '0000100a000b0102800000000000000000000000' \
              '0000000000000000000000000000000000000015' \
              '000000282d3ae0a6'

        results = omci_cc.receive_message(hex2raw(msg))

        self.assertTrue(True, 'Truth is the truth')

    def test_rx_decode_onu_g(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        msg = '001e2e0a0002000001000000e000424657530000' \
              '0000000000000000000000324246575300107496' \
              '00000028e7fb4a91'

        omci_cc.receive_message(hex2raw(msg))

        # Note: No counter increments
        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'] + 1)
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'] + 1)
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'])

if __name__ == '__main__':
    main()

