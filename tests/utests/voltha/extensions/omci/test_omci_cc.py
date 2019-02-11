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
import binascii
from common.frameio.frameio import hexify
from twisted.python.failure import Failure
from unittest import TestCase, main, skip
from mock.mock_adapter_agent import MockAdapterAgent
from mock.mock_onu_handler import MockOnuHandler
from mock.mock_olt_handler import MockOltHandler
from mock.mock_onu import MockOnu
from voltha.extensions.omci.omci_defs import *
from voltha.extensions.omci.omci_frame import *
from voltha.extensions.omci.omci_entities import *
from voltha.extensions.omci.omci_me import ExtendedVlanTaggingOperationConfigurationDataFrame
from voltha.extensions.omci.omci_cc import OMCI_CC, UNKNOWN_CLASS_ATTRIBUTE_KEY,\
    MAX_OMCI_REQUEST_AGE

DEFAULT_OLT_DEVICE_ID = 'default_olt_mock'
DEFAULT_ONU_DEVICE_ID = 'default_onu_mock'
DEFAULT_PON_ID = 0
DEFAULT_ONU_ID = 0
DEFAULT_ONU_SN = 'TEST00000001'

OP = EntityOperations
RC = ReasonCodes

successful = False
error_reason = None


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
    def setUp(self, let_msg_timeout=False):
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

    def setup_one_of_each(self, timeout_messages=False):
        # Most tests will use at lease one or more OLT and ONU
        self.olt_handler = self.setup_mock_olt()
        self.onu_handler = self.setup_mock_onu(parent_id=self.olt_handler.device_id)
        self.onu_device = self.onu_handler.onu_mock
        self.adapter_agent.timeout_the_message = timeout_messages

        self.adapter_agent.add_child_device(self.olt_handler.device,
                                            self.onu_handler.device)

    def _is_omci_frame(self, results, omci_msg_type):
        assert isinstance(results, OmciFrame), 'Not OMCI Frame'
        assert 'omci_message' in results.fields, 'Not OMCI Frame'
        if omci_msg_type is not None:
            assert isinstance(results.fields['omci_message'], omci_msg_type)
        return results

    def _check_status(self, results, value):
        if value is not None: assert results is not None, 'unexpected emtpy message'
        status = results.fields['omci_message'].fields['success_code']
        assert status == value,\
            'Unexpected Status Code. Got {}, Expected: {}'.format(status, value)
        return results

    def _check_mib_sync(self, results, value):
        assert self.onu_device.mib_data_sync == value, \
            'Unexpected MIB DATA Sync value. Got {}, Expected: {}'.format(
                self.onu_device.mib_data_sync, value)
        return results

    def _check_stats(self, results, _, stat, expected):
        snapshot = self._snapshot_stats()
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
            'rx_late': omci_cc.rx_late,
            'tx_errors': omci_cc.tx_errors,
            'consecutive_errors': omci_cc.consecutive_errors,
            'reply_min': omci_cc.reply_min,
            'reply_max': omci_cc.reply_max,
            'reply_average': omci_cc.reply_average,
            'hp_tx_queue_len': omci_cc.hp_tx_queue_len,
            'lp_tx_queue_len': omci_cc.lp_tx_queue_len,
            'max_hp_tx_queue': omci_cc.max_hp_tx_queue,
            'max_lp_tx_queue': omci_cc._max_lp_tx_queue,
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
        self.assertEqual(len(omci_cc._pending[OMCI_CC.LOW_PRIORITY]), 0)
        self.assertEqual(len(omci_cc._pending[OMCI_CC.HIGH_PRIORITY]), 0)

        # No active requests
        self.assertIsNone(omci_cc._tx_request[OMCI_CC.LOW_PRIORITY])
        self.assertIsNone(omci_cc._tx_request[OMCI_CC.HIGH_PRIORITY])

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
        self.assertEqual(omci_cc.rx_late, 0)
        self.assertEqual(omci_cc.tx_errors, 0)
        self.assertEqual(omci_cc.consecutive_errors, 0)
        self.assertNotEquals(omci_cc.reply_min, 0.0)
        self.assertEqual(omci_cc.reply_max, 0.0)
        self.assertEqual(omci_cc.reply_average, 0.0)
        self.assertEqual(omci_cc.lp_tx_queue_len, 0.0)
        self.assertEqual(omci_cc.max_hp_tx_queue, 0.0)
        self.assertEqual(omci_cc._max_hp_tx_queue, 0.0)
        self.assertEqual(omci_cc._max_lp_tx_queue, 0.0)

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
        self.assertEqual(len(omci_cc._pending[OMCI_CC.LOW_PRIORITY]), 0)
        self.assertEqual(len(omci_cc._pending[OMCI_CC.HIGH_PRIORITY]), 0)

        omci_cc.enabled = True      # Should be a NOP
        self.assertTrue(omci_cc.enabled)
        self.assertIsNotNone(omci_cc._proxy_address)
        self.assertEqual(len(omci_cc._pending[OMCI_CC.LOW_PRIORITY]), 0)
        self.assertEqual(len(omci_cc._pending[OMCI_CC.HIGH_PRIORITY]), 0)

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
        d.addCallback(self._check_stats, snapshot, 'rx_late', snapshot['rx_late'])
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
        d.addCallback(self._check_stats, snapshot, 'rx_late', snapshot['rx_late'])
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

    def test_message_send_no_timeout(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        self.onu_device.mib_data_sync = 10
        snapshot = self._snapshot_stats()

        d = omci_cc.send_mib_reset(timeout=0)
        d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 1)
        d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'])
        d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        return d

    def test_message_send_bad_timeout(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        self.onu_device.mib_data_sync = 10
        snapshot = self._snapshot_stats()

        d = omci_cc.send_mib_reset(timeout=MAX_OMCI_REQUEST_AGE + 1)
        d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'])
        d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'])
        d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'] + 1)
        return d

    def test_message_send_not_a_frame(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        self.onu_device.mib_data_sync = 10
        snapshot = self._snapshot_stats()

        d = omci_cc.send('hello world', timeout=1)
        d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'])
        d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'])
        d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'] + 1)
        return d

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
        d.addCallback(self._check_stats, snapshot, 'rx_late', snapshot['rx_late'])
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
        self.assertEqual(omci_cc.rx_late, 0)
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
        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'] + 1)
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

    def test_rx_unknown_me_avc(self):
        # ME without a known decoder but is and attribute value change
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        msg = '0000110aff78000080000e000000' \
              '00000000000000000000000000000000000000000000000000000' \
              '00000028'

        omci_cc.receive_message(hex2raw(msg))

        # Blob decode should work and then it should be passed off to the
        # ONU Autonomous frame processor
        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'])
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'] + 1)
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'] + 1)
        self.assertEqual(omci_cc.rx_onu_discards, snapshot['rx_onu_discards'])
        self.assertEqual(omci_cc.consecutive_errors, 0)

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

    def test_omci_alarm_decode(self):
        """
        This test covers an issue discovered in Sept 2018 (JIRA-1213).  It was
        an exception during frame decode.
        """
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # Frame from the JIRA issue
        msg = '0000100a000b0102800000000000000000000000' \
              '0000000000000000000000000000000000000015' \
              '000000282d3ae0a6'

        _results = omci_cc.receive_message(hex2raw(msg))

        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'])
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'] + 1)
        self.assertEqual(omci_cc.rx_onu_discards, snapshot['rx_onu_discards'])

    def test_omci_avc_decode(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # Frame from the JIRA issue
        msg = '0000110a0007000080004d4c2d33363236000000' \
              '0000000020202020202020202020202020202020' \
              '00000028'

        _results = omci_cc.receive_message(hex2raw(msg))

        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'])
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'] + 1)
        self.assertEqual(omci_cc.rx_onu_discards, snapshot['rx_onu_discards'])

    def test_omci_unknown_onu_decode(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # Frame from the JIRA issue
        msg = '0000190a0007000080004d4c2d33363236000000' \
              '0000000020202020202020202020202020202020' \
              '00000028'

        _results = omci_cc.receive_message(hex2raw(msg))

        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'])
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'])
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'] + 1)
        self.assertEqual(omci_cc.rx_onu_discards, snapshot['rx_onu_discards'] + 1)

    def test_omci_bad_frame_decode(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # Frame from the JIRA issue
        msg = '0020190a0007000080004d4c2d33363236000000' \
              '0000000000000028'

        _results = omci_cc.receive_message(hex2raw(msg))
        # NOTE: Currently do not increment any Rx Discard counters, just throw it away
        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'] + 1)
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'] + 1)
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'])
        self.assertEqual(omci_cc.rx_onu_discards, snapshot['rx_onu_discards'])

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

    def test_rx_decode_extvlantagging(self):
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        msg = '030a290a00ab0201000d00000000001031323334' \
              '3536373839303132333435363738393031323334' \
              '000000281166d283'

        omci_cc.receive_message(hex2raw(msg))

        self.assertEqual(omci_cc.rx_frames, snapshot['rx_frames'] + 1)
        self.assertEqual(omci_cc.rx_unknown_me, snapshot['rx_unknown_me'])
        self.assertEqual(omci_cc.rx_unknown_tid, snapshot['rx_unknown_tid'] + 1)
        self.assertEqual(omci_cc.rx_onu_frames, snapshot['rx_onu_frames'])

    def _check_vlan_tag_op(self, results, attr, expected):
        omci_msg = results.fields['omci_message']
        data = omci_msg.fields['data']
        val = data[attr]
        self.assertEqual(expected, val)
        return results

    @skip('for unknown omci failure')
    #@deferred()
    def test_rx_table_get_extvlantagging(self):
        self.setup_one_of_each()

        onu = self.onu_handler.onu_mock
        entity_id = 1
        vlan_tag_op1 = VlanTaggingOperation(
                                     filter_outer_priority=15,
                                     filter_outer_vid=4096,
                                     filter_outer_tpid_de=2,
                                     filter_inner_priority=15,
                                     filter_inner_vid=4096,
                                     filter_inner_tpid_de=0,
                                     filter_ether_type=0,
                                     treatment_tags_to_remove=0,
                                     treatment_outer_priority=15,
                                     treatment_outer_vid=1234,
                                     treatment_outer_tpid_de=0,
                                     treatment_inner_priority=0,
                                     treatment_inner_vid=4091,
                                     treatment_inner_tpid_de=4,
                                 )
        vlan_tag_op2 = VlanTaggingOperation(
                                     filter_outer_priority=14,
                                     filter_outer_vid=1234,
                                     filter_outer_tpid_de=5,
                                     filter_inner_priority=1,
                                     filter_inner_vid=2345,
                                     filter_inner_tpid_de=1,
                                     filter_ether_type=0,
                                     treatment_tags_to_remove=1,
                                     treatment_outer_priority=15,
                                     treatment_outer_vid=2222,
                                     treatment_outer_tpid_de=1,
                                     treatment_inner_priority=1,
                                     treatment_inner_vid=3333,
                                     treatment_inner_tpid_de=5,
                                 )
        vlan_tag_op3 = VlanTaggingOperation(
                                     filter_outer_priority=13,
                                     filter_outer_vid=55,
                                     filter_outer_tpid_de=1,
                                     filter_inner_priority=7,
                                     filter_inner_vid=4567,
                                     filter_inner_tpid_de=1,
                                     filter_ether_type=0,
                                     treatment_tags_to_remove=1,
                                     treatment_outer_priority=2,
                                     treatment_outer_vid=1111,
                                     treatment_outer_tpid_de=1,
                                     treatment_inner_priority=1,
                                     treatment_inner_vid=3131,
                                     treatment_inner_tpid_de=5,
                                 )
        tbl = [vlan_tag_op1, vlan_tag_op2, vlan_tag_op3]
        tblstr = str(vlan_tag_op1) + str(vlan_tag_op2) + str(vlan_tag_op3)

        onu._omci_response[OP.Get.value][ExtendedVlanTaggingOperationConfigurationData.class_id] = {
            entity_id: OmciFrame(transaction_id=0,
                         message_type=OmciGetResponse.message_id,
                         omci_message=OmciGetResponse(
                               entity_class=ExtendedVlanTaggingOperationConfigurationData.class_id,
                               entity_id=1,
                               success_code=RC.Success.value,
                               attributes_mask=ExtendedVlanTaggingOperationConfigurationData.mask_for(
                                   'received_frame_vlan_tagging_operation_table'),
                               data={'received_frame_vlan_tagging_operation_table': 16 * len(tbl)}
                         ))
        }

        rsp1 = binascii.a2b_hex(hexify(tblstr[0:OmciTableField.PDU_SIZE]))
        rsp2 = binascii.a2b_hex(hexify(tblstr[OmciTableField.PDU_SIZE:]))
        onu._omci_response[OP.GetNext.value][ExtendedVlanTaggingOperationConfigurationData.class_id] = {
            entity_id: {0: {'failures':2,
                            'frame':OmciFrame(transaction_id=0,
                                 message_type=OmciGetNextResponse.message_id,
                                 omci_message=OmciGetNextResponse(
                                     entity_class=ExtendedVlanTaggingOperationConfigurationData.class_id,
                                     entity_id=1,
                                     success_code=RC.Success.value,
                                     attributes_mask=ExtendedVlanTaggingOperationConfigurationData.mask_for(
                                         'received_frame_vlan_tagging_operation_table'),
                                     data={'received_frame_vlan_tagging_operation_table': rsp1
                                     }
                         ))},
                        1: OmciFrame(transaction_id=0,
                         message_type=OmciGetNextResponse.message_id,
                         omci_message=OmciGetNextResponse(
                             entity_class=ExtendedVlanTaggingOperationConfigurationData.class_id,
                             entity_id=1,
                             success_code=RC.Success.value,
                             attributes_mask=ExtendedVlanTaggingOperationConfigurationData.mask_for(
                                 'received_frame_vlan_tagging_operation_table'),
                             data={'received_frame_vlan_tagging_operation_table': rsp2
                             }
                         ))
                       }
        }

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True

        msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
            entity_id,
            attributes={'received_frame_vlan_tagging_operation_table':True}
        )

        snapshot = self._snapshot_stats()

        frame = msg.get()
        d = omci_cc.send(frame, timeout=5.0)

        d.addCallbacks(self._is_omci_frame, self._default_errback, [OmciGetResponse])
        d.addCallback(self._check_status, RC.Success)

        d.addCallback(self._check_stats, snapshot, 'tx_frames', snapshot['tx_frames'] + 5)
        d.addCallback(self._check_stats, snapshot, 'rx_frames', snapshot['rx_frames'] + 3)
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_tid', snapshot['rx_unknown_tid'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_frames', snapshot['rx_onu_frames'])
        d.addCallback(self._check_stats, snapshot, 'rx_onu_discards', snapshot['rx_onu_discards'])
        d.addCallback(self._check_stats, snapshot, 'rx_unknown_me', snapshot['rx_unknown_me'])
        d.addCallback(self._check_stats, snapshot, 'rx_timeouts', snapshot['rx_timeouts'] + 2)
        d.addCallback(self._check_stats, snapshot, 'rx_late', snapshot['rx_late'])
        d.addCallback(self._check_stats, snapshot, 'tx_errors', snapshot['tx_errors'])
        d.addCallback(self._check_stats, snapshot, 'consecutive_errors', 0)
        d.addCallback(self._check_vlan_tag_op, 'received_frame_vlan_tagging_operation_table', tbl)

        return d

    ##################################################################
    # Start of tests specific to new stop_and_wait changes
    #
    def test_message_send_low_priority(self):
        # self.setup_one_of_each(timeout_messages=True)
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # MIB Upload
        d = omci_cc.send_mib_upload(timeout=1.0, high_priority=False)
        d.addCallback(self._check_stats, snapshot, 'lp_tx_queue_len', snapshot['lp_tx_queue_len'])
        d.addCallback(self._check_stats, snapshot, 'hp_tx_queue_len', snapshot['hp_tx_queue_len'])
        d.addCallback(self._check_stats, snapshot, 'max_lp_tx_queue', snapshot['max_lp_tx_queue'] + 1)
        d.addCallback(self._check_stats, snapshot, 'max_hp_tx_queue', snapshot['max_hp_tx_queue'])

        # Flush to get ready for next test (one frame queued)
        omci_cc.flush()
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        self.adapter_agent.timeout_the_message = True
        omci_cc.send_mib_upload(timeout=1.0, high_priority=False)
        omci_cc.send_mib_upload(timeout=1.0, high_priority=False)

        self.assertEqual(omci_cc.lp_tx_queue_len, 1)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)
        self.assertEqual(omci_cc.max_lp_tx_queue, 1)
        self.assertEqual(omci_cc.max_hp_tx_queue, 0)

        # Flush to get ready for next test (two queued and new max)
        omci_cc.flush()
        omci_cc.send_mib_upload(timeout=1.0, high_priority=False)
        omci_cc.send_mib_upload(timeout=1.0, high_priority=False)
        omci_cc.send_mib_upload(timeout=1.0, high_priority=False)

        self.assertEqual(omci_cc.lp_tx_queue_len, 2)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)
        self.assertEqual(omci_cc.max_lp_tx_queue, 2)
        self.assertEqual(omci_cc.max_hp_tx_queue, 0)

    def test_message_send_high_priority(self):
        # self.setup_one_of_each(timeout_messages=True)
        self.setup_one_of_each()

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True
        snapshot = self._snapshot_stats()

        # MIB Upload
        d = omci_cc.send_mib_upload(high_priority=True)
        d.addCallback(self._check_stats, snapshot, 'lp_tx_queue_len', snapshot['lp_tx_queue_len'])
        d.addCallback(self._check_stats, snapshot, 'hp_tx_queue_len', snapshot['hp_tx_queue_len'])
        d.addCallback(self._check_stats, snapshot, 'max_lp_tx_queue', snapshot['max_lp_tx_queue'])
        d.addCallback(self._check_stats, snapshot, 'max_hp_tx_queue', snapshot['max_hp_tx_queue'] + 1)

        # Flush to get ready for next test (one frame queued)
        omci_cc.flush()
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        self.adapter_agent.timeout_the_message = True
        omci_cc.send_mib_upload(high_priority=True)
        omci_cc.send_mib_upload(high_priority=True)

        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 1)
        self.assertEqual(omci_cc.max_lp_tx_queue, 0)
        self.assertEqual(omci_cc.max_hp_tx_queue, 1)

        # Flush to get ready for next test (two queued and new max)
        omci_cc.flush()
        omci_cc.send_mib_upload(high_priority=True)
        omci_cc.send_mib_upload(high_priority=True)
        omci_cc.send_mib_upload(high_priority=True)

        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 2)
        self.assertEqual(omci_cc.max_lp_tx_queue, 0)
        self.assertEqual(omci_cc.max_hp_tx_queue, 2)

    def test_message_send_and_cancel(self):
        global error_reason
        global successful
        # Do not send messages to adapter_agent
        self.setup_one_of_each(timeout_messages=True)

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True

        def success(_results):
            global successful
            successful = True

        def failure(reason):
            global error_reason
            error_reason = reason

        def notCalled(reason):
            assert isinstance(reason, Failure), 'Should not be called with success'

        # Cancel one that is actively being sent
        d = omci_cc.send_mib_upload(high_priority=False)
        d.addCallbacks(success, failure)
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        d.cancel()
        self.assertIsInstance(error_reason, Failure)
        self.assertFalse(successful)
        self.assertTrue(d.called)

        self.assertEqual(omci_cc.max_lp_tx_queue, 1)
        self.assertEqual(omci_cc.max_hp_tx_queue, 0)

        # Flush to get ready for next test (one running, one queued, cancel the
        # running one, so queued runs)
        omci_cc.flush()
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        error_reason = None
        d1 = omci_cc.send_mib_upload(high_priority=False)
        d2 = omci_cc.send_mib_upload(high_priority=False)
        d1.addCallbacks(success, failure)
        d2.addCallbacks(notCalled, notCalled)
        self.assertEqual(omci_cc.lp_tx_queue_len, 1)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        d1.cancel()
        self.assertIsInstance(error_reason, Failure)
        self.assertFalse(successful)
        self.assertTrue(d1.called)
        self.assertFalse(d2.called)

        self.assertEqual(omci_cc.max_lp_tx_queue, 1)
        self.assertEqual(omci_cc.max_hp_tx_queue, 0)
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        # Flush to get ready for next test (one running, one queued, cancel the queued one)

        omci_cc.flush()
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        error_reason = None
        d3 = omci_cc.send_mib_upload(timeout=55, high_priority=False)
        d4 = omci_cc.send_mib_upload(timeout=55, high_priority=False)
        d5 = omci_cc.send_mib_upload(timeout=55, high_priority=False)
        d3.addCallbacks(notCalled, notCalled)
        d4.addCallbacks(success, failure)
        d5.addCallbacks(notCalled, notCalled)
        self.assertEqual(omci_cc.lp_tx_queue_len, 2)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        d4.cancel()
        self.assertIsInstance(error_reason, Failure)
        self.assertFalse(successful)
        self.assertFalse(d3.called)
        self.assertTrue(d4.called)
        self.assertFalse(d5.called)

    def test_message_send_low_and_high_priority(self):
        self.setup_one_of_each(timeout_messages=True)

        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True

        omci_cc.send_mib_reset(high_priority=False)
        omci_cc.send_mib_reset(high_priority=True)
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        omci_cc.flush()
        self.assertEqual(omci_cc.lp_tx_queue_len, 0)
        self.assertEqual(omci_cc.hp_tx_queue_len, 0)

        omci_cc.send_mib_reset(high_priority=False)
        omci_cc.send_mib_reset(high_priority=True)
        omci_cc.send_mib_reset(high_priority=False)
        omci_cc.send_mib_reset(high_priority=True)
        self.assertEqual(omci_cc.lp_tx_queue_len, 1)
        self.assertEqual(omci_cc.hp_tx_queue_len, 1)

    def test_no_sw_download_and_mib_upload_at_same_time(self):
        # Section B.2.3 of ITU G.988-2017 specifies that a MIB
        # upload or software download at a given priority level
        # is not allowed while a similar action in the other
        # priority level is in progress. Relates to possible memory
        # consumption/needs on the ONU.
        #
        # OMCI_CC only checks if the commands are currently in
        # progress. ONU should reject messages if the upload/download
        # is in progress (but not an active request is in progress).

        self.setup_one_of_each(timeout_messages=True)
        omci_cc = self.onu_handler.omci_cc
        omci_cc.enabled = True

        mib_upload_msgs = [omci_cc.send_mib_upload,
                           # omci_cc.send_mib_upload_next
                           ]
        sw_download_msgs = [omci_cc.send_start_software_download,
                            # omci_cc.send_download_section,
                            # omci_cc.send_end_software_download
                            ]

        for upload in mib_upload_msgs:
            for download in sw_download_msgs:
                self.assertEqual(omci_cc.lp_tx_queue_len, 0)
                self.assertEqual(omci_cc.hp_tx_queue_len, 0)

                upload(high_priority=False)
                download(1, 1, 1, high_priority=True)    # Should stall send-next 50mS
                self.assertEqual(omci_cc.lp_tx_queue_len, 0)
                self.assertEqual(omci_cc.hp_tx_queue_len, 1)

                omci_cc.flush()
                self.assertEqual(omci_cc.lp_tx_queue_len, 0)
                self.assertEqual(omci_cc.hp_tx_queue_len, 0)

                upload(high_priority=True)
                download(1, 1, 1, high_priority=False)    # Should stall send-next 50mS
                self.assertEqual(omci_cc.lp_tx_queue_len, 1)
                self.assertEqual(omci_cc.hp_tx_queue_len, 0)

                omci_cc.flush()
                self.assertEqual(omci_cc.lp_tx_queue_len, 0)
                self.assertEqual(omci_cc.hp_tx_queue_len, 0)

                download(1, 1, 1, high_priority=False)
                upload(high_priority=True)    # Should stall send-next 50mS
                self.assertEqual(omci_cc.lp_tx_queue_len, 0)
                self.assertEqual(omci_cc.hp_tx_queue_len, 1)

                omci_cc.flush()
                self.assertEqual(omci_cc.lp_tx_queue_len, 0)
                self.assertEqual(omci_cc.hp_tx_queue_len, 0)

                download(1, 1, 1, high_priority=True)
                upload(high_priority=False)    # Should stall send-next 50mS)
                self.assertEqual(omci_cc.lp_tx_queue_len, 1)
                self.assertEqual(omci_cc.hp_tx_queue_len, 0)

                omci_cc.flush()
                self.assertEqual(omci_cc.lp_tx_queue_len, 0)
                self.assertEqual(omci_cc.hp_tx_queue_len, 0)

    # Some more ideas for tests that we could add
    # Send explicit tid that is not valid
    #       - Look at top of 'Send' method and test all the error conditions could may hit

    # Send multiple and have the OLT proxy throw an exception. Should call errback and
    # schedule remainder in queue to still tx.

    # Send a frame and then inject a response and test the RX logic out, including late
    # rx and retries by the OMCI_CC transmitter.


if __name__ == '__main__':
    main()
