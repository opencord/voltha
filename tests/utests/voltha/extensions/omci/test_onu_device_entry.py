#
# Copyright 2018 the original author or authors.
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
from nose.tools import assert_raises
from nose.twistedtools import deferred
from copy import deepcopy
from mock.mock_adapter_agent import MockAdapterAgent, MockCore
from mock.mock_onu_handler import MockOnuHandler
from mock.mock_olt_handler import MockOltHandler
from mock.mock_onu import MockOnu
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent, OpenOmciAgentDefaults
from voltha.extensions.omci.omci_defs import *
from common.utils.asleep import asleep
from voltha.extensions.omci.database.mib_db_api import DEVICE_ID_KEY, CLASS_ID_KEY, CREATED_KEY, \
    MODIFIED_KEY, MDS_KEY, LAST_SYNC_KEY, VERSION_KEY, DatabaseStateError
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict


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


class TestOnuDeviceEntry(TestCase):
    """
    Test the ONU Device Entry methods
    """
    def setUp(self):
        self.adapter_agent = MockAdapterAgent()

        custom = deepcopy(OpenOmciAgentDefaults)
        custom['mib-synchronizer']['database'] = MibDbVolatileDict

        self.agent = OpenOMCIAgent(MockCore, support_classes=custom)
        self.agent.start()

    def tearDown(self):
        if self.agent is not None:
            self.agent.stop()

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

    def test_add_remove_device(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.agent.device_ids()), 0)

        onu_device = self.agent.add_device(DEFAULT_ONU_DEVICE_ID,
                                           self.adapter_agent)
        self.assertIsNotNone(onu_device)
        self.assertEqual(len(self.agent.device_ids()), 1)
        self.assertEqual(self.agent.get_device(DEFAULT_ONU_DEVICE_ID), onu_device)

        # No MIB if not started
        assert_raises(KeyError, onu_device.query_mib)

        self.agent.remove_device(DEFAULT_ONU_DEVICE_ID)
        self.assertEqual(len(self.agent.device_ids()), 1)

    def test_delete_device(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.agent.device_ids()), 0)

        onu_device = self.agent.add_device(DEFAULT_ONU_DEVICE_ID,
                                           self.adapter_agent)
        self.assertIsNotNone(onu_device)
        self.assertEqual(len(self.agent.device_ids()), 1)
        self.assertEqual(self.agent.get_device(DEFAULT_ONU_DEVICE_ID), onu_device)
        # Can delete if it was not started
        onu_device.delete()
        self.assertEqual(len(self.agent.device_ids()), 0)

        ##########################################
        # Delete of ONU device okay if it is started
        onu_device = self.agent.add_device(DEFAULT_ONU_DEVICE_ID,
                                           self.adapter_agent)
        self.assertIsNotNone(onu_device)
        self.assertEqual(len(self.agent.device_ids()), 1)
        self.assertEqual(self.agent.get_device(DEFAULT_ONU_DEVICE_ID), onu_device)

        # Start it and then delete it
        onu_device.start()
        onu_device.delete()
        self.assertEqual(len(self.agent.device_ids()), 0)

    @deferred(timeout=5)
    def test_mib_query_fails_if_dev_not_started(self):
        self.setup_one_of_each()

        onu_device = self.agent.add_device(DEFAULT_ONU_DEVICE_ID,
                                           self.adapter_agent)
        self.assertIsNotNone(onu_device)
        self.assertEqual(len(self.agent.device_ids()), 1)
        self.assertEqual(self.agent.get_device(DEFAULT_ONU_DEVICE_ID), onu_device)

        def not_called(_reason):
            assert False, 'Should never be called'

        def check_status(_results):
            # Device not yet started. Query should fail with KeyError since
            # ONU is not in database yet
            assert_raises(KeyError, onu_device.query_mib)

        # Yield context so that MIB Database callLater runs. This is a waiting
        # Async task from when the OpenOMCIAgent was started.
        d = asleep(0.2)
        d.addCallbacks(check_status, not_called)

        return d

    @deferred(timeout=5)
    def test_mib_query_ok_if_dev_started(self):
        self.setup_one_of_each()

        onu_device = self.agent.add_device(DEFAULT_ONU_DEVICE_ID,
                                           self.adapter_agent)
        self.assertIsNotNone(onu_device)
        self.assertEqual(len(self.agent.device_ids()), 1)
        self.assertEqual(self.agent.get_device(DEFAULT_ONU_DEVICE_ID), onu_device)

        def not_called(_reason):
            onu_device.stop()
            assert False, 'Should never be called'

        def check_status(_results):
            # Device started. Query will succeed but nothing should be populated
            # but the most basic items

            results = onu_device.query_mib()
            self.assertTrue(isinstance(results, dict))
            self.assertEqual(results.get(DEVICE_ID_KEY), DEFAULT_ONU_DEVICE_ID)

            self.assertIsNotNone(results.get(VERSION_KEY))
            self.assertIsNotNone(results.get(CREATED_KEY))
            self.assertIsNone(results.get(MODIFIED_KEY))        # Created! but not yet modified

            self.assertEqual(results.get(MDS_KEY), 0)
            self.assertIsNone(results.get(LAST_SYNC_KEY))

            self.assertIsNone(results.get(CLASS_ID_KEY))

            # Stopping still allows a query.  Note you just delete a device
            # to clean up any associated databases
            onu_device.stop()
            results = onu_device.query_mib()
            self.assertTrue(isinstance(results, dict))

        # Yield context so that MIB Database callLater runs. This is a waiting
        # Async task from when the OpenOMCIAgent was started. But also start the
        # device so that it's queued async state machines can run as well
        onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(check_status, not_called)

        return d

    @deferred(timeout=5)
    def test_delete_scrubs_mib(self):
        self.setup_one_of_each()

        onu_device = self.agent.add_device(DEFAULT_ONU_DEVICE_ID,
                                           self.adapter_agent)
        self.assertIsNotNone(onu_device)
        self.assertEqual(len(self.agent.device_ids()), 1)
        self.assertEqual(self.agent.get_device(DEFAULT_ONU_DEVICE_ID), onu_device)

        def not_called(_reason):
            onu_device.stop()
            assert False, 'Should never be called'

        def check_status(_results):
            # Device started. Query will succeed but nothing should be populated
            # but the most basic items

            results = onu_device.query_mib()
            self.assertTrue(isinstance(results, dict))
            self.assertEqual(results.get(DEVICE_ID_KEY), DEFAULT_ONU_DEVICE_ID)

            # Delete should wipe out any MIB data. Note that a delete of a started
            # or stopped ONU device is allowed.  In this case we are deleting a
            # started ONU Device

            onu_device.delete()
            assert_raises(Exception, onu_device.query_mib)
            # TODO: When capabilities are supported, make sure capabilities get cleared as well

        # Yield context so that MIB Database callLater runs. This is a waiting
        # Async task from when the OpenOMCIAgent was started. But also start the
        # device so that it's queued async state machines can run as well
        onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(check_status, not_called)

        return d

    # TODO: Test pub/sub interface if possible
    # TODO: Test custom/vendor-specific ME support
    # TODO: Test override of various state machines or OMCI tasks if possible


if __name__ == '__main__':
    main()

