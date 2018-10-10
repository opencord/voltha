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
from copy import deepcopy
from mock.mock_adapter_agent import MockAdapterAgent, MockCore
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent, OpenOmciAgentDefaults
from voltha.extensions.omci.database.mib_db_ext import MibDbExternal
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict
from voltha.extensions.omci.state_machines.mib_sync import MibSynchronizer
from voltha.extensions.omci.tasks.mib_upload import MibUploadTask
from voltha.extensions.omci.tasks.get_mds_task import GetMdsTask
from voltha.extensions.omci.tasks.mib_resync_task import MibResyncTask
from voltha.extensions.omci.tasks.mib_reconcile_task import MibReconcileTask


class TestOpenOmciAgent(TestCase):
    """
    Test the Open OMCI Agent
    """
    def setUp(self):
        self.adapter_agent = MockAdapterAgent()

    def tearDown(self):
        if self.adapter_agent is not None:
            self.adapter_agent.tearDown()

    def test_omci_agent_defaults(self):
        # Make sure someone does not check in bad default values

        mib_sync = OpenOmciAgentDefaults.get('mib-synchronizer')

        self.assertIsNotNone(mib_sync)
        self.assertTrue(isinstance(mib_sync['state-machine'], type(MibSynchronizer)))
        self.assertTrue(isinstance(mib_sync['database'], type(MibDbExternal)))

        mib_sync_tasks = mib_sync.get('tasks')

        self.assertIsNotNone(mib_sync_tasks)
        self.assertTrue(isinstance(mib_sync_tasks['mib-upload'], type(MibUploadTask)))
        self.assertTrue(isinstance(mib_sync_tasks['get-mds'], type(GetMdsTask)))
        self.assertTrue(isinstance(mib_sync_tasks['mib-audit'], type(GetMdsTask)))
        self.assertTrue(isinstance(mib_sync_tasks['mib-resync'], type(MibResyncTask)))
        self.assertTrue(isinstance(mib_sync_tasks['mib-reconcile'], type(MibReconcileTask)))

        # caps = OpenOmciAgentDefaults.get('onu-capabilities')
        #
        # self.assertIsNotNone(caps)

    def test_omci_agent_default_init(self):
        agent = OpenOMCIAgent(MockCore)

        self.assertTrue(isinstance(agent.core, type(MockCore)))
        self.assertTrue(isinstance(agent.database_class, type(MibDbExternal)))
        self.assertEqual(len(agent.device_ids()), 0)
        assert_raises(KeyError, agent.get_device, 'deadbeef')

    def test_omci_agent_custom_mib_database(self):
        custom = deepcopy(OpenOmciAgentDefaults)
        custom['mib-synchronizer']['database'] = MibDbVolatileDict
        agent = OpenOMCIAgent(MockCore, support_classes=custom)

        self.assertTrue(isinstance(agent.core, type(MockCore)))
        self.assertTrue(isinstance(agent.database_class, type(MibDbVolatileDict)))

    def test_omci_agent_start_stop(self):
        agent = OpenOMCIAgent(MockCore)

        agent.start()
        agent.start()       # Should be a NOP, no side effects

        agent.stop()
        agent.stop()        # Should be a NOP, no side effects


if __name__ == '__main__':
    main()

