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
from collections import OrderedDict
from copy import copy
import resource
from random import randint, seed
from time import time
from unittest import main, TestCase

import gc

from google.protobuf.json_format import MessageToDict
from mock import Mock
from simplejson import dumps

from common.event_bus import EventBusClient
from voltha.core.config.config_proxy import CallbackType
from voltha.core.config.config_rev import _rev_cache
from voltha.core.config.config_root import ConfigRoot, MergeConflictException
from voltha.core.config.config_txn import ClosedTransactionError
from voltha.protos import third_party
from voltha.protos.events_pb2 import ConfigEvent, ConfigEventType
from voltha.protos.openflow_13_pb2 import ofp_port
from voltha.protos.voltha_pb2 import VolthaInstance, Adapter, HealthStatus, \
    AdapterConfig, LogicalDevice, LogicalPort


def memusage():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def rev_count():
    return len(_rev_cache)


def probe():
    return time(), memusage() / 1024. / 1024, rev_count()


def print_metrics():
    print '%20f %20f %8d' % probe()


class TestConfigNodeShallow(TestCase):

    def setUp(self):
        self.empty = VolthaInstance()
        self.other = VolthaInstance(instance_id='other')
        self.node = ConfigRoot(VolthaInstance())

    def test_init(self):
        pass

    def test_immutability(self):
        self.assertEqual(self.node.latest.data, self.empty)
        self.empty.instance_id = 'overwritten id'
        self.assertEqual(self.node.latest.data, VolthaInstance())

    def test_retrieve_latest(self):
        self.assertEqual(self.node.latest.data, self.empty)
        hash = self.node.latest.hash
        self.assertEqual(self.node.revisions, [hash])

    def test_update_with_bad_data(self):
        self.assertRaises(ValueError, self.node.update, '/', Adapter())


class DeepTestsBase(TestCase):
    """Shared test class for test using a simple node tree"""

    def setUp(self):
        gc.collect()
        _rev_cache.clear()
        self.health = HealthStatus(state=HealthStatus.DYING)
        self.base_shallow = VolthaInstance(instance_id='1')
        self.base_deep = copy(self.base_shallow)
        self.base_deep.health.state = HealthStatus.DYING  # = self.health
        for i in xrange(5):
            self.base_deep.adapters.add().MergeFrom(Adapter(
                id=str(i),
                config=AdapterConfig(
                    log_level=3
                )
            ))
        self.node = ConfigRoot(self.base_deep)
        self.hash_orig = self.node.latest.hash

    def tearDown(self):
        del self.node


class TestConfigNodeDeep(DeepTestsBase):

    def test_init(self):
        pass

    def test_reject_duplicate_keys(self):
        data = VolthaInstance(
            instance_id='42', adapters=[Adapter(id='same') for _ in xrange(5)])
        self.assertRaises(ValueError, ConfigRoot, data)

    def test_shallow_get(self):
        self.assertEqual(self.node.latest.data, self.base_shallow)
        self.assertEqual(self.node.get(), self.base_shallow)
        self.assertEqual(self.node.get(hash=self.hash_orig), self.base_shallow)

    def test_deep_get(self):
        self.assertEqual(self.node.get(deep=True), self.base_deep)

    def test_path_based_get_access(self):
        self.assertEqual(self.node.get(path='/'), self.node.get())
        self.assertEqual(self.node.get(path='/health'), self.health)

    def test_path_list_retrieval(self):
        adapters = self.node.get(path='/adapters')
        self.assertEqual(len(adapters), 5)
        self.assertEqual(adapters[2].id, '2')

    def test_indexing_into_containers(self):
        adapter = self.node.get(path='/adapters/3')
        self.assertEqual(adapter.id, '3')

    def test_update_handle_invalid_paths(self):
        self.assertRaises(KeyError, self.node.update, 'foo', None)
        self.assertRaises(KeyError, self.node.update, '/foo', None)
        self.assertRaises(KeyError, self.node.update, '/health/foo', None)
        self.assertRaises(ValueError, self.node.update, '/adapters', None)
        self.assertRaises(KeyError, self.node.update, '/adapters/foo', None)
        self.assertRaises(KeyError, self.node.update, '/adapters/1/foo', None)

    def test_update_handle_invalid_type(self):
        self.assertRaises(ValueError, self.node.update, '/', Adapter())
        self.assertRaises(ValueError, self.node.update, '/health', Adapter())
        self.assertRaises(ValueError, self.node.update, '/adapters/1', VolthaInstance())

    def test_update_handle_key_change_attempt(self):
        self.assertRaises(
            ValueError, self.node.update, '/adapters/1', Adapter(id='changed'))


    def test_add_handle_invalid_cases(self):
        # invalid paths
        self.assertRaises(KeyError, self.node.add, 'foo', None)
        self.assertRaises(KeyError, self.node.add, '/foo', None)
        self.assertRaises(KeyError, self.node.add, '/adapters/foo', None)

        # cannot add to non-container nodes
        self.assertRaises(ValueError, self.node.add, '/health', None)
        self.assertRaises(ValueError, self.node.add, '/adapters/1', None)

        # cannot add to container data with duplicate key
        self.assertRaises(
            ValueError, self.node.add, '/adapters', Adapter(id='1'))


    def test_remove_handle_invalid_cases(self):
        # invalid paths
        self.assertRaises(KeyError, self.node.remove, 'foo')
        self.assertRaises(KeyError, self.node.remove, '/foo')
        self.assertRaises(KeyError, self.node.remove, '/adapters/foo')
        self.assertRaises(KeyError, self.node.remove, '/adapters/1/id')

        # cannot add to non-container nodes
        self.assertRaises(ValueError, self.node.remove, '/health')


class TestPruningPerformance(DeepTestsBase):



    def test_strict_read_only(self):
        # it shall not be possible to change a read-only field
        self.assertRaises(ValueError, self.node.update,
                          '/', VolthaInstance(version='foo'), strict=True)
        self.assertRaises(ValueError, self.node.update,
                          '/adapters/1', Adapter(version='foo'), strict=True)


class TestNodeOwnershipAndHooks(DeepTestsBase):

    def test_init(self):
        pass

    def test_passive_ownership(self):

        # grab a proxy for a given node
        proxy = self.node.get_proxy('/health')

        # able to read the value directly using this proxy
        self.assertEqual(proxy.get(), HealthStatus(state=HealthStatus.DYING))

        # able to update value directly using this proxy, but the whole tree
        # updates
        proxy.update('/', HealthStatus(state=HealthStatus.HEALTHY))
        self.assertEqual(proxy.get().state, HealthStatus.HEALTHY)
        self.assertNotEqual(self.node.latest.hash, self.hash_orig)

        # access constraints are still enforced
        self.assertRaises(
            ValueError, proxy.update,
            '/', HealthStatus(state=HealthStatus.OVERLOADED), strict=1)

    def test_exclusivity(self):
        proxy = self.node.get_proxy('/adapters/1', exclusive=True)
        self.assertRaises(ValueError, self.node.get_proxy, '/adapters/1')

    def test_get_hook(self):

        proxy = self.node.get_proxy('/health')

        # getting health without callback just returns what's stored in node
        self.assertEqual(proxy.get().state, HealthStatus.DYING)

        # register callback
        def get_health_callback(msg):
            msg.state = HealthStatus.OVERLOADED
            return msg

        proxy.register_callback(CallbackType.GET, get_health_callback)

        # once registered, callback can touch up object
        self.assertEqual(proxy.get().state, HealthStatus.OVERLOADED)

    def test_pre_update_hook(self):

        proxy = self.node.get_proxy('/adapters/1')

        # before hook, change is allowed
        adapter = proxy.get()
        adapter.version = 'foo'
        proxy.update('/', adapter)

        # and for sanity, check if update made it through
        self.assertEqual(self.node.get('/adapters/1').version, 'foo')

        # regsiter hook that rejects all changes
        def bully(msg):
            raise RuntimeError('bully')
        proxy.register_callback(CallbackType.PRE_UPDATE, bully)

        # test that rejection applies
        adapter.version = 'bar'
        self.assertRaises(RuntimeError, proxy.update, '/', adapter)
        self.assertRaises(RuntimeError, self.node.update, '/adapters/1', adapter)

    def test_post_update_hook(self):
        proxy = self.node.get_proxy('/adapters/1')
        callback = Mock()
        proxy.register_callback(CallbackType.POST_UPDATE, callback,
                                'zizi', 42, x=1, y='baz')
        data = Adapter(id='1', version='zoo')
        proxy.update('/', data)
        callback.assert_called_once_with(data, 'zizi', 42, x=1, y='baz')

    def test_pre_and_post_add_hooks(self):
        proxy = self.node.get_proxy('/')
        pre_callback = Mock()
        post_callback = Mock()
        proxy.register_callback(CallbackType.PRE_ADD, pre_callback)
        proxy.register_callback(CallbackType.POST_ADD, post_callback)
        new_adapter = Adapter(id='99', version='12.2', vendor='ace')
        proxy.add('/adapters', new_adapter)
        pre_callback.assert_called_with(new_adapter)
        post_callback.assert_called_with(new_adapter)

    def test_pre_and_post_remove_hooks(self):
        proxy = self.node.get_proxy('/')
        pre_callback = Mock()
        post_callback = Mock()
        proxy.register_callback(CallbackType.PRE_REMOVE, pre_callback)
        proxy.register_callback(CallbackType.POST_REMOVE, post_callback)
        adapter = proxy.get('/adapters/1')  # so that we can verify callback
        proxy.remove('/adapters/1')
        pre_callback.assert_called_with(adapter)
        post_callback.assert_called_with(adapter)

class TestEventLogic(DeepTestsBase):

    def setUp(self):
        super(TestEventLogic, self).setUp()
        self.ebc = EventBusClient()
        self.event_mock = Mock()
        self.ebc.subscribe('model-change-events', self.event_mock)

    def test_add_event(self):

        data = Adapter(id='10', version='zoo')
        self.node.add('/adapters', data)
        event = ConfigEvent(
            type=ConfigEventType.add,
            hash=self.node.latest.hash,
            data=dumps(MessageToDict(data, True, True))
        )

        self.event_mock.assert_called_once_with('model-change-events', event)

    def test_remove_event(self):
        data = Adapter(
            id='1',
            config=AdapterConfig(
                log_level=3
            )
        )
        self.node.remove('/adapters/1')
        event = ConfigEvent(
            type=ConfigEventType.remove,
            hash=self.node.latest.hash,
            data=dumps(MessageToDict(data, True, True))
        )

        self.event_mock.assert_called_once_with('model-change-events', event)

class TestTransactionalLogic(DeepTestsBase):

    def make_change(self, tx, path, attr_name, new_value):
        data = o = tx.get(path)
        rest = attr_name
        while 1:
            subfield, _, rest = rest.partition('.')
            if rest:
                o = getattr(o, subfield)
                attr_name = rest
            else:
                setattr(o, attr_name, new_value)
                break
        tx.update(path, data)

    def check_no_tx_branches(self):
        visited = set()

        def check_node(n):
            if n not in visited:
                self.assertEqual(n._branches.keys(), [None])
                for rev in n._branches[None]._revs.itervalues():
                    for children in rev._children.itervalues():
                        if isinstance(children, OrderedDict):
                            children = children.itervalues()
                        for child_rev in children:
                            child_node = child_rev.node
                            check_node(child_node)
                visited.add(n)

        check_node(self.node)

    def log_levels(self):
        return OrderedDict(
            (a.id, a.config.log_level)
            for a in self.node.get('/adapters', deep=1))

    def tearDown(self):
        self.check_no_tx_branches()
        super(TestTransactionalLogic, self).tearDown()

    def test_transaction_isolation(self):
        """
        Test that changes made in a transaction mode are not visible to others
        """
        proxy = self.node.get_proxy('/')

        # look under the hood to verify that branches are added
        # recursively
        _latest_root_rev = self.node._branches[None].latest
        adapter_node = _latest_root_rev._children['adapters'][2].node
        self.assertEqual(len(self.node._branches.keys()), 1)
        self.assertEqual(len(adapter_node._branches.keys()), 1)

        tx = proxy.open_transaction()
        self.assertEqual(len(self.node._branches.keys()), 2)
        self.assertEqual(len(adapter_node._branches.keys()), 1)

        path = '/adapters/2'
        self.make_change(tx, path, 'config.log_level', 0)
        self.assertEqual(len(self.node._branches.keys()), 2)
        self.assertEqual(len(adapter_node._branches.keys()), 2)

        # verify that reading from the transaction exposes the change
        self.assertEqual(tx.get(path).config.log_level, 0)

        # but that reading from the proxy or directly from tree does not
        self.assertEqual(self.node.latest.hash, self.hash_orig)
        self.assertEqual(proxy.get(path).config.log_level, 3)
        self.assertEqual(self.node.get(path).config.log_level, 3)

        tx.cancel()

    def test_cannot_reuse_tx(self):
        proxy = self.node.get_proxy('/')
        tx = proxy.open_transaction()
        tx.cancel()
        self.assertRaises(ClosedTransactionError, tx.get, '/')
        self.assertRaises(ClosedTransactionError, tx.add, '/', None)
        self.assertRaises(ClosedTransactionError, tx.remove, '/')

    def test_multiple_concurrent_transactions(self):
        """
        Test that two transactions can make independent changes, without
        affecting each other, until committed.
        """
        proxy1 = self.node.get_proxy('/')
        proxy2 = self.node.get_proxy('/')

        tx1 = proxy1.open_transaction()
        tx2 = proxy1.open_transaction()
        tx3 = proxy2.open_transaction()

        path = '/adapters/2'
        self.make_change(tx1, path, 'config.log_level', 0)

        # the other transaction does not see the change
        self.assertEqual(tx2.get(path).config.log_level, 3)
        self.assertEqual(tx3.get(path).config.log_level, 3)
        self.assertEqual(proxy1.get(path).config.log_level, 3)
        self.assertEqual(proxy2.get(path).config.log_level, 3)

        # we can attempt to make change in other txs
        self.make_change(tx2, path, 'config.log_level', 1)
        self.make_change(tx3, path, 'config.log_level', 2)

        # each can see its own tree, but no one else can see theirs
        self.assertEqual(tx1.get(path).config.log_level, 0)
        self.assertEqual(tx2.get(path).config.log_level, 1)
        self.assertEqual(tx3.get(path).config.log_level, 2)
        self.assertEqual(proxy1.get(path).config.log_level, 3)
        self.assertEqual(proxy2.get(path).config.log_level, 3)
        self.assertEqual(self.node.latest.hash, self.hash_orig)

        tx1.cancel()
        tx2.cancel()
        tx3.cancel()

    def test_transaction_canceling(self):
        """After abort, transaction is no longer stored"""

        proxy = self.node.get_proxy('/')

        # look under the hood to verify that branches are added
        # recursively
        _latest_root_rev = self.node._branches[None].latest
        adapter_node = _latest_root_rev._children['adapters'][2].node
        self.assertEqual(len(self.node._branches.keys()), 1)
        self.assertEqual(len(adapter_node._branches.keys()), 1)

        tx = proxy.open_transaction()
        self.assertEqual(len(self.node._branches.keys()), 2)
        self.assertEqual(len(adapter_node._branches.keys()), 1)

        self.make_change(tx, '/adapters/2', 'config.log_level', 4)

        self.assertEqual(len(self.node._branches.keys()), 2)
        self.assertEqual(len(adapter_node._branches.keys()), 2)

        del tx

        self.assertEqual(len(self.node._branches.keys()), 1)
        self.assertEqual(len(adapter_node._branches.keys()), 1)

    def test_transaction_explitic_canceling(self):
        """After abort, transaction is no longer stored"""

        proxy = self.node.get_proxy('/')

        # look under the hood to verify that branches are added
        # recursively
        _latest_root_rev = self.node._branches[None].latest
        adapter_node = _latest_root_rev._children['adapters'][2].node
        self.assertEqual(len(self.node._branches.keys()), 1)
        self.assertEqual(len(adapter_node._branches.keys()), 1)

        tx = proxy.open_transaction()
        self.assertEqual(len(self.node._branches.keys()), 2)
        self.assertEqual(len(adapter_node._branches.keys()), 1)

        self.make_change(tx, '/adapters/2', 'config.log_level', 4)

        self.assertEqual(len(self.node._branches.keys()), 2)
        self.assertEqual(len(adapter_node._branches.keys()), 2)

        tx.cancel()

        self.assertEqual(len(self.node._branches.keys()), 1)
        self.assertEqual(len(adapter_node._branches.keys()), 1)



    def make_complex_changes(self):

        # Plan:
        # Have two root proxies and two proxies on specific adapters
        # Make several transactions, including conflicting ones
        # Check as much as possible in terms of expected operations

        proxy1 = self.node.get_proxy('/')
        proxy2 = self.node.get_proxy('/')
        proxy3 = self.node.get_proxy('/adapters/0')
        proxy4 = self.node.get_proxy('/adapters/1')

        tx1 = proxy1.open_transaction()
        tx2 = proxy1.open_transaction()
        tx3 = proxy2.open_transaction()
        tx4 = proxy3.open_transaction()
        tx5 = proxy4.open_transaction()

        # Make multiple changes via tx1
        self.make_change(tx1, '/adapters/0', 'config.log_level', 1)
        tx1.add('/adapters', Adapter(id='new1'))
        tx1.remove('/adapters/2')

        # Make a non-conflicting change from tx2
        self.make_change(tx2, '/adapters/3', 'config.log_level', 0)

        # Make some conflicting changes via tx3 now
        self.make_change(tx3, '/adapters/1', 'config.log_level', 1)

        # Make some changes via leaf proxies
        my_adapter = tx4.get('/')
        my_adapter.version = 'zulu'
        my_adapter.config.log_level = 0
        tx4.update('/', my_adapter)

        # Make some changes via leaf proxies
        my_adapter = tx5.get('/')
        my_adapter.version = 'brand new'
        my_adapter.config.log_level = 4
        tx5.update('/', my_adapter)

        # Make some more changes on tx2
        tx2.add('/adapters', Adapter(id='new2'))

        # Conflicts:
        # - tx4 conflicts with tx0
        # - tx5 conflicts with tx3
        return tx1, tx2, tx3, tx4, tx5



    def test_canceling_adds(self):
        proxy = self.node.get_proxy('/')
        tx = proxy.open_transaction()
        tx.add('/adapters', Adapter(id='new'))
        tx.add('/adapters', Adapter(id='new2'))
        tx.cancel()
        self.assertEqual(self.log_levels().keys(), ['0', '1', '2', '3', '4'])


    # TODO need more tests to hammer out potential issues with transactions \
        # on nested nodes


if __name__ == '__main__':
    main()
