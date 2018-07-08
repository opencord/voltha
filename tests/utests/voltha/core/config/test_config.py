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

    def test_update(self):
        hash0 = self.node.latest.hash
        self.node.update('/', copy(self.other))
        hash1 = self.node.latest.hash
        self.assertEqual(len(self.node.revisions), 2)
        self.assertNotEqual(hash0, hash1)
        self.assertEqual(self.node.latest.data, VolthaInstance(instance_id='other'))

    def test_update_with_bad_data(self):
        self.assertRaises(ValueError, self.node.update, '/', Adapter())

    def test_many_simple_updates(self):
        n = 1000
        for i in xrange(n):
            self.node.update('/', VolthaInstance(instance_id='id%d' % i))
        self.node.update('/', self.other)
        self.assertEqual(len(self.node.revisions), 1002)
        self.assertEqual(self.node.latest.data, self.other)

    def test_retrieve_by_rev_hash(self):
        n = 1000
        for i in xrange(n):
            self.node.update('/', VolthaInstance(instance_id='id%d' % i))
        self.node.update('/', self.other)
        hashes = self.node.revisions
        self.assertEqual(self.node[hashes[0]].data, self.empty)
        self.assertEqual(self.node[hashes[10]].data, VolthaInstance(instance_id='id9'))
        self.assertEqual(self.node[hashes[-1]].data, self.other)

    def test_diffs(self):
        self.node.update('/', self.other)
        self.assertEqual(self.node.diff(self.node.latest.hash).patch, [])
        hashes = self.node.revisions
        self.assertEqual(self.node.diff(hashes[0]).patch, [
            dict(op='replace', path='/instance_id', value='other')
        ])
        self.assertEqual(self.node.diff(hashes[0], hashes[1]).patch, [
            dict(op='replace', path='/instance_id', value='other')
        ])
        self.assertEqual(self.node.diff(hashes[1], hashes[0]).patch, [
            dict(op='replace', path='/instance_id', value='')
        ])
        self.assertEqual(self.node.diff(hashes[1], hashes[1]).patch, [])

    def test_tagging(self):
        self.node.tag('original')
        hash1 = self.node.latest.hash

        # add a bunch of changes
        for a in xrange(10):
            self.node.update('/', VolthaInstance(instance_id=str(a)))
        hash2 = self.node.latest.hash

        # apply tag to latest
        self.node.tag('latest')

        # apply another tag to latest
        self.node.tag('other')

        # apply tag to specific rev hash
        self.node.tag('yetmore', hash2)

        # invalid hash
        self.assertRaises(KeyError, self.node.tag, 'sometag', 'badhash')

        # retrieve data based on tag
        self.assertEqual(self.node.by_tag('original').hash, hash1)
        self.assertEqual(self.node.by_tag('latest').hash, hash2)
        self.assertEqual(self.node.by_tag('other').hash, hash2)
        self.assertEqual(self.node.by_tag('yetmore').hash, hash2)

        # generate diff from tags
        self.assertEqual(self.node.diff_by_tag('original', 'latest').patch, [
            dict(op='replace', path='/instance_id', value='9')
        ])

        # move tags to given revision
        self.node.tag('original', self.node.revisions[2])
        self.node.tag('latest', self.node.revisions[9])

        # add another tag
        self.node.tag('another', self.node.revisions[7])

        # list tags
        self.assertEqual(self.node.tags,
                         ['another', 'latest', 'original', 'other', 'yetmore'])

        # delete a tag
        self.node.delete_tag('another')
        self.node.delete_tags('yetmore', 'other')
        self.assertEqual(self.node.tags, ['latest', 'original'])

        # prune untagged revisions from revision list
        self.node.prune_untagged()
        self.assertEqual(len(self.node.revisions), 3) # latest is always kept

        # retrieve and compare working tagged revs
        self.assertEqual(self.node.diff_by_tag('original', 'latest').patch, [
            dict(op='replace', path='/instance_id', value='8')
        ])


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

    def test_top_level_update(self):
        # test that top-level update retains children
        self.node.update('/', VolthaInstance(version='1.2.3'))
        hash_new = self.node.latest.hash
        self.assertNotEqual(self.hash_orig, hash_new)
        self.assertEqual(self.node.get(
            hash=self.hash_orig, deep=1), self.base_deep)
        latest = self.node.get(deep=1)
        self.assertNotEqual(latest, self.base_deep)
        self.assertEqual(len(latest.adapters), 5)
        self.assertEqual(len(latest.logical_devices), 0)
        self.assertEqual(latest.version, '1.2.3')

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

    def test_deep_update_non_container(self):

        self.node.update('/health', HealthStatus(state=HealthStatus.HEALTHY))

        # root hash is now different
        hash_new = self.node.latest.hash
        self.assertNotEqual(self.hash_orig, hash_new)

        # original tree is still intact
        orig = self.node.get(hash=self.hash_orig, deep=1)
        self.assertEqual(orig, self.base_deep)
        self.assertEqual(orig.health.state, HealthStatus.DYING)

        # but the latest contains the change
        new = self.node.get(deep=1)
        self.assertNotEqual(new, orig)
        self.assertEqual(new.health.state, HealthStatus.HEALTHY)

    def test_deep_update_container(self):

        self.node.update('/adapters/0', Adapter(id='0', version='new'))

        # root hash is now different
        hash_new = self.node.latest.hash
        self.assertNotEqual(self.hash_orig, hash_new)

        # original tree is still intact
        orig = self.node.get(hash=self.hash_orig, deep=1)
        self.assertEqual(orig, self.base_deep)
        self.assertEqual(orig.adapters[0].id, '0')

        # but the new tree contains the change
        new = self.node.get(deep=1)
        self.assertNotEqual(new, orig)
        self.assertEqual(new.adapters[0].version, 'new')

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

    def test_add_node(self):
        new = Adapter(id='new')
        self.node.add('/adapters', new)
        self.assertNotEqual(self.node.latest.hash, self.hash_orig)
        self.assertEqual(len(self.node.get('/adapters')), 6)
        self.assertEqual(
            len(self.node.get('/adapters', hash=self.hash_orig)), 5)
        self.assertEqual(self.node.get('/adapters/new'), new)

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

    def test_remove_node(self):
        self.node.remove('/adapters/3')
        self.assertNotEqual(self.node.latest.hash, self.hash_orig)
        self.assertEqual(len(self.node.get('/adapters')), 4)
        self.assertEqual(
            len(self.node.get('/adapters', hash=self.hash_orig)), 5)
        self.assertRaises(KeyError, self.node.get, '/adapters/3')

    def test_remove_handle_invalid_cases(self):
        # invalid paths
        self.assertRaises(KeyError, self.node.remove, 'foo')
        self.assertRaises(KeyError, self.node.remove, '/foo')
        self.assertRaises(KeyError, self.node.remove, '/adapters/foo')
        self.assertRaises(KeyError, self.node.remove, '/adapters/1/id')

        # cannot add to non-container nodes
        self.assertRaises(ValueError, self.node.remove, '/health')

    def test_pruning_after_shallow_change(self):

        self.node.update('/', VolthaInstance(version='10.1'))

        # sanity check
        self.assertEqual(len(self.node.revisions), 2)

        # prune
        self.node.prune_untagged()

        self.assertEqual(len(self.node.revisions), 1)

        # we can nevertheless access the whole tree
        new = self.node.get('/', deep=1)
        self.assertEqual(new.adapters, self.base_deep.adapters)
        self.assertEqual(new.version, '10.1')

    def test_pruning_after_deep_change(self):

        self.node.update('/adapters/3', Adapter(id='3', version='changed'))

        # sanity check
        self.assertEqual(len(self.node.revisions), 2)

        # prune
        self.node.prune_untagged()

        self.assertEqual(len(self.node.revisions), 1)

        # we can nevertheless access the whole tree
        new = self.node.get('/', deep=1)
        self.assertEqual(len(new.adapters), 5)
        self.assertEqual(new.adapters[2], self.base_deep.adapters[2])
        self.assertEqual(new.adapters[3].version, 'changed')


class TestPruningPerformance(DeepTestsBase):

    def test_repeated_prunning_keeps_memory_stable(self):
        # The auto-pruning feature of the config system is that leaf nodes
        # in the config tree that are no longer in use are pruned from memory,
        # once they revision is removed from root using the .prune_untagged()
        # method. This test is to verify that.

        n = 1000

        seed(0)  # makes things consistently random

        # this should be the number of nodes in the VolthaInstance tree
        self.assertLess(rev_count(), 20)
        print; print_metrics()

        def mk_change():
            key = str(randint(0, 4))
            path = '/adapters/' + key
            adapter = self.node.get(path)
            adapter.version = 'v{}'.format(randint(0, 100000))
            self.node.update(path, adapter)

        # first we perform many changes without pruning
        for i in xrange(n):
            mk_change()

        # at this point we shall have more than 2*n revs laying around
        self.assertGreater(rev_count(), 2 * n)
        print_metrics()

        # prune now
        self.node.prune_untagged()

        # at this point the rev count shall fall back to the original
        self.assertLess(rev_count(), 15)
        print_metrics()

        # no make an additional set of modifications while constantly pruning
        for i in xrange(n):
            mk_change()
            self.node.prune_untagged()

        # the rev count should not have increased
        self.assertLess(rev_count(), 15)
        print_metrics()

    def test_churn_efficiency(self):
        # Two config revisions that hash to the same hash value also share the
        # same in-memory object. So if the same config node goes through churn
        # (like flip-flopping fields), we don't eat up memory unnecessarily.
        # This test is to verify that behavior.

        n = 1000
        modulo = 2

        self.assertEqual(rev_count(), 14)
        print_metrics()

        def mk_change(seq):
            # make change module of the sequence number so we periodically
            # return to the same config
            path = '/adapters/3'
            adapter = self.node.get(path)
            adapter.version = 'v{}'.format(seq % modulo)
            self.node.update(path, adapter)

        # make n changes back and forth
        for i in xrange(n):
            _tmp_rc = rev_count()
            mk_change(i)

        _tmp_rc = rev_count()
        # verify that the node count did not increase significantly, yet we
        # have access to all ditinct revisions
        self.assertEqual(rev_count(), 20)
        print_metrics()

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

    def test_transaction_commit(self):
        """Once committed, changes become latest"""

        proxy = self.node.get_proxy('/')
        _latest_root_rev = self.node._branches[None].latest
        adapter_node = _latest_root_rev._children['adapters'][2].node
        tx = proxy.open_transaction()

        # publicly visible value before change
        path = '/adapters/2'
        self.assertEqual(proxy.get(path).config.log_level, 3)
        self.assertEqual(self.node.get(path).config.log_level, 3)

        # make the change, but not commit yet
        self.make_change(tx, path, 'config.log_level', 4)
        self.assertEqual(proxy.get(path).config.log_level, 3)
        self.assertEqual(self.node.get(path).config.log_level, 3)

        # commit the change
        tx.commit()
        self.assertNotEqual(self.node.latest.hash, self.hash_orig)
        self.assertEqual(proxy.get('/adapters/2').config.log_level, 4)
        self.assertEqual(len(self.node._branches.keys()), 1)
        self.assertEqual(len(adapter_node._branches.keys()), 1)
        self.assertEqual(proxy.get(path).config.log_level, 4)
        self.assertEqual(self.node.get(path).config.log_level, 4)

    def test_collision_detection(self):
        """Correctly detect transaction collision and abort the 2nd tx"""

        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        path = '/adapters/2'
        self.make_change(tx1, path, 'config.log_level', 0)

        # make another tx before tx1 is committed
        tx2 = proxy.open_transaction()
        print tx2._txid
        self.make_change(tx2, path, 'config.log_level', 4)

        # commit first
        print tx1._txid
        tx1.commit()

        # committing 2nd one should fail
        self.assertRaises(MergeConflictException, tx2.commit)
        self.check_no_tx_branches()

    def test_nonconfliciting_changes(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        self.make_change(tx1, '/adapters/1', 'config.log_level', 1)
        self.make_change(tx2, '/adapters/2', 'config.log_level', 2)
        tx1.commit()
        tx2.commit()
        self.assertEqual(self.log_levels(), {
            '0': 3, '1': 1, '2': 2, '3': 3, '4': 3
        })

    def test_additive_changes(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx1.add('/adapters', Adapter(id='new'))
        tx1.add('/adapters', Adapter(id='new2'))
        self.assertEqual(len(proxy.get('/adapters')), 5)
        self.assertEqual(len(self.node.get('/adapters')), 5)
        self.assertEqual(len(tx1.get('/adapters')), 7)
        tx1.commit()
        self.assertEqual(len(proxy.get('/adapters')), 7)
        self.assertEqual(len(self.node.get('/adapters')), 7)
        self.assertEqual(self.log_levels().keys(),
                         ['0', '1', '2', '3', '4', 'new', 'new2'])

    def test_remove_changes(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx1.remove('/adapters/2')
        tx1.remove('/adapters/4')
        self.assertEqual(len(proxy.get('/adapters')), 5)
        self.assertEqual(len(self.node.get('/adapters')), 5)
        self.assertEqual(len(tx1.get('/adapters')), 3)
        tx1.commit()
        self.assertEqual(len(proxy.get('/adapters')), 3)
        self.assertEqual(len(self.node.get('/adapters')), 3)
        self.assertEqual(self.log_levels().keys(), ['0', '1', '3'])

    def test_mixed_add_remove_update_changes(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        self.make_change(tx1, '/adapters/2', 'config.log_level', 2)
        tx1.remove('/adapters/0')
        tx1.add('/adapters', Adapter(id='new'))
        tx1.remove('/adapters/4')
        tx1.add('/adapters', Adapter(id='new2'))
        tx1.add('/adapters', Adapter(id='new3'))
        self.assertEqual(len(proxy.get('/adapters')), 5)
        self.assertEqual(len(self.node.get('/adapters')), 5)
        self.assertEqual(len(tx1.get('/adapters')), 6)
        tx1.commit()
        self.assertEqual(len(proxy.get('/adapters')), 6)
        self.assertEqual(len(self.node.get('/adapters')), 6)
        self.assertEqual(self.log_levels(), {
            '1': 3, '2': 2, '3': 3, 'new': 0, 'new2': 0, 'new3': 0
        })

    def test_compatible_updates(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        tx4 = proxy.open_transaction()
        tx5 = proxy.open_transaction()
        tx1.update('/health', HealthStatus(state=HealthStatus.OVERLOADED))
        self.make_change(tx2, '/adapters/1', 'version', '42')
        self.make_change(tx3, '/adapters/2', 'config.log_level', 2)
        self.make_change(tx4, '/adapters/1', 'version', '42')
        self.make_change(tx5, '/adapters/1', 'version', '422')
        tx1.commit()
        tx2.commit()
        tx3.commit()
        tx4.commit()
        self.assertRaises(MergeConflictException, tx5.commit)

        # verify outcome
        self.assertEqual(self.node.get('/health').state, 1)
        self.assertEqual(self.node.get('/', deep=1).adapters[1].version, '42')
        self.assertEqual(self.log_levels(), {
            '0': 3, '1': 3, '2': 2, '3': 3, '4': 3
        })

    def test_conflciting_updates(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        tx1.update('/health', HealthStatus(state=HealthStatus.OVERLOADED))
        self.make_change(tx2, '/adapters/1', 'version', '42')
        self.make_change(tx3, '/adapters/1', 'config.log_level', 2)
        tx1.commit()
        tx2.commit()
        self.assertRaises(MergeConflictException, tx3.commit)

        # verify outcome
        self.assertEqual(self.node.get('/health').state, 1)
        self.assertEqual(self.node.get('/', deep=1).adapters[1].version, '42')
        self.assertEqual(self.log_levels(), {
            '0': 3, '1': 3, '2': 3, '3': 3, '4': 3
        })

    def test_compatible_adds(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        tx1.add('/adapters', Adapter(id='new1'))
        tx2.add('/adapters', Adapter(id='new2'))
        tx3.add('/adapters', Adapter(id='new3'))
        tx1.commit()
        tx2.commit()
        tx3.commit()
        self.assertEqual(self.log_levels().keys(), [
            '0', '1', '2', '3', '4', 'new1', 'new2', 'new3'
        ])

    def test_colliding_adds(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        tx4 = proxy.open_transaction()
        tx1.add('/adapters', Adapter(id='new1'))
        tx2.add('/adapters', Adapter(id='new2'))
        tx3.add('/adapters', Adapter(id='new1', version='foobar'))
        tx4.add('/adapters', Adapter(id='new1'))
        tx1.commit()
        tx2.commit()
        self.assertRaises(MergeConflictException, tx3.commit)
        tx4.commit()  # is fine since it added the same data
        self.assertEqual(self.log_levels().keys(), [
            '0', '1', '2', '3', '4', 'new1', 'new2'
        ])

    def test_compatible_removes(self):
        # removes are always compatible with each other
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        tx1.remove('/adapters/0')
        tx2.remove('/adapters/3')
        tx3.remove('/adapters/0')
        tx1.commit()
        tx2.commit()
        tx3.commit()
        self.assertEqual(self.log_levels().keys(), ['1', '2', '4'])

    def test_update_remove_conflict(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        self.make_change(tx1, '/adapters/0', 'version', '42')
        tx1.remove('/adapters/1')
        self.make_change(tx2, '/adapters/1', 'version', '13')
        tx3.remove('/adapters/0')
        tx1.commit()
        self.assertRaises(MergeConflictException, tx2.commit)
        self.assertRaises(MergeConflictException, tx3.commit)
        self.assertEqual(self.log_levels().keys(), ['0', '2', '3', '4'])

    def test_compatible_update_remove_mix(self):
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        self.make_change(tx1, '/adapters/0', 'version', '42')
        tx1.remove('/adapters/1')
        self.make_change(tx2, '/adapters/2', 'version', '13')
        tx3.remove('/adapters/3')
        tx1.commit()
        tx2.commit()
        tx3.commit()
        self.assertEqual(self.log_levels().keys(), ['0', '2', '4'])

    def test_update_add_mix(self):
        # at same nodes updates are always compatible with adds
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        self.make_change(tx1, '/adapters/0', 'config.log_level', 4)
        self.make_change(tx1, '/adapters/2', 'config.log_level', 4)
        tx2.add('/adapters', Adapter(id='new1'))
        tx3.add('/adapters', Adapter(id='new2'))
        tx1.commit()
        tx2.commit()
        tx3.commit()
        self.assertEqual(self.log_levels().keys(), [
            '0', '1', '2', '3', '4', 'new1', 'new2'
        ])

    def test_remove_add_mix(self):
        # at same node, adds are always compatible with removes
        proxy = self.node.get_proxy('/')
        tx1 = proxy.open_transaction()
        tx2 = proxy.open_transaction()
        tx3 = proxy.open_transaction()
        tx1.remove('/adapters/0')
        tx2.add('/adapters', Adapter(id='new1'))
        tx3.add('/adapters', Adapter(id='new2'))
        tx1.remove('/adapters/4')
        tx1.commit()
        tx2.commit()
        tx3.commit()
        self.assertEqual(self.log_levels().keys(), [
            '1', '2', '3', 'new1', 'new2'
        ])

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

    def test_complex_changes_seq1(self):
        tx1, tx2, tx3, tx4, tx5 = self.make_complex_changes()
        tx1.commit()
        tx2.commit()
        tx3.commit()
        self.assertRaises(MergeConflictException, tx4.commit)
        self.assertRaises(MergeConflictException, tx5.commit)
        self.assertEqual(self.log_levels(), {
            '0': 1, '1': 1, '3': 0, '4': 3, 'new1': 0, 'new2': 0
        })

    def test_complex_changes_seq2(self):
        tx1, tx2, tx3, tx4, tx5 = self.make_complex_changes()
        tx5.commit()
        tx4.commit()
        self.assertRaises(MergeConflictException, tx3.commit)
        tx2.commit()
        self.assertRaises(MergeConflictException, tx1.commit)
        self.assertEqual(self.log_levels(), {
            '0': 0, '1': 4, '2': 3, '3': 0, '4': 3, 'new2': 0
        })

    def test_complex_changes_seq3(self):
        tx1, tx2, tx3, tx4, tx5 = self.make_complex_changes()
        tx4.commit()
        tx3.commit()
        tx2.commit()
        self.assertRaises(MergeConflictException, tx1.commit)
        self.assertRaises(MergeConflictException, tx5.commit)
        self.assertEqual(self.log_levels(), {
            '0': 0, '1': 1, '2': 3, '3': 0, '4': 3, 'new2': 0
        })

    def test_canceling_adds(self):
        proxy = self.node.get_proxy('/')
        tx = proxy.open_transaction()
        tx.add('/adapters', Adapter(id='new'))
        tx.add('/adapters', Adapter(id='new2'))
        tx.cancel()
        self.assertEqual(self.log_levels().keys(), ['0', '1', '2', '3', '4'])

    def test_nested_adds(self):
        self.node.add('/logical_devices', LogicalDevice(id='0'))
        self.node.add('/logical_devices', LogicalDevice(id='1'))
        proxy0 = self.node.get_proxy('/logical_devices/0')
        proxy1 = self.node.get_proxy('/logical_devices/1')
        tx0 = proxy0.open_transaction()
        tx1 = proxy1.open_transaction()

        tx0.add('/ports', LogicalPort(
            id='0', ofp_port=ofp_port(port_no=0, name='/0')))
        tx0.add('/ports', LogicalPort(
            id='1', ofp_port=ofp_port(port_no=1, name='/1')))
        tx1.add('/ports', LogicalPort(
            id='2', ofp_port=ofp_port(port_no=0, name='/0')))

        # at this point none of these are visible outside of tx
        self.assertEqual(len(proxy0.get('/', deep=1).ports), 0)
        self.assertEqual(len(proxy1.get('/', deep=1).ports), 0)

        tx0.commit()
        self.assertEqual(len(proxy0.get('/', deep=1).ports), 2)
        self.assertEqual(len(proxy1.get('/', deep=1).ports), 0)

        tx1.commit()
        self.assertEqual(len(proxy0.get('/', deep=1).ports), 2)
        self.assertEqual(len(proxy1.get('/', deep=1).ports), 1)

    def test_nested_removes(self):
        self.node.add('/logical_devices', LogicalDevice(id='0'))
        proxy0 = self.node.get_proxy('/logical_devices/0')

        # add some ports to a device
        tx0 = proxy0.open_transaction()
        for i in xrange(10):
            tx0.add('/ports', LogicalPort(
                id=str(i), ofp_port=ofp_port(port_no=i, name='/{}'.format(i))))
        # self.assertRaises(ValueError, tx0.add, '/ports', LogicalPort(id='1'))
        tx0.commit()

        # now to the removal

        tx0 = proxy0.open_transaction()
        tx0.remove('/ports/0')
        tx0.remove('/ports/5')

        tx1 = proxy0.open_transaction()
        tx1.remove('/ports/2')
        tx1.remove('/ports/7')

        tx0.commit()
        tx1.commit()

        port_ids = [
            p.ofp_port.port_no for p
            in self.node.get(deep=1).logical_devices[0].ports
        ]
        self.assertEqual(port_ids, [1, 3, 4, 6, 8, 9])

    # TODO need more tests to hammer out potential issues with transactions \
        # on nested nodes

    def test_transactions_defer_post_op_callbacks(self):

        proxy = self.node.get_proxy('/')

        pre_update = Mock()
        post_update = Mock()
        pre_add = Mock()
        post_add = Mock()
        pre_remove = Mock()
        post_remove = Mock()

        proxy.register_callback(CallbackType.PRE_UPDATE, pre_update)
        proxy.register_callback(CallbackType.POST_UPDATE, post_update)
        proxy.register_callback(CallbackType.PRE_ADD, pre_add)
        proxy.register_callback(CallbackType.POST_ADD, post_add)
        proxy.register_callback(CallbackType.PRE_REMOVE, pre_remove)
        proxy.register_callback(CallbackType.POST_REMOVE, post_remove)

        tx = proxy.open_transaction()

        # make some changes of each type
        v = tx.get('/')
        v.version = '42'
        tx.update('/', v)
        ad = tx.get('/adapters/1')
        tx.remove('/adapters/1')
        ld = LogicalDevice(id='1')
        tx.add('/logical_devices', ld)

        # each pre_* should have been called exactly once, but none of the
        # post_* callbacks have been called yet
        pre_update.assert_called_once_with(v)
        pre_add.assert_called_once_with(ld)
        pre_remove.assert_called_once_with(ad)
        post_update.assert_not_called()
        post_add.assert_not_called()
        post_remove.assert_not_called()

        # once we commit, we shall get the other callbacks
        tx.commit()
        post_update.assert_called_once_with(v)
        post_add.assert_called_once_with(ld)
        # OperationContext(
        #     data=ld,
        #     field_name='logical_devices',
        #     child_key='1'
        # ))
        post_remove.assert_called_once_with(ad)


if __name__ == '__main__':
    main()
