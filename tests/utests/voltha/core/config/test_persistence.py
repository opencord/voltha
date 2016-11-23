from copy import copy
from random import randint, seed
from time import time
from unittest import main, TestCase

from voltha.core.config.config_root import ConfigRoot
from voltha.protos.openflow_13_pb2 import ofp_desc
from voltha.protos.voltha_pb2 import Voltha, HealthStatus, Adapter, \
    AdapterConfig, LogicalDevice


n_adapters = 100
n_logical_nodes = 100


class TestPersistence(TestCase):

    def pump_some_data(self, node):
        seed(0)
        node.update('/', Voltha(
            instance_id='1',
            version='42',
            log_level=1
        ))
        node.update('/health', HealthStatus(state=HealthStatus.OVERLOADED))
        for i in xrange(n_adapters):
            node.add('/adapters', Adapter(
                id=str(i),
                vendor='cord',
                version=str(randint(1, 10)),
                config=AdapterConfig(
                    log_level=0
                )
            ))
        for i in xrange(n_logical_nodes):
            node.add('/logical_devices', LogicalDevice(
                id=str(i),
                datapath_id=randint(1, 100000),
                desc=ofp_desc(
                    mfr_desc='foo',
                    hw_desc='bar',
                    sw_desc='zoo'
                )
            ))

    def test_inmemory_kv_store(self):
        t0 = [time()]
        def pt(msg=''):
            t1 = time()
            print '%20.8f ms - %s' % (1000 * (t1 - t0[0]), msg)
            t0[0] = t1

        kv_store = dict()

        # create node and pump data
        node = ConfigRoot(Voltha(), kv_store=kv_store)
        pt('init')
        self.pump_some_data(node)
        pt('pump')

        # check that content of kv_store looks ok
        size1 = len(kv_store)
        self.assertEqual(size1, 10 + 3 * (n_adapters + n_logical_nodes))

        # this should actually drop if we pune
        node.prune_untagged()
        pt('prunning')

        size2 = len(kv_store)
        self.assertEqual(size2, 3 + 2 * (1 + 1 + n_adapters + n_logical_nodes))
        all_latest_data = node.get('/', deep=1)
        pt('deep get')

        # save dict so that deleting the node will not wipe it
        kv_store = copy(kv_store)
        pt('copy kv store')
        del node
        pt('delete node')
        # self.assertEqual(size2, 1 + 2 * (1 + 1 + n_adapters + n_logical_nodes))

        # recreate tree from persistence
        node = ConfigRoot.load(Voltha, kv_store)
        pt('load from kv store')
        self.assertEqual(node.get('/', deep=1), all_latest_data)
        pt('deep get')

if __name__ == '__main__':
    main()
