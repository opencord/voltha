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
from copy import copy
from random import randint, seed
from time import time
from unittest import main, TestCase
import json

from voltha.core.config.config_root import ConfigRoot
from voltha.protos.openflow_13_pb2 import ofp_desc
from voltha.protos.voltha_pb2 import VolthaInstance, HealthStatus, Adapter, \
    AdapterConfig, LogicalDevice


n_adapters = 1000
n_logical_nodes = 1000


class TestPersistence(TestCase):

    def pump_some_data(self, node):
        seed(0)
        node.update('/', VolthaInstance(
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
        node = ConfigRoot(VolthaInstance(), kv_store=kv_store)
        node.tag('original')
        pt('init')
        self.pump_some_data(node)
        pt('pump')
        node.tag('pumped')

        # check that content of kv_store looks ok
        size1 = len(kv_store)
        self.assertEqual(size1, 16 + 3 * (n_adapters + n_logical_nodes))

        # this should actually drop if we pune
        node.prune_untagged()
        pt('prunning')

        size2 = len(kv_store)
        self.assertEqual(size2, 9 + 2 * (1 + 1 + n_adapters + n_logical_nodes) + 2)
        all_latest_data = node.get('/', deep=1)
        pt('deep get')

        # save dict so that deleting the node will not wipe it
        latest_hash = node.latest.hash
        kv_store = copy(kv_store)
        pt('copy kv store')
        del node
        pt('delete node')
        # self.assertEqual(size2, 1 + 2 * (1 + 1 + n_adapters + n_logical_nodes))

        self.assertEqual(json.loads(kv_store['root'])['latest'], latest_hash)
        # recreate tree from persistence
        node = ConfigRoot.load(VolthaInstance, kv_store)
        pt('load from kv store')
        self.assertEqual(node.get('/', deep=1), all_latest_data)
        pt('deep get')
        self.assertEqual(latest_hash, node.latest.hash)
        self.assertEqual(node.tags, ['original', 'pumped'])


if __name__ == '__main__':
    main()
