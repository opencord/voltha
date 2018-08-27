#
# Copyright 2018 the original author or authors.
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
#
import json
from unittest import TestCase, main

from bitstring import BitArray
from mock import Mock
from common.pon_resource_manager.resource_manager import PONResourceManager


class TestResourceManager(TestCase):
    def setUp(self):
        self._rm = PONResourceManager("xpon", '0001c889ee7189fb', 'consul',
                                      'localhost', 8500)

    def tearDown(self):
        self._rm = None

    def test_init_resource_id_pool(self):
        self._rm._get_resource = Mock(return_value=None)
        self._rm._kv_store.update_to_kv_store = Mock(return_value=True)
        self.assertTrue(self._rm.init_resource_id_pool(0, 'ONU_ID', 1, 127))
        self.assertTrue(self._rm.init_resource_id_pool(1, 'ALLOC_ID',
                                                       1024, 16383))
        self.assertTrue(self._rm.init_resource_id_pool(2, 'GEMPORT_ID',
                                                       1023, 65534))

    def test_get_resource_id(self):
        # Get onu id test
        onu_id_resource = self._rm._format_resource(0, 1, 127)
        self._rm._kv_store.get_from_kv_store = Mock(
            return_value=json.dumps(onu_id_resource).encode('utf-8'))
        self._rm._kv_store.update_to_kv_store = Mock(return_value=True)
        self.assertEqual(self._rm.get_resource_id(0, 'ONU_ID'), 1)

        # Get alloc id test
        alloc_id_resource = self._rm._format_resource(1, 1024, 16383)
        self._rm._kv_store.get_from_kv_store = Mock(
            return_value=json.dumps(alloc_id_resource).encode('utf-8'))
        self.assertEqual(self._rm.get_resource_id(1, 'ALLOC_ID', 1)[0], 1024)
        self.assertEqual(self._rm.get_resource_id(1, 'ALLOC_ID', 4),
                         [1024, 1025, 1026, 1027])

        # Get gemport id test
        gemport_id_resource = self._rm._format_resource(2, 1023, 65534)
        self._rm._kv_store.get_from_kv_store = Mock(
            return_value=json.dumps(gemport_id_resource).encode('utf-8'))
        self.assertEqual(self._rm.get_resource_id(2, 'GEMPORT_ID', 1)[0], 1023)
        self.assertEqual(self._rm.get_resource_id(2, 'GEMPORT_ID', 5),
                         [1023, 1024, 1025, 1026, 1027])

    def test_free_resource_id(self):
        # Free onu id test
        self._rm._kv_store.update_to_kv_store = Mock(return_value=True)
        onu_id_resource = self._rm._format_resource(0, 1, 127)
        onu_id_resource['pool'] = BitArray('0b' + onu_id_resource['pool'])
        self._rm._generate_next_id(onu_id_resource)
        onu_id_resource['pool'] = onu_id_resource['pool'].bin
        self._rm._kv_store.get_from_kv_store = Mock(
            return_value=json.dumps(onu_id_resource).encode('utf-8'))
        self.assertTrue(self._rm.free_resource_id(0, 'ONU_ID', 1))

        # Free alloc id test
        alloc_id_resource = self._rm._format_resource(1, 1024, 16383)
        alloc_id_resource['pool'] = BitArray('0b' + alloc_id_resource['pool'])

        for num in range(5):
            self._rm._generate_next_id(alloc_id_resource)

        alloc_id_resource['pool'] = alloc_id_resource['pool'].bin
        self._rm._kv_store.get_from_kv_store = Mock(
            return_value=json.dumps(alloc_id_resource).encode('utf-8'))
        self.assertTrue(self._rm.free_resource_id(1, 'ALLOC_ID',
                                                  [1024, 1025, 1026, 1027,
                                                   1028]))

        # Free gemport id test
        gemport_id_resource = self._rm._format_resource(2, 1023, 65534)
        gemport_id_resource['pool'] = BitArray(
            '0b' + gemport_id_resource['pool'])

        for num in range(6):
            self._rm._generate_next_id(gemport_id_resource)

        gemport_id_resource['pool'] = gemport_id_resource['pool'].bin
        self._rm._kv_store.get_from_kv_store = Mock(
            return_value=json.dumps(gemport_id_resource).encode('utf-8'))
        self.assertTrue(self._rm.free_resource_id(2, 'GEMPORT_ID',
                                                  [1023, 1024, 1025, 1026, 1027,
                                                   1028]))


if __name__ == '__main__':
    main()
