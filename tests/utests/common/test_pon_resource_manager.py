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
from common.pon_resource_manager.resource_manager import PONResourceManager
from mock import Mock


class TestResourceManager(TestCase):
    def setUp(self):
        self._rm = PONResourceManager('xgspon', 'default',
                                      '0001c889ee7189fb', 'consul',
                                      'localhost', 8500)
        self.default_resource_range = {
            "onu_id_start": 1,
            "onu_id_end": 127,
            "alloc_id_start": 1024,
            "alloc_id_end": 2816,
            "gemport_id_start": 1024,
            "gemport_id_end": 8960,
            "pon_ports": 16
        }

    def tearDown(self):
        self._rm = None
        self.default_resource_range = None

    def test_init_pon_resource_ranges(self):
        output = json.dumps(self.default_resource_range).encode('utf-8')
        self._rm._get_olt_model = Mock(return_value='default')
        self._rm._kv_store.get_from_kv_store = Mock(return_value=output)

        self._rm.init_resource_ranges_from_kv_store()
        self.assertEqual(self._rm.pon_resource_ranges,
                         self.default_resource_range)

        self._rm.init_default_pon_resource_ranges()
        self.assertEqual(self._rm.pon_resource_ranges,
                         self.default_resource_range)

    def test_init_resource_id_pool(self):
        self._rm._kv_store.get_from_kv_store = Mock(return_value=None)
        self._rm._kv_store.update_to_kv_store = Mock(return_value=True)
        status = self._rm.init_resource_id_pool(0, 'ONU_ID', 1, 127)
        self.assertTrue(status)
        status = self._rm.init_resource_id_pool(
            1, 'ALLOC_ID', 1024, 16383)
        self.assertTrue(status)
        status = self._rm.init_resource_id_pool(
            2, 'GEMPORT_ID', 1023, 65534)
        self.assertTrue(status)

    def test_get_resource_id(self):
        # Get onu id test
        onu_id_resource = self._rm._format_resource(0, 1, 127)
        output = onu_id_resource.encode('utf-8')
        self._rm._kv_store.get_from_kv_store = Mock(return_value=output)
        self._rm._kv_store.update_to_kv_store = Mock(return_value=True)
        result = self._rm.get_resource_id(0, 'ONU_ID')
        self.assertEqual(result, 1)

        # Get alloc id test
        alloc_id_resource = self._rm._format_resource(1, 1024, 16383)
        output = alloc_id_resource.encode('utf-8')
        self._rm._kv_store.get_from_kv_store = Mock(return_value=output)
        result = self._rm.get_resource_id(1, 'ALLOC_ID', 1)
        self.assertEqual(result[0], 1024)
        result = self._rm.get_resource_id(1, 'ALLOC_ID', 4)
        self.assertEqual(result, [1024, 1025, 1026, 1027])

        # Get gemport id test
        gemport_id_resource = self._rm._format_resource(2, 1023, 65534)
        output = gemport_id_resource.encode('utf-8')
        self._rm._kv_store.get_from_kv_store = Mock(return_value=output)
        result = self._rm.get_resource_id(2, 'GEMPORT_ID', 1)
        self.assertEqual(result[0], 1023)
        result = self._rm.get_resource_id(2, 'GEMPORT_ID', 5)
        self.assertEqual(result, [1023, 1024, 1025, 1026, 1027])

    def test_free_resource_id(self):
        # Free onu id test
        self._rm._kv_store.update_to_kv_store = Mock(return_value=True)
        onu_id_resource = eval(self._rm._format_resource(0, 1, 127))
        onu_id_resource['pool'] = BitArray('0b' + onu_id_resource['pool'])
        self._rm._generate_next_id(onu_id_resource)
        onu_id_resource['pool'] = onu_id_resource['pool'].bin
        output = json.dumps(onu_id_resource).encode('utf-8')
        self._rm._kv_store.get_from_kv_store = Mock(return_value=output)
        result = self._rm.free_resource_id(0, 'ONU_ID', 1)
        self.assertTrue(result)

        # Free alloc id test
        alloc_id_resource = eval(self._rm._format_resource(1, 1024, 16383))
        alloc_id_resource['pool'] = BitArray('0b' + alloc_id_resource['pool'])

        for num in range(5):
            self._rm._generate_next_id(alloc_id_resource)

        alloc_id_resource['pool'] = alloc_id_resource['pool'].bin
        output = json.dumps(alloc_id_resource).encode('utf-8')
        self._rm._kv_store.get_from_kv_store = Mock(return_value=output)
        result = self._rm.free_resource_id(1, 'ALLOC_ID',
                                           [1024, 1025, 1026, 1027, 1028])
        self.assertTrue(result)

        # Free gemport id test
        gemport_id_resource = eval(self._rm._format_resource(2, 1023, 65534))
        gemport_id_resource['pool'] = BitArray(
            '0b' + gemport_id_resource['pool'])

        for num in range(6):
            self._rm._generate_next_id(gemport_id_resource)

        gemport_id_resource['pool'] = gemport_id_resource['pool'].bin
        output = json.dumps(gemport_id_resource).encode('utf-8')
        self._rm._kv_store.get_from_kv_store = Mock(return_value=output)
        result = self._rm.free_resource_id(2, 'GEMPORT_ID',
                                           [1023, 1024, 1025, 1026, 1027, 1028])
        self.assertTrue(result)

    def test_clear_resource_id_pool(self):
        self._rm._kv_store.remove_from_kv_store = Mock(return_value=True)
        status = self._rm.clear_resource_id_pool(0, 'ONU_ID')
        self.assertTrue(status)
        self._rm._kv_store.remove_from_kv_store = Mock(return_value=False)
        status = self._rm.clear_resource_id_pool(1, 'ALLOC_ID')
        self.assertFalse(status)


if __name__ == '__main__':
    main()
