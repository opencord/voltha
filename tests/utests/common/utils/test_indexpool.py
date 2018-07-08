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
from unittest import TestCase, main
from common.utils.indexpool import IndexPool

class TestIndexPool(TestCase):
    pool = IndexPool(8, 0)
    def test_01_get_next(self):
        self.assertEqual(self.pool.indices.bin, '00000000')
        for i in range(8):
            self.assertEqual(self.pool.get_next(), i)
        #to check if there's any bit left after using all 8 bits
        self.assertIsNone(self.pool.get_next())

    def test_02_pre_allocate(self):
        _pool2 = IndexPool(8, 0)
        self.assertEqual(_pool2.indices.bin, '00000000')
        _pool2.pre_allocate((0,1,2,))
        self.assertEqual(_pool2.indices.bin, '11100000')

    def test_03_release(self):
        self.pool.release(5)
        self.assertEqual(self.pool.indices.bin, '11111011')
        self.pool.release(10)
        self.assertEqual(self.pool.indices.bin, '11111011')
        self.pool.release(0)
        self.assertEqual(self.pool.indices.bin, '01111011')

    def test_04_check_offset(self):
        _offset = 5
        self.pool = IndexPool(8, _offset)
        for i in range(8):
            self.assertEqual(self.pool.get_next(), _offset + i)


if __name__ == '__main__':
    main()