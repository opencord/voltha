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
import loxi.of13 as ofp

class TestConection_mgr(TestCase):

    def test_bitmap_to_version(self):
        bitmaps = [18]
        versions = ofp.util.bitmap_to_version(bitmaps)
        self.assertEqual(versions,[1,4])

if __name__ == '__main__':
    main()
