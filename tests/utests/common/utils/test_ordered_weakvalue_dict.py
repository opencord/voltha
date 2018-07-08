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

from common.utils.ordered_weakvalue_dict import OrderedWeakValueDict


class O(object):
    def __init__(self, a):
        self.a = a


class TestOrderedWeakValueDict(TestCase):

    def test_standard_behavior(self):
        holder = dict()  # a real dict so we can control which object real ref
        def mk(k):
            o = O(k)
            holder[k] = o
            return o
        o = OrderedWeakValueDict((k, mk(k)) for k in xrange(10))
        self.assertEqual(len(o), 10)
        self.assertEqual(o[3].a, 3)
        o[3] = mk(-3)
        self.assertEqual(o[3].a, -3)
        del o[3]
        self.assertEqual(len(o), 9)
        o[100] = mk(100)
        self.assertEqual(len(o), 10)
        self.assertEqual(o.keys(), [0, 1, 2, 4, 5, 6, 7, 8, 9, 100])

        # remove a few items from the holder, they should be gone from o too
        del holder[1]
        del holder[5]
        del holder[6]

        self.assertEqual(o.keys(), [0, 2, 4, 7, 8, 9, 100])
        self.assertEqual([v.a for v in o.values()], [0, 2, 4, 7, 8, 9, 100])


