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


