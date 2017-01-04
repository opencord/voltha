#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from _weakref import ref
from weakref import KeyedRef
from collections import OrderedDict


class OrderedWeakValueDict(OrderedDict):
    """
    Modified OrderedDict to use weak references as values. Entries disappear
    automatically if the referred value has no more strong reference pointing
    ot it.

    Warning, this is not a complete implementation, only what is needed for
    now. See test_ordered_wealvalue_dict.py to see what is tested behavior.
    """
    def __init__(self, *args, **kw):
        def remove(wr, selfref=ref(self)):
            self = selfref()
            if self is not None:
                super(OrderedWeakValueDict, self).__delitem__(wr.key)
        self._remove = remove
        super(OrderedWeakValueDict, self).__init__(*args, **kw)

    def __setitem__(self, key, value):
        super(OrderedWeakValueDict, self).__setitem__(
            key, KeyedRef(value, self._remove, key))

    def __getitem__(self, key):
        o = super(OrderedWeakValueDict, self).__getitem__(key)()
        if o is None:
            raise KeyError, key
        else:
            return o

