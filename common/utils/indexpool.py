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
from bitstring import BitArray
import structlog

log = structlog.get_logger()

class IndexPool(object):
    def __init__(self, max_entries, offset):
        self.max_entries = max_entries
        self.offset = offset
        self.indices = BitArray(self.max_entries)

    def get_next(self):
        try:
            _pos = self.indices.find('0b0')
            self.indices.set(1, _pos)
            return self.offset + _pos[0]
        except IndexError:
            log.info("exception-fail-to-allocate-id-all-bits-in-use")
            return None

    def allocate(self, index):
        try:
            _pos = index - self.offset
            if not (0 <= _pos < self.max_entries):
                log.info("{}-out-of-range".format(index))
                return None
            if self.indices[_pos]:
                log.info("{}-is-already-allocated".format(index))
                return None
            self.indices.set(1, _pos)
            return index

        except IndexError:
            return None

    def release(self, index):
        index -= self.offset
        _pos = (index,)
        try:
            self.indices.set(0, _pos)
        except IndexError:
            log.info("bit-position-{}-out-of-range".format(index))

    #index or multiple indices to set all of them to 1 - need to be a tuple
    def pre_allocate(self, index):
        if(isinstance(index, tuple)):
            _lst = list(index)
            for i in range(len(_lst)):
                _lst[i] -= self.offset
            index = tuple(_lst)
            self.indices.set(1, index)
