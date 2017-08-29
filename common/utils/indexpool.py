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
