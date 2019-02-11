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
import binascii
import json
from scapy.fields import Field, StrFixedLenField, PadField, IntField, FieldListField, ByteField, StrField, \
    StrFixedLenField, PacketField
from scapy.packet import Raw

class FixedLenField(PadField):
    """
    This Pad field limits parsing of its content to its size
    """
    def __init__(self, fld, align, padwith='\x00'):
        super(FixedLenField, self).__init__(fld, align, padwith)

    def getfield(self, pkt, s):
        remain, val = self._fld.getfield(pkt, s[:self._align])
        if isinstance(val.payload, Raw) and \
                not val.payload.load.replace(self._padwith, ''):
            # raw payload is just padding
            val.remove_payload()
        return remain + s[self._align:], val


class StrCompoundField(Field):
    __slots__ = ['flds']

    def __init__(self, name, flds):
        super(StrCompoundField, self).__init__(name=name, default=None, fmt='s')
        self.flds = flds
        for fld in self.flds:
            assert not fld.holds_packets, 'compound field cannot have packet field members'

    def addfield(self, pkt, s, val):
        for fld in self.flds:
            # run though fake add/get to consume the relevant portion of the input value for this field
            x, extracted = fld.getfield(pkt, fld.addfield(pkt, '', val))
            l = len(extracted)
            s = fld.addfield(pkt, s, val[0:l])
            val = val[l:]
        return s;

    def getfield(self, pkt, s):
        data = ''
        for fld in self.flds:
            s, value = fld.getfield(pkt, s)
            if not isinstance(value, str):
                value = fld.i2repr(pkt, value)
            data += value
        return s, data


class XStrFixedLenField(StrFixedLenField):
    """
    XStrFixedLenField which value is printed as hexadecimal.
    """
    def i2m(self, pkt, x):
        l = self.length_from(pkt) * 2
        return None if x is None else binascii.a2b_hex(x)[0:l+1]

    def m2i(self, pkt, x):
        return None if x is None else binascii.b2a_hex(x)


class MultipleTypeField(object):
    """MultipleTypeField are used for fields that can be implemented by
        various Field subclasses, depending on conditions on the packet.

        It is initialized with `flds` and `default`.

        `default` is the default field type, to be used when none of the
        conditions matched the current packet.

        `flds` is a list of tuples (`fld`, `cond`), where `fld` if a field
        type, and `cond` a "condition" to determine if `fld` is the field type
        that should be used.

        `cond` is either:

        - a callable `cond_pkt` that accepts one argument (the packet) and
            returns True if `fld` should be used, False otherwise.

          - a tuple (`cond_pkt`, `cond_pkt_val`), where `cond_pkt` is the same
            as in the previous case and `cond_pkt_val` is a callable that
            accepts two arguments (the packet, and the value to be set) and
            returns True if `fld` should be used, False otherwise.

        See scapy.layers.l2.ARP (type "help(ARP)" in Scapy) for an example of
        use.
    """

    __slots__ = ["flds", "default", "name"]

    def __init__(self, flds, default):
        self.flds  = flds
        self.default = default
        self.name = self.default.name

    def _find_fld_pkt(self, pkt):
        """Given a Packet instance `pkt`, returns the Field subclass to be
            used. If you know the value to be set (e.g., in .addfield()), use
            ._find_fld_pkt_val() instead.
        """
        for fld, cond in self.flds:
            if isinstance(cond, tuple):
                cond = cond[0]
            if cond(pkt):
                return fld
        return self.default

    def _find_fld_pkt_val(self, pkt, val):
        """Given a Packet instance `pkt` and the value `val` to be set,
            returns the Field subclass to be used.
        """
        for fld, cond in self.flds:
            if isinstance(cond, tuple):
                if cond[1](pkt, val):
                    return fld
            elif cond(pkt):
                return fld
        return self.default

    def getfield(self, pkt, s):
        return self._find_fld_pkt(pkt).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        return self._find_fld_pkt_val(pkt, val).addfield(pkt, s, val)

    def any2i(self, pkt, val):
        return self._find_fld_pkt_val(pkt, val).any2i(pkt, val)

    def h2i(self, pkt, val):
        return self._find_fld_pkt_val(pkt, val).h2i(pkt, val)

    def i2h(self, pkt, val):
        return self._find_fld_pkt_val(pkt, val).i2h(pkt, val)

    def i2m(self, pkt, val):
        return self._find_fld_pkt_val(pkt, val).i2m(pkt, val)

    def i2len(self, pkt, val):
        return self._find_fld_pkt_val(pkt, val).i2len(pkt, val)

    def i2repr(self, pkt, val):
        return self._find_fld_pkt_val(pkt, val).i2repr(pkt, val)

    def register_owner(self, cls):
        for fld, _ in self.flds:
            fld.owners.append(cls)
        self.dflt.owners.append(cls)

    def __getattr__(self, attr):
        return getattr(self._find_fld(), attr)


class OmciSerialNumberField(StrCompoundField):
    def __init__(self, name, default=None):
        assert default is None or (isinstance(default, str) and len(default) == 12), 'invalid default serial number'
        vendor_default = default[0:4] if default is not None else None
        vendor_serial_default = default[4:12] if default is not None else None
        super(OmciSerialNumberField, self).__init__(name,
                                                    [StrFixedLenField('vendor_id', vendor_default, 4),
                                                     XStrFixedLenField('vendor_serial_number',
                                                                       vendor_serial_default, 4)])


class OmciTableField(MultipleTypeField):
    def __init__(self, tblfld):
        assert isinstance(tblfld, PacketField)
        assert hasattr(tblfld.cls, 'index'), 'No index() method defined for OmciTableField row object'
        assert hasattr(tblfld.cls, 'is_delete'), 'No delete() method defined for OmciTableField row object'
        super(OmciTableField, self).__init__(
            [
                (IntField('table_length', 0), (self.cond_pkt, self.cond_pkt_val)),
                (PadField(StrField('me_type_table', None), OmciTableField.PDU_SIZE),
                 (self.cond_pkt2, self.cond_pkt_val2))
            ], tblfld)

    PDU_SIZE = 29                           # Baseline message set raw get-next PDU size
    OmciGetResponseMessageId = 0x29         # Ugh circular dependency
    OmciGetNextResponseMessageId = 0x3a     # Ugh circular dependency

    def cond_pkt(self, pkt):
        return pkt is not None and pkt.message_id == self.OmciGetResponseMessageId

    def cond_pkt_val(self, pkt, val):
        return pkt is not None and pkt.message_id == self.OmciGetResponseMessageId

    def cond_pkt2(self, pkt):
        return pkt is not None and pkt.message_id == self.OmciGetNextResponseMessageId

    def cond_pkt_val2(self, pkt, val):
        return pkt is not None and pkt.message_id == self.OmciGetNextResponseMessageId

    def to_json(self, new_values, old_values_json):
        if not isinstance(new_values, list):
            new_values = [new_values]   # If setting a scalar, augment the old table
        else:
            old_values_json = None      # If setting a vector of new values, erase all old_values

        key_value_pairs = dict()

        old_table = self.load_json(old_values_json)
        for old in old_table:
            index = old.index()
            key_value_pairs[index] = old

        for new in new_values:
            index = new.index()
            if new.is_delete():
                del key_value_pairs[index]
            else:
                key_value_pairs[index] = new

        new_table = []
        for k, v in sorted(key_value_pairs.iteritems()):
            assert isinstance(v, self.default.cls), 'object type for Omci Table row object invalid'
            new_table.append(v.fields)

        str_values = json.dumps(new_table, separators=(',', ':'))

        return str_values

    def load_json(self, json_str):
        if json_str is None:
            json_str = '[]'

        json_values = json.loads(json_str)
        key_value_pairs = dict()

        for json_value in json_values:
            v = self.default.cls(**json_value)
            index = v.index()
            key_value_pairs[index] = v

        table = []
        for k, v in sorted(key_value_pairs.iteritems()):
            table.append(v)

        return table