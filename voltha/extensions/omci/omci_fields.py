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
from scapy.fields import Field, StrFixedLenField, PadField
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

class OmciSerialNumberField(StrCompoundField):
    def __init__(self, name, default=None):
        assert default is None or (isinstance(default, str) and len(default) == 12), 'invalid default serial number'
        vendor_default = default[0:4] if default is not None else None
        vendor_serial_default = default[4:12] if default is not None else None
        super(OmciSerialNumberField, self).__init__(name,
            [StrFixedLenField('vendor_id', vendor_default, 4),
            XStrFixedLenField('vendor_serial_number', vendor_serial_default, 4)])
