#
# Copyright 2016 the original author or authors.
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
import sys

from google.protobuf.message import Message
from termcolor import colored

_printfn = lambda l: sys.stdout.write(l + '\n')


class TablePrinter(object):
    """Simple tabular data printer utility. For usage, see bottom of file"""

    def __init__(self):
        self.max_field_lengths = {}
        self.field_names = {}
        self.cell_values = {}

    def add_cell(self, row_number, field_key, field_name, value):
        if not isinstance(value, str):
            value = str(value)
        self._add_field_type(field_key, field_name)
        row = self.cell_values.setdefault(row_number, {})
        row[field_key] = value
        self._update_max_length(field_key, value)

    def number_of_rows(self):
        return len(self.cell_values)

    def print_table(self, header=None, printfn=_printfn, dividers=10):

        if header is not None:
            printfn(header)

        field_keys = sorted(self.field_names.keys())

        if not field_keys:
            printfn('table empty')
            return

        def p_sep():
            printfn('+' + '+'.join(
                [(self.max_field_lengths[k] + 2) * '-'
                 for k in field_keys]) + '+')

        p_sep()

        printfn('| ' + ' | '.join(
            '%%%ds' % self.max_field_lengths[k] % self.field_names[k]
            for k in field_keys) + ' |')
        p_sep()

        for i in range(len(self.cell_values)):
            row = self.cell_values[i]
            printfn(colored('| ' + ' | '.join(
                '%%%ds' % self.max_field_lengths[k] % row.get(k, '')
                for k in field_keys
            ) + ' |'))
            if not ((i + 1) % dividers):
                p_sep()

        if (i + 1) % dividers:
            p_sep()

    def _update_max_length(self, field_key, string):
        length = len(string)
        if length > self.max_field_lengths.get(field_key, 0):
            self.max_field_lengths[field_key] = length

    def _add_field_type(self, field_key, field_name):
        if field_key not in self.field_names:
            self.field_names[field_key] = field_name
            self._update_max_length(field_key, field_name)
        else:
            assert self.field_names[field_key] == field_name


def print_pb_list_as_table(header, items, fields_to_omit=None,
                           printfn=_printfn, dividers=10, show_nulls=False,
                           presfns={}):
    from cli.utils import pb2dict

    t = TablePrinter()
    for row, obj in enumerate(items):
        assert isinstance(obj, Message)

        def set_row(pd_dict, _row, field, value, t, prefix,
                      fields_to_omit, number):
            fname = prefix + field.name
            if fname in fields_to_omit:
                return
            if isinstance(value, Message):
                add(_row, value, fname + '.',
                    100 * (number + field.number))
            else:
                presentationfn = presfns[fname] if fname in presfns else lambda x: x
                t.add_cell(_row, number + field.number, fname,
                           presentationfn(pd_dict.get(field.name)))

        def add(_row, pb, prefix='', number=0):
            d = pb2dict(pb)
            if show_nulls:
                fields = pb.DESCRIPTOR.fields
                for field in fields:
                    set_row(d,
                            _row,
                            field,
                            getattr(pb, field.name),
                            t,
                            prefix,
                            fields_to_omit,
                            number)
            else:
                fields = pb.ListFields()
                for (field, value) in fields:
                    set_row(d,
                            _row,
                            field,
                            value,
                            t,
                            prefix,
                            fields_to_omit,
                            number)
        add(row, obj)

    t.print_table(header, printfn, dividers)


def print_pb_as_table(header, pb, fields_to_omit={}, printfn=_printfn,
                      show_nulls=False):

    from cli.utils import pb2dict

    def is_repeated_item(msg):
        return hasattr(msg, "extend")

    def set_cell(pb, field, value, t, prefix, fields_to_omit):
        d = pb2dict(pb)
        fname = prefix + field.name

        if fname in fields_to_omit:
            return
        if isinstance(value, Message):
            pr(value, fname + '.')
        elif is_repeated_item(value): # handles any list
            row = t.number_of_rows()
            t.add_cell(row, 0, 'field', fname)
            t.add_cell(row, 1, 'value',
                       '{} item(s)'.format(len(d.get(field.name))))
        else:
            row = t.number_of_rows()
            t.add_cell(row, 0, 'field', fname)
            t.add_cell(row, 1, 'value', value)


    t = TablePrinter()

    def pr(_pb, prefix=''):
        if show_nulls:
            fields = _pb.DESCRIPTOR.fields
            for field in sorted(fields, key=lambda f: f.number):
                set_cell(_pb,
                        field,
                        getattr(_pb, field.name),
                        t,
                        prefix,
                        fields_to_omit)
        else:
            fields = _pb.ListFields()
            for (field, value) in sorted(fields, key=lambda (f, v): f.number):
                set_cell(_pb,
                        field,
                        value,
                        t,
                        prefix,
                        fields_to_omit)

    pr(pb)

    t.print_table(header, printfn)


if __name__ == '__main__':
    import random

    t = TablePrinter()
    for row in range(10):
        t.add_cell(row, 0, 'id', row + 100)
        t.add_cell(row, 1, 'name', 'Joe Somebody')
        t.add_cell(row, 2, 'ows', '${}'.format(random.randint(10, 100000)))
    t.print_table()
