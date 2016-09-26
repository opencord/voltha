#!/usr/bin/env python
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

"""Load a protobuf description file an make sense of it"""

# This is very experimental
import os
import inspect
from collections import OrderedDict

from enum import Enum
from google.protobuf.descriptor import FieldDescriptor, Descriptor
from google.protobuf.message import Message
from simplejson import dumps

from google.protobuf import descriptor_pb2

# TODO this hack needs to go
# don't worry if the below too lines are flagged by your IDE as unused and
# unresolvable; they are fine.
import voltha.northbound.grpc.pb2_loader
from google.api import http_pb2


class InvalidDescriptorError(Exception): pass


class DescriptorParser(object):

    def __init__(self, ignore_empty_source_code_info=True):
        self.ignore_empty_source_code_info = ignore_empty_source_code_info
        self.catalog = {}
        self.meta, blob = self.load_root_descriptor()
        self.load_descriptor(blob)

    def load_root_descriptor(self):
        """Load descriptor.desc to make things more data driven"""
        with open('descriptor.desc', 'r') as f:
            blob = f.read()
        proto = descriptor_pb2.FileDescriptorSet()
        proto.ParseFromString(blob)
        assert len(proto.file) == 1
        fdp = proto.file[0]

        # for i, (fd, v) in enumerate(fdp.ListFields()):
        #     assert isinstance(fd, FieldDescriptor)
        #     print fd.name, fd.full_name, fd.number, fd.type, fd.label, fd.message_type, type(v)

        return fdp, blob

    def get_catalog(self):
        return self.catalog

    def load_descriptor(self, descriptor_blob, fold_comments=True):

        # decode desciription
        file_descriptor_set = descriptor_pb2.FileDescriptorSet()
        file_descriptor_set.ParseFromString(descriptor_blob)

        d = self.parse(file_descriptor_set)
        for _file in d['file']:
            if fold_comments:
                self.fold_comments_in(_file)
            self.catalog[_file['package']] = _file

    def parse_message(self, m):
        assert isinstance(m, Message)
        d = OrderedDict()
        for fd, v in m.ListFields():
            assert isinstance(fd, FieldDescriptor)
            if fd.label in (1, 2):
                d[fd.name] = self.parse(v)
            elif fd.label == 3:
                d[fd.name] = [self.parse(x) for x in v]
            else:
                raise InvalidDescriptorError()

        return d

    parser_table = {
        unicode: lambda x: x,
        int: lambda x: x,
        bool: lambda x: x,
    }

    def parse(self, o):
        if isinstance(o, Message):
            return self.parse_message(o)
        else:
            return self.parser_table[type(o)](o)

    def fold_comments_in(self, descriptor):
        assert isinstance(descriptor, dict)

        locations = descriptor.get('source_code_info', {}).get('location', [])
        for location in locations:
            path = location.get('path', [])
            comments = ''.join([
                location.get('leading_comments', '').strip(' '),
                location.get('trailing_comments', '').strip(' '),
                ''.join(block.strip(' ') for block
                          in location.get('leading_detached_comments', ''))
            ]).strip()

            # ignore locations with no comments
            if not comments:
                continue

            # we ignore path with odd number of entries, since these do
            # not address our schema nodes, but rather the meta schema
            if (len(path) % 2 == 0):
                node = self.find_node_by_path(
                    path, self.meta.DESCRIPTOR, descriptor)
                assert isinstance(node, dict)
                node['_description'] = comments

        # remove source_code_info
        del descriptor['source_code_info']

    def find_node_by_path(self, path, meta, o):

        # stop recursion when path is empty
        if not path:
            return o

        # sanity check
        assert len(path) >= 2
        assert isinstance(meta, Descriptor)
        assert isinstance(o, dict)

        # find field name, then actual field
        field_number = path.pop(0)
        field_def = meta.fields_by_number[field_number]
        field = o[field_def.name]

        # field must be a list, extract entry with given index
        assert isinstance(field, list)  # expected to be a list field
        index = path.pop(0)
        child_o = field[index]

        child_meta = field_def.message_type
        return self.find_node_by_path(path, child_meta, child_o)


if __name__ == '__main__':
    # load desc into binary string
    from voltha.core.protos import voltha_pb2

    desc_dir = os.path.dirname(inspect.getfile(voltha_pb2))
    desc_file = os.path.join(desc_dir, 'voltha.desc')
    with open(desc_file, 'rb') as f:
        descriptor_blob = f.read()

    parser = DescriptorParser()
    parser.load_descriptor(descriptor_blob)
    print dumps(parser.get_catalog(), indent=4)


