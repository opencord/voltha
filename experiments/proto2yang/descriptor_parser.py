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
import os
from collections import OrderedDict

from google.protobuf import descriptor_pb2
from google.protobuf.descriptor import FieldDescriptor, Descriptor
from google.protobuf.message import Message


class InvalidDescriptorError(Exception): pass


class DescriptorParser(object):
    """
    Used to parse protobuf FileDescriptor objects into native Python
    data structures (nested dict/list/intrinsic values. Two of the typical
    sources of FileDescriptor objects are:
    1. CodeGeneratorRequest, used as binary input to any protoc plugin,
       contains a list of these FileDescriptor objects (under the
       proto_file attribute)
    2. FileDescriptorSet, as saved by protoc when using the -o option.

    An important feature of the parser is that it can process the source
    code annotations and can fold comments into the relevant defintions
    present in the proto file.

    Usage (in a protoc plugin):
    >>> request = plugin.CodeGeneratorRequest()
    >>> request.ParseFromString(sys.stdin.read())
    >>> parser = DescriptorParser()
    >>> for proto_file in request.proto_file:
    >>>     parsed_data = parser.parse_file_descriptor()
    >>>     print json.dumps(parsed_data, indent=4)
    """

    meta = None

    def __init__(self):
        if DescriptorParser.meta is None:
            DescriptorParser.meta = self.load_meta_descriptor()

    def load_meta_descriptor(self):
        """
        Load the protobuf version of descriptor.proto to use it in
        decoding protobuf paths.
        """
        fpath = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             'descriptor.desc'))
        with open(fpath, 'r') as f:
            blob = f.read()
        proto = descriptor_pb2.FileDescriptorSet()
        proto.ParseFromString(blob)
        assert len(proto.file) == 1
        return proto.file[0]

    parser_table = {
        unicode: lambda x: x,
        int: lambda x: x,
        bool: lambda x: x,
    }

    def parse(self, o, type_tag_name=None):
        if isinstance(o, Message):
            return self.parse_message(o, type_tag_name)
        else:
            return self.parser_table[type(o)](o)

    def parse_message(self, m, type_tag_name=None):
        assert isinstance(m, Message)
        d = OrderedDict()
        for field, value in m.ListFields():
            assert isinstance(field, FieldDescriptor)
            if field.label in (1, 2):
                d[field.name] = self.parse(value, type_tag_name)
            elif field.label == 3:
                d[field.name] = [self.parse(x, type_tag_name) for x in
                                 value]
            else:
                raise InvalidDescriptorError()

        if type_tag_name is not None:
            d[type_tag_name] = m.DESCRIPTOR.full_name.strip('.')

        return d

    def parse_file_descriptor(self, descriptor,
                              type_tag_name=None,
                              fold_comments=False):

        d = self.parse(descriptor, type_tag_name=type_tag_name)

        if fold_comments:
            locations = d.get('source_code_info', {}).get('location', [])
            for location in locations:
                path = location.get('path', [])
                comments = ''.join([
                    location.get('leading_comments', '').strip(' '),
                    location.get('trailing_comments', '').strip(' '),
                    ''.join(block.strip(' ') for block
                            in
                            location.get('leading_detached_comments', ''))
                ]).strip()

                # ignore locations with no comments
                if not comments:
                    continue

                # we ignore path with odd number of entries, since these do
                # not address our schema nodes, but rather the meta schema
                if (len(path) % 2 == 0):
                    node = self.find_node_by_path(
                        path, self.meta.DESCRIPTOR, d)
                    assert isinstance(node, dict)
                    node['_description'] = comments

            # remove source_code_info
            del d['source_code_info']

        return d

    def parse_file_descriptors(self, descriptors,
                              type_tag_name=None,
                              fold_comments=False):
        return [self.parse_file_descriptor(descriptor,
                                           type_tag_name=type_tag_name,
                                           fold_comments=fold_comments)
                for descriptor in descriptors]

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
