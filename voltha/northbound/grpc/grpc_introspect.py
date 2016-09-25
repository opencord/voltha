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
from google.protobuf.descriptor import FieldDescriptor
from simplejson import dumps

from google.protobuf import descriptor_pb2

# TODO this hack needs to go
# don't worry if the below too line is flagged by your IDE as unused and
# unresolvable; they are fine
import voltha.northbound.grpc.pb2_loader
from google.api import http_pb2


class Type(Enum):
    # 0 is reserved for errors.
    # Order is weird for historical reasons.
    TYPE_DOUBLE = 1
    TYPE_FLOAT = 2
    # Not ZigZag encoded.  Negative numbers take 10 bytes.  Use TYPE_SINT64 if
    # negative values are likely.
    TYPE_INT64 = 3
    TYPE_UINT64 = 4
    # Not ZigZag encoded.  Negative numbers take 10 bytes.  Use TYPE_SINT32 if
    # negative values are likely.
    TYPE_INT32 = 5
    TYPE_FIXED64= 6
    TYPE_FIXED32 = 7
    TYPE_BOOL = 8
    TYPE_STRING = 9
    TYPE_GROUP = 10  # Tag-delimited aggregate.
    TYPE_MESSAGE = 11  # Length-delimited aggregate.

    # New in version 2.
    TYPE_BYTES = 12
    TYPE_UINT32 = 13
    TYPE_ENUM = 14
    TYPE_SFIXED32 = 15
    TYPE_SFIXED64 = 16
    TYPE_SINT32 = 17  # Uses ZigZag encoding.
    TYPE_SINT64 = 18  # Uses ZigZag encoding.


class Label(Enum):
    LABEL_OPTIONAL = 1
    LABEL_REQUIRED = 2
    LABEL_REPEATED = 3


class OptimizeMode(Enum):
    SPEED = 1
    CODE_SIZE = 2
    LITE_RUNTIME = 3


class DescriptorParser(object):

    def __init__(self, ignore_empty_source_code_info=True):
        self.ignore_empty_source_code_info = ignore_empty_source_code_info
        self.catalog = {}

    def get_catalog(self):
        return self.catalog

    def load_descriptor(self, descriptor_blob):

        # decode desciription
        file_descriptor_set = descriptor_pb2.FileDescriptorSet()
        file_descriptor_set.ParseFromString(descriptor_blob)

        # walk the proto files and parse them and add to catalog (by .name)
        for file_descriptor_proto in file_descriptor_set.file:
            d = self.parse_file_descriptor_proto(file_descriptor_proto)
            self.catalog[d['name']] = d

    def parse_descriptor_proto(self, o):
        assert isinstance(o, descriptor_pb2.DescriptorProto)
        d = OrderedDict()
        d['name'] = o.name
        d['field'] = [
            self.parse_field_description_proto(x) for x in o.field]
        d['extension'] = [
            self.parse_field_description_proto(x) for x in o.extension]
        d['nested_type'] = [
            self.parse_descriptor_proto(x) for x in o.nested_type]
        d['enum_type'] = [
            self.parse_enum_description_proto(x) for x in o.enum_type]
        d['extension_range'] = [
            self.parse_extension_range(x) for x in o.extension_range]
        d['oneof_decl'] = [
            self.parse_oneof_description_proto(x) for x in o.oneof_decl]
        if hasattr(o, 'options'):
            d['options'] = self.parse_message_options(o.options)
        d['reserved_range'] = [
            self.parse_reserved_range(x) for x in o.reserved_range]
        d['reserved_name'] = [x for x in o.reserved_name]
        return d

    def parse_enum_description_proto(self, o):
        assert isinstance(o, descriptor_pb2.EnumDescriptorProto)
        d = OrderedDict()
        if hasattr(o, 'name'):
            d['name'] = o.name
        d['value'] = [self.parse_enum_value_descriptor_proto(x) for x in
                      o.value]
        if hasattr(o, 'options'):
            d['options'] = self.parse_enum_options(o.options)
        return d

    def parse_enum_options(self, o):
        assert isinstance(o, descriptor_pb2.EnumOptions)
        d = OrderedDict()
        if hasattr(o, 'allow_alias'):
            d['allow_alias'] = o.allow_alias
        d['deprecated'] = getattr(o, 'deprecated', False)
        d['uninterpreted_option'] = [self.parse_uninterpreted_option(x) for x
                                     in o.uninterpreted_option]
        return d

    def parse_enum_value_descriptor_proto(self, o):
        assert isinstance(o, descriptor_pb2.EnumValueDescriptorProto)
        d = OrderedDict()
        if hasattr(o, 'name'):
            d['name'] = o.name
        if hasattr(o, 'number'):
            d['number'] = o.number
        if hasattr(o, 'options'):
            d['options'] = self.parse_enum_value_options(o.options)
        return d

    def parse_enum_value_options(self, o):
        assert isinstance(o, descriptor_pb2.EnumValueOptions)
        d = OrderedDict()
        d['deprecated'] = getattr(o, 'deprecated', False)
        d['uninterpreted_option'] = [self.parse_uninterpreted_option(x) for x
                                     in o.uninterpreted_option]
        return d

    def parse_extension(self, o):
        assert isinstance(o, descriptor_pb2.FieldDescriptorProto)
        print [f for f in dir(o) if f[0].lower() == f[0] and f[0] != '_']
        raise NotImplementedError()

    def parse_extension_range(self, o):
        print type(o)
        print [f for f in dir(o) if f[0].lower() == f[0] and f[0] != '_']
        raise NotImplementedError()

    def parse_field_description_proto(self, o):
        assert isinstance(o, descriptor_pb2.FieldDescriptorProto)
        d = OrderedDict()
        if hasattr(o, 'name'):
            d['name'] = o.name
        if hasattr(o, 'number'):
            d['number'] = o.number
        if hasattr(o, 'label'):
            d['label'] = self.parse_label(o.label)
        if hasattr(o, 'type'):
            d['type'] = self.parse_type(o.type)
        if hasattr(o, 'type_name'):
            d['type_name'] = o.type_name
        if hasattr(o, 'extendee'):
            d['extendee'] = o.extendee
        if hasattr(o, 'default_value'):
            d['default_value'] = o.default_value
        if hasattr(o, 'oneof_index'):
            d['oneof_index'] = o.oneof_index
        if hasattr(o, 'json_name'):
            d['json_name'] = o.json_name
        if hasattr(o, 'field_options'):
            d['field_options'] = self.parse_field_options(o.field_options)
        return d

    def parse_field_options(self, o):
        assert isinstance(o, descriptor_pb2.FieldOptions)
        print [f for f in dir(o) if f[0].lower() == f[0] and f[0] != '_']
        raise NotImplementedError()

    def parse_file_descriptor_proto(self, o):
        assert isinstance(o, descriptor_pb2.FileDescriptorProto)
        d = OrderedDict()
        d['name'] = o.name
        d['package'] = o.package
        d['dependency'] =[x for x in o.dependency]
        d['public_dependency'] = [x for x in o.public_dependency]
        d['weakdependency'] = [x for x in o.weak_dependency]
        d['message_type'] = [
            self.parse_descriptor_proto(x) for x in o.message_type]
        d['enum_type'] = [
            self.parse_enum_description_proto(x) for x in o.enum_type]
        d['service'] = [
            self.parse_service(x) for x in o.service]
        d['extension'] = [
            self.parse_extension(x) for x in o.extension]
        if hasattr(o, 'options'):
            d['options'] = self.parse_options(o.options)
        if hasattr(o, 'source_code_info'):
            d['source_code_info'] = self.parse_source_code_info(
                o.source_code_info)
        if hasattr(o, 'syntax'):
            d['syntax'] = o.syntax
        return d

    def parse_label(self, o):
        isinstance(o, int)
        return Label(o).name

    def parse_location(self, o):
        assert isinstance(o, descriptor_pb2.SourceCodeInfo.Location)
        d = OrderedDict()
        d['path'] = [x for x in o.path]
        d['span'] = [x for x in o.span]
        if hasattr(o, 'leading_comments'):
            d['leading_comments'] = o.leading_comments
        if hasattr(o, 'trailing_comments'):
            d['trailing_comments'] = o.trailing_comments
        d['leading_detached_comments'] = [
            x for x in o.leading_detached_comments]
        return d

    def parse_message_options(self, o):
        assert isinstance(o, descriptor_pb2.MessageOptions)
        d = OrderedDict()
        d['message_set_wire_format'] = getattr(
            o, 'message_set_wire_format', False)
        d['no_standard_descriptor_accessor'] = getattr(
            o, 'no_standard_descriptor_accessor', False)
        d['deprecated'] = getattr(o, 'deprecated', False)
        if hasattr(o, 'map_entry'):
            d['map_entry'] = o.map_entry
        d['uninterpreted_option'] = [
            self.parse_uninterpreted_option(x) for x in
            o.uninterpreted_option]
        return d

    def parse_method_descriptor_proto(self, o):
        assert isinstance(o, descriptor_pb2.MethodDescriptorProto)
        d = OrderedDict()
        if hasattr(o, 'name'):
            d['name'] = o.name
        if hasattr(o, 'input_type'):
            d['input_type'] = o.input_type
        if hasattr(o, 'output_type'):
            d['output_type'] = o.output_type
        if hasattr(o, 'options'):
            d['options'] = self.parse_method_options(o.options)
        d['client_streaming'] = getattr(o, 'client_streamin', False)
        d['server_streaming'] = getattr(o, 'server_streamin', False)
        return d

    def parse_method_options(self, o):
        assert isinstance(o, descriptor_pb2.MethodOptions)
        d = OrderedDict()
        d['deprecated'] = getattr(o, 'deprecated', False)
        d['uninterpreted_option'] = [self.parse_uninterpreted_option(x) for x
                                     in o.uninterpreted_option]
        extensions = dict(
            (k.full_name, self.parse_method_extension(k.full_name, v))
             for k, v
             in o.Extensions._extended_message._fields.items()
            if k.full_name !=
            'google.protobuf.MethodOptions.uninterpreted_option' )
        if extensions:
            d['extensions'] = extensions
        return d

    def parse_method_extension(self, full_name, o):
        if full_name == 'google.api.http':
            d = self.parse_http_rule(o)
        else:
            pass  # ignore unrecognized extensions
        return d

    def parse_http_rule(self, o):
        assert isinstance(o, http_pb2.HttpRule)
        d = OrderedDict()
        if o.get:
            method, path = 'get', o.get
        elif o.put:
            method, path = 'put', o.put
        elif o.post:
            method, path = 'post', o.post
        elif o.delete:
            method, path = 'delete', o.delete
        elif o.patch:
            method, path = 'patch', o.patch
        else:
            custom = self.parse_custom_http_pattern(o.custom)
            method, path = custom['kind'], custom['path']
        d['method'] = method
        d['path'] = path
        d['body'] = o.body
        return d

    def parse_custom_http_pattern(self, o):
        assert isinstance(o, http_pb2.CustomHttpPattern)
        d = OrderedDict()
        d['kind'] = o.kind
        d['path'] = o.path
        return d

    def parse_oneof_description_proto(self, o):
        raise NotImplementedError()

    def parse_optimize_mode(self, o):
        assert isinstance(o, int)
        return OptimizeMode(o).name

    def parse_options(self, o):
        assert isinstance(o, descriptor_pb2.FileOptions)
        d = OrderedDict()
        if hasattr(o, 'java_package'):
            d['java+package'] = o.java_package
        if hasattr(o, 'java_outer_classname'):
            d['java_outer_classname'] = o.java_outer_classname
        d['java_multiple_files'] = getattr(o, 'java_multiple_files', False)
        d['java_generate_equals_and_hash'] = getattr(
            o, 'java_generate_equals_and_hash', False)
        d['java_string_check_utf8'] = getattr(
            o, 'java_string_check_utf8', False)
        d['optimize_for'] = self.parse_optimize_mode(
            getattr(o, 'optimize_for', OptimizeMode.SPEED))
        if hasattr(o, 'go_package'):
            d['go_package'] = o.go_package
        d['cc_generic_services'] = getattr(o, 'cc_generic_services', False)
        d['java_generic_services'] = getattr(o, 'java_generic_services', False)
        d['py_generic_services'] = getattr(o, 'py_generic_services', False)
        d['deprecated'] = getattr(o, 'deprecated', False)
        d['cc_enable_arenas'] = getattr(o, 'cc_enable_arenas', False)
        if hasattr(o, 'objc_class_prefix'):
            d['objc_class_prefix'] = o.objc_class_prefix
        if hasattr(o, 'csharp_namespace'):
            d['csharp_namespace'] = o.csharp_namespace
        d['uninterpreted_option'] = [self.parse_uninterpreted_option(x) for x
                                     in o.uninterpreted_option]
        return d

    def parse_reserved_range(self, o):
        print type(o)
        print [f for f in dir(o) if f[0].lower() == f[0] and f[0] != '_']
        raise NotImplementedError()

    def parse_service(self, o):
        assert isinstance(o, descriptor_pb2.ServiceDescriptorProto)
        d = OrderedDict()
        if hasattr(o, 'name'):
            d['name'] = o.name
        d['method'] = [self.parse_method_descriptor_proto(x) for x in
                       o.method]
        if hasattr(o, 'options'):
            d['options'] = self.parse_service_options(o.options)
        return d

    def parse_service_options(self, o):
        assert isinstance(o, descriptor_pb2.ServiceOptions)
        d = OrderedDict()
        d['deprecated'] = getattr(o, 'deprecated', False)
        d['uninterpreted_option'] = [self.parse_uninterpreted_option(x) for x
                                     in o.uninterpreted_option]
        return d

    def parse_source_code_info(self, o):
        assert isinstance(o, descriptor_pb2.SourceCodeInfo)

        def is_location_empty(l):
            return not (
                l['leading_comments'] or
                l['trailing_comments'] or
                l['leading_detached_comments'])

        d = OrderedDict()
        locations = (self.parse_location(x) for x in o.location)
        if self.ignore_empty_source_code_info:
            locations = [l for l in locations if not is_location_empty(l)]
        d['location'] = locations
        return d

    def parse_type(self, o):
        isinstance(o, int)
        return Type(o).name

    def parse_uninterpreted_option(self, o):
        print (type(o))
        print [f for f in dir(o) if f[0].lower() == f[0] and f[0] != '_']
        raise NotImplementedError()

    def fold_all_comments(self):
        """ For each catalog entry, update appropriate nodes (dicts) with a
            '_description' node with any comments found in
            the source_code_info. Also, drop
        """
        for descriptor in self.catalog.values():
            self.fold_comments_in(descriptor)

    def fold_comments_in(self, descriptor):
        assert isinstance(descriptor, dict)

        locations = descriptor.get('source_code_info', {}).get('location', [])
        for location in locations:
            path = location['path']
            comments = ''.join([
                location['leading_comments'].strip(' '),
                location['trailing_comments'].strip(' '),
                ''.join(block.strip(' ') for block
                          in location['leading_detached_comments'])
            ]).strip()
            print path, '->', comments

            root_path_map = {
                4: (self.find_in_message_type, 'message_type'),
                6: (self.find_in_service, 'service')
            }

            index = path.pop(0)
            finder, key = root_path_map.get(index, (None, None))
            if finder is not None:
                node = finder(descriptor[key], path)
                node['_description'] = comments

        # remove source_code_info
        del descriptor['source_code_info']

    def find_in_message_type(self, message_types, path):
        index = path.pop(0)
        message_type = message_types[index]
        if not path:
            return message_type

        path_map = {
            2: (self.find_in_field, 'field'),
            4: (self.find_in_enum_type, 'enum_type')
        }
        index = path.pop(0)
        finder, key = path_map.get(index, (None, None))
        if finder is not None:
            return finder(message_type[key], path)
        raise NotImplementedError()

    def find_in_methods(self, methods, path):
        index = path.pop(0)
        method = methods[index]
        if not path:
            return method
        raise NotImplementedError()

    def find_in_service(self, services, path):
        index = path.pop(0)
        service = services[index]
        if not path:
            return service
        path_map = {
            2: (self.find_in_methods, 'method')
        }
        index = path.pop(0)
        finder, key = path_map.get(index, (None, None))
        if finder is not None:
            return finder(service[key], path)
        raise NotImplementedError()

    def find_in_field(self, fields, path):
        index = path.pop(0)
        field = fields[index]
        if not path:
            return field
        raise NotImplementedError()

    def find_in_enum_type(self, enum_types, path):
        index = path.pop(0)
        enum_type = enum_types[index]
        if not path:
            return enum_type
        path_map = {
            2: (self.find_in_enum_values, 'value')
        }
        index = path.pop(0)
        finder, key = path_map.get(index, (None, None))
        if finder is not None:
            return finder(enum_type[key], path)
        raise NotImplementedError()

    def find_in_enum_values(self, enum_values, path):
        index = path.pop(0)
        enum_value = enum_values[index]
        if not path:
            return enum_value
        raise NotImplementedError()


if __name__ == '__main__':
    # load desc into binary string
    from voltha.core.protos import voltha_pb2

    desc_dir = os.path.dirname(inspect.getfile(voltha_pb2))
    desc_file = os.path.join(desc_dir, 'voltha.desc')
    with open(desc_file, 'rb') as f:
        descriptor_blob = f.read()
    print 'read desc blob of {} bytes'.format(len(descriptor_blob))

    parser = DescriptorParser()
    parser.load_descriptor(descriptor_blob)
    parser.fold_all_comments()
    print dumps(parser.get_catalog(), indent=4)


