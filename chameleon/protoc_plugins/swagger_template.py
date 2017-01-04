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
import re
from collections import OrderedDict
from copy import copy

from google.protobuf.descriptor import FieldDescriptor

re_path_param = re.compile(r'/{([^{]+)}')
re_segment = re.compile(r'/(?P<absolute>[^{}/]+)|(?P<symbolic>{[^}]+})')


class DuplicateMethodAndPathError(Exception): pass
class ProtobufCompilationFailedError(Exception): pass
class InvalidPathArgumentError(Exception): pass


def native_descriptors_to_swagger(native_descriptors):
    """
    Generate a swagger data dict from the native descriptors extracted
    from protobuf file(s).
    :param native_descriptors:
        Dict as extracted from proto file descriptors.
        See DescriptorParser and its parse_file_descriptors() method.
    :return: dict ready to be serialized to JSON as swagger.json file.
    """

    # gather all top-level and nested message type definitions and build map
    message_types_dict = gather_all_message_types(native_descriptors)
    message_type_names = set(message_types_dict.iterkeys())

    # create similar map for all top-level and nested enum definitions
    enum_types_dict = gather_all_enum_types(native_descriptors)
    enum_type_names = set(enum_types_dict.iterkeys())

    # make sure none clashes and generate set of all names (for sanity checks)
    assert not message_type_names.intersection(enum_type_names)
    all_type_names = message_type_names.union(enum_type_names)
    all_types = {}
    all_types.update(message_types_dict)
    all_types.update(enum_types_dict)

    # gather all method definitions and collect all referenced input/output
    # types
    types_referenced, methods_dict = gather_all_methods(native_descriptors)

    # process all directly and indirectly referenced types into JSON schema
    # type definitions
    definitions = generate_definitions(types_referenced, all_types)

    # process all method and generate the swagger path entries
    paths = generate_paths(methods_dict, definitions)

    # static part
    # last descriptor is assumed to be the top-most one
    root_descriptor = native_descriptors[-1]
    swagger = {
        'swagger': "2.0",
        'info': {
            'title': root_descriptor['name'],
            'version': "version not set"
        },
        'schemes': ["http", "https"],
        'consumes': ["application/json"],
        'produces': ["application/json"],
        'paths': paths,
        'definitions': definitions
    }

    return swagger


def gather_all_message_types(descriptors):
    return dict(
        (full_name, message_type)
        for full_name, message_type
        in iterate_message_types(descriptors)
    )


def gather_all_enum_types(descriptors):
    return dict(
        (full_name, enum_type)
        for full_name, enum_type
        in iterate_enum_types(descriptors)
    )


def gather_all_methods(descriptors):
    types_referenced = set()
    methods = OrderedDict()
    for full_name, service, method in iterate_methods(descriptors):
        methods[full_name] = (service, method)
        types_referenced.add(method['input_type'].strip('.'))
        types_referenced.add(method['output_type'].strip('.'))
    return types_referenced, methods


def iterate_methods(descriptors):
    for descriptor in descriptors:
        package = descriptor['package']
        for service in descriptor.get('service', []):
            service_prefix = package + '.' + service['name']
            for method in service.get('method', []):
                # skip methods that do not have http options
                options = method['options']
                if options.has_key('http'):
                    full_name = service_prefix + '.' + method['name']
                    yield full_name, service, method


def iterate_for_type_in(message_types, prefix):
    for message_type in message_types:
        full_name = prefix + '.' + message_type['name']
        yield full_name, message_type
        for nested_full_name, nested in iterate_for_type_in(
                message_type.get('nested_type', []), full_name):
            yield nested_full_name, nested


def iterate_message_types(descriptors):
    for descriptor in descriptors:
        package = descriptor['package']
        top_types = descriptor.get('message_type', [])
        for full_name, message_type in iterate_for_type_in(top_types, package):
            yield full_name, message_type


def iterate_enum_types(descriptors):
    for descriptor in descriptors:
        package = descriptor['package']
        for enum in descriptor.get('enum_type', []):
            enum_full_name = package + '.' + enum['name']
            yield enum_full_name, enum
        top_types = descriptor.get('message_type', [])
        for full_name, message_type in iterate_for_type_in(top_types, package):
            for enum in message_type.get('enum_type', []):
                enum_full_name = full_name + '.' + enum['name']
                yield enum_full_name, enum


def generate_definitions(types_referenced, types):
    """Walk all the referenced types and for each, generate a JSON schema
       definition. These may also refer to other types, so keep the needed
       set up-to-date.
    """
    definitions = {}
    wanted = copy(types_referenced)
    while wanted:
        full_name = wanted.pop()
        type = types[full_name]
        definition, types_referenced = make_definition(type, types)
        definitions[full_name] = definition
        for type_referenced in types_referenced:
            if not definitions.has_key(type_referenced):
                wanted.add(type_referenced)
    return definitions


def make_definition(type, types):
    if type['_type'] == 'google.protobuf.EnumDescriptorProto':
        return make_enum_definition(type), set()
    else:
        return make_object_definition(type, types)


def make_enum_definition(type):

    def make_value_desc(enum_value):
        txt = ' - {}'.format(enum_value['name'])
        description = enum_value.get('_description', '')
        if description:
            txt += ': {}'.format(description)
        return txt

    string_values = [v['name'] for v in type['value']]
    default = type['value'][0]['name']
    description = (
        (type.get('_description', '') or type['name'])
        + '\nValid values:\n'
        + '\n'.join(make_value_desc(v) for v in type['value'])
    )

    definition = {
        'type': 'string',
        'enum': string_values,
        'default': default,
        'description': description
    }

    return definition


def make_object_definition(type, types):

    definition = {
        'type': 'object'
    }

    referenced = set()
    properties = {}
    for field in type.get('field', []):
        field_name, property, referenced_by_field = make_property(field, types)
        properties[field_name] = property
        referenced.update(referenced_by_field)

    if properties:
        definition['properties'] = properties

    if type.has_key('_description'):
        definition['description'] = type['_description']

    return definition, referenced


def make_property(field, types):

    referenced = set()

    repeated = field['label'] == FieldDescriptor.LABEL_REPEATED

    def check_if_map_entry(type_name):
        type = types[type_name]
        if type.get('options', {}).get('map_entry', False):
            _, property, __ = make_property(type['field'][1], types)
            return property

    if field['type'] == FieldDescriptor.TYPE_MESSAGE:

        type_name = field['type_name'].strip('.')

        maybe_map_value_type = check_if_map_entry(type_name)
        if maybe_map_value_type:
            # map-entries are inlined
            repeated = False
            property = {
                'type': 'object',
                'additionalProperties': maybe_map_value_type
            }

        elif type_name == 'google.protobuf.Timestamp':
            # time-stamp is mapped back to JSON schema date-time string
            property = {
                'type': 'string',
                'format': 'date-time'
            }

        else:
            # normal nested object field
            property = {
                '$ref': '#/definitions/{}'.format(type_name)
            }
            referenced.add(type_name)

    elif field['type'] == FieldDescriptor.TYPE_ENUM:
        type_name = field['type_name'].strip('.')
        property = {
            '$ref': '#/definitions/{}'.format(type_name)
        }
        referenced.add(type_name)

    elif field['type'] == FieldDescriptor.TYPE_GROUP:
        raise NotImplementedError()

    else:
        _type, format = TYPE_MAP[field['type']]
        property = {
            'type': _type,
            'format': format
        }

    if repeated:
        property = {
            'type': 'array',
            'items': property
        }

    if field.has_key('_description'):
        property['description'] = field['_description']

    return field['name'], property, referenced


def generate_paths(methods_dict, definitions):

    paths = {}

    def _iterate():
        for full_name, (service, method) in methods_dict.iteritems():
            http_option = method['options']['http']
            yield service, method, http_option
            for binding in http_option.get('additional_bindings', []):
                yield service, method, binding

    def prune_path(path):
        """rid '=<stuff>' pattern from path symbolic segments"""
        segments = re_segment.findall(path)
        pruned_segments = []
        for absolute, symbolic in segments:
            if symbolic:
                full_symbol = symbolic[1:-1]
                pruned_symbol = full_symbol.split('=', 2)[0]
                pruned_segments.append('{' + pruned_symbol + '}')
            else:
                pruned_segments.append(absolute)

        return '/' + '/'.join(pruned_segments)

    def lookup_input_type(input_type_name):
        return definitions[input_type_name.strip('.')]

    def lookup_type(input_type, field_name):
        local_field_name, _, rest = field_name.partition('.')
        properties = input_type['properties']
        if not properties.has_key(local_field_name):
            raise InvalidPathArgumentError(
                'Input type has no field {}'.format(field_name))
        field = properties[local_field_name]
        if rest:
            field_type = field.get('type', 'object')
            assert field_type == 'object', (
                'Nested field name "%s" refers to field that of type "%s" '
                '(.%s should be nested object field)'
                % (field_name, field_type, local_field_name))
            ref = field['$ref']
            assert ref.startswith('#/definitions/')
            type_name = ref.replace('#/definitions/', '')
            nested_input_type = lookup_input_type(type_name)
            return lookup_type(nested_input_type, rest)
        else:
            return field['type'], field['format']

    def make_entry(service, method, http):
        parameters = []
        verb = None
        for verb_candidate in ('get', 'delete', 'patch', 'post', 'put'):
            if verb_candidate in http:
                verb, path = verb_candidate, http[verb_candidate]
                break
        if 'custom' in http:
            assert verb is None
            verb = http['custom']['kind']
            path = http['custom']['path']
        assert verb is not None
        path = prune_path(path)

        # for each symbolic segment in path, add a path parameter entry
        input_type = lookup_input_type(method['input_type'])
        for segment in re_path_param.findall(path):
            symbol = segment.split('=')[0]
            _type, format = lookup_type(input_type, symbol)
            parameters.append({
                'in': 'path',
                'name': symbol,
                'required': True,
                'type': _type,
                'format': format
            })

        if 'body' in http:
            if 'body' in http:  # TODO validate if body lists fields
                parameters.append({
                    'in': 'body',
                    'name': 'body',
                    'required': True,
                    'schema': {'$ref': '#/definitions/{}'.format(
                        method['input_type'].strip('.'))}
                })

        entry = {
            'operationId': method['name'],
            'tags': [service['name'],],
            'responses': {
                '200': {  # TODO: code is 201 and 209 in POST/DELETE?
                    'description': unicode(""),  # TODO: ever filled by proto?
                    'schema': {
                        '$ref': '#/definitions/{}'.format(
                        method['output_type'].strip('.'))
                    }
                },
                # TODO shall we prefill with standard error (verb specific),
                # such as 400, 403, 404, 409, 509, 500, 503 etc.
            }
        }

        if parameters:
            entry['parameters'] = parameters

        summary, description = extract_summary_and_description(method)
        if summary:
            entry['summary'] = summary
        if description:
            entry['description'] = description

        return path, verb, entry

    for service, method, http in _iterate():
        path, verb, entry = make_entry(service, method, http)
        path_dict = paths.setdefault(path, {})
        if verb in path_dict:
            raise DuplicateMethodAndPathError(
                'There is already a {} method defined for path ({})'.format(
                verb, path))
        path_dict[verb] = entry

    return paths


def extract_summary_and_description(obj):
    """
    Break raw _description field (if present) into a summary line and/or
    detailed description text as follows:
    * if text is a single line (not counting white-spaces), then it is a
      summary and there is no detailed description.
    * if text starts with a non-empty line followied by an empty line followed
      by at least one non-empty line, that the 1s line is the summary and the
      lines after the empty line is the description.
    * in all other cases the text is considered a description and no summary
      is generated.
    """
    assert isinstance(obj, dict)
    summary, description = None, None
    text = obj.get('_description', '')
    if text:
        s, blank, d = (text.split('\n', 2) + ['', ''])[:3]  # so we can demux
        if not blank.strip():
            summary = s
            if d.strip():
                description = d
        else:
            description = text

    return summary, description


TYPE_MAP = {
        FieldDescriptor.TYPE_BOOL: ('boolean', 'boolean'),
        FieldDescriptor.TYPE_BYTES: ('string', 'byte'),
        FieldDescriptor.TYPE_DOUBLE: ('number', 'double'),
        FieldDescriptor.TYPE_ENUM: ('string', 'string'),
        FieldDescriptor.TYPE_FIXED32: ('integer', 'int64'),
        FieldDescriptor.TYPE_FIXED64: ('string', 'uint64'),
        FieldDescriptor.TYPE_FLOAT: ('number', 'float'),
        FieldDescriptor.TYPE_INT32: ('integer', 'int32'),
        FieldDescriptor.TYPE_INT64: ('string', 'int64'),
        FieldDescriptor.TYPE_SFIXED32: ('integer', 'int32'),
        FieldDescriptor.TYPE_SFIXED64: ('string', 'int64'),
        FieldDescriptor.TYPE_STRING: ('string', 'string'),
        FieldDescriptor.TYPE_SINT32: ('integer', 'int32'),
        FieldDescriptor.TYPE_SINT64: ('string', 'int64'),
        FieldDescriptor.TYPE_UINT32: ('integer', 'int64'),
        FieldDescriptor.TYPE_UINT64: ('string', 'uint64'),
        # FieldDescriptor.TYPE_MESSAGE:
        # FieldDescriptor.TYPE_GROUP:
}
