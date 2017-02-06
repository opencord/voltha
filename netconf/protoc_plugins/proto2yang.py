#!/usr/bin/env python
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

"""protoc plugin to convert a protobuf schema to a yang schema

   - basic support for message, fields. enumeration, service, method

   - yang semantic rules needs to be implemented

   - to run this plugin :

   $ python -m grpc.tools.protoc -I.
   --plugin=protoc-gen-custom=./proto2yang.py --custom_out=. <proto file>.proto

   - the above will produce a <proto file>.yang file formatted for yang

   - two examples of proto that can be used in the same directory are
   yang.proto and addressbook.proto

"""

import sys

from google.protobuf.compiler import plugin_pb2 as plugin
from google.protobuf.descriptor_pb2 import DescriptorProto, \
    FieldDescriptorProto
from descriptor_parser import DescriptorParser
import copy
from netconf.constants import Constants as C
import yang_options_pb2

from google.protobuf.descriptor import FieldDescriptor

import jinja2

env = jinja2.Environment(extensions=["jinja2.ext.do", ], trim_blocks=True,
                         lstrip_blocks=True)

template_yang_definition = env.from_string("""
# Generated file; please do not edit

from structlog import get_logger

log = get_logger()

message_definitions = {
    {% for m in messages %}
    '{{ m.name }}': {{ m.fields }},
     {% if loop.last %}{% endif %}
    {% endfor %}
}

def get_fields(package, type_name, **kw):
    log.info('fields-request', type=type_name, package=package, **kw)
    full_name = ''.join([package, '-', type_name])
    if message_definitions.has_key(full_name):
        return message_definitions[full_name]
    else:
        return None

""")

template_yang = env.from_string("""
module {{ module.name }} {

    {% macro set_module_prefix(type) %}
        {% set found = [] %}
        {% for t in module.data_types %}
            {% if t.type == type %}
                {% if t.module != module.name %} {{ t.module }}:{{ type }};
                {% else %} {{ type }};
                {% endif %}
                {% do found.append(1) %}
            {% endif %}
        {% if loop.last %}
            {% if not found %} {{ type }}; {% endif %}
        {% endif %}
        {% endfor %}
    {% endmacro %}


    {% macro process_oneofs(oneofs, ref_msgs) %}

        {% for key, value in oneofs.iteritems() %}
        choice {{ key }} {
        {% for field in value %}
            case {{ field.name }} {
            {% if field.type_ref %}
                {% for dict_item in ref_msgs %}
                    {% if dict_item.name == field.type %}
                container {{ field.name }} {
                    uses {{ set_module_prefix(field.type) }}
                    description
                        "{{ field.description }}";
                        {% endif %}
                {% endfor %}
                }
            {% else %}
                leaf {{ field.name }} {
                    {% if field.type == "decimal64" %}
                    type {{ field.type }} {
                        fraction-digits 5;
                    }
                    {% else %}
                    type {{ set_module_prefix(field.type) }}
                        {% endif %}
                    description
                        "{{ field.description }}";
                }
            {% endif %}
            }
        {% endfor %}
        }
        {% endfor %}
    {% endmacro %}


    namespace "urn:opencord:params:xml:ns:voltha:{{ module.name }}";
    prefix {{ module.name }};

    {% for imp in module.imports %}
    import {{ imp.name }} { prefix {{ imp.name }} ; }
    {% endfor %}

    organization "CORD";
    contact
        " Any name";

    description
        "{{ module.description }}";

    revision "2016-11-15" {
        description "Initial revision.";
        reference "reference";
    }

    {% for enum in module.enums %}
    typedef {{ enum.name }} {
        type enumeration {
        {% for v in enum.value %}
            enum {{ v.name }} {
                description "{{ v.description }}";
            }
        {% endfor %}
        }
        description
            "{{ enum.description }}";
    }
    {% endfor %}

    {% for message in module.messages recursive %}
    {% if message.name in module.referred_messages %}
    grouping {{ message.name }} {
    {% else %}
    container {{ message.name }} {
    {% endif %}
        description
            "{{ message.description }}";
        {% for field in message.fields %}
        {% if field.type_ref %}
        {% for dict_item in module.referred_messages_with_keys %}
            {% if dict_item.name == field.type %}
                {% if not field.repeated %}
        container {{ field.name }} {
                {% else %}
        list {{ field.name }} {
            key "{{ dict_item.key }}";
            {% if not field.repeated %}
            max-elements 1;
            {% endif %}
            {% endif %}
            uses {{ set_module_prefix(field.type) }}
            description
                "{{ field.description }}";
        }
            {% endif %}
        {% endfor %}
        {% elif field.repeated %}
        list {{ field.name }} {
            key "{{ field.name }}";
            leaf {{ field.name }} {
                {% if field.type == "decimal64" %}
                type {{ field.type }} {
                   fraction-digits 5;
                }
                {% else %}
                type {{ set_module_prefix(field.type) }}
                {% endif %}
                description
                    "{{ field.description }}";
            }
            description
                "{{ field.description }}";
        }
        {% else %}
        leaf {{ field.name }} {
            {% if field.type == "decimal64" %}
            type {{ field.type }} {
               fraction-digits 5;
            }
            {% else %}
            type {{ set_module_prefix(field.type) }}
            {% endif %}
            description
                "{{ field.description }}";
        }
        {% endif %}

        {% endfor %}

        {% if message.oneofs %}
        {{ process_oneofs(message.oneofs, module.referred_messages_with_keys) }}
        {% endif %}

        {% for enum_type in message.enums %}
        typedef {{ enum_type.name }} {
            type enumeration {
            {% for v in enum_type.value %}
                enum {{ v.name }} {
                    description "{{ v.description }}";
                }
            {% endfor %}
            }
            description
                "{{ enum_type.description }}";
        }

        {% endfor %}
    {% if message.messages %}
    {{ loop (message.messages)|indent(4, false) }}
    {% endif %}
    }

    {% endfor %}
    {% for service in module.services %}
    {% if service.description %}
    /*  {{ service.description }}" */
    {% endif %}
    {% for method in service.methods %}
    rpc {{ service.service }}-{{ method.method }} {
        description
            "{{ method.description }}";
        {% if method.input %}
        input {
            {% if method.input_ref %}
            uses {{ set_module_prefix(method.input) }}
            {% else %}
            leaf {{ method.input }} {
                type {{ set_module_prefix(method.input) }}
            }
            {% endif %}
        }
        {% endif %}
        {% if method.output %}
        output {
            {% if method.output_ref %}
            uses {{ set_module_prefix(method.output) }}
            {% else %}
            leaf {{ method.output }} {
                type {{ set_module_prefix(method.output) }}
            }
            {% endif %}
        }
        {% endif %}
    }

    {% endfor %}

    {% endfor %}
}
""")


def traverse_field_options(fields, prefix):
    field_options = []
    for field in fields:
        assert isinstance(field, FieldDescriptorProto)
        full_name = prefix + '-' + field.name
        option = None
        if field.type == FieldDescriptor.TYPE_MESSAGE and field.label != \
                FieldDescriptor.LABEL_REPEATED:
            if field.options:
                for fd, val in field.options.ListFields():
                    if fd.full_name == 'voltha.yang_inline_node':
                        field_options.append(
                            {'name': full_name,
                             'option': fd.full_name,
                             'proto_name': val.id,
                             'proto_type': val.type
                             }
                        )
        return field_options


def traverse_message_options(message_types, prefix):
    message_options = []
    for message_type in message_types:
        assert isinstance(message_type, DescriptorProto)
        full_name = prefix + '-' + message_type.name
        option_rules = []

        options = message_type.options
        if options:
            for fd, val in options.ListFields():
                if fd.full_name in ['voltha.yang_child_rule',
                                    'voltha.yang_message_rule']:
                    option_rules.append({
                        'name': fd.full_name,
                        'value': val
                    })

        # parse fields for options
        field_options = traverse_field_options(message_type.field,
                                               full_name)

        # parse nested messages
        nested_messages_options = []
        nested = message_type.nested_type
        if nested:
            nested_messages_options = traverse_message_options(nested,
                                                               full_name)

        if option_rules or nested_messages_options or field_options:
            message_options.append(
                {
                    'name': full_name,
                    'options': option_rules,
                    'field_options': field_options,
                    'nested_options': nested_messages_options,
                }
            )
    return message_options


def get_message_options(name, options):
    result = None
    for opt in options:
        if opt['name'] == name:
            return opt['options']
        if opt['nested_options']:
            result = get_message_options(name, opt['nested_options'])
        if result:
            return result


def get_field_options(name, options):
    result = None
    for opt in options:
        if opt['field_options']:
            for field_opt in opt['field_options']:
                if field_opt['name'] == name:
                    result = field_opt
        if opt['nested_options']:
            result = get_field_options(name, opt['nested_options'])
        if result:
            return result


def traverse_options(proto_file):
    package = proto_file.name
    prefix = package.replace('.proto', '')
    if proto_file.message_type:
        message_options = traverse_message_options(proto_file.message_type,
                                                   prefix)
        return message_options


def traverse_messages(message_types, prefix, referenced_messages):
    messages = []
    for message_type in message_types:
        assert message_type['_type'] == 'google.protobuf.DescriptorProto'

        full_name = prefix + '-' + message_type['name']
        name = message_type['name']

        # parse the fields
        oneofs, fields = traverse_fields(message_type.get('field', []),
                                         full_name, referenced_messages)

        # parse the enums
        enums = traverse_enums(message_type.get('enum_type', []), full_name)

        # parse nested messages
        nested = message_type.get('nested_type', [])
        nested_messages = traverse_messages(nested, full_name,
                                            referenced_messages)

        messages.append(
            {
                'full_name': full_name,
                'name': name,
                'fields': fields,
                'oneofs': oneofs,
                'enums': enums,
                'messages': nested_messages,
                'description': remove_unsupported_characters(
                    message_type.get('_description', '')),
            }
        )
    return messages


def traverse_fields(fields_desc, prefix, referenced_messages):
    fields = []
    oneofs = {}
    for field in fields_desc:
        # if field.get('oneof_index', None) >= 0:
        #     print '{},{}'.format(field.get('name', ''), field.get('number'))
        assert field['_type'] == 'google.protobuf.FieldDescriptorProto'
        yang_base_type = is_base_type(field['type'])
        _type = get_yang_type(field)
        if not yang_base_type:
            referenced_messages.append(_type)
        # add to referred messages also if it is an enumeration type
        if is_enumeration(field['type']):
            referenced_messages.append(_type)

        if field.get('oneof_index', None) >= 0:
            # Oneof fields
            key = ''.join(['choice_', str(field['oneof_index'])])
            if not oneofs.has_key(key):
                oneofs[key] = []
            oneofs[key].append(
                {
                    'full_name': prefix + '-' + field.get('name', ''),
                    'oneof_index': field.get('oneof_index', None),
                    'name': field.get('name', ''),
                    'label': field.get('label', ''),
                    'repeated': field[
                                    'label'] == FieldDescriptor.LABEL_REPEATED,
                    'number': field.get('number', ''),
                    'options': field.get('options', ''),
                    'type_name': field.get('type_name', ''),
                    'type': _type,
                    'type_ref': not yang_base_type,
                    'description': remove_unsupported_characters(field.get(
                        '_description', ''))
                }
            )
        else:
            fields.append(
                {
                    'full_name': prefix + '-' + field.get('name', ''),
                    'name': field.get('name', ''),
                    'label': field.get('label', ''),
                    'repeated': field[
                                    'label'] == FieldDescriptor.LABEL_REPEATED,
                    'number': field.get('number', ''),
                    'options': field.get('options', ''),
                    'type_name': field.get('type_name', ''),
                    'type': _type,
                    'type_ref': not yang_base_type,
                    'description': remove_unsupported_characters(field.get(
                        '_description', ''))
                }
            )
    # print oneofs
    return oneofs, fields


def traverse_enums(enums_desc, prefix):
    enums = []
    for enum in enums_desc:
        assert enum['_type'] == 'google.protobuf.EnumDescriptorProto'
        full_name = prefix + '-' + enum.get('name', '')
        name = enum.get('name', '')
        enums.append(
            {
                'full_name': full_name,
                'name': name,
                'value': enum.get('value', ''),
                'description': remove_unsupported_characters(enum.get(
                    '_description', ''))
            }
        )
    return enums


def traverse_services(service_desc, referenced_messages):
    services = []
    for service in service_desc:
        methods = []
        for method in service.get('method', []):
            assert method['_type'] == 'google.protobuf.MethodDescriptorProto'

            input_name = method.get('input_type')
            input_ref = False
            if not is_base_type(input_name):
                input_name = remove_first_character_if_match(input_name, '.')
                # input_name = input_name.replace(".", "-")
                input_name = input_name.split('.')[-1]
                referenced_messages.append(input_name)
                input_ref = True

            output_name = method.get('output_type')
            output_ref = False
            if not is_base_type(output_name):
                output_name = remove_first_character_if_match(output_name, '.')
                # output_name = output_name.replace(".", "-")
                output_name = output_name.split('.')[-1]
                referenced_messages.append(output_name)
                output_ref = True

            methods.append(
                {
                    'method': method.get('name', ''),
                    'input': input_name,
                    'input_ref': input_ref,
                    'output': output_name,
                    'output_ref': output_ref,
                    'description': remove_unsupported_characters(method.get(
                        '_description', '')),
                    'server_streaming': method.get('server_streaming',
                                                   False) == True
                }
            )
        services.append(
            {
                'service': service.get('name', ''),
                'methods': methods,
                'description': remove_unsupported_characters(service.get(
                    '_description', '')),
            }
        )
    return services


def rchop(thestring, ending):
    if thestring.endswith(ending):
        return thestring[:-len(ending)]
    return thestring


def traverse_desc(descriptor):
    referenced_messages = []
    name = rchop(descriptor.get('name', ''), '.proto')
    package = descriptor.get('package', '')
    description = descriptor.get('_description', '')
    messages = traverse_messages(descriptor.get('message_type', []),
                                 name, referenced_messages)
    enums = traverse_enums(descriptor.get('enum_type', []), name)
    services = traverse_services(descriptor.get('service', []),
                                 referenced_messages)

    # Get a list of type definitions (messages, enums) defined in this
    # descriptor
    defined_types = [m['name'].split('/')[-1] for m in messages] + \
                    [e['name'].split('/')[-1] for e in enums]

    data = {
        'name': name.split('/')[-1],
        'package': package,
        'description': description,
        'messages': messages,
        'enums': enums,
        'services': services,
        'defined_types': defined_types,
        'referenced_messages': list(set(referenced_messages)),
    }
    return data


# For now, annotations are added to first level messages only.
# Therefore, at this time no need to tackle nested messages.
def move_message_to_parent_level(message, messages, enums):
    new_message = []
    new_enum = copy.deepcopy(enums)
    for msg in messages:
        if msg['full_name'] == message['full_name']:
            # Move all sub messages and enums to top level
            if msg['messages']:
                new_message = new_message + copy.deepcopy(msg['messages'])
            if msg['enums']:
                new_enum = new_enum + copy.deepcopy(msg['enums'])

            # if the message has some fields then enclose them in a container
            if msg['fields']:
                new_message.append(
                    {
                        'full_name': msg['full_name'],
                        'name': msg['name'],
                        'fields': msg['fields'],
                        'oneofs': msg['oneofs'],
                        'description': msg['description'],
                        'messages': [],
                        'enums': []
                    }
                )
        else:
            new_message.append(msg)

    return new_message, new_enum


def update_messages_per_annotations_rule(options, messages, enums):
    new_messages = messages
    new_enums = enums
    # Used when a message needs to exist both as a type and a container
    duplicate_messages = []
    for message in messages:
        opts = get_message_options(message['full_name'], options)
        if opts:
            for opt in opts:
                if opt['name'] == 'voltha.yang_child_rule':
                    new_messages, new_enums = move_message_to_parent_level(
                        message,
                        new_messages, new_enums)
                elif opt['name'] == 'voltha.yang_message_rule':
                    # create a duplicate message
                    # TODO: update references to point to the
                    duplicate_messages.append(message['name'])
                    clone = copy.deepcopy(message)
                    clone['full_name'] = ''.join(
                        [clone['full_name'], '_', 'grouping'])
                    clone['name'] = ''.join([clone['name'], '_', 'grouping'])
                    new_messages = new_messages + [clone]

    return new_messages, new_enums, duplicate_messages


def inline_field(message, field, option, messages):
    new_message = copy.deepcopy(message)
    new_message['fields'] = []
    for f in message['fields']:
        if f['full_name'] == field['full_name']:
            # look for the message this field referred to.
            # Addresses only top-level messages
            for m in messages:
                # 'proto_type' is the name of the message type this field
                # refers to
                if m['full_name'] == option['proto_type']:
                    # Copy all content of m into the field
                    new_message['fields'] = new_message['fields'] + \
                                            copy.deepcopy(m['fields'])
                    new_message['oneofs'] = new_message['oneofs'].update(
                        copy.deepcopy(m['oneofs']))
                    new_message['enums'] = new_message['enums'] + \
                                           copy.deepcopy(m['enums'])
                    new_message['messages'] = new_message['messages'] + \
                                              copy.deepcopy(m['messages'])
        else:
            new_message['fields'].append(f)

    return new_message


# Address only annotations on top-level messages, i.e. no nested messages
def update_fields_per_annotations_rule(options, messages):
    new_messages = []
    for message in messages:
        new_message = None
        for field in message['fields']:
            opt = get_field_options(field['full_name'], options)
            if opt:
                if opt['option'] == 'voltha.yang_inline_node':
                    new_message = inline_field(message, field, opt, messages)

        if new_message:
            new_messages.append(new_message)
        else:
            new_messages.append(message)

    return new_messages


def set_messages_keys(messages):
    for message in messages:
        message['key'] = _get_message_key(message, messages)
        if message['messages']:
            set_messages_keys(message['messages'])


def _get_message_key(message, messages):
    # assume key is first yang base type field
    for field in message['fields']:
        if not field['type_ref']:
            return field['name']
        else:
            # if the field name is a message then loop for the key in that
            # message
            ref_message = _get_message(field['type'], messages)
            if ref_message:
                return _get_message_key(ref_message, messages)

    # no key yet - search nested messaged
    for m in message['messages']:
        key = _get_message_key(m, messages)
        if key is not None:
            return key
    else:
        return None


def _get_message(name, messages):
    for m in messages:
        if m['name'] == name:
            return m
    return None


def get_message_key(message_name, messages):
    for message in messages:
        if message_name == message['name']:
            return message['key']
        if message['messages']:
            return get_message_key(message_name, message['messages'])
    return None


def update_module_imports(module):
    used_imports = set()
    for ref_msg in module['referenced_messages']:
        for type_dict in module['data_types']:
            if ref_msg == type_dict['type']:
                if module['name'] != type_dict['module']:
                    used_imports.add(type_dict['module'])
                break
    module['imports'] = [{'name': i} for i in used_imports]


def update_referred_messages(all_referred_messages, all_duplicate_messages):
    new_referred_messages = []
    for ref in all_referred_messages:
        if ref in all_duplicate_messages:
            new_referred_messages.append(''.join([ref, '_grouping']))
        else:
            new_referred_messages.append(ref)

    return new_referred_messages


def update_message_references_based_on_duplicates(duplicates, messages):
    # Duplicates has a list of messages that exist both as a grouping and as
    # a container.   All reference to the container name by existing fields
    # should be changed to the grouping name instead
    for m in messages:
        for f in m['fields']:
            if f['type'] in duplicates:
                f['type'] = ''.join([f['type'], '_grouping'])
        if m['messages']:
            update_message_references_based_on_duplicates(duplicates,
                                                          m['messages'])


def update_servic_references_based_on_duplicates(duplicates, services):
    # Duplicates has a list of messages that exist both as a grouping and as
    # a container.   All reference to the container name by existing fields
    # should be changed to the grouping name instead
    for s in services:
        for m in s['methods']:
            if m['input_ref'] and m['input'] in duplicates:
                m['input'] = ''.join([m['input'], '_grouping'])
            if m['output_ref'] and m['output'] in duplicates:
                m['output'] = ''.join([m['output'], '_grouping'])


def get_module_name(type, data_types):
    for t in data_types:
        # Verify both the type and when it is a referred type as they will
        # both be in the same module
        if t['type'] in [type, ''.join([type, '_grouping'])]:
            return t['module']

    # return the default module name
    return 'voltha'


def get_message_defs(messages, data_types, msg_response):
    for msg in messages:
        fields = []

        # First process the fields as they appear before the oneofs in the
        # YANG module
        for f in msg['fields']:
            module_name = '.'
            if f['type_ref']:
                module_name = get_module_name(f['type'], data_types)
            fields.append(
                {
                    'oneof_key': None,
                    'repeated': f['repeated'],
                    'name': f['name'],
                    'full_name': f['full_name'],
                    'type': f['type'],
                    'type_ref': f['type_ref'],
                    'module': module_name
                }
            )

        # Now process the oneofs
        if msg['oneofs']:
            for key, value in msg['oneofs'].iteritems():
                # Value contains a list of fields
                for v in value:
                    module_name = '.'
                    if v['type_ref']:
                        module_name = get_module_name(v['type'], data_types)
                    fields.append(
                        {
                            'oneof_key': key,
                            'repeated': v['repeated'],
                            'name': v['name'],
                            'full_name': v['full_name'],
                            'type': v['type'],
                            'type_ref': v['type_ref'],
                            'module': module_name
                        }
                    )

        msg_response.append({
            'name': msg['full_name'],
            'fields': fields
        })

        if msg['messages']:
            get_message_defs(msg['messages'], data_types, msg_response)


def build_yang_definitions(all_proto_data):
    msg_response = []
    for proto_data in all_proto_data:
        get_message_defs(proto_data['module']['messages'], proto_data[
            'module']['data_types'], msg_response)

    return msg_response


def generate_code(request, response):
    assert isinstance(request, plugin.CodeGeneratorRequest)

    parser = DescriptorParser()

    # First process the proto file with the imports
    all_defined_types = []
    all_proto_data = []
    all_referred_messages = []
    all_messages = []
    all_duplicate_messages = []
    for proto_file in request.proto_file:
        options = traverse_options(proto_file)
        # print options

        native_data = parser.parse_file_descriptor(proto_file,
                                                   type_tag_name='_type',
                                                   fold_comments=True)

        # Consolidate the defined types across imports
        yang_data = traverse_desc(native_data)

        duplicates = []
        if options:
            new_messages, new_enums, duplicates = \
                update_messages_per_annotations_rule(
                    options, yang_data['messages'], yang_data['enums'])

            new_messages = update_fields_per_annotations_rule(options,
                                                              new_messages)

            # TODO:  Need to do the change across all schema files.  Not
            # needed as annotations are single file based for now
            if duplicates:
                update_message_references_based_on_duplicates(duplicates,
                                                              new_messages)
                update_servic_references_based_on_duplicates(duplicates,
                                                             yang_data[
                                                                 'services'])

            yang_data['messages'] = new_messages
            yang_data['enums'] = new_enums

        for type in yang_data['defined_types']:
            all_defined_types.append(
                {
                    'type': type,
                    'module': yang_data['name']
                }
            )

        all_proto_data.append(
            {
                'file_name': '{}'.format(proto_file.name.split(
                    '/')[-1].replace('.proto', '.yang')),
                'module': yang_data
            }
        )

        # Consolidate all duplicate messages
        all_duplicate_messages = all_duplicate_messages + duplicates

        # Consolidate referred messages across imports
        all_referred_messages = all_referred_messages + yang_data[
            'referenced_messages']

        # consolidate all messages
        all_messages = all_messages + yang_data['messages']

    # # Update the referred_messages
    all_referred_messages = update_referred_messages(all_referred_messages,
                                                     all_duplicate_messages)

    # Set the message keys - required for List definitions (repeated label)
    set_messages_keys(all_messages)
    unique_referred_messages_with_keys = []
    for m in all_messages:
        unique_referred_messages_with_keys.append(
            {
                'name': m['name'],
                'key': m['key']
            }
        )

    # print_referred_msg(unique_referred_messages_with_keys)
    # Create the files
    for proto_data in all_proto_data:
        f = response.file.add()
        f.name = proto_data['file_name']
        proto_data['module']['data_types'] = all_defined_types
        proto_data['module']['referred_messages'] = all_referred_messages
        proto_data['module'][
            'referred_messages_with_keys'] = unique_referred_messages_with_keys
        proto_data['module']['duplicates'] = all_duplicate_messages
        update_module_imports(proto_data['module'])
        # print_message(proto_data['module']['messages'])
        f.content = template_yang.render(module=proto_data['module'])

    # Create a summary of the YANG definitions with the order in which the
    # attributes appear in each message.  It would have been easier to sort
    # the attributes in the YANG files and then sort the XML tags when a
    # XML response is built.  However, this strategy won't work with the oneof
    # protobuf definition.  The attributes in the oneof need to be kept
    # together and as such will break the sort strategy.
    msg_response = build_yang_definitions(all_proto_data)
    yang_def = response.file.add()
    yang_def.name = C.YANG_MESSAGE_DEFINITIONS_FILE
    yang_def.content = template_yang_definition.render(messages=msg_response)


def get_yang_type(field):
    type = field['type']
    if type in YANG_TYPE_MAP.keys():
        _type, _ = YANG_TYPE_MAP[type]
        if _type in ['enumeration', 'message', 'group']:
            return field['type_name'].split('.')[-1]
        else:
            return _type
    else:
        return type


def is_enumeration(type):
    if type in YANG_TYPE_MAP.keys():
        _type, _ = YANG_TYPE_MAP[type]
        return _type in ['enumeration']
    return False


def is_base_type(type):
    # check numeric value of the type first
    if type in YANG_TYPE_MAP.keys():
        _type, _ = YANG_TYPE_MAP[type]
        return _type not in ['message', 'group']
    else:
        # proto name of the type
        result = [_format for (_, _format) in YANG_TYPE_MAP.values() if
                  _format == type and _format not in ['message',
                                                      'group']]
        return len(result) > 0


def remove_unsupported_characters(text):
    unsupported_characters = ["{", "}", "[", "]", "\"", "\\", "*", "/", "<",
                              ">"]
    return ''.join([i if i not in unsupported_characters else ' ' for i in
                    text])


def remove_first_character_if_match(str, char):
    if str.startswith(char):
        return str[1:]
    return str


YANG_TYPE_MAP = {
    FieldDescriptor.TYPE_BOOL: ('boolean', 'boolean'),
    FieldDescriptor.TYPE_BYTES: ('binary', 'byte'),
    FieldDescriptor.TYPE_DOUBLE: ('decimal64', 'double'),
    FieldDescriptor.TYPE_ENUM: ('enumeration', 'enum'),
    FieldDescriptor.TYPE_FIXED32: ('int32', 'int64'),
    FieldDescriptor.TYPE_FIXED64: ('int64', 'uint64'),
    FieldDescriptor.TYPE_FLOAT: ('decimal64', 'float'),
    FieldDescriptor.TYPE_INT32: ('int32', 'int32'),
    FieldDescriptor.TYPE_INT64: ('int64', 'int64'),
    FieldDescriptor.TYPE_SFIXED32: ('int32', 'int32'),
    FieldDescriptor.TYPE_SFIXED64: ('int64', 'int64'),
    FieldDescriptor.TYPE_STRING: ('string', 'string'),
    FieldDescriptor.TYPE_SINT32: ('int32', 'int32'),
    FieldDescriptor.TYPE_SINT64: ('int64', 'int64'),
    FieldDescriptor.TYPE_UINT32: ('uint32', 'int64'),
    FieldDescriptor.TYPE_UINT64: ('uint64', 'uint64'),
    FieldDescriptor.TYPE_MESSAGE: ('message', 'message'),
    FieldDescriptor.TYPE_GROUP: ('group', 'group')
}

if __name__ == '__main__':
    # Read request message from stdin
    data = sys.stdin.read()

    # Parse request
    request = plugin.CodeGeneratorRequest()
    request.ParseFromString(data)

    # Create response
    response = plugin.CodeGeneratorResponse()

    # Generate code
    generate_code(request, response)

    # Serialise response message
    output = response.SerializeToString()

    # Write to stdout
    sys.stdout.write(output)
    # print is_base_type(9)
