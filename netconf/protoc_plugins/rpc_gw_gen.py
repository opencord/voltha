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

import sys

from google.protobuf.compiler import plugin_pb2 as plugin
from google.protobuf.descriptor_pb2 import ServiceDescriptorProto, \
    MethodOptions
from jinja2 import Template
from simplejson import dumps
import yang_options_pb2

from netconf.protos.third_party.google.api import annotations_pb2, http_pb2

_ = annotations_pb2, http_pb2  # to keep import line from being optimized out

template = Template("""
# Generated file; please do not edit

from simplejson import dumps, load
from structlog import get_logger
from google.protobuf.json_format import MessageToDict, ParseDict
from twisted.internet.defer import inlineCallbacks, returnValue

{% set package = file_name.replace('.proto', '') %}

{% for pypackage, module in includes %}
{% if pypackage %}
from {{ pypackage }} import {{ module }}
{% else %}
import {{ module }}
{% endif %}
{% endfor %}

log = get_logger()

{% for method in methods %}
{% set method_name = method['service'].rpartition('.')[2] + '_' + method['method'] %}
@inlineCallbacks
def {{ method_name }}(grpc_client, params, metadata, **kw):
    log.info('{{ method_name }}', params=params, metadata=metadata, **kw)
    data = params
    data.update(kw)
    try:
        req = ParseDict(data, {{ type_map[method['input_type']] }}())
    except Exception, e:
        log.error('cannot-convert-to-protobuf', e=e, data=data)
        raise
    res, _ = yield grpc_client.invoke(
        {{ type_map[method['service']] }}Stub,
        '{{ method['method'] }}', req, metadata)
    try:
        out_data = grpc_client.convertToDict(res)
    except AttributeError, e:
        filename = '/tmp/netconf_failed_to_convert_data.pbd'
        with file(filename, 'w') as f:
            f.write(res.SerializeToString())
        log.error('cannot-convert-from-protobuf', outdata_saved=filename)
        raise
    log.info('{{ method_name }}', **out_data)
    returnValue(out_data)

def get_xml_tag_{{ method_name }}():
    return '{{ method['xml_tag'] }}'

def get_list_items_name_{{ method_name }}():
    return '{{ method['list_item_name'] }}'

def get_return_type_{{ method_name }}():
    return '{{ type_map[method['output_type']] }}'

{% endfor %}

""", trim_blocks=True, lstrip_blocks=True)


def traverse_methods(proto_file):
    package = proto_file.name
    for service in proto_file.service:
        assert isinstance(service, ServiceDescriptorProto)

        for method in service.method:
            input_type = method.input_type
            if input_type.startswith('.'):
                input_type = input_type[1:]

            output_type = method.output_type
            if output_type.startswith('.'):
                output_type = output_type[1:]

            # Process any specific yang option
            xml_tag = ''
            list_item_name = ''
            options = method.options
            assert isinstance(options, MethodOptions)
            for fd, yang_tag in options.ListFields():
                if fd.full_name == 'voltha.yang_xml_tag':
                    if yang_tag.xml_tag:
                        xml_tag = yang_tag.xml_tag
                    if yang_tag.list_items_name:
                        list_item_name = yang_tag.list_items_name

            data = {
                'package': package,
                'filename': proto_file.name,
                'service': proto_file.package + '.' + service.name,
                'method': method.name,
                'input_type': input_type,
                'output_type': output_type,
                'xml_tag': xml_tag,
                'list_item_name': list_item_name
            }

            yield data


def generate_gw_code(file_name, methods, type_map, includes):
    return template.render(file_name=file_name, methods=methods,
                           type_map=type_map, includes=includes)


class IncludeManager(object):
    # need to keep track of what files define what message types and
    # under what package name. Later, when we analyze the methods, we
    # need to be able to derive the list of files we need to load and we
    # also need to replce the <proto-package-name>.<artifact-name> in the
    # templates with <python-package-name>.<artifact-name> so Python can
    # resolve these.
    def __init__(self):
        self.package_to_localname = {}
        self.fullname_to_filename = {}
        self.prefix_table = []  # sorted table of top-level symbols in protos
        self.type_map = {}  # full name as used in .proto -> python name
        self.includes_needed = set()  # names of files needed to be included
        self.filename_to_module = {}  # filename -> (package, module)

    def extend_symbol_tables(self, proto_file):
        # keep track of what file adds what top-level symbol to what abstract
        # package name
        package_name = proto_file.package
        file_name = proto_file.name
        self._add_filename(file_name)
        all_defs = list(proto_file.message_type)
        all_defs.extend(list(proto_file.enum_type))
        all_defs.extend(list(proto_file.service))
        for typedef in all_defs:
            name = typedef.name
            fullname = package_name + '.' + name
            self.fullname_to_filename[fullname] = file_name
            self.package_to_localname.setdefault(package_name, []).append(name)
        self._update_prefix_table()

    def _add_filename(self, filename):
        if filename not in self.filename_to_module:
            python_path = filename.replace('.proto', '_pb2').replace('/', '.')
            package_name, _, module_name = python_path.rpartition('.')
            self.filename_to_module[filename] = (package_name, module_name)

    def _update_prefix_table(self):
        # make a sorted list symbol prefixes needed to resolv for potential use
        # of nested symbols
        self.prefix_table = sorted(self.fullname_to_filename.iterkeys(),
                                   reverse=True)

    def _find_matching_prefix(self, fullname):
        for prefix in self.prefix_table:
            if fullname.startswith(prefix):
                return prefix
        # This should never happen
        raise Exception('No match for type name "{}"'.format(fullname))

    def add_needed_symbol(self, fullname):
        if fullname in self.type_map:
            return
        top_level_symbol = self._find_matching_prefix(fullname)
        name = top_level_symbol.rpartition('.')[2]
        nested_name = fullname[len(top_level_symbol):]  # may be empty
        file_name = self.fullname_to_filename[top_level_symbol]
        self.includes_needed.add(file_name)
        module_name = self.filename_to_module[file_name][1]
        python_name = module_name + '.' + name + nested_name
        self.type_map[fullname] = python_name

    def get_type_map(self):
        return self.type_map

    def get_includes(self):
        return sorted(
            self.filename_to_module[fn] for fn in self.includes_needed)


def generate_code(request, response):
    assert isinstance(request, plugin.CodeGeneratorRequest)

    include_manager = IncludeManager()
    for proto_file in request.proto_file:

        include_manager.extend_symbol_tables(proto_file)

        methods = []

        for data in traverse_methods(proto_file):
            methods.append(data)
            include_manager.add_needed_symbol(data['input_type'])
            include_manager.add_needed_symbol(data['output_type'])
            include_manager.add_needed_symbol(data['service'])

        type_map = include_manager.get_type_map()
        includes = include_manager.get_includes()

        # as a nice side-effect, generate a json file capturing the essence
        # of the RPC method entries
        f = response.file.add()
        f.name = proto_file.name + '.json'
        f.content = dumps(dict(
            type_rename_map=type_map,
            includes=includes,
            methods=methods), indent=4)

        # generate the real Python code file
        f = response.file.add()
        assert proto_file.name.endswith('.proto')
        f.name = proto_file.name.replace('.proto', '_rpc_gw.py')
        f.content = generate_gw_code(proto_file.name,
                                     methods, type_map, includes)


if __name__ == '__main__':

    if len(sys.argv) >= 2:
        # read input from file, to allow troubleshooting
        with open(sys.argv[1], 'r') as f:
            data = f.read()
    else:
        # read input from stdin
        data = sys.stdin.read()

    # parse request
    request = plugin.CodeGeneratorRequest()
    request.ParseFromString(data)

    # create response object
    response = plugin.CodeGeneratorResponse()

    # generate the output and the response
    generate_code(request, response)

    # serialize the response
    output = response.SerializeToString()

    # write response to stdout
    sys.stdout.write(output)
