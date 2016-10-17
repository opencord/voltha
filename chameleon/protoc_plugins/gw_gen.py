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
import sys

from google.protobuf.compiler import plugin_pb2 as plugin
from google.protobuf.descriptor_pb2 import ServiceDescriptorProto, \
    MethodOptions
from jinja2 import Template
from simplejson import dumps

from chameleon.protos.third_party.google.api import annotations_pb2, http_pb2
_ = annotations_pb2, http_pb2  # to keep import line from being optimized out


template = Template("""
# Generated file; please do not edit

from simplejson import dumps, load
from structlog import get_logger
from protobuf_to_dict import protobuf_to_dict, dict_to_protobuf

{% set package = file_name.replace('.proto', '') %}
import {{ package + '_pb2' }} as {{ package }}

log = get_logger()

def add_routes(app, grpc_client):

    pass  # so that if no endpoints are defined, Python is still happy

    {% for method in methods %}
    {% set method_name = method['service'] + '_' + method['method'] %}
    {% set path = method['path'].replace('{', '<string:').replace('}', '>') %}
    @app.route('{{ path }}', methods=['{{ method['verb'].upper() }}'])
    def {{ method_name }}(server, request, **kw):
        log.debug('{{ method_name }}', request=request, server=server, **kw)
        {% if method['body'] == '*' %}
        data = load(request.content)
        data.update(kw)
        {% elif method['body'] == '' %}
        data = kw
        {% else %}
        riase NotImplementedError('cannot handle specific body field list')
        {% endif %}
        req = dict_to_protobuf({{ method['input_type'] }}, data)
        res = grpc_client.invoke(
            {{ '.'.join([package, method['service']]) }}Stub,
            '{{ method['method'] }}', req)
        out_data = protobuf_to_dict(res, use_enum_labels=True)
        request.setHeader('Content-Type', 'application/json')
        log.debug('{{ method_name }}', **out_data)
        return dumps(out_data)

    {% endfor %}

""", trim_blocks=True, lstrip_blocks=True)


def traverse_methods(proto_file):

    package = proto_file.name
    for service in proto_file.service:
        assert isinstance(service, ServiceDescriptorProto)

        for method in service.method:
            options = method.options
            assert isinstance(options, MethodOptions)
            for fd, http in options.ListFields():
                if fd.full_name == 'google.api.http':
                    assert fd.name == 'http'
                    assert isinstance(http, http_pb2.HttpRule)

                    input_type = method.input_type
                    if input_type.startswith('.'):
                        input_type = input_type[1:]

                    output_type = method.output_type
                    if output_type.startswith('.'):
                        output_type = output_type[1:]

                    if http.delete:
                        verb = 'delete'
                        path = http.delete
                    elif http.get:
                        verb = 'get'
                        path = http.get
                    elif http.patch:
                        verb = 'patch'
                        path = http.patch
                    elif http.post:
                        verb = 'post'
                        path = http.post
                    elif http.put:
                        verb = 'put'
                        path = http.put
                    else:
                        raise AttributeError('No valid verb in method %s' %
                                             method.name)

                    body = http.body

                    data = {
                        'package': package,
                        'filename': proto_file.name,
                        'service': service.name,
                        'method': method.name,
                        'input_type': input_type,
                        'output_type': output_type,
                        'path': path,
                        'verb': verb,
                        'body': body
                    }

                    yield data


def generate_gw_code(file_name, methods):
    return template.render(file_name=file_name, methods=methods)


def generate_code(request, response):

    assert isinstance(request, plugin.CodeGeneratorRequest)
    for proto_file in request.proto_file:
        output = []

        for data in traverse_methods(proto_file):
            output.append(data)

        # as a nice side-effect, generate a json file capturing the essence
        # of the RPC method entries
        f = response.file.add()
        f.name = proto_file.name + '.json'
        f.content = dumps(output, indent=4)

        # generate the real Python code file
        f = response.file.add()
        assert proto_file.name.endswith('.proto')
        f.name = proto_file.name.replace('.proto', '_gw.py')
        f.content = generate_gw_code(proto_file.name, output)


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
