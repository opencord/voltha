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
from simplejson import dumps

# without this import, http method annotations would not be recognized:
from google.api import annotations_pb2, http_pb2

from chameleon.protoc_plugins.descriptor_parser import DescriptorParser
from swagger_template import native_descriptors_to_swagger


def generate_code(request, response):

    assert isinstance(request, plugin.CodeGeneratorRequest)

    parser = DescriptorParser()
    native_data = parser.parse_file_descriptors(request.proto_file,
                                                type_tag_name='_type',
                                                fold_comments=True)
    swagger = native_descriptors_to_swagger(native_data)

    # generate the native decoded schema as json
    # f = response.file.add()
    # f.name = proto_file.name.replace('.proto', '.native.json')
    # f.content = dumps(data)

    # generate the real swagger.json file
    f = response.file.add()
    f.name = 'swagger.json'
    f.content = dumps(swagger)


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
