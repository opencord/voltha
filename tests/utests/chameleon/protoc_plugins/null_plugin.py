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

"""
Protoc plugin that simply emits the binary content of the CodeGeneratorRequest
it is called with for each <name>.proto file. The name of the file the content
is saved is protoc.request.
"""
import base64
import sys

from google.protobuf.compiler import plugin_pb2

if __name__ == '__main__':
    response = plugin_pb2.CodeGeneratorResponse()
    f = response.file.add()
    f.name = 'protoc.request'
    f.content = base64.encodestring(sys.stdin.read())
    sys.stdout.write(response.SerializeToString())
