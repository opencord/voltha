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

"""
Convert a schema.Schema object given on the standard input as protobuf data
file (from standard output) to a Python dictionary.
"""
import json
import sys
from chameleon.protos.third_party.google.api import annotations_pb2
_ = annotations_pb2
from chameleon.protos import schema_pb2
from protobuf_to_dict import protobuf_to_dict


if __name__ == '__main__':

    data = sys.stdin.read()
    schemas = schema_pb2.Schemas()
    schemas.ParseFromString(data)

    data = protobuf_to_dict(schemas, use_enum_labels=True)
    json.dump(data, sys.stdout)
