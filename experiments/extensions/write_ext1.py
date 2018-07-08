#!/usr/bin/env python
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Write adapter data without any custom fields
"""
import sys

import ext1_pb2
from voltha.protos import adapter_pb2
from google.protobuf import any_pb2

def custom_config():
    any = any_pb2.Any()
    any.Pack(ext1_pb2.AdapterConfig(
        volume=20,
        bass=50,
        treble=50
    ))
    return any


def custom_description():
    any = any_pb2.Any()
    any.Pack(ext1_pb2.AdapterDescription(
        internal_name='hulu',
        internal_code='foo',
        price=42
    ))
    return any


adapter = adapter_pb2.Adapter(
    id='42',
    config=adapter_pb2.AdapterConfig(
        additional_config=custom_config()
    ),
    additional_description=custom_description()
)

sys.stdout.write(adapter.SerializeToString())

