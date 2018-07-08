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
Read adapter data while decoding ext2 custom fields
"""
import sys
from json import dumps

from common.utils.json_format import MessageToDict
from voltha.protos import adapter_pb2

adapter = adapter_pb2.Adapter()
binary = sys.stdin.read()
adapter.ParseFromString(binary)

print dumps(MessageToDict(adapter, strict_any_handling=False))

