#!/usr/bin/env python
"""
Read adapter data while decoding ext1 custom fields.
"""
import sys
from json import dumps

from common.utils.json_format import MessageToDict
from voltha.protos import adapter_pb2

adapter = adapter_pb2.Adapter()
binary = sys.stdin.read()
adapter.ParseFromString(binary)

print dumps(MessageToDict(adapter, strict_any_handling=False))

