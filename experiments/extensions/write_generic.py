#!/usr/bin/env python
"""
Write adapter data without any custom fields
"""
import sys

from voltha.protos import adapter_pb2

adapter = adapter_pb2.Adapter(
    id='42',
    config=adapter_pb2.AdapterConfig()
)

sys.stdout.write(adapter.SerializeToString())

