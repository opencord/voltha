#!/usr/bin/env python
"""
Write adapter data without any custom fields
"""
import sys

import ext2_pb2
from voltha.protos import adapter_pb2
from google.protobuf import any_pb2


def custom_config():
    any = any_pb2.Any()
    any.Pack(ext2_pb2.AdapterConfig(
        conf1=1,
        conf2=42,
        conf3=0,
        conf4=11111111111,
        conf5=11231231,
        things = ['foo', 'bar', 'baz', 'zoo']
    ))
    return any


def custom_description():
    any = any_pb2.Any()
    any.Pack(ext2_pb2.AdapterDescription(
        foo='hulu',
        arg1=42,
        arg2=42,
        arg3=42,
        arg4=42,
        arg5=42
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

