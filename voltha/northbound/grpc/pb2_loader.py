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

"""Assist in loading *_pb2.py protobuf files"""

import sys


# TODO this hack needs to go
#~~~~~~~~~~~~~~~~~~~~ begin import hach ~~~~~~~~~~~~~~~~~~~~~~~~~
# Import hack to allow loading the google.api local files
# without shadowing the google.protoc dependency. We needed
# to do this because the grpc-generated pb2 files use
# "from google.api import ..." directive and we cannot alter
# the path.
class ModuleProxy(object):
    def __getattr__(self, key):
        if key == 'http_pb2':
            return http_pb2
        elif key == 'annotations_pb2':
            return annotations_pb2
        else:
            return None
sys.modules['google.api'] = ModuleProxy()
from voltha.core.protos.google2.api import http_pb2
from voltha.core.protos.google2.api import annotations_pb2
#~~~~~~~~~~~~~~~~~~~~  end import hach  ~~~~~~~~~~~~~~~~~~~~~~~~~

