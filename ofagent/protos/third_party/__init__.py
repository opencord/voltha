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
This helps loading http_pb2 and annotations_pb2.
Without this, the Python importer will not be able to process the lines:
from google.api import http_pb2 or
from google.api import annotations_pb2
(Without importing these, the protobuf loader will not recognize http options
in the protobuf definitions.)
"""

from importlib import import_module
import os
import sys


class GoogleApiImporter(object):

    def find_module(self, full_name, path=None):
        if full_name == 'google.api':
            self.path = [os.path.dirname(__file__)]
            return self

    def load_module(self, name):
        if name in sys.modules:
            return sys.modules[name]
        full_name = 'ofagent.protos.third_party.' + name
        import_module(full_name)
        module = sys.modules[full_name]
        sys.modules[name] = module
        return module


sys.meta_path.append(GoogleApiImporter())
from google.api import http_pb2, annotations_pb2
_ = http_pb2, annotations_pb2
