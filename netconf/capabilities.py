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
import structlog
import sys
from constants import Constants as C

URN_PREFIX = "urn:opencord:params:xml:ns:voltha:"
log = structlog.get_logger()


class Capabilities:
    def __init__(self):
        self.server_caps = set()
        self.client_caps = set()
        self.voltha_schemas = set()
        self.schema_dir = None

    def add_client_capability(self, cap):
        self.client_caps.add(cap)

    def set_server_capabilities(self, schemas):
        # first add the basic capabilities
        self.server_caps.add(C.NETCONF_BASE_10)
        self.server_caps.add(C.NETCONF_BASE_11)
        self.server_caps.add(C.NETCONF_MONITORING)
        self.server_caps.add(C.NETCONF_WRITABLE)
        for schema in schemas:
            self.server_caps.add(''.join([URN_PREFIX, schema]))
            self.voltha_schemas.add(schema)

    def set_schema_dir(self, schema_dir):
        self.schema_dir = schema_dir

    def get_yang_schemas_definitions(self):
        defs = []
        for schema in self.voltha_schemas:
            defs.append(
                {
                    'id': schema,
                    'version': '2016-11-15',
                    # TODO: need to extract from voltha
                    'format': 'yang',
                    'location': 'NETCONF',
                    'namespace': ''.join([URN_PREFIX, schema])
                }
            )
        return defs

    def is_schema_supported(self, schema):
        return schema in self.voltha_schemas

    def get_schema_content(self, schema):
        if self.schema_dir not in sys.path:
            sys.path.insert(0, self.schema_dir)

        try:
            with open(''.join([self.schema_dir, '/', schema, '.yang']),
                      'r') as f:
                content = f.read()
                return content
        except Exception as e:
            log.error("error-opening-file", file=''.join([schema, '.yang']),
                      dir=self.schema_dir, exception=repr(e))
