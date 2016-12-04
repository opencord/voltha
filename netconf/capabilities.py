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
from constants import Constants as C

class Capabilities:

    def __init__(self):
        self.server_caps = (C.NETCONF_BASE_10, C.NETCONF_BASE_11)
        self.client_caps = set()

    def add_client_capability(self, cap):
        self.client_caps.add(cap)

