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
import os
import sys

from scripts.scriptbase import ScriptBase


class _(ScriptBase):

    usage = """
Usage: {} <logical-device-id>

Make sure you have VOLTHA_BASE_URL environment variable
defined, examples:

export VOLTHA_BASE_URL=http://localhost:8881/api/v1

or

export VOLTHA_BASE_URL=http://10.100.192.220:8881/api/v1
""".format(sys.argv[0])

    def main(self):

        if len(sys.argv) != 2:
            self.err(1)

        logical_device_id = sys.argv[1]

        logical_device = self.fetch_logical_device_info(
            self.voltha_base_url, logical_device_id)
        self.print_flows(
            'Logical device',
            logical_device_id,
            type='n/a',
            flows=logical_device['flows']['items'],
            groups=logical_device['flow_groups']['items']
        )


if __name__ == '__main__':
    _().main()

