#!/usr/bin/env python
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

