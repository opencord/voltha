#!/usr/bin/env python
import os
import sys

from scripts.scriptbase import ScriptBase


class _(ScriptBase):

    usage = """
Usage: {} <device-id>

Make sure you have VOLTHA_BASE_URL environment variable
defined, examples:

export VOLTHA_BASE_URL=https://localhost:8881/api/v1

or

export VOLTHA_BASE_URL=https://10.100.192.220:8881/api/v1
""".format(sys.argv[0])

    def main(self):

        if len(sys.argv) != 2:
            self.err(1)

        device_id = sys.argv[1]

        device = self.fetch_device_info(self.voltha_base_url, device_id)
        self.print_flows(
            'Device',
            device_id,
            type=device['type'],
            flows=device['flows']['items'],
            groups=device['flow_groups']['items']
        )


if __name__ == '__main__':
    _().main()

