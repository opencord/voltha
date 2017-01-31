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
Some network related convenience functions
"""

from netifaces import AF_INET

import netifaces as ni


def get_my_primary_interface():
    gateways = ni.gateways()
    assert 'default' in gateways, \
        ("No default gateway on host/container, "
         "cannot determine primary interface")
    default_gw_index = gateways['default'].keys()[0]
    # gateways[default_gw_index] has the format (example):
    # [('10.15.32.1', 'en0', True)]
    interface_name = gateways[default_gw_index][0][1]
    return interface_name


def get_my_primary_local_ipv4(ifname=None):
    ifname = get_my_primary_interface() if ifname is None else ifname
    addresses = ni.ifaddresses(ifname)
    ipv4 = addresses[AF_INET][0]['addr']
    return ipv4


if __name__ == '__main__':
    print get_my_primary_local_ipv4()