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
import netaddr


def _get_all_interfaces():
    m_interfaces = []
    for iface in ni.interfaces():
        m_interfaces.append((iface, ni.ifaddresses(iface)))
    return m_interfaces


def _get_my_primary_interface():
    gateways = ni.gateways()
    assert 'default' in gateways, \
        ("No default gateway on host/container, "
         "cannot determine primary interface")
    default_gw_index = gateways['default'].keys()[0]
    # gateways[default_gw_index] has the format (example):
    # [('10.15.32.1', 'en0', True)]
    interface_name = gateways[default_gw_index][0][1]
    return interface_name


def get_my_primary_local_ipv4(inter_core_subnet=None, ifname=None):
    if not inter_core_subnet:
        return _get_my_primary_local_ipv4(ifname)
    # My IP should belong to the specified subnet
    for iface in ni.interfaces():
        addresses = ni.ifaddresses(iface)
        if AF_INET in addresses:
            m_ip = addresses[AF_INET][0]['addr']
            _ip = netaddr.IPAddress(m_ip).value
            m_network = netaddr.IPNetwork(inter_core_subnet)
            if _ip >= m_network.first and _ip <= m_network.last:
                return m_ip
    return None


def get_my_primary_interface(pon_subnet=None):
    if not pon_subnet:
        return _get_my_primary_interface()
    # My interface should have an IP that belongs to the specified subnet
    for iface in ni.interfaces():
        addresses = ni.ifaddresses(iface)
        if AF_INET in addresses:
            m_ip = addresses[AF_INET][0]['addr']
            m_ip = netaddr.IPAddress(m_ip).value
            m_network = netaddr.IPNetwork(pon_subnet)
            if m_ip >= m_network.first and m_ip <= m_network.last:
                return iface
    return None


def _get_my_primary_local_ipv4(ifname=None):
    try:
        ifname = get_my_primary_interface() if ifname is None else ifname
        addresses = ni.ifaddresses(ifname)
        ipv4 = addresses[AF_INET][0]['addr']
        return ipv4
    except Exception as e:
        return None

if __name__ == '__main__':
    print get_my_primary_local_ipv4()
