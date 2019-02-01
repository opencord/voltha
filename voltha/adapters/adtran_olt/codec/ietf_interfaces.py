# CCopyright 2017-present Adtran, Inc.
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

from twisted.internet.defer import inlineCallbacks, returnValue
import xmltodict
import structlog
from voltha.protos.openflow_13_pb2 import OFPPF_1GB_FD, OFPPF_10GB_FD, OFPPF_40GB_FD, OFPPF_100GB_FD
from voltha.protos.openflow_13_pb2 import OFPPF_FIBER, OFPPF_COPPER
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPC_PORT_DOWN, OFPPS_LINK_DOWN, OFPPF_OTHER
from voltha.protos.common_pb2 import OperStatus, AdminState

log = structlog.get_logger()

_ietf_interfaces_config_rpc = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
        <interface/>
      </interfaces>
    </filter>
"""

_ietf_interfaces_state_rpc = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
        <interface>
          <name/>
          <type/>
          <admin-status/>
          <oper-status/>
          <last-change/>
          <phys-address/>
          <speed/>
        </interface>
      </interfaces-state>
    </filter>
"""

_allowed_with_default_types = ['report-all', 'report-all-tagged', 'trim', 'explicit']

# TODO: Centralize the item below as a function in a core util module


def _with_defaults(default_type=None):
    if default_type is None:
        return ""

    assert(default_type in _allowed_with_default_types)
    return """
    <with-defaults xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults">
        {}</with-defaults>""".format(default_type)


class IetfInterfacesConfig(object):
    def __init__(self, session):
        """

        :param session: this should be a netconf session
        """
        self._session = session

    @inlineCallbacks
    def get_config(self, source='running', with_defaults=None):

        filter = _ietf_interfaces_config_rpc + _with_defaults(with_defaults)

        request = self._session.get(source, filter=filter)
        rpc_reply = yield request
        returnValue(rpc_reply)

    def get_interfaces(self, rpc_reply, interface_type=None):
        """
        Get the physical entities of a particular type
        :param rpc_reply: Reply from previous get or request
        :param interface_type: (String or List) The type of interface (case-insensitive)
        :return: list) of OrderDict interface entries
        """
        result_dict = xmltodict.parse(rpc_reply.data_xml)

        entries = result_dict['data']['interfaces']

        if interface_type is None:
            return entries

        # for entry in entries:
        #     import pprint
        #     log.info(pprint.PrettyPrinter(indent=2).pformat(entry))

        def _matches(entry, value):
            if 'type' in entry and '#text' in entry['type']:
                text_val = entry['type']['#text'].lower()
                if isinstance(value, list):
                    return any(v.lower() in text_val for v in value)
                return value.lower() in text_val
            return False

        return [entry for entry in entries if _matches(entry, interface_type)]


class IetfInterfacesState(object):
    def __init__(self, session):
        self._session = session

    @inlineCallbacks
    def get_state(self):
        try:
            request = self._session.get(_ietf_interfaces_state_rpc)
            rpc_reply = yield request
            returnValue(rpc_reply)

        except Exception as e:
            log.exception('get_state', e=e)
            raise

    @staticmethod
    def get_interfaces(self, rpc_reply, key='type', key_value=None):
        """
        Get the physical entities of a particular type
        :param key_value: (String or List) The type of interface (case-insensitive)
        :return: list) of OrderDict interface entries
        """
        result_dict = xmltodict.parse(rpc_reply.data_xml)
        entries = result_dict['data']['interfaces-state']['interface']

        if key_value is None:
            return entries

        for entry in entries:
            import pprint
            log.info(pprint.PrettyPrinter(indent=2).pformat(entry))

        def _matches(entry, key, value):
            if key in entry and '#text' in entry[key]:
                text_val = entry[key]['#text'].lower()
                if isinstance(value, list):
                    return any(v.lower() in text_val for v in value)
                return value.lower() in text_val
            return False

        return [entry for entry in entries if _matches(entry, key, key_value)]

    @staticmethod
    def _get_admin_state(entry):
        state_map = {
            'up': AdminState.ENABLED,
            'down': AdminState.DISABLED,
            'testing': AdminState.DISABLED
        }
        return state_map.get(entry.get('admin-status', 'down'),
                             AdminState.UNKNOWN)

    @staticmethod
    def _get_oper_status(entry):
        state_map = {
            'up': OperStatus.ACTIVE,
            'down': OperStatus.FAILED,
            'testing': OperStatus.TESTING,
            'unknown': OperStatus.UNKNOWN,
            'dormant': OperStatus.DISCOVERED,
            'not-present': OperStatus.UNKNOWN,
            'lower-layer-down': OperStatus.FAILED
        }
        return state_map.get(entry.get('oper-status', 'down'),
                             OperStatus.UNKNOWN)

    @staticmethod
    def _get_mac_addr(entry):
        mac_addr = entry.get('phys-address', None)
        if mac_addr is None:
            import random
            # TODO: Get with qumram team about phys addr
            mac_addr = '08:00:{}{}:{}{}:{}{}:00'.format(random.randint(0, 9),
                                                        random.randint(0, 9),
                                                        random.randint(0, 9),
                                                        random.randint(0, 9),
                                                        random.randint(0, 9),
                                                        random.randint(0, 9))
        return mac_addr

    @staticmethod
    def _get_speed_value(entry):
        speed = entry.get('speed') or IetfInterfacesState._get_speed_via_name(entry.get('name'))
        if isinstance(speed, str):
            return long(speed)
        return speed

    @staticmethod
    def _get_speed_via_name(name):
        speed_map = {
            'terabit':         1000000000000,
            'hundred-gigabit':  100000000000,
            'fourty-gigabit':    40000000000,
            'ten-gigabit':       10000000000,
            'gigabit':            1000000000,
        }
        for n,v in speed_map.iteritems():
            if n in name.lower():
                return v
        return 0

    @staticmethod
    def _get_of_state(entry):
        # If port up and ready: OFPPS_LIVE
        # If port config bit is down: OFPPC_PORT_DOWN
        # If port state bit is down: OFPPS_LINK_DOWN
        # if IetfInterfacesState._get_admin_state(entry) == AdminState.ENABLED:
        #     return OFPPS_LIVE \
        #         if IetfInterfacesState._get_oper_status(entry) == OperStatus.ACTIVE \
        #         else OFPPS_LINK_DOWN
        #
        # return OFPPC_PORT_DOWN
        # TODO: Update of openflow port state is not supported, so always say we are alive
        return OFPPS_LIVE

    @staticmethod
    def _get_of_capabilities(entry):
        # The capabilities field is a bitmap that uses a combination of the following flags :
        # Capabilities supported by the datapath
        # enum ofp_capabilities {
        #    OFPC_FLOW_STATS = 1 << 0,   /* Flow statistics. */
        #    OFPC_TABLE_STATS = 1 << 1,  /* Table statistics. */
        #    OFPC_PORT_STATS = 1 << 2,   /* Port statistics. */
        #    OFPC_GROUP_STATS = 1 << 3,  /* Group statistics. */
        #    OFPC_IP_REASM = 1 << 5,     /* Can reassemble IP fragments. */
        #    OFPC_QUEUE_STATS = 1 << 6,  /* Queue statistics. */
        #    OFPC_PORT_BLOCKED = 1 << 8, /* Switch will block looping ports. */
        #    OFPC_BUNDLES = 1 << 9,      /* Switch supports bundles. */
        #    OFPC_FLOW_MONITORING = 1 << 10, /* Switch supports flow monitoring. */
        # }
        # enum ofp_port_features {
        #     OFPPF_10MB_HD = 1 << 0, /* 10 Mb half-duplex rate support. */
        #     OFPPF_10MB_FD = 1 << 1, /* 10 Mb full-duplex rate support. */
        #     OFPPF_100MB_HD = 1 << 2, /* 100 Mb half-duplex rate support. */
        #     OFPPF_100MB_FD = 1 << 3, /* 100 Mb full-duplex rate support. */
        #     OFPPF_1GB_HD = 1 << 4, /* 1 Gb half-duplex rate support. */
        #     OFPPF_1GB_FD = 1 << 5, /* 1 Gb full-duplex rate support. */
        #     OFPPF_10GB_FD = 1 << 6, /* 10 Gb full-duplex rate support. */
        #     OFPPF_40GB_FD = 1 << 7, /* 40 Gb full-duplex rate support. */
        #     OFPPF_100GB_FD = 1 << 8, /* 100 Gb full-duplex rate support. */
        #     OFPPF_1TB_FD = 1 << 9, /* 1 Tb full-duplex rate support. */
        #     OFPPF_OTHER = 1 << 10, /* Other rate, not in the list. */
        #     OFPPF_COPPER = 1 << 11, /* Copper medium. */
        #     OFPPF_FIBER = 1 << 12, /* Fiber medium. */
        #     OFPPF_AUTONEG = 1 << 13, /* Auto-negotiation. */
        #     OFPPF_PAUSE = 1 << 14, /* Pause. */
        #     OFPPF_PAUSE_ASYM = 1 << 15 /* Asymmetric pause. */
        # }
        # TODO: Look into adtran-physical-entities and decode xSFP type any other settings
        return IetfInterfacesState._get_of_speed(entry) | OFPPF_FIBER

    @staticmethod
    def _get_of_speed(entry):
        speed = IetfInterfacesState._get_speed_value(entry)
        speed_map = {
            1000000000: OFPPF_1GB_FD,
            10000000000: OFPPF_10GB_FD,
            40000000000: OFPPF_40GB_FD,
            100000000000: OFPPF_100GB_FD,
        }
        # return speed_map.get(speed, OFPPF_OTHER)
        # TODO: For now, force 100 GB
        return OFPPF_100GB_FD

    @staticmethod
    def _get_port_number(name, if_index):
        import re

        formats = [
            'xpon \d/{1,2}\d',                          # OLT version 3 (Feb 2018++)
            'Hundred-Gigabit-Ethernet \d/\d/{1,2}\d',   # OLT version 2
            'XPON \d/\d/{1,2}\d',                       # OLT version 2
            'hundred-gigabit-ethernet \d/{1,2}\d',      # OLT version 1
            'channel-termination {1,2}\d',              # OLT version 1
        ]
        p2 = re.compile('\d+')

        for regex in formats:
            p = re.compile(regex, re.IGNORECASE)
            match = p.match(name)
            if match is not None:
                return int(p2.findall(name)[-1])

    @staticmethod
    def get_port_entries(rpc_reply, port_type):
        """
        Get the port entries that make up the northbound and
        southbound interfaces

        :param rpc_reply:
        :param port_type:
        :return:
        """
        ports = dict()
        result_dict = xmltodict.parse(rpc_reply.data_xml)
        entries = result_dict['data']['interfaces-state']['interface']
        if not isinstance(entries, list):
            entries = [entries]
        port_entries = [entry for entry in entries if 'name' in entry and
                        port_type.lower() in entry['name'].lower()]

        for entry in port_entries:
            port = {
                'port_no': IetfInterfacesState._get_port_number(entry.get('name'),
                                                                entry.get('ifindex')),
                'name': entry.get('name', 'unknown'),
                'ifIndex': entry.get('ifIndex'),
                # 'label': None,
                'mac_address': IetfInterfacesState._get_mac_addr(entry),
                'admin_state': IetfInterfacesState._get_admin_state(entry),
                'oper_status': IetfInterfacesState._get_oper_status(entry),
                'ofp_state': IetfInterfacesState._get_of_state(entry),
                'ofp_capabilities': IetfInterfacesState._get_of_capabilities(entry),
                'current_speed': IetfInterfacesState._get_of_speed(entry),
                'max_speed': IetfInterfacesState._get_of_speed(entry),
            }
            port_no = port['port_no']
            if port_no not in ports:
                ports[port_no] = port
            else:
                ports[port_no].update(port)

        return ports
