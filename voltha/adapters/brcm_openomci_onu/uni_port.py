#
# Copyright 2018 the original author or authors.
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

import structlog
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.openflow_13_pb2 import OFPPF_10GB_FD
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, OFPPS_LINK_DOWN
from voltha.protos.openflow_13_pb2 import ofp_port


class UniPort(object):
    """Wraps southbound-port(s) support for ONU"""
    DEFAULT_UNTAGGED_VLAN = 4091

    def __init__(self, handler, name, port_no, ofp_port_no, subscriber_vlan=None,
                 untagged_vlan=None):
        self.log = structlog.get_logger(device_id=handler.device_id,
                                        port_no=port_no)
        self.log.debug('function-entry')
        self._enabled = False
        self._handler = handler
        self._name = name
        self._port = None
        self._port_number = port_no
        self._ofp_port_no = ofp_port_no         # Set at by creator (vENET create)
        self._logical_port_number = None        # Set at time of logical port creation
        self._subscriber_vlan = subscriber_vlan
        self._untagged_vlan = untagged_vlan
        self._entity_id = None                  # TODO: Use port number from UNI-G entity ID
        self._mac_bridge_port_num = 0

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        # TODO Add state, stats, alarm reference, ...
        pass

    def __str__(self):
        return "UniPort: {}:{}".format(self.name, self.port_number)

    @staticmethod
    def create(handler, name, port_no, ofp_port_no, subscriber_vlan, untagged_vlan):
        log = structlog.get_logger(device_id=handler.device_id, name=name)
        log.debug('function-entry')
        port = UniPort(handler, name, port_no, ofp_port_no, subscriber_vlan, untagged_vlan)
        return port

    def _start(self):
        self.log.debug('function-entry')
        self._cancel_deferred()

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        self._update_adapter_agent()
        # TODO: start h/w sync
        # TODO: Enable the actual physical port?
        pass

    def _stop(self):
        self.log.debug('function-entry')
        self._cancel_deferred()

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN

        self._update_adapter_agent()
        # TODO: Disable/power-down the actual physical port?
        pass

    def delete(self):
        self.log.debug('function-entry')
        self.enabled = False
        self._handler = None
        # TODO: anything else

    def _cancel_deferred(self):
        self.log.debug('function-entry')
        pass

    @property
    def name(self):
        self.log.debug('function-entry')
        return self._name

    @property
    def enabled(self):
        self.log.debug('function-entry')
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        self.log.debug('function-entry')
        if self._enabled != value:
            self._enabled = value

            if value:
                self._start()
            else:
                self._stop()

    @property
    def mac_bridge_port_num(self):
        """
        Port number used when creating MacBridgePortConfigurationDataFrame port number
        :return: (int) port number
        """
        self.log.debug('function-entry')
        return self._mac_bridge_port_num

    @mac_bridge_port_num.setter
    def mac_bridge_port_num(self, value):
        self.log.debug('function-entry')
        self._mac_bridge_port_num = value

    @property
    def port_number(self):
        """
        Physical device port number
        :return: (int) port number
        """
        self.log.debug('function-entry')
        return self._port_number

    @property
    def entity_id(self):
        """
        OMCI UNI_G entity ID for port
        """
        self.log.debug('function-entry')
        return self._entity_id

    @entity_id.setter
    def entity_id(self, value):
        self.log.debug('function-entry')
        assert self._entity_id is None, 'Cannot reset the Entity ID'
        self._entity_id = value

    @property
    def subscriber_vlan(self):
        """
        Subscriber vlan assigned to this UNI
        :return: (int) subscriber vlan
        """
        self.log.debug('function-entry')
        return self._subscriber_vlan

    @property
    def logical_port_number(self):
        """
        Logical device port number (used as OpenFlow port for UNI)
        :return: (int) port number
        """
        self.log.debug('function-entry')
        return self._logical_port_number

    def _update_adapter_agent(self):
        """
        Update the port status and state in the core
        """
        self.log.debug('function-entry')
        self.log.debug('update-adapter-agent', admin_state=self._admin_state,
                       oper_status=self._oper_status)

        if self._port is not None:
            self._port.admin_state = self._admin_state
            self._port.oper_status = self._oper_status

        try:
            # adapter_agent add_port also does an update of existing port
            self._handler.adapter_agent.add_port(self._handler.device_id,
                                                 self.get_port())

        except Exception as e:
            self.log.exception('update-port', e=e)

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        self.log.debug('function-entry')

        if self._port is None:
            self._port = Port(port_no=self.port_number,
                              label='Ethernet port',
                              type=Port.ETHERNET_UNI,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status)
        return self._port

    def port_id_name(self):
        return 'uni-{}'.format(self._logical_port_number)

    def add_logical_port(self, openflow_port_no, subscriber_vlan=None,
                         capabilities=OFPPF_10GB_FD | OFPPF_FIBER,
                         speed=OFPPF_10GB_FD):

        self.log.debug('function-entry')

        if self._logical_port_number is not None:
            # delete old logical port if it exists
            try:
                port = self._handler.adapter_agent.get_logical_port(self._handler.logical_device_id,
                                                           self.port_id_name())
                self._handler.adapter_agent.delete_logical_port(self._handler.logical_device_id, port)

            except Exception as e:
                # assume this exception was because logical port does not already exist
                pass

            self._logical_port_number = None

        port_no = openflow_port_no or self._ofp_port_no
        vlan = subscriber_vlan or self._subscriber_vlan

        if self._logical_port_number is None and port_no is not None:
            self._logical_port_number = port_no
            self._subscriber_vlan = vlan

            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            if vlan is not None and device.vlan != vlan:
                device.vlan = vlan
                self._handler.adapter_agent.update_device(device)

            # leave the ports down until omci mib download has finished.  otherwise flows push before time
            openflow_port = ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('08:00:%02x:%02x:%02x:%02x' %
                                         ((device.parent_port_no >> 8 & 0xff),
                                          device.parent_port_no & 0xff,
                                          (port_no >> 8) & 0xff,
                                          port_no & 0xff)),
                name=device.serial_number,
                config=0,
                state=OFPPS_LINK_DOWN,
                curr=capabilities,
                advertised=capabilities,
                peer=capabilities,
                curr_speed=speed,
                max_speed=speed
            )
            self._handler.adapter_agent.add_logical_port(self._handler.logical_device_id,
                                                         LogicalPort(
                                                             id=self.port_id_name(),
                                                             ofp_port=openflow_port,
                                                             device_id=device.id,
                                                             device_port_no=self._port_number))

            self.log.debug('logical-port', openflow_port=openflow_port)
            # TODO: Should we use the UNI object 'name' as the id for OpenFlow?
