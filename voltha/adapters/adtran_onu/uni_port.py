# Copyright 2017-present Adtran, Inc.
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

import structlog
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.openflow_13_pb2 import OFPPF_10GB_FD
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER
from voltha.protos.openflow_13_pb2 import ofp_port


class UniPort(object):
    """Wraps southbound-port(s) support for ONU"""

    def __init__(self, handler, name, port_no, control_vlan=None):
        self.log = structlog.get_logger(device_id=handler.device_id,
                                        port_no=port_no)
        self._enabled = False
        self._handler = handler
        self._name = name
        self._port = None
        self._port_number = port_no
        self._logical_port_number = None
        self._control_vlan = control_vlan

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        # TODO Add state, stats, alarm reference, ...

        pass

    def __str__(self):
        return "UniPort: {}:{}".format(self.name, self.port_number)

    @staticmethod
    def create(handler, name, port_no, control_vlan):
        port = UniPort(handler, name, port_no, control_vlan)
        return port

    def _start(self):
        self._cancel_deferred()

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        self._update_adapter_agent()
        # TODO: start h/w sync
        # TODO: Enable the actual physical port?
        pass

    def _stop(self):
        self._cancel_deferred()

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()
        # TODO: Disable/power-down the actual physical port?
        pass

    def delete(self):
        self.enabled = False
        self._handler = None
        # TODO: anything else

    def _cancel_deferred(self):
        pass

    @property
    def name(self):
        return self._name

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._enabled != value:
            self._enabled = value

            if value:
                self._start()
            else:
                self._stop()

    @property
    def port_number(self):
        """
        Physical device port number
        :return: (int) port number
        """
        return self._port_number

    @property
    def logical_port_number(self):
        """
        Logical device port number (used as OpenFlow port for UNI)
        :return: (int) port number
        """
        return self._logical_port_number

    def _update_adapter_agent(self):
        # TODO: Currently does the adapter_agent allow 'update' of port status
        # self.adapter_agent.update_port(self.olt.device_id, self.get_port())
        pass

    @staticmethod
    def decode_openflow_port_and_control_vlan(self, venet_info):
        try:
            # Allow spaces or dashes as separator, select last as
            # the port number

            port_no = int(venet_info['name'].replace(' ', '-').split('-')[-1:][0])
            cntl_vlan = port_no

            return port_no, cntl_vlan

        except ValueError:
            self.log.error('invalid-uni-port-name', name=venet_info['name'])
        except KeyError:
            self.log.error('invalid-venet-data', data=venet_info)

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self._port is None:
            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            self._port = Port(port_no=self.port_number,
                              label='Ethernet port',
                              type=Port.ETHERNET_UNI,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status,
                              peers=[Port.PeerPort(device_id=device.parent_id,
                                                   port_no=device.parent_port_no)])
        return self._port

    def add_logical_port(self, openflow_port_no, control_vlan=None,
                         capabilities=OFPPF_10GB_FD | OFPPF_FIBER,
                         speed=OFPPF_10GB_FD):

        if self._logical_port_number is None:
            self._logical_port_number = openflow_port_no
            self._control_vlan = control_vlan

            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            if control_vlan is not None and device.vlan != control_vlan:
                device.vlan = control_vlan
                self._handler.adapter_agent.update_device(device)

            openflow_port = ofp_port(
                port_no=openflow_port_no,
                hw_addr=mac_str_to_tuple('08:00:%02x:%02x:%02x:%02x' %
                                         ((device.parent_port_no >> 8 & 0xff),
                                          device.parent_port_no & 0xff,
                                          (openflow_port_no >> 8) & 0xff,
                                          openflow_port_no & 0xff)),
                name='uni-{}'.format(openflow_port_no),
                config=0,
                state=OFPPS_LIVE,
                curr=capabilities,
                advertised=capabilities,
                peer=capabilities,
                curr_speed=speed,
                max_speed=speed
            )
            self._handler.adapter_agent.add_logical_port(self._handler.logical_device_id,
                                                         LogicalPort(
                                                             id='uni-{}'.format(openflow_port),
                                                             ofp_port=openflow_port,
                                                             device_id=device.id,
                                                             device_port_no=self._port_number))
            # TODO: Should we use the UNI object 'name' as the id for OpenFlow?
