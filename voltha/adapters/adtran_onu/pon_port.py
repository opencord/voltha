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
from twisted.internet.defer import inlineCallbacks, returnValue
from voltha.protos.common_pb2 import AdminState, OperStatus
from voltha.protos.device_pb2 import Port


class PonPort(object):
    """Wraps northbound-port/ANI support for ONU"""
    MIN_GEM_ENTITY_ID = 0x4900
    MAX_GEM_ENTITY_ID = 0x4AFF

    def __init__(self, handler, port_no):
        self.log = structlog.get_logger(device_id=handler.device_id, port_no=port_no)

        self._enabled = False
        self._valid = True
        self._handler = handler
        self._deferred = None
        self._port = None
        self._port_number = port_no
        self._entity_id = None                  # ANI entity ID
        self._next_entity_id = PonPort.MIN_GEM_ENTITY_ID

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        self._gem_ports = {}                           # gem-id -> GemPort
        self._tconts = {}                              # alloc-id -> TCont

        # OMCI resources
        # TODO: These could be dynamically chosen (can be most any value)
        self.ieee_mapper_service_profile_entity_id = 0x100
        self.mac_bridge_port_ani_entity_id = 0x100

    def __str__(self):
        return "PonPort"      # TODO: Encode current state

    @staticmethod
    def create(handler, port_no):
        port = PonPort(handler, port_no)
        return port

    def _start(self):
        self._cancel_deferred()

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        self._update_adapter_agent()

    def _stop(self):
        self._cancel_deferred()

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()

        # TODO: stop h/w sync

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None

        for d in [d1]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def delete(self):
        self.enabled = False
        self._valid = False
        self._handler = None

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
            return self._port_number

    @property
    def entity_id(self):
        """
        OMCI ANI_G entity ID for port
        """
        return self._entity_id

    @entity_id.setter
    def entity_id(self, value):
        assert self._entity_id is None or self._entity_id == value, 'Cannot reset the Entity ID'
        self._entity_id = value

    @property
    def next_gem_entity_id(self):
        entity_id = self._next_entity_id

        self._next_entity_id = self._next_entity_id + 1
        if self._next_entity_id > PonPort.MAX_GEM_ENTITY_ID:
            self._next_entity_id = PonPort.MIN_GEM_ENTITY_ID

        return entity_id

    @property
    def tconts(self):
        return self._tconts

    @property
    def gem_ports(self):
        return self._gem_ports

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self._port is None:
            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            self._port = Port(port_no=self.port_number,
                              label='PON port',
                              type=Port.PON_ONU,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status,
                              peers=[Port.PeerPort(device_id=device.parent_id,
                                                   port_no=device.parent_port_no)])
        return self._port

    def _update_adapter_agent(self):
        """
        Update the port status and state in the core
        """
        self.log.debug('update-adapter-agent', admin_state=self._admin_state,
                       oper_status=self._oper_status)

        if self._port is not None:
            self._port.admin_state = self._admin_state
            self._port.oper_status = self._oper_status

        # adapter_agent add_port also does an update of port status
        try:
            self._handler.adapter_agent.add_port(self._handler.device_id, self.get_port())
        except Exception as e:
            self.log.exception('update-port', e=e)

    def add_tcont(self, tcont, reflow=False):
        """
        Creates/ a T-CONT with the given alloc-id

        :param tcont: (TCont) Object that maintains the TCONT properties
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            return      # Deleting

        if not reflow and tcont.alloc_id in self._tconts:
            return      # already created

        self.log.info('add', tcont=tcont, reflow=reflow)
        self._tconts[tcont.alloc_id] = tcont

    @inlineCallbacks
    def remove_tcont(self, alloc_id):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue('nop')

        try:
            del self._tconts[alloc_id]
            results = yield tcont.remove_from_hardware(self._handler.openomci.omci_cc)
            returnValue(results)

        except Exception as e:
            self.log.exception('delete', e=e)
            raise

    def gem_port(self, gem_id):
        return self._gem_ports.get(gem_id)

    @property
    def gem_ids(self):
        """Get all GEM Port IDs used by this ONU"""
        return sorted([gem_id for gem_id, gem in self._gem_ports.items()])

    def add_gem_port(self, gem_port, reflow=False):
        """
        Add a GEM Port to this ONU

        :param gem_port: (GemPort) GEM Port to add
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            return  # Deleting

        if not reflow and gem_port.gem_id in self._gem_ports:
            return  # nop

        self.log.info('add', gem_port=gem_port, reflow=reflow)
        self._gem_ports[gem_port.gem_id] = gem_port

    @inlineCallbacks
    def remove_gem_id(self, gem_id):
        """
        Remove a GEM Port from this ONU

        :param gem_port: (GemPort) GEM Port to remove
        :return: deferred
        """
        gem_port = self._gem_ports.get(gem_id)

        if gem_port is None:
            returnValue('nop')

        try:
            del self._gem_ports[gem_id]
            results = yield gem_port.remove_from_hardware(self._handler.openomci.omci_cc)
            returnValue(results)

        except Exception as ex:
            self.log.exception('gem-port-delete', e=ex)
            raise
