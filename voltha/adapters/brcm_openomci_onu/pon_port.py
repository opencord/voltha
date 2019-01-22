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
from twisted.internet.defer import inlineCallbacks, returnValue
from voltha.protos.common_pb2 import AdminState, OperStatus
from voltha.protos.device_pb2 import Port
from voltha.extensions.omci.tasks.task import Task

BRDCM_DEFAULT_VLAN = 4091
TASK_PRIORITY = Task.DEFAULT_PRIORITY + 10
DEFAULT_TPID = 0x8100
DEFAULT_GEM_PAYLOAD = 48


class PonPort(object):
    """Wraps northbound-port/ANI support for ONU"""
    # TODO: possibly get from olt
    MIN_GEM_ENTITY_ID = 0x408
    MAX_GEM_ENTITY_ID = 0x4FF  # TODO: This limits is internal to specific ONU. It should be more "discoverable"?

    def __init__(self, handler, port_no):
        self.log = structlog.get_logger(device_id=handler.device_id, port_no=port_no)
        self.log.debug('function-entry')

        self._enabled = False
        self._valid = True
        self._handler = handler
        self._deferred = None
        self._port = None
        self._port_number = port_no
        self._next_entity_id = PonPort.MIN_GEM_ENTITY_ID

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        self._gem_ports = {}                           # gem-id -> GemPort
        self._tconts = {}                              # alloc-id -> TCont

        self.ieee_mapper_service_profile_entity_id = 0x8001
        self.mac_bridge_port_ani_entity_id = 0x2102  # TODO: can we just use the entity id from the anis list?

    def __str__(self):
        return "PonPort - port_number: {}, next_entity_id: {}, num_gem_ports: {}, num_tconts: {}".format(
            self._port_number, self._next_entity_id, len(self._gem_ports), len(self._tconts))

    def __repr__(self):
        return str(self)

    @staticmethod
    def create(handler, port_no):
        log = structlog.get_logger(device_id=handler.device_id, port_no=port_no)
        log.debug('function-entry')
        port = PonPort(handler, port_no)

        return port

    def _start(self):
        self.log.debug('function-entry')
        self._cancel_deferred()

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        self._update_adapter_agent()

    def _stop(self):
        self.log.debug('function-entry')
        self._cancel_deferred()

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()

        # TODO: stop h/w sync

    def _cancel_deferred(self):
        self.log.debug('function-entry')
        d1, self._deferred = self._deferred, None

        for d in [d1]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def delete(self):
        self.log.debug('function-entry')
        self.enabled = False
        self._valid = False
        self._handler = None

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
    def port_number(self):
        self.log.debug('function-entry')
        return self._port_number

    @property
    def next_gem_entity_id(self):
        self.log.debug('function-entry')
        entity_id = self._next_entity_id

        self._next_entity_id = self._next_entity_id + 1
        if self._next_entity_id > PonPort.MAX_GEM_ENTITY_ID:
            self._next_entity_id = PonPort.MIN_GEM_ENTITY_ID

        return entity_id

    @property
    def tconts(self):
        self.log.debug('function-entry')
        return self._tconts

    @property
    def gem_ports(self):
        self.log.debug('function-entry')
        return self._gem_ports

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        self.log.debug('function-entry')

        if self._port is None:
            self._port = Port(port_no=self.port_number,
                              label='PON port',
                              type=Port.PON_ONU,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status,
                              peers=[])
        return self._port

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
        self.log.debug('function-entry', tcont=tcont.alloc_id)

        if not self._valid:
            return      # Deleting

        if not reflow and tcont.alloc_id in self._tconts:
            return      # already created

        self.log.info('add-tcont', tcont=tcont.alloc_id, reflow=reflow)
        self._tconts[tcont.alloc_id] = tcont

    def update_tcont_td(self, alloc_id, new_td):
        self.log.debug('function-entry')

        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            return  # not-found

        tcont.traffic_descriptor = new_td

        # TODO: Not yet implemented
        #TODO: How does this affect ONU tcont settings?
        #try:
        #    results = yield tcont.add_to_hardware(self._handler.omci)
        #except Exception as e:
        #    self.log.exception('tcont', tcont=tcont, e=e)
        #    # May occur with xPON provisioning, use hw-resync to recover
        #    results = 'resync needed'
        # returnValue(results)

    @inlineCallbacks
    def remove_tcont(self, alloc_id):
        self.log.debug('function-entry')

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

    def gem_port(self, gem_id, direction):
        self.log.debug('function-entry')
        return self._gem_ports.get((gem_id, direction))

    @property
    def gem_ids(self):
        """Get all GEM Port IDs used by this ONU"""
        self.log.debug('function-entry')
        return sorted([gem_id_and_direction[0] for gem_id_and_direction, gem in self._gem_ports.items()])

    def add_gem_port(self, gem_port, reflow=False):
        """
        Add a GEM Port to this ONU

        :param gem_port: (GemPort) GEM Port to add
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        self.log.debug('function-entry', gem_port=gem_port.gem_id)

        if not self._valid:
            return  # Deleting

        if not reflow and (gem_port.gem_id, gem_port.direction) in self._gem_ports:
            return  # nop

        # if this is actually a new gem port then issue the next entity_id
        gem_port.entity_id = self.next_gem_entity_id
        self.log.info('add-gem-port', gem_port=gem_port, reflow=reflow)
        self._gem_ports[(gem_port.gem_id, gem_port.direction)] = gem_port

    @inlineCallbacks
    def remove_gem_id(self, gem_id, direction):
        """
        Remove a GEM Port from this ONU

        :param gem_id: (GemPort) GEM Port to remove
        :param direction: Direction of the gem port
        :return: deferred
        """
        self.log.debug('function-entry', gem_id=gem_id)

        gem_port = self._gem_ports.get((gem_id, direction))

        if gem_port is None:
            returnValue('nop')

        try:
            del self._gem_ports[(gem_id, direction)]
            results = yield gem_port.remove_from_hardware(self._handler.openomci.omci_cc)
            returnValue(results)

        except Exception as ex:
            self.log.exception('gem-port-delete', e=ex)
            raise


