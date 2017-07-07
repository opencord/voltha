#
# Copyright 2017-present Adtran, Inc.
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
import json
import pprint
import random

import os
import structlog
from enum import Enum
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, succeed

from adtran_olt_handler import AdtranOltHandler
from codec.olt_config import OltConfig
from onu import Onu
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Device
from voltha.protos.device_pb2 import Port


class PonPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA
    
    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """
    MAX_ONUS_SUPPORTED = 256
    DEFAULT_ENABLED = False

    class State(Enum):
        INITIAL = 0  # Created and initialization in progress
        RUNNING = 1  # PON port contacted, ONU discovery active
        STOPPED = 2  # Disabled
        DELETING = 3  # Cleanup

    def __init__(self, pon_index, port_no, parent, admin_state=AdminState.UNKNOWN, label=None):
        # TODO: Weed out those properties supported by common 'Port' object (future)
        assert admin_state != AdminState.UNKNOWN

        self.log = structlog.get_logger(pon_id=pon_index)

        self._parent = parent
        self._pon_id = pon_index
        self._port_no = port_no
        self._name = 'xpon {}'.format(pon_index)
        self._label = label or 'PON-{}'.format(pon_index)
        self._port = None
        self._no_onu_discover_tick = 5.0  # TODO: Decrease to 1 or 2 later
        self._discovery_tick = 20.0
        self._discovered_onus = []  # List of serial numbers
        self._onus = {}  # serial_number -> ONU  (allowed list)
        self._next_onu_id = Onu.MIN_ONU_ID

        # TODO: Currently cannot update admin/oper status, so create this enabled and active
        # self._admin_state = admin_state
        # self._oper_status = OperStatus.UNKNOWN
        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        self._deferred = None
        self._state = PonPort.State.INITIAL

        # Local cache of PON configuration

        self._enabled = None
        self._downstream_fec_enable = None
        self._upstream_fec_enable = None

    def __del__(self):
        self.stop()

    def __str__(self):
        return "PonPort-{}: Admin: {}, Oper: {}, parent: {}".format(self._label,
                                                                    self._admin_state,
                                                                    self._oper_status,
                                                                    self._parent)

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self._port is None:
            self._port = Port(port_no=self._port_no,
                              label=self._label,
                              type=Port.PON_OLT,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status)
        return self._port

    @property
    def port_number(self):
        return self._port_no

    @property
    def name(self):
        return self._name

    @property
    def pon_id(self):
        return self._pon_id

    @property
    def olt(self):
        return self._parent

    @property
    def state(self):
        return self._state

    @property
    def adapter_agent(self):
        return self.olt.adapter_agent

    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port. For PON ports, a logical port
        is not currently created, so always return None

        :return: VOLTHA logical port or None if not supported
        """
        return None

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None
        if d is not None:
            d.cancel()

    def _update_adapter_agent(self):
        # TODO: Currently the adapter_agent does not allow 'update' of port status
        # self.adapter_agent.update_port(self.olt.device_id, self.get_port())
        pass

    def start(self):
        """
        Start/enable this PON and start ONU discover
        :return: (deferred)
        """
        if self._state == PonPort.State.RUNNING:
            return succeed('Running')

        self.log.info('Starting {}'.format(self._label))

        self._cancel_deferred()
        self._state = PonPort.State.INITIAL

        # Do the rest of the startup in an async method
        self._deferred = reactor.callLater(0.5, self._finish_startup)
        return self._deferred

    @inlineCallbacks
    def _finish_startup(self):
        """
        Do all startup offline since REST may fail
        """
        if self._state != PonPort.State.INITIAL:
            returnValue('Done')

        self.log.debug('Performing final port startup')

        if self._enabled is None or self._downstream_fec_enable is None or self._upstream_fec_enable is None:
            try:
                self._deferred = self.get_pon_config()
                results = yield self._deferred

            except Exception as e:
                self.log.exception('Initial GET of config failed: {}'.format(e.message))
                self._deferred = reactor.callLater(5, self._finish_startup)
                returnValue(self._deferred)

            # Load cache

            self._enabled = results.get('enabled', False)
            self._downstream_fec_enable = results.get('downstream-fec-enable', False)
            self._upstream_fec_enable = results.get('upstream-fec-enable', False)

        if not self._enabled:
            try:
                self._deferred = self.set_pon_config("enabled", True)
                results = yield self._deferred
                self._enabled = True

            except Exception as e:
                self.log.exception('enabled failed: {}'.format(str(e)))
                self._deferred = reactor.callLater(3, self._finish_startup)
                returnValue(self._deferred)

        if not self._downstream_fec_enable:
            try:
                self._deferred = self.set_pon_config("downstream-fec-enable", True)
                results = yield self._deferred
                self._downstream_fec_enable = True

            except Exception as e:
                self.log.exception('downstream FEC enable failed: {}'.format(str(e)))
                self._deferred = reactor.callLater(5, self._finish_startup)
                returnValue(self._deferred)

        if not self._upstream_fec_enable:
            try:
                self._deferred = self.set_pon_config("upstream-fec-enable", True)
                results = yield self._deferred
                self._upstream_fec_enable = True

            except Exception as e:
                self.log.exception('upstream FEC enable failed: {}'.format(str(e)))
                self._deferred = reactor.callLater(5, self._finish_startup)
                returnValue(self._deferred)

            self.log.debug('ONU Startup complete: results: {}'.format(pprint.PrettyPrinter().pformat(results)))

        if self._enabled:
            self._admin_state = AdminState.ENABLED
            self._oper_status = OperStatus.ACTIVE  # TODO: is this correct, how do we tell GRPC
            self._state = PonPort.State.RUNNING

            # Begin to ONU discovery. Once a second if no ONUs found and once every 20
            #                         seconds after one or more ONUs found on the PON
            self._deferred = reactor.callLater(1, self.discover_onus)

            self._update_adapter_agent()
            returnValue('Enabled')

        else:
            # Startup failed. Could be due to object creation with an invalid initial admin_status
            #                 state.  May want to schedule a start to occur again if this happens
            self._admin_state = AdminState.DISABLED
            self._oper_status = OperStatus.UNKNOWN
            self._state = PonPort.State.STOPPED

            self._update_adapter_agent()
            returnValue('Disabled')

    def stop(self):
        if self._state == PonPort.State.STOPPED:
            return succeed('Stopped')

        self.log.info('Stopping {}'.format(self._label))

        self._cancel_deferred()
        self._deferred = self.set_pon_config("enabled", False)

        # Flush config cache
        self._enabled = None
        self._downstream_fec_enable = None
        self._upstream_fec_enable = None

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()

        self._state = PonPort.State.STOPPED
        return self._deferred

    @inlineCallbacks
    def reset(self):
        """
        Set the PON Port to a known good state on initial port startup.  Actual
        PON 'Start' is done elsewhere
        """
        if self._state != PonPort.State.INITIAL:
            self.log.error('Reset ignored, only valid during initial startup', state=self._state)
            returnValue('Ignored')

        self.log.info('Reset {}'.format(self._label))

        if self._admin_state != self._parent.initial_port_state:
            try:
                enable = self._parent.initial_port_state == AdminState.ENABLED
                yield self.set_pon_config("enabled", enable)

                # TODO: Move to 'set_pon_config' method and also make sure GRPC/Port is ok
                self._admin_state = AdminState.ENABLED if enable else AdminState.DISABLE

            except Exception as e:
                self.log.exception('Reset of PON to initial state failed', e=e)
                raise

        if self._admin_state == AdminState.ENABLED and self._parent.initial_onu_state == AdminState.DISABLED:
            try:
                # Walk the provisioned ONU list and disable any exiting ONUs
                results = yield self.get_onu_config()

                if isinstance(results, list) and len(results) > 0:
                    onu_configs = OltConfig.Pon.Onu.decode(results)
                    for onu_id in onu_configs.iterkeys():
                        try:
                            yield self.delete_onu(onu_id)

                        except Exception as e:
                            self.log.exception('Delete of ONU {} on PON failed'.format(onu_id), e=e)
                            pass  # Non-fatal

            except Exception as e:
                self.log.exception('Failed to get current ONU config', e=e)
                raise

        returnValue('Reset complete')

    def delete(self):
        """
        Parent device is being deleted. Do not change any config but
        stop all polling
        """
        self.log.info('Deleteing {}'.format(self._label))
        self._state = PonPort.State.DELETING
        self._cancel_deferred()

    def get_pon_config(self):
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self._pon_id)
        name = 'pon-get-config-{}'.format(self._pon_id)
        return self._parent.rest_client.request('GET', uri, name=name)

    def get_onu_config(self, onu_id=None):
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(self._pon_id)
        if onu_id is not None:
            uri += '={}'.format(onu_id)
        name = 'pon-get-onu_config-{}-{}'.format(self._pon_id, onu_id)
        return self._parent.rest_client.request('GET', uri, name=name)

    def set_pon_config(self, leaf, value):
        data = json.dumps({leaf: value})
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self._pon_id)
        name = 'pon-set-config-{}-{}-{}'.format(self._pon_id, leaf, str(value))
        return self._parent.rest_client.request('PATCH', uri, data=data, name=name)

    def discover_onus(self):
        self.log.debug('Initiating discover of ONU/ONTs')

        if self._admin_state == AdminState.ENABLED:
            data = json.dumps({'pon-id': self._pon_id})
            uri = AdtranOltHandler.GPON_PON_DISCOVER_ONU
            name = 'pon-discover-onu-{}'.format(self._pon_id)

            self._deferred = self._parent.rest_client.request('POST', uri, data, name=name)
            self._deferred.addBoth(self.onu_discovery_init_complete)

    def onu_discovery_init_complete(self, _):
        """
        This method is called after the REST POST to request ONU discovery is
        completed.  The results (body) of the post is always empty / 204 NO CONTENT
        """
        self.log.debug('ONU Discovery requested')

        # Reschedule

        delay = self._no_onu_discover_tick if len(self._onus) == 0 else self._discovery_tick
        delay += random.uniform(-delay / 10, delay / 10)

        self._deferred = reactor.callLater(delay, self.discover_onus)

    def process_status_poll(self, status):
        """
        Process PON status poll request
        
        :param status: (OltState.Pon object) results from RESTCONF GET
        """
        self.log.debug('process_status_poll:  {}{}'.format(os.linesep, status))

        if self._admin_state != AdminState.ENABLED:
            return

        # Process the ONU list in for this PON, may have previously provisioned ones there
        # were discovered on an earlier boot

        new = self._process_status_onu_list(status.onus)

        for onu_id in new:
            # self.add_new_onu(serial_number, status)
            self.log.info('Found ONU {} in status list'.format(onu_id))
            raise NotImplementedError('TODO: Adding ONUs from existing ONU (status list) not supported')

        # Get new/missing from the discovered ONU leaf

        new, missing = self._process_status_onu_discovered_list(status.discovered_onu)

        # TODO: Do something useful (Does the discovery list clear out activated ONU's?)
        # if len(missing):
        #     self.log.info('Missing ONUs are: {}'.format(missing))

        for serial_number in new:
            reactor.callLater(0, self.add_onu, serial_number, status)

        # Process discovered ONU list

        # TODO: Process LOS list
        # TODO: Process status
        pass

    def _process_status_onu_list(self, onus):
        """
        Look for new or missing ONUs

        :param onus: (dict) Set of known ONUs
        """
        self.log.debug('Processing ONU list: {}'.format(onus))

        my_onu_ids = frozenset([o.onu_id for o in self._onus.itervalues()])
        discovered_onus = frozenset(onus.keys())

        new_onus_ids = discovered_onus - my_onu_ids
        missing_onus_ids = my_onu_ids - discovered_onus

        new = {o: v for o, v in onus.iteritems() if o in new_onus_ids}
        missing_onus = {o: v for o, v in onus.iteritems() if o in missing_onus_ids}

        return new  # , missing_onus        # TODO: Support ONU removal

    def _process_status_onu_discovered_list(self, discovered_onus):
        """
        Look for new or missing ONUs
        
        :param discovered_onus: (frozenset) Set of ONUs currently discovered
        """
        self.log.debug('Processing discovered ONU list: {}'.format(discovered_onus))

        my_onus = frozenset(self._onus.keys())

        new_onus = discovered_onus - my_onus
        missing_onus = my_onus - discovered_onus

        return new_onus, missing_onus

    @inlineCallbacks
    def add_onu(self, serial_number, status):
        self.log.info('Add ONU: {}'.format(serial_number))

        if serial_number not in status.onus:
            # Newly found and not enabled ONU, enable it now if not at max

            if len(self._onus) < self.MAX_ONUS_SUPPORTED:
                # TODO: For now, always allow any ONU to be activated

                if serial_number not in self._onus:
                    try:
                        onu = Onu(serial_number, self)
                        yield onu.create(True)

                        self.on_new_onu_discovered(onu)
                        self._onus[serial_number] = onu

                    except Exception as e:
                        self.log.exception('Exception during add_onu, onu: {}'.format(onu.onu_id), e=e)
                else:
                    self.log.info('TODO: Code this')

            else:
                self.log.warning('Maximum number of ONUs already provisioned')
        else:
            # ONU has been enabled
            pass

    def on_new_onu_discovered(self, onu):
        """
        Called when a new ONU is discovered and VOLTHA device adapter needs to be informed
        :param onu: 
        :return: 
        """
        olt = self.olt
        adapter = self.adapter_agent
        channel_id = self.olt.get_channel_id(self._pon_id, onu.onu_id)

        proxy = Device.ProxyAddress(device_id=olt.device_id, channel_id=channel_id)

        adapter.child_device_detected(parent_device_id=olt.device_id,
                                      parent_port_no=self._port_no,
                                      child_device_type=onu.vendor_device,
                                      proxy_address=proxy,
                                      admin_state=AdminState.ENABLED,
                                      vlan=channel_id)

    def get_next_onu_id(self):
        used_ids = [onu.onu_id for onu in self._onus.itervalues()]

        while True:
            onu_id = self._next_onu_id
            self._next_onu_id += 1

            if self._next_onu_id > Onu.MAX_ONU_ID:
                self._next_onu_id = Onu.MIN_ONU_ID

            if onu_id not in used_ids:
                return onu_id

    def delete_onu(self, onu_id):
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(self._pon_id)
        uri += '={}'.format(onu_id)
        name = 'pon-delete-onu-{}-{}'.format(self._pon_id, onu_id)

        # TODO: Need removal from VOLTHA child_device method

        return self._parent.rest_client.request('DELETE', uri, name=name)
