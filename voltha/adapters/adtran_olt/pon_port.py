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

import json
import random
import arrow

import structlog
from enum import Enum
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue, succeed

from adtran_olt_handler import AdtranOltHandler
from codec.olt_config import OltConfig
from onu import Onu
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Device
from voltha.protos.device_pb2 import Port
from voltha.protos.events_pb2 import AlarmEventType, AlarmEventSeverity, AlarmEventState, AlarmEventCategory


class PonPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA

    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """
    MAX_ONUS_SUPPORTED = 256
    DEFAULT_ENABLED = False
    MAX_DEPLOYMENT_RANGE = 40000    # Meters

    _MCAST_ONU_ID = 253
    _MCAST_ALLOC_BASE = 0x500

    class State(Enum):
        INITIAL = 0   # Created and initialization in progress
        RUNNING = 1   # PON port contacted, ONU discovery active
        STOPPED = 2   # Disabled
        DELETING = 3  # Cleanup

    _SUPPORTED_ACTIVATION_METHODS = ['autodiscovery', 'autoactivate']
    _SUPPORTED_AUTHENTICATION_METHODS = ['serial-number']

    def __init__(self, pon_index, port_no, parent):
        # TODO: Weed out those properties supported by common 'Port' object (future)
        self.log = structlog.get_logger(device_id=parent.device_id, pon_id=pon_index)

        self._parent = parent
        self._pon_id = pon_index
        self._port_no = port_no
        self._name = 'xpon 0/{}'.format(pon_index+1)
        self._label = 'pon-{}'.format(pon_index)
        self._port = None
        self._no_onu_discover_tick = 5.0
        self._discovery_tick = 20.0
        self._discovered_onus = []  # List of serial numbers
        self._sync_tick = 20.0
        self._in_sync = False
        self._expedite_sync = False
        self._expedite_count = 0

        self._onus = {}         # serial_number-base64 -> ONU  (allowed list)
        self._onu_by_id = {}    # onu-id -> ONU
        self._next_onu_id = Onu.MIN_ONU_ID + 128
        self._mcast_gem_ports = {}                # VLAN -> GemPort

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.DISCOVERED
        self._state = PonPort.State.INITIAL
        self._deferred = None                     # General purpose
        self._discovery_deferred = None           # Specifically for ONU discovery
        self._sync_deferred = None                # For sync of PON config to hardware

        self._active_los_alarms = set()           # ONU-ID

        # xPON configuration

        self._xpon_name = None
        self._enabled = False
        self._downstream_fec_enable = False
        self._upstream_fec_enable = False
        self._deployment_range = 25000
        self._authentication_method = 'serial-number'

        if self.olt.autoactivate:
            # Enable PON on startup
            self._activation_method = 'autoactivate'
            self._admin_state = AdminState.ENABLED
        else:
            self._activation_method = 'autodiscovery'

    def __del__(self):
        self.stop()

    def __str__(self):
        return "PonPort-{}: Admin: {}, Oper: {}, OLT: {}".format(self._label,
                                                                 self._admin_state,
                                                                 self._oper_status,
                                                                 self.olt)

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self._port is None:
            self._port = Port(port_no=self._port_no,
                              label=self._label,
                              type=Port.PON_OLT,
                              admin_state=AdminState.ENABLED,
                              oper_status=OperStatus.ACTIVE)
            # TODO: For now, no way to report the proper ADMIN or OPER status
            # admin_state=self._admin_state,
            # oper_status=self._oper_status)
        return self._port

    @property
    def port_number(self):
        return self._port_no

    @property
    def name(self):
        return self._name

    @property
    def xpon_name(self):
        return self._xpon_name

    @xpon_name.setter
    def xpon_name(self, value):
        assert '/' not in value, "xPON names cannot have embedded forward slashes '/'"
        self._xpon_name = value

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
    def admin_state(self):
        return self._admin_state

    @admin_state.setter
    def admin_state(self, value):
        if self._admin_state != value:
            self._admin_state = value
            if self._admin_state == AdminState.ENABLED:
                self.start()
            else:
                self.stop()

    @property
    def adapter_agent(self):
        return self.olt.adapter_agent

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        assert isinstance(value, bool), 'enabled is a boolean'
        if self._enabled != value:
            if value:
                self.start()
            self.stop()

    @property
    def downstream_fec_enable(self):
        return self._downstream_fec_enable

    @downstream_fec_enable.setter
    def downstream_fec_enable(self, value):
        assert isinstance(value, bool), 'downstream FEC enabled is a boolean'

        if self._downstream_fec_enable != value:
            self._downstream_fec_enable = value
            if self._state == PonPort.State.RUNNING:
                self._deferred = self._set_pon_config("downstream-fec-enable", value)

    @property
    def upstream_fec_enable(self):
        return self._upstream_fec_enable

    @upstream_fec_enable.setter
    def upstream_fec_enable(self, value):
        assert isinstance(value, bool), 'upstream FEC enabled is a boolean'

        if self._upstream_fec_enable != value:
            self._upstream_fec_enable = value
            if self._state == PonPort.State.RUNNING:
                self._deferred = self._set_pon_config("upstream-fec-enable", value)

    @property
    def deployment_range(self):
        """Maximum deployment range (in meters)"""
        return self._deployment_range

    @deployment_range.setter
    def deployment_range(self, value):
        """Maximum deployment range (in meters)"""
        if not 0 <= value <= PonPort.MAX_DEPLOYMENT_RANGE:
            raise ValueError('Deployment range should be 0..{} meters'.
                             format(PonPort.MAX_DEPLOYMENT_RANGE))
        if self._deployment_range != value:
            self._deployment_range = value
            if self._state == PonPort.State.RUNNING:
                self._deferred = self._set_pon_config("deployment-range", value)

    @property
    def discovery_tick(self):
        return self._discovery_tick * 10
    
    @discovery_tick.setter
    def discovery_tick(self, value):
        if value < 0:
            raise ValueError("Polling interval must be >= 0")

        if self.discovery_tick != value:
            self._discovery_tick = value / 10

            try:
                if self._discovery_deferred is not None and \
                        not self._discovery_deferred.called:
                    self._discovery_deferred.cancel()
            except:
                pass
            self._discovery_deferred = None

            if self._discovery_tick > 0:
                self._discovery_deferred = reactor.callLater(self._discovery_tick,
                                                             self._discover_onus)

    @property
    def activation_method(self):
        return self._activation_method

    @activation_method.setter
    def activation_method(self, value):
        value = value.lower()
        if value not in PonPort._SUPPORTED_ACTIVATION_METHODS:
            raise ValueError('Invalid ONU activation method')
        self._activation_method = value

    @property
    def authentication_method(self):
        return self._authentication_method

    @authentication_method.setter
    def authentication_method(self, value):
        value = value.lower()
        if value not in PonPort._SUPPORTED_AUTHENTICATION_METHODS:
            raise ValueError('Invalid ONU authentication method')
        self._authentication_method = value

    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port. For PON ports, a logical port
        is not currently created, so always return None

        :return: VOLTHA logical port or None if not supported
        """
        return None

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._discovery_deferred = self._discovery_deferred, None
        d3, self._sync_deferred = self._sync_deferred, None

        for d in [d1, d2, d3]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except Exception as e:
                pass

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

        self.log.info('start')

        self._cancel_deferred()
        self._state = PonPort.State.INITIAL
        self._oper_status = OperStatus.ACTIVATING
        self._enabled = True

        # Do the rest of the startup in an async method
        self._deferred = reactor.callLater(0.5, self._finish_startup)
        self._update_adapter_agent()

        return succeed('Scheduled')

    @inlineCallbacks
    def _finish_startup(self):
        """
        Do all startup offline since REST may fail
        """
        if self._state != PonPort.State.INITIAL:
            returnValue('Done')

        self.log.debug('final-startup')

        try:
            self._deferred = self._get_pon_config()
            results = yield self._deferred

        except Exception as e:
            self.log.exception('initial-GET', e=e)
            self._deferred = reactor.callLater(5, self._finish_startup)
            returnValue(self._deferred)

        # Load config from hardware

        enabled = results.get('enabled', False)
        downstream_fec_enable = results.get('downstream-fec-enable', False)
        upstream_fec_enable = results.get('upstream-fec-enable', False)
        deployment_range = results.get('deployment-range', 25000)
        self._in_sync = True

        if enabled != self._enabled:
            try:
                self._deferred = self._set_pon_config("enabled", True)
                yield self._deferred

            except Exception as e:
                self.log.exception('final-startup-enable', e=e)
                self._deferred = reactor.callLater(3, self._finish_startup)
                returnValue(self._deferred)

        if downstream_fec_enable != self._downstream_fec_enable:
            try:
                self._deferred = self._set_pon_config("downstream-fec-enable",
                                                      self._downstream_fec_enable)
                yield self._deferred

            except Exception as e:
                self.log.warning('final-startup-downstream-FEC', e=e)
                self._in_sync = False
                # Non-fatal. May have failed due to no SFQ in slot

        if upstream_fec_enable != self._upstream_fec_enable:
            try:
                self._deferred = self._set_pon_config("upstream-fec-enable",
                                                      self._upstream_fec_enable)
                yield self._deferred

            except Exception as e:
                self.log.warning('final-startup-upstream-FEC', e=e)
                self._in_sync = False
                # Non-fatal. May have failed due to no SFQ in slot

        if deployment_range != self._deployment_range:
            try:
                self._deferred = self._set_pon_config("deployment-range",
                                                      self._deployment_range)
                yield self._deferred

            except Exception as e:
                self.log.warning('final-startup-deployment-range', e=e)
                self._in_sync = False
                # Non-fatal. May have failed due to no SFQ in slot

        # If here, initial settings were successfully written to hardware

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE  # TODO: is this correct, how do we tell GRPC
        self._state = PonPort.State.RUNNING

        # Restart any ONU's in case here due to reboot

        if len(self._onus) > 0:
            dl = []
            for onu in self._onus.itervalues():
                dl.append(onu.restart())
            yield defer.gatherResults(dl, consumeErrors=True)

        # Begin to ONU discovery and hardware sync

        self._discovery_deferred = reactor.callLater(5, self._discover_onus)
        self._sync_deferred = reactor.callLater(60, self._sync_hardware)

        self._update_adapter_agent()
        returnValue('Enabled')

    @inlineCallbacks
    def stop(self):
        if self._state == PonPort.State.STOPPED:
            self.log.debug('already stopped')
            returnValue(succeed('Stopped'))

        self.log.info('stopping')

        self._cancel_deferred()
        self._enabled = False
        results = yield self._set_pon_config("enabled", False)
        self._sync_deferred = reactor.callLater(self._sync_tick, self._sync_hardware)

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()

        self._state = PonPort.State.STOPPED
        self.log.debug('stopped')
        returnValue(results)

    @inlineCallbacks
    def reset(self):
        """
        Set the PON Port to a known good state on initial port startup.  Actual
        PON 'Start' is done elsewhere
        """
        if self._state != PonPort.State.INITIAL:
            self.log.error('reset-ignored', state=self._state)
            returnValue('Ignored')

        initial_port_state = AdminState.ENABLED if self.olt.autoactivate else AdminState.DISABLED
        self.log.info('reset', initial_state=initial_port_state)

        try:
            self._deferred = self._get_pon_config()
            results = yield self._deferred
            enabled = results.get('enabled', False)

        except Exception as e:
            self.log.exception('get-config', e=e)
            enabled = False

        enable = initial_port_state == AdminState.ENABLED

        if enable != enabled:
            try:
                self._deferred = yield self._set_pon_config("enabled", enable)
            except Exception as e:
                self.log.exception('reset-enabled', e=e, enabled=enabled)

        # TODO: Move to 'set_pon_config' method and also make sure GRPC/Port is ok
        self._admin_state = AdminState.ENABLED if enable else AdminState.DISABLED

        try:
            # Walk the provisioned ONU list and disable any exiting ONUs
            results = yield self._get_onu_config()

            if isinstance(results, list) and len(results) > 0:
                onu_configs = OltConfig.Pon.Onu.decode(results)
                dl = []
                for onu_id in onu_configs.iterkeys():
                    dl.append(self.delete_onu(onu_id))

                try:
                    if len(dl) > 0:
                        yield defer.gatherResults(dl, consumeErrors=True)

                except Exception as e:
                    self.log.exception('rest-ONU-delete', onu_id=onu_id, e=e)
                    pass  # Non-fatal

        except Exception as e:
            self.log.exception('onu-delete', e=e)

        returnValue('Reset complete')

    def restart(self):
        if self._state == PonPort.State.RUNNING or self._state == PonPort.State.STOPPED:
            start_it = (self._state == PonPort.State.RUNNING)
            self._state = PonPort.State.INITIAL

            return self.start() if start_it else self.stop()
        return succeed('nop')

    def delete(self):
        """
        Parent device is being deleted. Do not change any config but
        stop all polling
        """
        self.log.info('Deleting')
        self._state = PonPort.State.DELETING
        self._cancel_deferred()

    def gem_ids(self, vid, exception_gems, multicast_gems):
        """
        Get all GEM Port IDs used on a given PON

        :param vid: (int) VLAN ID if customer ONU specific. None if for all ONUs
                          on PON, if Multicast, VID for Multicast, or None for all\
                          Multicast GEMPorts
        :param exception_gems: (boolean) Select from special purpose ACL GEM-Portas
        :param multicast_gems: (boolean) Select from available Multicast GEM Ports
        :return: (dict) data_gem -> key -> onu-id, value -> tuple(sorted list of GEM Port IDs, onu_vid)
                        mcast_gem-> key -> mcast-vid, value -> GEM Port IDs
        """
        gem_ids = {}

        if multicast_gems:
            # Multicast GEMs belong to the PON, but we may need to register them on
            # all ONUs. Rework when BBF MCAST Gems are supported
            for vlan, gem_port in self._mcast_gem_ports.iteritems():
                if vid is None or (vid == vlan and vid in self.olt.multicast_vlans):
                    gem_ids[vlan] = ([gem_port.gem_id], None)
        else:
            for onu_id, onu in self._onu_by_id.iteritems():
                if vid is None or vid == onu.onu_vid:
                    gem_ids[onu_id] = (onu.gem_ids(exception_gems), onu.onu_vid)  # FIXED_ONU

        return gem_ids

    def _get_pon_config(self):
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self._pon_id)
        name = 'pon-get-config-{}'.format(self._pon_id)
        return self._parent.rest_client.request('GET', uri, name=name)

    def _get_onu_config(self, onu_id=None):
        if onu_id is None:
            uri = AdtranOltHandler.GPON_ONU_CONFIG_LIST_URI.format(self._pon_id)
        else:
            uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, onu_id)

        name = 'pon-get-onu_config-{}-{}'.format(self._pon_id, onu_id)
        return self._parent.rest_client.request('GET', uri, name=name)

    def _set_pon_config(self, leaf, value):
        data = json.dumps({leaf: value})
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self._pon_id)
        name = 'pon-set-config-{}-{}-{}'.format(self._pon_id, leaf, str(value))
        return self._parent.rest_client.request('PATCH', uri, data=data, name=name)

    def _discover_onus(self):
        self.log.debug('discovery', state=self._admin_state, in_sync=self._in_sync)
        if self._admin_state == AdminState.ENABLED:
            if self._in_sync:
                data = json.dumps({'pon-id': self._pon_id})
                uri = AdtranOltHandler.GPON_PON_DISCOVER_ONU
                name = 'pon-discover-onu-{}'.format(self._pon_id)

                self._discovery_deferred = self._parent.rest_client.request('POST', uri, data, name=name)
                self._discovery_deferred.addBoth(self._onu_discovery_init_complete)
            else:
                self.discovery_deferred = reactor.callLater(0,
                                                            self._onu_discovery_init_complete,
                                                            None)

    def _onu_discovery_init_complete(self, _):
        """
        This method is called after the REST POST to request ONU discovery is
        completed.  The results (body) of the post is always empty / 204 NO CONTENT
        """
        delay = self._no_onu_discover_tick if len(self._onus) == 0 else self._discovery_tick
        delay += random.uniform(-delay / 10, delay / 10)
        self._discovery_deferred = reactor.callLater(delay, self._discover_onus)

    def _sync_hardware(self):
        if self._state == PonPort.State.RUNNING or self._state == PonPort.State.STOPPED:
            def read_config(results):
                self.log.debug('read-config', results=results)
                config = OltConfig.Pon.decode([results])
                assert self.pon_id in config, 'sync-pon-not-found-{}'.format(self.pon_id)
                config = config[self.pon_id]
                self._in_sync = True

                dl = []

                if self.enabled != config.enabled:
                    self._in_sync = False
                    self._expedite_sync = True
                    dl.append(self._set_pon_config("enabled", self.enabled))

                elif self._state == PonPort.State.RUNNING:
                    if self.deployment_range != config.deployment_range:
                        self._in_sync = False
                        self._expedite_sync = True
                        dl.append(self._set_pon_config("deployment-range",
                                                       self.deployment_range))

                    if self.downstream_fec_enable != config.downstream_fec_enable:
                        self._in_sync = False
                        self._expedite_sync = True
                        dl.append(self._set_pon_config("downstream-fec-enable",
                                                       self.downstream_fec_enable))

                    if self.upstream_fec_enable != config.upstream_fec_enable:
                        self._in_sync = False
                        self._expedite_sync = True
                        dl.append(self._set_pon_config("upstream-fec-enable",
                                                       self.upstream_fec_enable))
                return defer.gatherResults(dl)

            def sync_onus(results):
                if self._state == PonPort.State.RUNNING:
                    self.log.debug('sync-pon-results', results=results)
                    assert isinstance(results, list), 'expected-list'
                    assert isinstance(results[0], OltConfig.Pon), 'expected-pon-at-front'
                    hw_onus = results[0].onus

                    # ONU's have their own sync task, extra (should be deleted) are
                    # handled here. Missing are handled by normal discovery mechanisms.

                    hw_onu_ids = frozenset([onu.onu_id for onu in hw_onus])
                    my_onu_ids = frozenset(self._onu_by_id.keys())

                    extra_onus = hw_onu_ids - my_onu_ids
                    dl = [self.delete_onu(onu_id) for onu_id in extra_onus]

                    return defer.gatherResults(dl, consumeErrors=True)

            def failure(reason, what):
                self.log.error('hardware-sync-{}-failed'.format(what), reason=reason)
                self._in_sync = False
                self._expedite_sync = False

            def reschedule(_):
                # Speed up sequential resync a limited number of times if out of sync.

                delay = self._sync_tick

                if self._expedite_sync:
                    self._expedite_count += 1
                    if self._expedite_count < 5:
                        delay = 1
                else:
                    self._expedite_count = 0

                delay += random.uniform(-delay / 10, delay / 10)
                self._sync_deferred = reactor.callLater(delay, self._sync_hardware)

            self._sync_deferred = self._get_pon_config()
            self._sync_deferred.addCallbacks(read_config, failure, errbackArgs=['get-config'])
            self._sync_deferred.addCallbacks(sync_onus, failure, errbackArgs=['pon-sync'])
            self._sync_deferred.addBoth(reschedule)

    def process_status_poll(self, status):
        """
        Process PON status poll request
        
        :param status: (OltState.Pon object) results from RESTCONF GET
        """
        self.log.debug('process-status-poll', status=status)

        if self._admin_state != AdminState.ENABLED:
            return

        # Get new/missing from the discovered ONU leaf.  Stale ONUs from previous
        # configs are now cleaned up during h/w re-sync/reflow.

        new, rediscovered_onus = self._process_status_onu_discovered_list(status.discovered_onu)

        # Process newly discovered ONU list and rediscovered ONUs

        for serial_number in new | rediscovered_onus:
            reactor.callLater(0, self.add_onu, serial_number, status)

        # Process LOS list
        self._process_los_alarms(frozenset(status.ont_los))

        # Process ONU info. Note that newly added ONUs will not be processed
        # until the next pass

        self._update_onu_status(status.onus)

    def _update_onu_status(self, onus):
        """
        Process ONU status for this PON
        :param onus: (dict) onu_id: ONU State
        """
        for onu_id, onu_status in onus.iteritems():
            if onu_id in self._onu_by_id:
                self._onu_by_id[onu_id].rssi = onu_status.rssi
                self._onu_by_id[onu_id].equalization_delay = onu_status.equalization_delay
                self._onu_by_id[onu_id].fiber_length = onu_status.fiber_length

    def _process_los_alarms(self, ont_los):
        """
        Walk current LOS and set/clear LOS as appropriate
        :param ont_los: (frozenset) ONU IDs of ONUs in LOS alarm state
        """
        cleared_alarms = self._active_los_alarms - ont_los
        new_alarms = ont_los - self._active_los_alarms

        def los_alarm(status, _id):
            alarm = 'LOS'
            alarm_data = {
                'ts': arrow.utcnow().timestamp,
                'description': self.olt.alarms.format_description('onu LOS', alarm, status),
                'id': self.olt.alarms.format_id(alarm),
                'type': AlarmEventType.COMMUNICATION,
                'category': AlarmEventCategory.ONT,
                'severity': AlarmEventSeverity.MAJOR,
                'state': AlarmEventState.RAISED if status else AlarmEventState.CLEARED
            }
            context_data = {'onu_id': _id}
            self.olt.alarms.send_alarm(context_data, alarm_data)

        if len(cleared_alarms) > 0 or len(new_alarms) > 0:
            self.log.info('onu-los', cleared=cleared_alarms, new=new_alarms)

        for onu_id in cleared_alarms:
            # TODO: test 'clear' of LOS alarm when you delete an ONU in LOS
            self._active_los_alarms.remove(onu_id)
            los_alarm(False, onu_id)

        for onu_id in new_alarms:
            self._active_los_alarms.add(onu_id)
            los_alarm(True, onu_id)

        # TODO: A method to update the AdapterAgent's child device state (operStatus)
        #       would be useful here

    def _process_status_onu_discovered_list(self, discovered_onus):
        """
        Look for new ONUs
        
        :param discovered_onus: (frozenset) Set of ONUs currently discovered
        """
        self.log.debug('discovered-ONUs', list=discovered_onus)

        # Only request discovery if activation is auto-discovery or auto-activate
        continue_discovery = ['autodiscovery', 'autoactivate']

        if self._activation_method not in continue_discovery:
            return set(), set()

        my_onus = frozenset(self._onus.keys())

        new_onus = discovered_onus - my_onus
        rediscovered_onus = my_onus & discovered_onus

        return new_onus, rediscovered_onus

    def _get_onu_info(self, serial_number):
        """
        Parse through available xPON information for ONU configuration settings
        :param serial_number: (string) Decoded (not base64) serial number string
        :return: (dict) onu config data or None on lookup failure
        """
        try:
            from flow.demo_data import get_tconts, get_gem_ports, get_onu_id
            
            if self.activation_method == "autoactivate":
                onu_id = get_onu_id(serial_number)
                if onu_id is None:
                    onu_id = self.get_next_onu_id()
                enabled = True
                channel_speed = 0
                tconts = get_tconts(serial_number, onu_id)
                gem_ports = get_gem_ports(serial_number, onu_id)

            elif self.activation_method == "autodiscovery":
                if self.authentication_method == 'serial-number':
                    gpon_info = self.olt.get_xpon_info(self.pon_id)

                    try:
                        # TODO: Change iteration to itervalues below
                        vont_info = next(info for _, info in gpon_info['v-ont-anis'].items()
                                         if info.get('expected-serial-number') == serial_number)

                        onu_id = vont_info['onu-id']
                        enabled = vont_info['enabled']
                        channel_speed = vont_info['upstream-channel-speed']

                        tconts = {key: val for key, val in gpon_info['tconts'].iteritems()
                                  if val.vont_ani == vont_info['name']}
                        tcont_names = set(tconts.keys())

                        gem_ports = {key: val for key, val in gpon_info['gem-ports'].iteritems()
                                     if val.tconf_ref in tcont_names}

                    except StopIteration:
                        return None     # Can happen if vont-ani has not yet been configured
                else:
                    return None
            else:
                return None

            onu_info = {
                'device-id': self.olt.device_id,
                'serial-number': serial_number,
                'xpon-name': None,
                'pon': self,
                'onu-id': onu_id,
                'enabled': enabled,
                'upstream-channel-speed': channel_speed,
                'password': Onu.DEFAULT_PASSWORD,
                't-conts': tconts,
                'gem-ports': gem_ports,
                'onu-vid': self.olt.get_channel_id(self._pon_id, onu_id),
                'channel-id': self.olt.get_channel_id(self._pon_id, onu_id)
            }
            # Hold off ONU activation until at least one GEM Port is defined.

            return onu_info if len(gem_ports) > 0 else None

        except Exception as e:
            self.log.exception('get-onu-info', e=e)
            return None

    @inlineCallbacks
    def add_onu(self, serial_number, status):
        self.log.info('add-onu', serial_number=serial_number, status=status)

        if serial_number not in status.onus:
            # Newly found and not enabled ONU, enable it now if not at max

            onu_info = self._get_onu_info(Onu.serial_number_to_string(serial_number))

            if onu_info is None:
                self.log.info('lookup-failure', serial_number=serial_number)

            elif serial_number in self._onus or onu_info['onu-id'] in self._onu_by_id:
                # May be here due to unmanaged power-cycle on OLT
                self.log.info('onu-already-added', serial_number=serial_number)
                assert serial_number in self._onus and\
                       onu_info['onu-id'] in self._onu_by_id, \
                    'ONU not in both lists'

                # Recover ONU information and attempt to reflow TCONT/GEM-PORT
                # information as well

                onu = self._onus[serial_number]
                reflow = True

            elif len(self._onus) >= self.MAX_ONUS_SUPPORTED:
                    self.log.warning('max-onus-provisioned', count=len(self._onus))
            else:
                # TODO: Make use of upstream_channel_speed variable
                onu = Onu(onu_info)
                reflow = False
                self._onus[serial_number] = onu
                self._onu_by_id[onu.onu_id] = onu

            try:
                tconts = onu_info['t-conts']
                gem_ports = onu_info['gem-ports']

                # Add Multicast to PON on a per-ONU basis until xPON multicast support is ready
                # In xPON/BBF, mcast gems tie back to the channel-pair
                # MCAST VLAN IDs stored as a negative value

                for id_or_vid, gem_port in gem_ports.iteritems():  # TODO: Deprecate this when BBF ready
                    if gem_port.multicast:
                        self.add_mcast_gem_port(gem_port, -id_or_vid)

                yield onu.create(tconts, gem_ports, reflow=reflow)
                if not reflow:
                    self.activate_onu(onu)

            except Exception as e:
                self.log.exception('add-onu', serial_number=serial_number, reflow=reflow, e=e)

                if not reflow:
                    del self._onus[serial_number]
                    del self._onu_by_id[onu.onu_id]

    def activate_onu(self, onu):
        """
        Called when a new ONU is discovered and VOLTHA device adapter needs to be informed
        :param onu: 
        :return: 
        """
        # Only call older 'child_device_detected' if not using xPON to configure the system

        if self.activation_method == "autoactivate":
            olt = self.olt
            adapter = self.adapter_agent
            channel_id = onu.onu_vid

            proxy = Device.ProxyAddress(device_id=olt.device_id,
                                        channel_id=channel_id,
                                        onu_id=onu.onu_id,
                                        onu_session_id=onu.onu_id)

            adapter.child_device_detected(parent_device_id=olt.device_id,
                                          parent_port_no=self._port_no,
                                          child_device_type=onu.vendor_id,
                                          proxy_address=proxy,
                                          admin_state=AdminState.ENABLED,
                                          vlan=channel_id)

    def get_next_onu_id(self):
        used_ids = [onu.onu_id for onu in self._onus.itervalues()]

        while True:
            onu_id = self._next_onu_id
            self._next_onu_id += 1

            if self._next_onu_id > Onu.MAX_ONU_ID:
                self._next_onu_id = Onu.MIN_ONU_ID + 128

            if onu_id not in used_ids:
                return onu_id

    @inlineCallbacks
    def delete_onu(self, onu_id):
        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, onu_id)
        name = 'pon-delete-onu-{}-{}'.format(self._pon_id, onu_id)

        onu = self._onu_by_id.get(onu_id)

        # Remove from any local dictionary
        if onu_id in self._onu_by_id:
            del self._onu_by_id[onu_id]
        for sn in [onu.serial_numbers for onu in self._onus.itervalues() if onu.onu_id == onu_id]:
            del self._onus[sn]
        try:
            yield self._parent.rest_client.request('DELETE', uri, name=name)

        except Exception as e:
            self.log.exception('onu', serial_number=onu.serial_number, e=e)

        if onu is not None:
            # Clean up adapter agent of this ONU

            proxy = Device.ProxyAddress(device_id=self.olt.device_id,
                                        channel_id=onu.channel_id)
            onu_device = self.olt.adapter_agent.get_child_device_with_proxy_address(proxy)

            if onu_device is not None:
                self.olt.adapter_agent.delete_child_device(self.olt.device_id,
                                                           onu_device.device_id)

        self.olt.adapter_agent.update_child_devices_state(self.olt.device_id,
                                                          admin_state=AdminState.DISABLED)

        def delete_child_device(self, parent_device_id, child_device_id):
            onu_device = self.root_proxy.get('/devices/{}'.format(child_device_id))
            if onu_device is not None:
                if onu_device.parent_id == parent_device_id:
                    self.log.debug('deleting-child-device', parent_device_id=parent_device_id,
                                   child_device_id=child_device_id)
                    self._remove_node('/devices', child_device_id)

    def add_mcast_gem_port(self, mcast_gem, vlan):
        """
        Add any new Multicast GEM Ports to the PON
        :param mcast_gem: (GemPort)
        """
        if vlan in self._mcast_gem_ports:
            return

        assert len(self._mcast_gem_ports) == 0, 'Only 1 MCAST GEMPort until BBF Support'
        assert 1 <= vlan <= 4095, 'Invalid Multicast VLAN ID'
        assert len(self.olt.multicast_vlans) == 1, 'Only support 1 MCAST VLAN until BBF Support'

        self._mcast_gem_ports[vlan] = mcast_gem

    @inlineCallbacks
    def channel_partition(self, name, partition=0, xpon_system=0, operation=None):
        """
        Delete/enable/disable a specified channel partition on this PON.

        When creating a new Channel Partition, create it disabled, then define any associated
        Channel Pairs. Then enable the Channel Partition.

        :param name: (string) Name of the channel partition
        :param partition: (int: 0..15) An index of the operator-specified channel subset
                          in a NG-PON2 system. For XGS-PON, this is typically 0
        :param xpon_system: (int: 0..1048575) Identifies a specific xPON system
        :param operation: (string) 'delete', 'enable', or 'disable'
        """
        if operation.lower() not in ['delete', 'enable', 'disable']:
            raise ValueError('Unsupported operation: {}'.format(operation))

        try:
            xml = 'interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"'

            if operation.lower() is 'delete':
                xml += '<interface operation="delete">'
            else:
                xml += '<interface>'
                xml += '<type xmlns:adtn-xp="http://www.adtran.com/ns/yang/adtran-xpon">' +\
                       'adtn-xp:xpon-channel-partition</type>'
                xml += '<adtn-xp:channel-partition xmlns:adtn-xp="http://www.adtran.com/ns/yang/adtran-xpon">'
                xml += '  <adtn-xp:partition-id>{}</adtn-xp:partition-id>'.format(partition)
                xml += '  <adtn-xp:xpon-system>{}</adtn-xp:xpon-system>'.format(xpon_system)
                xml += '</adtn-xp:channel-partition>'
                xml += '<enabled>{}</enabled>'.format('true' if operation.lower() == 'enable' else 'false')

            xml += '<name>{}</name>'.format(name)
            xml += '</interface></interfaces>'

            results = yield self.olt.netconf_client.edit_config(xml)
            returnValue(results)

        except Exception as e:
            self.log.exception('channel_partition')
            raise

    @inlineCallbacks
    def channel_pair(self, name, partition, operation=None, **kwargs):
        """
        Create/delete a channel pair on a specific channel_partition for a PON

        :param name: (string) Name of the channel pair
        :param partition: (string) Name of the channel partition
        :param operation: (string) 'delete', 'enable', or 'disable'
        :param kwargs: (dict) Additional leaf settings if desired
        """
        if operation.lower() not in ['delete', 'enable', 'disable']:
            raise ValueError('Unsupported operation: {}'.format(operation))

        try:
            xml = 'interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"'

            if operation.lower() is 'delete':
                xml += '<interface operation="delete">'
            else:
                xml += '<interface>'
                xml += '<type xmlns:adtn-xp="http://www.adtran.com/ns/yang/adtran-xpon">' +\
                       'adtn-xp:xpon-channel-pair</type>'
                xml += '<adtn-xp:channel-pair xmlns:adtn-xp="http://www.adtran.com/ns/yang/adtran-xpon">'
                xml += '  <adtn-xp:channel-partition>{}</adtn-xp:channel-partition>'.format(partition)
                xml += '  <adtn-xp:channel-termination>channel-termination {}</adtn-xp:channel-termination>'.\
                    format(self.pon_id)
                xml += '  <adtn-xp:upstream-admin-label>{}</adtn-xp:upstream-admin-label>'.\
                    format(kwargs.get('upstream-admin-label', 1))
                xml += '  <adtn-xp:downstream-admin-label>{}</adtn-xp:downstream-admin-label>'.\
                    format(kwargs.get('downstream-admin-label', 1))
                xml += '  <adtn-xp:upstream-channel-id>{}</adtn-xp:upstream-channel-id>'.\
                    format(kwargs.get('upstream-channel-id', 15))
                xml += '  <adtn-xp:downstream-channel-id>{}</adtn-xp:downstream-channel-id>'.\
                    format(kwargs.get('downstream-channel-id', 15))
                xml += '  <adtn-xp:downstream-channel-fec-enable>{}</adtn-xp:downstream-channel-fec-enable>'. \
                    format('true' if kwargs.get('downstream-channel-fec-enable', True) else 'false')
                xml += '  <adtn-xp:upstream-channel-fec-enable>{}</adtn-xp:upstream-channel-fec-enable>'. \
                    format('true' if kwargs.get('upstream-channel-fec-enable', True) else 'false')
                xml += '</adtn-xp:channel-pair>'
                # TODO: Add support for upstream/downstream FEC-enable coming from here and not hard-coded

            xml += '<name>{}</name>'.format(name)
            xml += '</interface></interfaces>'

            results = yield self.olt.netconf_client.edit_config(xml)
            returnValue(results)

        except Exception as e:
            self.log.exception('channel_pair')
            raise
