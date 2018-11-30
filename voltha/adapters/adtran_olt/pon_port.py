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
from port import AdtnPort
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue
from adtran_olt_handler import AdtranOltHandler
from net.adtran_rest import RestInvalidResponseCode
from codec.olt_config import OltConfig
from onu import Onu
from voltha.extensions.alarms.onu.onu_los_alarm import OnuLosAlarm
from voltha.extensions.alarms.onu.onu_discovery_alarm import OnuDiscoveryAlarm
from voltha.protos.common_pb2 import AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from xpon.olt_traffic_descriptor import OltTrafficDescriptor
import resources.adtranolt_platform as platform


class PonPort(AdtnPort):
    """
    GPON Port
    """
    MAX_ONUS_SUPPORTED = 128
    MAX_DEPLOYMENT_RANGE = 25000    # Meters (OLT-PB maximum)

    _MCAST_ONU_ID = 253
    _MCAST_ALLOC_BASE = 0x500

    # AutoActivate should be used if xPON configuration is not supported
    _SUPPORTED_ACTIVATION_METHODS = ['autodiscovery', 'autoactivate']
    _SUPPORTED_AUTHENTICATION_METHODS = ['serial-number']

    def __init__(self, parent, **kwargs):
        super(PonPort, self).__init__(parent, **kwargs)
        assert 'pon-id' in kwargs, 'PON ID not found'

        self._parent = parent
        self._pon_id = kwargs['pon-id']
        self.log = structlog.get_logger(device_id=parent.device_id, pon_id=self._pon_id)
        self._port_no = kwargs['port_no']
        self._physical_port_name = 'xpon 0/{}'.format(self._pon_id+1)
        self._label = 'pon-{}'.format(self._pon_id)

        self._in_sync = False
        self._expedite_sync = False
        self._expedite_count = 0

        self._discovery_tick = 20.0
        self._no_onu_discover_tick = self._discovery_tick / 2
        self._discovered_onus = []  # List of serial numbers
        self._discovery_deferred = None     # Specifically for ONU discovery

        self._onus = {}                     # serial_number-base64 -> ONU  (allowed list)
        self._onu_by_id = {}                # onu-id -> ONU
        self._mcast_gem_ports = {}          # VLAN -> GemPort

        self._active_los_alarms = set()     # ONU-ID

        # xPON configuration
        self._activation_method = 'autoactivate'

        self._downstream_fec_enable = True
        self._upstream_fec_enable = True
        self._deployment_range = 25000
        self._authentication_method = 'serial-number'
        self._mcast_aes = False

        # Statistics
        self.tx_bip_errors = 0

        # xPON Configuration (TODO: Move Tcont/GEMPort to ONU eventually)
        #                     TODO: TD may be system-wide, wait for Service Profiles
        self._v_ont_anis = {}             # Name -> dict
        self._ont_anis = {}               # Name -> dict
        self._tconts = {}                 # Name -> dict
        self._traffic_descriptors = {}    # Name -> dict
        self._gem_ports = {}              # Name -> dict

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
                              admin_state=self._admin_state,
                              oper_status=self._oper_status)

        return self._port

    @property
    def pon_id(self):
        return self._pon_id

    @property
    def onus(self):
        """
        Get a set of all ONUs.  While the set is immutable, do not use this method
        to get a collection that you will iterate through that my yield the CPU
        such as inline callback.  ONUs may be deleted at any time and they will
        set some references to other objects to NULL during the 'delete' call.
        Instead, get a list of ONU-IDs and iterate on these and call the 'onu'
        method below (which will return 'None' if the ONU has been deleted.

        :return: (frozenset) collection of ONU objects on this PON
        """
        return frozenset(self._onus.values())

    @property
    def onu_ids(self):
        return frozenset(self._onu_by_id.keys())

    def onu(self, onu_id):
        return self._onu_by_id.get(onu_id)

    @property
    def in_service_onus(self):
        return len({onu.onu_id for onu in self.onus
                    if onu.onu_id not in self._active_los_alarms})

    @property
    def closest_onu_distance(self):
        distance = -1
        for onu in self.onus:
            if onu.fiber_length < distance or distance == -1:
                distance = onu.fiber_length
        return distance

    @property
    def downstream_fec_enable(self):
        return self._downstream_fec_enable

    @downstream_fec_enable.setter
    def downstream_fec_enable(self, value):
        assert isinstance(value, bool), 'downstream FEC enabled is a boolean'

        if self._downstream_fec_enable != value:
            self._downstream_fec_enable = value
            if self.state == AdtnPort.State.RUNNING:
                self.deferred = self._set_pon_config("downstream-fec-enable", value)

    @property
    def upstream_fec_enable(self):
        return self._upstream_fec_enable

    @upstream_fec_enable.setter
    def upstream_fec_enable(self, value):
        assert isinstance(value, bool), 'upstream FEC enabled is a boolean'
        if self._upstream_fec_enable != value:
            self._upstream_fec_enable = value
            if self.state == AdtnPort.State.RUNNING:
                self.deferred = self._set_pon_config("upstream-fec-enable", value)

    @property
    def any_upstream_fec_enabled(self):
        for onu in self.onus:
            if onu.upstream_fec_enable and onu.enabled:
                return True
        return False

    @property
    def mcast_aes(self):
        return self._mcast_aes

    @mcast_aes.setter
    def mcast_aes(self, value):
        assert isinstance(value, bool), 'MCAST AES is a boolean'
        if self._mcast_aes != value:
            self._mcast_aes = value
            if self.state == AdtnPort.State.RUNNING:
                pass    # TODO

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
            if self.state == AdtnPort.State.RUNNING:
                self.deferred = self._set_pon_config("deployment-range", value)

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

    def cancel_deferred(self):
        super(PonPort, self).cancel_deferred()

        d, self._discovery_deferred = self._discovery_deferred, None

        try:
            if d is not None and not d.called:
                d.cancel()
        except Exception as e:
            pass

    def _update_adapter_agent(self):
        """
        Update the port status and state in the core
        """
        self.log.debug('update-adapter-agent', admin_state=self._admin_state,
                       oper_status=self._oper_status)

        # because the core does not provide methods for updating admin
        # and oper status per port, we need to copy any existing port
        # info so that we don't wipe out the peers
        if self._port is not None:
            agent_ports = self.adapter_agent.get_ports(self.olt.device_id, Port.PON_OLT)

            agent_port = next((ap for ap in agent_ports if ap.port_no == self._port_no), None)

            # copy current Port info
            if agent_port is not None:
                self._port = agent_port

        # set new states
        self._port.admin_state = self._admin_state
        self._port.oper_status = self._oper_status

        # adapter_agent add_port also does an update of existing port
        self.adapter_agent.add_port(self.olt.device_id, self.get_port())

    @inlineCallbacks
    def finish_startup(self):
        """
        Do all startup offline since REST may fail
        """
        if self.state != AdtnPort.State.INITIAL:
            returnValue('Done')

        self.log.debug('final-startup')
        results = None

        try:
            self.deferred = self._get_pon_config()
            results = yield self.deferred

        except Exception as e:
            self.log.exception('initial-GET', e=e)
            self.deferred = reactor.callLater(5, self.finish_startup)
            returnValue(self.deferred)

        # Load config from hardware

        enabled = results.get('enabled', False)
        downstream_fec_enable = results.get('downstream-fec-enable', False)
        upstream_fec_enable = results.get('upstream-fec-enable', False)
        deployment_range = results.get('deployment-range', 25000)
        self._in_sync = True

        if enabled != self._enabled:
            try:
                self.deferred = self._set_pon_config("enabled", True)
                yield self.deferred

            except Exception as e:
                self.log.exception('final-startup-enable', e=e)
                self.deferred = reactor.callLater(3, self.finish_startup)
                returnValue(self.deferred)

        if downstream_fec_enable != self._downstream_fec_enable:
            try:
                self.deferred = self._set_pon_config("downstream-fec-enable",
                                                     self._downstream_fec_enable)
                yield self.deferred

            except Exception as e:
                self.log.warning('final-startup-downstream-FEC', e=e)
                self._in_sync = False
                # Non-fatal. May have failed due to no SFQ in slot

        if upstream_fec_enable != self._upstream_fec_enable:
            try:
                self.deferred = self._set_pon_config("upstream-fec-enable",
                                                     self._upstream_fec_enable)
                yield self.deferred

            except Exception as e:
                self.log.warning('final-startup-upstream-FEC', e=e)
                self._in_sync = False
                # Non-fatal. May have failed due to no SFQ in slot

        if deployment_range != self._deployment_range:
            try:
                self.deferred = self._set_pon_config("deployment-range",
                                                     self._deployment_range)
                yield self.deferred

            except Exception as e:
                self.log.warning('final-startup-deployment-range', e=e)
                self._in_sync = False
                # Non-fatal. May have failed due to no SFQ in slot

        if len(self._onus) > 0:
            dl = []
            for onu_id in self.onu_ids:
                onu = self.onu(onu_id)
                if onu is not None:
                    dl.append(onu.restart())
            yield defer.gatherResults(dl, consumeErrors=True)

        # Begin to ONU discovery and hardware sync

        self._discovery_deferred = reactor.callLater(5, self._discover_onus)

        # If here, initial settings were successfully written to hardware

        super(PonPort, self).finish_startup()
        returnValue('Enabled')

    def finish_stop(self):
        # Remove all existing ONUs. They will need to be re-discovered
        dl = []
        onu_ids = frozenset(self._onu_by_id.keys())
        for onu_id in onu_ids:
            try:
                dl.append(self.delete_onu(onu_id))

            except Exception as e:
                self.log.exception('onu-cleanup', onu_id=onu_id, e=e)

        dl.append(self._set_pon_config("enabled", False))
        return defer.gatherResults(dl, consumeErrors=True)

    @inlineCallbacks
    def reset(self):
        """
        Set the PON Port to a known good state on initial port startup.  Actual
        PON 'Start' is done elsewhere
        """
        initial_port_state = AdminState.ENABLED
        self.log.info('reset', initial_state=initial_port_state)

        try:
            self.deferred = self._get_pon_config()
            results = yield self.deferred
            enabled = results.get('enabled', False)

        except Exception as e:
            self.log.exception('get-config', e=e)
            enabled = False

        enable = initial_port_state == AdminState.ENABLED

        if enable != enabled:
            try:
                self.deferred = yield self._set_pon_config("enabled", enable)
            except Exception as e:
                self.log.exception('reset-enabled', e=e, enabled=enabled)

        # TODO: Move to 'set_pon_config' method and also make sure GRPC/Port is ok
        self._admin_state = AdminState.ENABLED if enable else AdminState.DISABLED

        try:
            # Walk the provisioned ONU list and disable any existing ONUs
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
                    self.log.exception('rest-ONU-delete', e=e)
                    pass  # Non-fatal

        except Exception as e:
            self.log.exception('onu-delete', e=e)

        returnValue('Reset complete')

    def gem_ids(self, logical_port, flow_vlan, multicast_gems=False):
        """
        Get all GEM Port IDs used on a given PON

        :param logical_port: (int) Logical port number of ONU. None if for all ONUs
                          on PON, if Multicast, VID for Multicast, or None for all
                          Multicast GEMPorts
        :param flow_vlan: (int) If not None, this is the ingress tag (c-tag)
        :param multicast_gems: (boolean) Select from available Multicast GEM Ports
        :return: (dict) data_gem -> key -> onu-id, value -> tuple(sorted list of GEM Port IDs, onu_vid)
                        mcast_gem-> key -> mcast-vid, value -> GEM Port IDs
        """
        gem_ids = {}

        if multicast_gems:
            # Multicast GEMs belong to the PON, but we may need to register them on
            # all ONUs. TODO: Rework when BBF MCAST is addressed in VOLTHA v2.O+
            for vlan, gem_port in self._mcast_gem_ports.iteritems():
                if logical_port is None or (logical_port == vlan and logical_port in self.olt.multicast_vlans):
                    gem_ids[vlan] = ([gem_port.gem_id], None)
        else:
            for onu_id, onu in self._onu_by_id.iteritems():
                if logical_port is None or logical_port == onu.logical_port:
                    gem_ids[onu_id] = (onu.gem_ids(), flow_vlan)
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
        # If no optics on PON, then PON config fails with status 400, suppress this
        suppress_error = len(self.onu_ids) == 0
        return self._parent.rest_client.request('PATCH', uri, data=data, name=name,
                                                suppress_error=suppress_error)

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

    def _onu_discovery_init_complete(self, _result):
        """
        This method is called after the REST POST to request ONU discovery is
        completed.  The results (body) of the post is always empty / 204 NO CONTENT
        """
        delay = self._no_onu_discover_tick if len(self._onus) == 0 else self._discovery_tick
        delay += random.uniform(-delay / 10, delay / 10)
        self._discovery_deferred = reactor.callLater(delay, self._discover_onus)

    def sync_hardware(self):
        if self.state == AdtnPort.State.RUNNING or self.state == AdtnPort.State.STOPPED:
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

                elif self.state == AdtnPort.State.RUNNING:
                    if self.deployment_range != config.deployment_range:
                        self._in_sync = False
                        self._expedite_sync = True
                        dl.append(self._set_pon_config("deployment-range",
                                                       self.deployment_range))

                    # A little side note: FEC enable/disable cannot be changed and
                    # will remain in the previous status until an optical module
                    # is plugged in.
                    if self.downstream_fec_enable != config.downstream_fec_enable:
                        self._in_sync = False
                        dl.append(self._set_pon_config("downstream-fec-enable",
                                                       self.downstream_fec_enable))

                    if self.upstream_fec_enable != config.upstream_fec_enable:
                        self._in_sync = False
                        self._expedite_sync = True
                        dl.append(self._set_pon_config("upstream-fec-enable",
                                                       self.upstream_fec_enable))
                defer.gatherResults(dl, consumeErrors=True)
                return config.onus

            def sync_onus(hw_onus):
                if self.state == AdtnPort.State.RUNNING:
                    self.log.debug('sync-pon-onu-results', config=hw_onus)

                    # ONU's have their own sync task, extra (should be deleted) are
                    # handled here.
                    hw_onu_ids = frozenset(hw_onus.keys())
                    my_onu_ids = frozenset(self._onu_by_id.keys())

                    extra_onus = hw_onu_ids - my_onu_ids
                    dl = [self.delete_onu(onu_id, hw_only=True) for onu_id in extra_onus]

                    if self.activation_method == "autoactivate":
                        # Autoactivation of ONUs requires missing ONU detection. If
                        # not found, create them here but let the TCont/GEM-Port restore
                        # be handle by ONU H/w sync logic.
                        for onu in [self._onu_by_id[onu_id] for onu_id in my_onu_ids - hw_onu_ids
                                    if self._onu_by_id.get(onu_id) is not None]:
                            dl.append(onu.create(dict(), dict(), reflow=True))

                    return defer.gatherResults(dl, consumeErrors=True)

            def failure(reason, what):
                self.log.error('hardware-sync-{}-failed'.format(what), reason=reason)
                self._in_sync = False
                self._expedite_sync = False

            def reschedule(_):
                # Speed up sequential resync a limited number of times if out of sync.

                delay = self.sync_tick

                if self._expedite_sync:
                    self._expedite_count += 1
                    if self._expedite_count < 5:
                        delay = 1
                else:
                    self._expedite_count = 0

                delay += random.uniform(-delay / 10, delay / 10)
                self.sync_deferred = reactor.callLater(delay, self.sync_hardware)

            self.sync_deferred = self._get_pon_config()
            self.sync_deferred.addCallbacks(read_config, failure, errbackArgs=['get-config'])
            self.sync_deferred.addCallbacks(sync_onus, failure, errbackArgs=['pon-sync'])
            self.sync_deferred.addBoth(reschedule)

    def process_status_poll(self, status):
        """
        Process PON status poll request
        
        :param status: (OltState.Pon object) results from RESTCONF GET
        """
        self.log.debug('process-status-poll', status=status)

        if self._admin_state != AdminState.ENABLED:
            return

        # Process LOS list
        self._process_los_alarms(frozenset(status.ont_los))

        # Get new/missing from the discovered ONU leaf.  Stale ONUs from previous
        # configs are now cleaned up during h/w re-sync/reflow.

        new, rediscovered_onus = self._process_status_onu_discovered_list(status.discovered_onu)

        # Process newly discovered ONU list and rediscovered ONUs

        for serial_number in new | rediscovered_onus:
            reactor.callLater(0, self.add_onu, serial_number, status)

        # PON Statistics
        timestamp = arrow.utcnow().float_timestamp
        self._process_statistics(status, timestamp)

        # Process ONU info. Note that newly added ONUs will not be processed
        # until the next pass
        self._update_onu_status(status.onus, timestamp)

        # Process GEM Port information
        self._update_gem_status(status.gems, timestamp)

    def _process_statistics(self, status, timestamp):
        self.timestamp = timestamp
        self.rx_packets = status.rx_packets
        self.rx_bytes = status.rx_bytes
        self.tx_packets = status.tx_packets
        self.tx_bytes = status.tx_bytes
        self.tx_bip_errors = status.tx_bip_errors

    def _update_onu_status(self, onus, timestamp):
        """
        Process ONU status for this PON
        :param onus: (dict) onu_id: ONU State
        """
        for onu_id, onu_status in onus.iteritems():
            if onu_id in self._onu_by_id:
                onu = self._onu_by_id[onu_id]
                onu.timestamp = timestamp
                onu.rssi = onu_status.rssi
                onu.equalization_delay = onu_status.equalization_delay
                onu.equalization_delay = onu_status.equalization_delay
                onu.fiber_length = onu_status.fiber_length
                onu.password = onu_status.reported_password

    def _update_gem_status(self, gems, timestamp):
        for gem_id, gem_status in gems.iteritems():
            onu = self._onu_by_id.get(gem_status.onu_id)
            if onu is not None:
                gem_port = onu.gem_port(gem_status.gem_id)
                if gem_port is not None:
                    gem_port.timestamp = timestamp
                    gem_port.rx_packets = gem_status.rx_packets
                    gem_port.rx_bytes = gem_status.rx_bytes
                    gem_port.tx_packets = gem_status.tx_packets
                    gem_port.tx_bytes = gem_status.tx_bytes

    def _process_los_alarms(self, ont_los):
        """
        Walk current LOS and set/clear LOS as appropriate
        :param ont_los: (frozenset) ONU IDs of ONUs in LOS alarm state
        """
        cleared_alarms = self._active_los_alarms - ont_los
        new_alarms = ont_los - self._active_los_alarms

        if len(cleared_alarms) > 0 or len(new_alarms) > 0:
            self.log.info('onu-los', cleared=cleared_alarms, new=new_alarms)

        for onu_id in cleared_alarms:
            self._active_los_alarms.remove(onu_id)
            OnuLosAlarm(self.olt.alarms, onu_id, self.port_no).clear_alarm()

        for onu_id in new_alarms:
            self._active_los_alarms.add(onu_id)
            OnuLosAlarm(self.olt.alarms, onu_id, self.port_no).raise_alarm()
            reactor.callLater(0, self.delete_onu, onu_id)

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
            if self.activation_method == "autodiscovery":
                # if self.authentication_method == 'serial-number':
                raise NotImplemented('TODO: Not supported at this time')

            elif self.activation_method == "autoactivate":
                # TODO: Currently a somewhat copy of the xPON way to do things
                #       update here with Technology profile info when it becomes available
                activate_onu, tconts, gem_ports = self.get_device_profile_info(serial_number)

                try:
                    # TODO: (SEBA) All of this can be greatly simplified once we fully
                    #       deprecate xPON support
                    vont_ani = next(info for _, info in self._v_ont_anis.items()
                                    if info.get('expected-serial-number') == serial_number)

                    onu_id = vont_ani['onu-id']
                    enabled = vont_ani['enabled']
                    channel_speed = vont_ani['upstream-channel-speed']
                    upstream_fec_enabled = self._ont_anis[vont_ani['name']]['upstream-fec']

                except StopIteration:
                    # Can happen if vont-ani or ont-ani has not yet been configured
                    self.log.error('no-vont-or-ont-autoactivate')
                    return None, False

                except Exception as e:
                    self.log.exception('autoactivate', e=e)
                    raise
            else:
                self.log.debug('unsupported-activation-method', method=self.activation_method)
                return None, False

            onu_info = {
                'device-id': self.olt.device_id,
                'serial-number': serial_number,
                'pon': self,
                'onu-id': onu_id,
                'enabled': enabled,
                'upstream-channel-speed': channel_speed,
                'upstream-fec': upstream_fec_enabled,
                'password': Onu.DEFAULT_PASSWORD,
                't-conts': tconts,
                'gem-ports': gem_ports,
            }
            intf_id = platform.intf_id_to_port_no(self._pon_id, Port.PON_OLT)

            # TODO: Currently only one ONU port and it is hardcoded to port 0
            onu_info['uni-ports'] = [platform.mk_uni_port_num(intf_id, onu_id)]

            # Hold off ONU activation until at least one GEM Port is defined.
            self.log.debug('onu-info-tech-profiles', gem_ports=gem_ports)

            # return onu_info
            return onu_info, activate_onu

        except Exception as e:
            self.log.exception('get-onu-info-tech-profiles', e=e)
            return None, False

    @inlineCallbacks
    def add_onu(self, serial_number_64, status):
        """
        Add an ONU to the PON

        TODO:  This needs major refactoring after xPON is deprecated to be more maintainable
        """
        serial_number = Onu.serial_number_to_string(serial_number_64)
        self.log.info('add-onu', serial_number=serial_number,
                      serial_number_64=serial_number_64, status=status)

        # It takes a little while for a new ONU to be removed from the discovery
        # list. Return early here so extra ONU IDs are not allocated
        if serial_number_64 in self._onus:
            returnValue('wait-for-fpga')

        onu_info, activate_onu = self._get_onu_info(serial_number)

        if activate_onu:
            alarm = OnuDiscoveryAlarm(self.olt.alarms, self.pon_id, serial_number)
            reactor.callLater(0, alarm.raise_alarm)

        if serial_number_64 not in status.onus or onu_info['onu-id'] in self._active_los_alarms:
            onu = None
            onu_id = onu_info['onu-id']

            if serial_number_64 in self._onus and onu_id in self._onu_by_id:
                # Handles fast entry into this task before FPGA can set/clear results
                returnValue('sticky-onu')

            elif (serial_number_64 in self._onus and onu_id not in self._onu_by_id) or \
                    (serial_number_64 not in self._onus and onu_id in self._onu_by_id):
                # May be here due to unmanaged power-cycle on OLT or fiber bounced for a
                # previously activated ONU.
                #
                # TODO: Track when the ONU was discovered, and if > some maximum amount
                #       place the ONU (with serial number & ONU ID) on a wait list and
                #       use that to recover the ONU ID should it show up within a
                #       reasonable amount of time.  Periodically groom the wait list and
                #       delete state ONUs so we can reclaim the ONU ID.
                #
                returnValue('waiting-for-fpga')    # non-XPON mode will not

            elif len(self._onus) >= self.MAX_ONUS_SUPPORTED:
                self.log.warning('max-onus-provisioned', count=len(self._onus))
                returnValue('max-onus-reached')

            else:
                # TODO: Make use of upstream_channel_speed variable
                onu = Onu(onu_info)
                self._onus[serial_number_64] = onu
                self._onu_by_id[onu.onu_id] = onu

            if onu is not None:
                tconts = onu_info.pop('t-conts')
                gem_ports = onu_info.pop('gem-ports')

                if activate_onu:
                    _onu_device = self._parent.add_onu_device(self._port_no,     # PON ID
                                                              onu.onu_id,        # ONU ID
                                                              serial_number,
                                                              tconts,
                                                              gem_ports)
                try:
                    # Add Multicast to PON on a per-ONU basis until xPON multicast support
                    # is ready
                    # In xPON/BBF, mcast gems tie back to the channel-pair
                    # MCAST VLAN IDs stored as a negative value

                    # for id_or_vid, gem_port in gem_ports.iteritems():  # TODO: Deprecate this when BBF ready
                    #     try:
                    #         if gem_port.multicast:
                    #             self.log.debug('id-or-vid', id_or_vid=id_or_vid)
                    #             vid = self.olt.multicast_vlans[0] if len(self.olt.multicast_vlans) else None
                    #             if vid is not None:
                    #                 self.add_mcast_gem_port(gem_port, vid)
                    #
                    #     except Exception as e:
                    #         self.log.exception('id-or-vid', e=e)

                    # TODO: Need to clean up TCont and GEM-Port on ONU delete in non-xPON mode
                    _results = yield onu.create(tconts, gem_ports)

                except Exception as e:
                    self.log.exception('add-onu', serial_number=serial_number_64, e=e)
                    # allowable exception.  H/w re-sync will recover any issues

    @property
    def get_next_onu_id(self):
        return self._parent.resource_mgr.get_onu_id(self._pon_id)

    def release_onu_id(self, onu_id):
        self._parent.resource_mgr.free_onu_id(self._pon_id, onu_id)

    @inlineCallbacks
    def _remove_from_hardware(self, onu_id):
        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, onu_id)
        name = 'pon-delete-onu-{}-{}'.format(self._pon_id, onu_id)

        try:
            yield self._parent.rest_client.request('DELETE', uri, name=name)

        except RestInvalidResponseCode as e:
            if e.code != 404:
                self.log.exception('onu-delete', e=e)

        except Exception as e:
            self.log.exception('onu-hw-delete', onu_id=onu_id, e=e)

    @inlineCallbacks
    def delete_onu(self, onu_id, hw_only=False):
        onu = self._onu_by_id.get(onu_id)

        # Remove from any local dictionary
        if onu_id in self._onu_by_id:
            del self._onu_by_id[onu_id]

        for sn_64 in [onu.serial_number_64 for onu in self.onus if onu.onu_id == onu_id]:
            del self._onus[sn_64]

        if onu is not None:
            try:
                # And removal from VOLTHA adapter agent
                if not hw_only:
                    self._parent.delete_child_device(onu.proxy_address)

                # Remove from hardware
                onu.delete()

            except Exception as e:
                self.log.exception('onu-delete', serial_number=onu.serial_number, e=e)

        else:
            try:
                yield self._remove_from_hardware(onu_id)

            except Exception as e:
                self.log.debug('onu-remove', serial_number=onu.serial_number, e=e)

        # Remove from LOS list if needed
        if onu.id in self._active_los_alarms:
            self._active_los_alarms.remove(onu.id)

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

    #  ===========================================================================
    #
    #  Some xPON methods that need refactoring

    @property
    def tconts(self):
        return self._tconts

    @property
    def traffic_descriptors(self):
        return self._traffic_descriptors

    @property
    def gem_ports(self):
        return self._gem_ports

    def get_device_profile_info(self, serial_number):
        vont_ani_info = next((info for _, info in self._v_ont_anis.items()
                             if info.get('expected-serial-number') == serial_number), None)
        # New ONU?
        activate_onu = vont_ani_info is None

        tconts = list()
        gem_ports = list()

        if activate_onu:
            onu_id = self.get_next_onu_id
            name = 'customer-{}-{}'.format(self.pon_id, onu_id)
            vont_ani_info = {
                'name'                    : name,
                'enabled'                 : True,
                'description'             : '',
                'pon-id'                  : self.pon_id,
                'onu-id'                  : onu_id,
                'expected-serial-number'  : serial_number,
                'expected-registration-id': '',                         # TODO: How about this?
                'upstream-channel-speed'  : 10000000000,
            }
            ont_ani_info = {
                'name':             name,
                'description':      '',
                'enabled':          True,
                'upstream-fec':     True,
                'mgnt-gemport-aes': False
            }
            assert name not in self._v_ont_anis
            assert name not in self._ont_anis
            self._v_ont_anis[name] = vont_ani_info
            self._ont_anis[name] = ont_ani_info

            tcont, tc, td = self.create_xpon_tcont(onu_id)
            from xpon.olt_tcont import OltTCont
            tc['object'] = OltTCont.create(tc,
                                           OltTrafficDescriptor.create(tc['td-ref']),
                                           self.pon_id, onu_id)
            self._tconts[tcont.name] = tc['object']
            tconts.append(tc)

            # Now create the User-Data GEM-Ports
            num_priorities = 1                          # TODO: Pull from tech-profile later
            for index in range(0, num_priorities):
                gem_port, gp = self.create_xpon_gem_port(onu_id, index, tcont)

                from xpon.olt_gem_port import OltGemPort
                gp['object'] = OltGemPort.create(self, gp, tcont.alloc_id, self.pon_id, onu_id)
                self._gem_ports[gem_port.name] = gp['object']
                gem_ports.append(gp)

        return activate_onu, tconts, gem_ports

    def create_xpon_gem_port(self, onu_id, index, tcont):
        # gem port creation (this initial one is for untagged ONU data support / EAPOL)
        gem_port = GemportsConfigData()
        gem_port.name = 'gem-{}-{}-{}'.format(self.pon_id, onu_id, gem_port.gemport_id)
        pon_intf_onu_id = (self.pon_id, onu_id)
        gem_port.gemport_id = self._parent.resource_mgr.get_gemport_id(pon_intf_onu_id)
        # TODO: Add release of alloc_id on ONU delete and/or TCONT delete

        gem_port.tcont_ref = tcont.name
        gp = {
            'name': gem_port.name,
            'gemport-id': gem_port.gemport_id,
            'tcont-ref': gem_port.tcont_ref,
            'encryption': False,
            'traffic-class': 0,
            'data': gem_port
        }
        return gem_port, gp

    def create_xpon_tcont(self, onu_id):
        """ Create the xPON TCONT Config data """
        tcont = TcontsConfigData()
        tcont.name = 'tcont-{}-{}-data'.format(self.pon_id, onu_id)
        pon_intf_onu_id = (self.pon_id, onu_id)
        tcont.alloc_id = self._parent.resource_mgr.get_alloc_id(pon_intf_onu_id)
        # TODO: Add release of alloc_id on ONU delete and/or TCONT delete

        traffic_desc = TrafficDescriptorProfileData(name='BestEffort',
                                                    fixed_bandwidth=0,
                                                    assured_bandwidth=0,
                                                    maximum_bandwidth=10000000000,
                                                    priority=0,
                                                    weight=0,
                                                    additional_bw_eligibility_indicator=0)
        tc = {
            'name': tcont.name,
            'alloc-id': tcont.alloc_id,
            'pon-id': self.pon_id,
            'onu-id': onu_id,
            'td-ref': {  # TODO: This should be the TD Name and the TD installed in xpon cache
                'name': traffic_desc.name,
                'fixed-bandwidth': traffic_desc.fixed_bandwidth,
                'assured-bandwidth': traffic_desc.assured_bandwidth,
                'maximum-bandwidth': traffic_desc.maximum_bandwidth,
                'priority': traffic_desc.priority,
                'weight': traffic_desc.weight,
                'additional-bw-eligibility-indicator': 0,
                'data': traffic_desc
            },
            'data': tcont
        }
        return tcont, tc, traffic_desc
