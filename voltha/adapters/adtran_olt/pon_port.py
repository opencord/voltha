# Copyright 2017-present Open Networking Foundation
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
import pprint
import random

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

    _SUPPORTED_ACTIVATION_METHODS = ['autodiscovery', 'autoactivate']
    _SUPPORTED_AUTHENTICATION_METHODS = ['serial-number']

    def __init__(self, pon_index, port_no, parent, admin_state=AdminState.UNKNOWN, label=None):
        # TODO: Weed out those properties supported by common 'Port' object (future)
        assert admin_state != AdminState.UNKNOWN

        self.log = structlog.get_logger(device_id=parent.device_id, pon_id=pon_index)

        self._parent = parent
        self._pon_id = pon_index
        self._port_no = port_no
        self._name = 'xpon 0/{}'.format(pon_index+1)
        self._label = label or 'PON-{}'.format(pon_index)
        self._port = None
        self._no_onu_discover_tick = 5.0  # TODO: Decrease to 1 or 2 later
        self._discovery_tick = 20.0
        self._discovered_onus = []  # List of serial numbers
        self._onus = {}         # serial_number-base64 -> ONU  (allowed list)
        self._onu_by_id = {}    # onu-id -> ONU
        self._next_onu_id = Onu.MIN_ONU_ID

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.DISCOVERED
        self._deferred = None                   # General purpose
        self._discovery_deferred = None           # Specifically for ONU discovery
        self._state = PonPort.State.INITIAL

        # Local cache of PON configuration

        self._xpon_name = None
        self._enabled = None
        self._downstream_fec_enable = None
        self._upstream_fec_enable = None
        self._authentication_method = 'serial-number'
        self._activation_method = 'autoactivate' if self.olt.autoactivate else 'autodiscovery'

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
    def adapter_agent(self):
        return self.olt.adapter_agent

    @property
    def discovery_tick(self):
        return self._discovery_tick * 10
    
    @discovery_tick.setter
    def discovery_tick(self, value):
        if value < 0:
            raise ValueError("Polling interval must be >= 0")

        if self.discovery_tick != value:
            self._discovery_tick = value / 10

            if self._discovery_deferred is not None:
                self._discovery_deferred.cancel()
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
        
        if d1 is not None:
            d1.cancel()            
        if d2 is not None:
            d2.cancel()

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

        # Do the rest of the startup in an async method
        self._deferred = reactor.callLater(0.5, self._finish_startup)
        self._update_adapter_agent()

        return self._deferred

    @inlineCallbacks
    def _finish_startup(self):
        """
        Do all startup offline since REST may fail
        """
        if self._state != PonPort.State.INITIAL:
            returnValue('Done')

        self.log.debug('final-startup')

        if self._enabled is None or self._downstream_fec_enable is None or self._upstream_fec_enable is None:
            try:
                self._deferred = self.get_pon_config()
                results = yield self._deferred

            except Exception as e:
                self.log.exception('initial-GET', e=e)
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
                self.log.exception('final-startup-enable', e=e)
                self._deferred = reactor.callLater(3, self._finish_startup)
                returnValue(self._deferred)

        if not self._downstream_fec_enable:
            try:
                self._deferred = self.set_pon_config("downstream-fec-enable", True)
                results = yield self._deferred
                self._downstream_fec_enable = True

            except Exception as e:
                self.log.exception('final-startup-downstream-FEC', e=e)
                self._deferred = reactor.callLater(5, self._finish_startup)
                returnValue(self._deferred)

        if not self._upstream_fec_enable:
            try:
                self._deferred = self.set_pon_config("upstream-fec-enable", True)
                results = yield self._deferred
                self._upstream_fec_enable = True

            except Exception as e:
                self.log.exception('final-startup-upstream-FEC', e=e)
                self._deferred = reactor.callLater(5, self._finish_startup)
                returnValue(self._deferred)

            self.log.debug('startup-complete', results=pprint.PrettyPrinter().pformat(results))

        if self._enabled:
            self._admin_state = AdminState.ENABLED
            self._oper_status = OperStatus.ACTIVE  # TODO: is this correct, how do we tell GRPC
            self._state = PonPort.State.RUNNING

            # Begin to ONU discovery

            self._discovery_deferred = reactor.callLater(5, self._discover_onus)

            self._update_adapter_agent()
            returnValue('Enabled')

        else:
            # Startup failed. Could be due to object creation with an invalid initial admin_status
            #                 state.  May want to schedule a start to occur again if this happens
            self._admin_state = AdminState.DISABLED
            self._oper_status = OperStatus.FAILED
            self._state = PonPort.State.STOPPED

            self._update_adapter_agent()
            returnValue('Disabled')

    def stop(self):
        if self._state == PonPort.State.STOPPED:
            return succeed('Stopped')

        self.log.info('stopping')

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
            self.log.error('reset-ignored', state=self._state)
            returnValue('Ignored')

        self.log.info('reset')

        try:
            self._deferred = self.get_pon_config()
            results = yield self._deferred

            # Load cache
            self._enabled = results.get('enabled', False)

        except Exception as e:
            self._enabled = None
            self.log.exception('GET-failed', e=e)

        initial_port_state = AdminState.ENABLED if self.olt.autoactivate else AdminState.DISABLED

        if self._admin_state != initial_port_state:
            try:
                enable = initial_port_state == AdminState.ENABLED
                if self._enabled is None or self._enabled != enable:
                    yield self.set_pon_config("enabled", enable)

                # TODO: Move to 'set_pon_config' method and also make sure GRPC/Port is ok
                self._admin_state = AdminState.ENABLED if enable else AdminState.DISABLED

            except Exception as e:
                self.log.exception('reset', e=e)
                raise

        # Walk the provisioned ONU list and disable any exiting ONUs

        try:
            results = yield self.get_onu_config()

            if isinstance(results, list) and len(results) > 0:
                onu_configs = OltConfig.Pon.Onu.decode(results)
                for onu_id in onu_configs.iterkeys():
                    try:
                        yield self.delete_onu(onu_id)

                    except Exception as e:
                        self.log.exception('rest-ONU-delete', onu_id=onu_id, e=e)
                        pass  # Non-fatal

        except Exception as e:
            self.log.exception('onu-delete', e=e)
            raise

        returnValue('Reset complete')

    def delete(self):
        """
        Parent device is being deleted. Do not change any config but
        stop all polling
        """
        self.log.info('Deleting')
        self._state = PonPort.State.DELETING
        self._cancel_deferred()

    # @property
    def gem_ids(self, exception_gems):
        """
        Get all GEM Port IDs used on a given PON

        :return: (dict) key -> onu-id, value -> frozenset of GEM Port IDs
        """
        gem_ids = {}
        for onu_id, onu in self._onu_by_id.iteritems():
            gem_ids[onu_id] = onu.gem_ids(exception_gems)
        return gem_ids

    def get_pon_config(self):
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self._pon_id)
        name = 'pon-get-config-{}'.format(self._pon_id)
        return self._parent.rest_client.request('GET', uri, name=name)

    def get_onu_config(self, onu_id=None):
        if onu_id is None:
            uri = AdtranOltHandler.GPON_ONU_CONFIG_LIST_URI.format(self._pon_id)
        else:
            uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, onu_id)

        name = 'pon-get-onu_config-{}-{}'.format(self._pon_id, onu_id)
        return self._parent.rest_client.request('GET', uri, name=name)

    def set_pon_config(self, leaf, value):
        data = json.dumps({leaf: value})
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self._pon_id)
        name = 'pon-set-config-{}-{}-{}'.format(self._pon_id, leaf, str(value))
        return self._parent.rest_client.request('PATCH', uri, data=data, name=name)

    def _discover_onus(self):
        self.log.debug('discovery')

        if self._admin_state == AdminState.ENABLED:
            data = json.dumps({'pon-id': self._pon_id})
            uri = AdtranOltHandler.GPON_PON_DISCOVER_ONU
            name = 'pon-discover-onu-{}'.format(self._pon_id)

            self._discovery_deferred = self._parent.rest_client.request('POST', uri, data, name=name)
            self._discovery_deferred.addBoth(self._onu_discovery_init_complete)

    def _onu_discovery_init_complete(self, _):
        """
        This method is called after the REST POST to request ONU discovery is
        completed.  The results (body) of the post is always empty / 204 NO CONTENT
        """
        # Reschedule

        delay = self._no_onu_discover_tick if len(self._onus) == 0 else self._discovery_tick
        delay += random.uniform(-delay / 10, delay / 10)

        self._discovery_deferred = reactor.callLater(delay, self._discover_onus)

    def process_status_poll(self, status):
        """
        Process PON status poll request
        
        :param status: (OltState.Pon object) results from RESTCONF GET
        """
        self.log.debug('process-status-poll', status=status)

        if self._admin_state != AdminState.ENABLED:
            return

        # Process the ONU list in for this PON, may have previously provisioned ones there
        # were discovered on an earlier boot

        new = self._process_status_onu_list(status.onus)

        for onu_id in new:
            # self.add_new_onu(serial_number, status)
            self.log.info('found-ONU', onu_id=onu_id)
            raise NotImplementedError('TODO: Adding ONUs from existing ONU (status list) not supported')

        # Get new/missing from the discovered ONU leaf

        new, missing = self._process_status_onu_discovered_list(status.discovered_onu)

        # TODO: Do something useful (Does the discovery list clear out activated ONU's?)
        # if len(missing):
        #     self.log.info('missing-ONUs', missing=missing)

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
        self.log.debug('ONU-list', onus=onus)

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
        self.log.debug('discovered-ONUs', list=discovered_onus)

        # Only request discovery if activation is auto-discovery or auto-activate
        continue_discovery = ['autodiscovery', 'autoactivate']

        if self._activation_method not in continue_discovery:
            return set(), set()

        my_onus = frozenset(self._onus.keys())

        new_onus = discovered_onus - my_onus
        missing_onus = my_onus - discovered_onus

        return new_onus, missing_onus

    def _get_onu_info(self, serial_number):
        """
        Parse through available xPON information for ONU configuration settings
        :param serial_number: (string) Decoded (not base64) serial number string
        :return: (dict) onu config data or None on lookup failure
        """
        try:
            from flow.demo_data import get_tconts, get_gem_ports
            
            if self.activation_method == "autoactivate":
                onu_id = self.get_next_onu_id()
                enabled = True
                channel_speed = 0

            elif self.activation_method == "autodiscovery":
                if self.authentication_method == 'serial-number':
                    gpon_info = self.olt.get_xpon_info(self.pon_id)

                    try:
                        vont_info = next(info for _, info in gpon_info['v_ont_anis'].items()
                                         if info.get('expected-serial-number') == serial_number)

                        onu_id = vont_info['onu-id']
                        enabled = vont_info['enabled']
                        channel_speed = vont_info['upstream-channel-speed']

                    except StopIteration:
                        return None
                else:
                    return None
            else:
                return None

            onu_info = {
                'serial-number': serial_number,
                'xpon-name': None,
                'pon': self,
                'onu-id': onu_id,
                'enabled': enabled,
                'upstream-channel-speed': channel_speed,
                'password': Onu.DEFAULT_PASSWORD,
                't-conts': get_tconts(self.pon_id, serial_number, onu_id),
                'gem-ports': get_gem_ports(self.pon_id, serial_number, onu_id),
            }
            return onu_info

        except Exception as e:
            self.log.exception('get-onu-info', e=e)
            return None

    @inlineCallbacks
    def add_onu(self, serial_number, status):
        self.log.info('add-ONU', serial_number=serial_number)

        if serial_number not in status.onus:
            # Newly found and not enabled ONU, enable it now if not at max

            if len(self._onus) >= self.MAX_ONUS_SUPPORTED:
                self.log.warning('max-onus-provisioned')
            else:
                onu_info = self._get_onu_info(Onu.serial_number_to_string(serial_number))

                if onu_info is None:
                    self.log.info('lookup-failure', serial_number=serial_number)

                elif serial_number in self._onus or onu_info['onu-id'] in self._onu_by_id:
                    self.log.warning('onu-already-added', serial_number=serial_number)

                else:
                    # TODO: Make use of upstream_channel_speed variable
                    onu = Onu(onu_info)
                    self._onus[serial_number] = onu
                    self._onu_by_id[onu.onu_id] = onu

                    try:
                        yield onu.create(onu_info)
                        self.activate_onu(onu)

                    except Exception as e:
                        del self._onus[serial_number]
                        del self._onu_by_id[onu.onu_id]
                        self.log.exception('add_onu', serial_number=serial_number, e=e)

    def activate_onu(self, onu):
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
                self._next_onu_id = Onu.MIN_ONU_ID

            if onu_id not in used_ids:
                return onu_id

    def delete_onu(self, onu_id):
        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, onu_id)
        name = 'pon-delete-onu-{}-{}'.format(self._pon_id, onu_id)

        # Remove from any local dictionary
        if onu_id in self._onu_by_id:
            del self._onu_by_id[onu_id]
        for sn in [onu.serial_numbers for onu in self._onus.itervalues() if onu.onu_id == onu_id]:
            del self._onus[sn]

        # TODO: Need removal from VOLTHA child_device method

        return self._parent.rest_client.request('DELETE', uri, name=name)

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
