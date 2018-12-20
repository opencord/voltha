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

import base64
import binascii
import json
import structlog
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
from common.tech_profile.tech_profile import DEFAULT_TECH_PROFILE_TABLE_ID
from voltha.protos.device_pb2 import Device

from adtran_olt_handler import AdtranOltHandler
from net.adtran_rest import RestInvalidResponseCode

_MAX_EXPEDITE_COUNT = 5
_EXPEDITE_SECS = 2
_HW_SYNC_SECS = 60


class Onu(object):
    """
    Wraps an ONU
    """
    DEFAULT_PASSWORD = ''

    def __init__(self, onu_info):
        self._onu_id = onu_info['onu-id']
        if self._onu_id is None:
            raise ValueError('No ONU ID available')

        pon = onu_info['pon']
        self._olt = pon.olt
        self._pon_id = pon.pon_id
        self._name = '{}@{}'.format(pon.physical_port_name, self._onu_id)
        self.log = structlog.get_logger(pon_id=self._pon_id, onu_id=self._onu_id)

        self._valid = True          # Set false during delete/cleanup
        self._serial_number_base64 = Onu.string_to_serial_number(onu_info['serial-number'])
        self._serial_number_string = onu_info['serial-number']
        self._device_id = onu_info['device-id']
        self._password = onu_info['password']
        self._created = False
        self._proxy_address = Device.ProxyAddress(device_id=self.olt.device_id,
                                                  channel_id=self.olt.pon_id_to_port_number(self._pon_id),
                                                  onu_id=self._onu_id,
                                                  onu_session_id=self._onu_id)
        self._sync_tick = _HW_SYNC_SECS
        self._expedite_sync = False
        self._expedite_count = 0
        self._resync_flows = False
        self._sync_deferred = None     # For sync of ONT config to hardware

        self._gem_ports = {}                        # gem-id -> GemPort
        self._tconts = {}                           # alloc-id -> TCont
        self._uni_ports = onu_info['uni-ports']

        # Provisionable items
        self._enabled = onu_info['enabled']
        self._upstream_fec_enable = onu_info.get('upstream-fec')

        # KPI related items
        self._rssi = -9999
        self._equalization_delay = 0
        self._fiber_length = 0
        self._timestamp = None     # Last time the KPI items were updated

    def __str__(self):
        return "ONU-{}:{}, SN: {}/{}".format(self._pon_id, self._onu_id,
                                             self._serial_number_string, self._serial_number_base64)

    @staticmethod
    def serial_number_to_string(value):
        sval = base64.decodestring(value)
        unique = [elem.encode("hex") for elem in sval[4:8]]
        return '{}{}{}{}{}'.format(sval[:4], unique[0], unique[1], unique[2], unique[3]).upper()

    @staticmethod
    def string_to_serial_number(value):
        bvendor = [octet for octet in value[:4]]
        bunique = [binascii.a2b_hex(value[offset:offset + 2]) for offset in xrange(4, 12, 2)]
        bvalue = ''.join(bvendor + bunique)
        return base64.b64encode(bvalue)

    @property
    def olt(self):
        return self._olt

    @property
    def pon(self):
        return self.olt.southbound_ports[self._pon_id]

    @property
    def intf_id(self):
        return self.pon.intf_id

    @property
    def pon_id(self):
        return self._pon_id

    @property
    def onu_id(self):
        return self._onu_id

    @property
    def device_id(self):
        return self._device_id

    @property
    def name(self):
        return self._name

    @property
    def upstream_fec_enable(self):
        return self._upstream_fec_enable

    @upstream_fec_enable.setter
    def upstream_fec_enable(self, value):
        assert isinstance(value, bool), 'upstream FEC enabled is a boolean'
        if self._upstream_fec_enable != value:
            self._upstream_fec_enable = value

        # Recalculate PON upstream FEC
        self.pon.upstream_fec_enable = self.pon.any_upstream_fec_enabled

    @property
    def password(self):
        """
        Get password.  Base 64 format
        """
        return self._password

    @password.setter
    def password(self, value):
        """
        Set the password
        :param value: (str) base 64 encoded value
        """
        if self._password is None and value is not None:
            self._password = value
            reg_id = (value.decode('base64')).rstrip('\00').lstrip('\00')
            # Must remove any non-printable characters
            reg_id = ''.join([i if 127 > ord(i) > 31 else '_' for i in reg_id])
            # Generate alarm here for regID
            from voltha.extensions.alarms.onu.onu_active_alarm import OnuActiveAlarm
            self.log.info('onu-Active-Alarm', serial_number=self._serial_number_string)
            device = self._olt.adapter_agent.get_device(self._olt.device_id)

            OnuActiveAlarm(self._olt.alarms, self._olt.device_id, self._pon_id,
                           self._serial_number_string, reg_id, device.serial_number,
                           ipv4_address=device.ipv4_address).raise_alarm()

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._enabled != value:
            self._enabled = value
            self._resync_flows = True

            self.set_config('enable', self._enabled)

            if self._enabled:
                self.start()
            else:
                self.stop()

        # Recalculate PON upstream FEC
        self.pon.upstream_fec_enable = self.pon.any_upstream_fec_enabled

    @property
    def uni_ports(self):
        return self._uni_ports

    @property
    def logical_port(self):
        """Return the logical PORT number of this ONU's UNI"""
        # TODO: once we support multiple UNIs, this needs to be revisited
        return self._uni_ports[0]

    @property
    def gem_ports(self):
        return self._gem_ports.values()

    @property
    def proxy_address(self):
        return self._proxy_address

    @property
    def serial_number_64(self):
        return self._serial_number_base64

    @property
    def serial_number(self):
        return self._serial_number_string

    @property
    def timestamp(self):
        # Last time the KPI items were updated
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value

    @property
    def rssi(self):
        """The received signal strength indication of the ONU"""
        return self._rssi

    @rssi.setter
    def rssi(self, value):
        if self._rssi != value:
            self._rssi = value
            # TODO: Notify anyone?

    @property
    def equalization_delay(self):
        """Equalization delay (bits)"""
        return self._equalization_delay

    @equalization_delay.setter
    def equalization_delay(self, value):
        if self._equalization_delay != value:
            self._equalization_delay = value
            # TODO: Notify anyone?

    @property
    def fiber_length(self):
        """Distance to ONU"""
        return self._fiber_length

    @fiber_length.setter
    def fiber_length(self, value):
        if self._fiber_length != value:
            self._fiber_length = value
            # TODO: Notify anyone?

    def _cancel_deferred(self):
        d, self._sync_deferred = self._sync_deferred, None

        if d is not None and not d.called:
            try:
                d.cancel()
            except Exception:
                pass

    @inlineCallbacks
    def create(self, reflow=False):
        """
        Create (or reflow) this ONU to hardware
        :param reflow: (boolean) Flag, if True, indicating if this is a reflow ONU
                                 information after an unmanaged OLT hardware reboot
        """
        self.log.debug('create', reflow=reflow)
        self._cancel_deferred()

        data = json.dumps({'onu-id': self._onu_id,
                           'serial-number': self._serial_number_base64,
                           'enable': self._enabled})
        uri = AdtranOltHandler.GPON_ONU_CONFIG_LIST_URI.format(self._pon_id)
        name = 'onu-create-{}-{}-{}: {}'.format(self._pon_id, self._onu_id,
                                                self._serial_number_base64, self._enabled)

        first_sync = self._sync_tick if self._created else 5

        if not self._created or reflow:
            try:
                yield self.olt.rest_client.request('POST', uri, data=data, name=name)
                self._created = True

            except Exception as e:
                self.log.exception('onu-create', e=e)
                # See if it failed due to already being configured
                url = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, self._onu_id)
                url += '/serial-number'

                try:
                    results = yield self.olt.rest_client.request('GET', uri, name=name)
                    self.log.debug('onu-create-check', results=results)
                    if len(results) == 1 and results[0].get('serial-number', '') != self._serial_number_base64:
                        self._created = True

                except Exception as _e:
                    self.log.warn('onu-exists-check', pon_id=self.pon_id, onu_id=self.onu_id,
                                  serial_number=self.serial_number)

        self._sync_deferred = reactor.callLater(first_sync, self._sync_hardware)

        # Recalculate PON upstream FEC
        self.pon.upstream_fec_enable = self.pon.any_upstream_fec_enabled
        returnValue('created')

    @inlineCallbacks
    def delete(self):
        """
        Clean up ONU (gems/tconts). ONU removal from OLT h/w done by PonPort
        :return: (deferred)
        """
        self._valid = False
        self._cancel_deferred()

        # Remove from H/W
        gem_ids = self._gem_ports.keys()
        alloc_ids = self._tconts.keys()

        dl = []
        for gem_id in gem_ids:
            dl.append(self.remove_gem_id(gem_id))

        try:
            yield defer.gatherResults(dl, consumeErrors=True)
        except Exception as _e:
            pass

        dl = []
        for alloc_id in alloc_ids:
            dl.append(self.remove_tcont(alloc_id))

        try:
            yield defer.gatherResults(dl, consumeErrors=True)
        except Exception as _e:
             pass

        self._gem_ports.clear()
        self._tconts.clear()
        olt, self._olt = self._olt, None

        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, self._onu_id)
        name = 'onu-delete-{}-{}-{}: {}'.format(self._pon_id, self._onu_id,
                                                self._serial_number_base64, self._enabled)
        try:
            yield olt.rest_client.request('DELETE', uri, name=name)

        except RestInvalidResponseCode as e:
            if e.code != 404:
                self.log.exception('onu-delete', e=e)

        except Exception as e:
            self.log.exception('onu-delete', e=e)

        # Release resource manager resources for this ONU
        pon_intf_id_onu_id = (self.pon_id, self.onu_id)
        olt.resource_mgr.free_pon_resources_for_onu(pon_intf_id_onu_id)

        returnValue('deleted')

    def start(self):
        self._cancel_deferred()
        self._sync_deferred = reactor.callLater(0, self._sync_hardware)

    def stop(self):
        self._cancel_deferred()

    def restart(self):
        if not self._valid:
            return succeed('Deleting')

        self._cancel_deferred()
        self._sync_deferred = reactor.callLater(0, self._sync_hardware)

        return self.create()

    def _sync_hardware(self):
        from codec.olt_config import OltConfig
        self.log.debug('sync-hardware')

        def read_config(results):
            self.log.debug('read-config', results=results)

            dl = []

            try:
                config = OltConfig.Pon.Onu.decode([results])
                assert self.onu_id in config, 'sync-onu-not-found-{}'.format(self.onu_id)
                config = config[self.onu_id]

                if self._enabled != config.enable:
                    dl.append(self.set_config('enable', self._enabled))

                if self.serial_number_64 != config.serial_number_64:
                    dl.append(self.set_config('serial-number', self.serial_number_64))

                if self._enabled:
                    # Sync TCONTs if everything else in sync
                    if len(dl) == 0:
                        dl.extend(sync_tconts(config.tconts))

                    # Sync GEM Ports if everything else in sync

                    if len(dl) == 0:
                        dl.extend(sync_gem_ports(config.gem_ports))

                    if len(dl) == 0:
                        sync_flows()

            except Exception as e:
                self.log.exception('hw-sync-read-config', e=e)

            # Run h/w sync again a bit faster if we had to sync anything
            self._expedite_sync = len(dl) > 0

            # TODO: do checks
            return defer.gatherResults(dl, consumeErrors=True)

        def sync_tconts(hw_tconts):
            hw_alloc_ids = frozenset(hw_tconts.iterkeys())
            my_alloc_ids = frozenset(self._tconts.iterkeys())
            dl = []

            try:
                extra_alloc_ids = hw_alloc_ids - my_alloc_ids
                dl.extend(sync_delete_extra_tconts(extra_alloc_ids))

                missing_alloc_ids = my_alloc_ids - hw_alloc_ids
                dl.extend(sync_add_missing_tconts(missing_alloc_ids))

                matching_alloc_ids = my_alloc_ids & hw_alloc_ids
                matching_hw_tconts = {alloc_id: tcont
                                      for alloc_id, tcont in hw_tconts.iteritems()
                                      if alloc_id in matching_alloc_ids}
                dl.extend(sync_matching_tconts(matching_hw_tconts))

            except Exception as e2:
                self.log.exception('hw-sync-tconts', e=e2)

            return dl

        def sync_delete_extra_tconts(alloc_ids):
            return [self.remove_tcont(alloc_id) for alloc_id in alloc_ids]

        def sync_add_missing_tconts(alloc_ids):
            return [self.add_tcont(self._tconts[alloc_id], reflow=True) for alloc_id in alloc_ids]

        def sync_matching_tconts(hw_tconts):
            from xpon.traffic_descriptor import TrafficDescriptor

            dl = []
            # TODO: sync TD & Best Effort. Only other TCONT leaf is the key
            for alloc_id, hw_tcont in hw_tconts.iteritems():
                my_tcont = self._tconts[alloc_id]
                my_td = my_tcont.traffic_descriptor
                hw_td = hw_tcont.traffic_descriptor
                if my_td is None:
                    continue

                my_additional = TrafficDescriptor.AdditionalBwEligibility.\
                    to_string(my_td.additional_bandwidth_eligibility)

                reflow = hw_td is None or \
                    my_td.fixed_bandwidth != hw_td.fixed_bandwidth or \
                    my_td.assured_bandwidth != hw_td.assured_bandwidth or \
                    my_td.maximum_bandwidth != hw_td.maximum_bandwidth or \
                    my_additional != hw_td.additional_bandwidth_eligibility

                if not reflow and \
                        my_td.additional_bandwidth_eligibility == \
                        TrafficDescriptor.AdditionalBwEligibility.BEST_EFFORT_SHARING and \
                        my_td.best_effort is not None:

                    hw_be = hw_td.best_effort
                    my_be = my_td.best_effort

                    reflow = hw_be is None or \
                        my_be.bandwidth != hw_be.bandwidth or \
                        my_be.priority != hw_be.priority or \
                        my_be.weight != hw_be.weight

                if reflow:
                    dl.append(my_tcont.add_to_hardware(self.olt.rest_client))
            return dl

        def sync_gem_ports(hw_gem_ports):
            hw_gems_ids = frozenset(hw_gem_ports.iterkeys())
            my_gems_ids = frozenset(self._gem_ports.iterkeys())
            dl = []

            try:
                extra_gems_ids = hw_gems_ids - my_gems_ids
                dl.extend(sync_delete_extra_gem_ports(extra_gems_ids))

                missing_gem_ids = my_gems_ids - hw_gems_ids
                dl.extend(sync_add_missing_gem_ports(missing_gem_ids))

                matching_gem_ids = my_gems_ids & hw_gems_ids
                matching_hw_gem_ports = {gem_id: gem_port
                                         for gem_id, gem_port in hw_gem_ports.iteritems()
                                         if gem_id in matching_gem_ids}

                dl.extend(sync_matching_gem_ports(matching_hw_gem_ports))
                self._resync_flows |= len(dl) > 0

            except Exception as ex:
                self.log.exception('hw-sync-gem-ports', e=ex)

            return dl

        def sync_delete_extra_gem_ports(gem_ids):
            return [self.remove_gem_id(gem_id) for gem_id in gem_ids]

        def sync_add_missing_gem_ports(gem_ids):
            return [self.add_gem_port(self._gem_ports[gem_id], reflow=True)
                    for gem_id in gem_ids]

        def sync_matching_gem_ports(hw_gem_ports):
            dl = []
            for gem_id, hw_gem_port in hw_gem_ports.iteritems():
                gem_port = self._gem_ports[gem_id]

                if gem_port.alloc_id != hw_gem_port.alloc_id or\
                        gem_port.encryption != hw_gem_port.encryption or\
                        gem_port.omci_transport != hw_gem_port.omci_transport:
                    dl.append(gem_port.add_to_hardware(self.olt.rest_client,
                                                       operation='PATCH'))
            return dl

        def sync_flows():
            from flow.flow_entry import FlowEntry

            reflow, self._resync_flows = self._resync_flows, False
            return FlowEntry.sync_flows_by_onu(self, reflow=reflow)

        def failure(_reason):
            # self.log.error('hardware-sync-get-config-failed', reason=_reason)
            pass

        def reschedule(_):
            import random
            delay = self._sync_tick if self._enabled else 5 * self._sync_tick

            # Speed up sequential resync a limited number of times if out of sync
            # With 60 second initial an typical worst case resync of 4 times, this
            # should resync an ONU and all it's gem-ports and tconts within <90 seconds
            if self._expedite_sync and self._enabled:
                self._expedite_count += 1
                if self._expedite_count < _MAX_EXPEDITE_COUNT:
                    delay = _EXPEDITE_SECS
            else:
                self._expedite_count = 0

            delay += random.uniform(-delay / 10, delay / 10)
            self._sync_deferred = reactor.callLater(delay, self._sync_hardware)
            self._expedite_sync = False

        # If PON is not enabled, skip hw-sync. If ONU not enabled, do it but less
        # frequently
        if not self.pon.enabled:
            return reschedule('not-enabled')

        try:
            self._sync_deferred = self._get_config()
            self._sync_deferred.addCallbacks(read_config, failure)
            self._sync_deferred.addBoth(reschedule)

        except Exception as e:
            self.log.exception('hw-sync-main', e=e)
            return reschedule('sync-exception')

    def _get_config(self):
        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, self.onu_id)
        name = 'pon-get-onu_config-{}-{}'.format(self._pon_id, self.onu_id)
        return self.olt.rest_client.request('GET', uri, name=name)

    def set_config(self, leaf, value):
        self.log.debug('set-config', leaf=leaf, value=value)
        data = json.dumps({leaf: value})
        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, self._onu_id)
        name = 'onu-set-config-{}-{}-{}: {}'.format(self._pon_id, self._onu_id, leaf, value)
        return self.olt.rest_client.request('PATCH', uri, data=data, name=name)

    @property
    def alloc_ids(self):
        """
        Get alloc-id's of all T-CONTs
        """
        return frozenset(self._tconts.keys())

    @inlineCallbacks
    def add_tcont(self, tcont, reflow=False):
        """
        Creates/ a T-CONT with the given alloc-id

        :param tcont: (TCont) Object that maintains the TCONT properties
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            returnValue('Deleting')

        if not reflow and tcont.alloc_id in self._tconts:
            returnValue('already created')

        self.log.info('add', tcont=tcont, reflow=reflow)
        self._tconts[tcont.alloc_id] = tcont

        try:
            results = yield tcont.add_to_hardware(self.olt.rest_client)

        except Exception as e:
            self.log.exception('tcont', tcont=tcont, reflow=reflow, e=e)
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def remove_tcont(self, alloc_id):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue('nop')

        del self._tconts[alloc_id]
        try:
            results = yield tcont.remove_from_hardware(self.olt.rest_client)

        except RestInvalidResponseCode as e:
            results = None
            if e.code != 404:
                self.log.exception('tcont-delete', e=e)

        except Exception as e:
            self.log.exception('delete', e=e)
            raise

        returnValue(results)

    def gem_port(self, gem_id):
        return self._gem_ports.get(gem_id)

    def gem_ids(self, tech_profile_id):
        """Get all GEM Port IDs used by this ONU"""
        assert tech_profile_id >= DEFAULT_TECH_PROFILE_TABLE_ID
        return sorted([gem_id for gem_id, gem in self._gem_ports.items()
                       if not gem.multicast and
                       tech_profile_id == gem.tech_profile_id])

    @inlineCallbacks
    def add_gem_port(self, gem_port, reflow=False):
        """
        Add a GEM Port to this ONU

        :param gem_port: (GemPort) GEM Port to add
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            returnValue('Deleting')

        if not reflow and gem_port.gem_id in self._gem_ports:
            returnValue('nop')

        self.log.info('add', gem_port=gem_port, reflow=reflow)
        self._gem_ports[gem_port.gem_id] = gem_port

        try:
            results = yield gem_port.add_to_hardware(self.olt.rest_client)

        except Exception as e:
            self.log.exception('gem-port', gem_port=gem_port, reflow=reflow, e=e)
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def remove_gem_id(self, gem_id):
        gem_port = self._gem_ports.get(gem_id)

        if gem_port is None:
            returnValue('nop')

        del self._gem_ports[gem_id]
        try:
            yield gem_port.remove_from_hardware(self.olt.rest_client)

        except RestInvalidResponseCode as e:
            if e.code != 404:
                self.log.exception('onu-delete', e=e)

        except Exception as ex:
            self.log.exception('gem-port-delete', e=ex)
            raise

        returnValue('done')

    @staticmethod
    def gem_id_to_gvid(gem_id):
        """Calculate GEM VID (gvid) for a given GEM port id"""
        return gem_id - 2048
