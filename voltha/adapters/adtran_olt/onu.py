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

from adtran_olt_handler import AdtranOltHandler
from net.adtran_rest import RestInvalidResponseCode

_MAX_EXPEDITE_COUNT = 5
_EXPEDITE_SECS = 2
_HW_SYNC_SECS = 30


class Onu(object):
    """
    Wraps an ONU
    """
    MIN_ONU_ID = 0
    MAX_ONU_ID = 253            # G.984. 0..253, 254=reserved, 255=broadcast
    BROADCAST_ONU_ID = 255
    DEFAULT_PASSWORD = ''

    def __init__(self, onu_info):
        self._onu_id = onu_info['onu-id']
        if self._onu_id is None:
            raise ValueError('No ONU ID available')

        pon = onu_info['pon']
        self._serial_number_base64 = Onu.string_to_serial_number(onu_info['serial-number'])
        self._serial_number_string = onu_info['serial-number']
        self._device_id = onu_info['device-id']
        self._password = onu_info['password']
        self._olt = pon.olt
        self._pon_id = pon.pon_id
        self._name = '{}@{}'.format(pon.name, self._onu_id)
        self._xpon_name = onu_info['xpon-name']
        self._gem_ports = {}                           # gem-id -> GemPort
        self._tconts = {}                              # alloc-id -> TCont
        self._onu_vid = onu_info['onu-vid']
        self.untagged_vlan = self._onu_vid
        self._uni_ports = [onu_info['onu-vid']]     # TODO: Get rid of this
        assert len(self._uni_ports) == 1, 'Only one UNI port supported at this time'
        self._channel_id = onu_info['channel-id']
        self._enabled = onu_info['enabled']
        self._vont_ani = onu_info.get('vont-ani')
        self._rssi = -9999
        self._equalization_delay = 0
        self._fiber_length = 0
        self._valid = True          # Set false during delete/cleanup
        self._created = False
        self._proxy_address = None
        self._upstream_fec_enable = onu_info.get('upstream-fec')
        self._upstream_channel_speed = onu_info['upstream-channel-speed']
        # TODO: how do we want to enforce upstream channel speed (if at all)?
        self._include_multicast = True   # TODO: May need to add multicast on a per-ONU basis
        self._sync_tick = _HW_SYNC_SECS
        self._expedite_sync = False
        self._expedite_count = 0
        self._resync_flows = False
        self._sync_deferred = None     # For sync of ONT config to hardware

        if onu_info['venet'] is not None:
            port_no, subscriber_vlan, self.untagged_vlan = Onu.decode_venet(onu_info['venet'],
                                                                            self.olt.untagged_vlan)
            if port_no is not None:
                self._uni_ports = [port_no]
            if subscriber_vlan is not None:
                self._onu_vid = subscriber_vlan

        self.log = structlog.get_logger(pon_id=self._pon_id, onu_id=self._onu_id)

    def __del__(self):
        # self.stop()
        pass

    def __str__(self):
        return "ONU-{}:{}, SN: {}/{}".format(self._onu_id, self._pon_id,
                                             self._serial_number_string, self._serial_number_base64)

    @staticmethod
    def decode_venet(venet_info, untagged_vlan):
        # TODO: Move this one and ONU one into venet decode to dict() area
        try:
            # Allow spaces or dashes as separator, select last as the
            # port number.  UNI-1,  UNI 1, and UNI 3-2-1 are the same
            port_no = int(venet_info['name'].replace(' ', '-').split('-')[-1:][0])
            subscriber_vlan = port_no
            try:
                # Subscriber VLAN and Untagged vlan are comma separated
                parts = venet_info['description'].split(',')
                sub_part = next((part for part in parts if 'vlan' in part.lower()), None)
                untagged_part = next((part for part in parts if 'untagged' in part.lower()), None)
                try:
                    if sub_part is not None:
                        subscriber_vlan = int(sub_part.split(':')[-1:][0])
                except Exception as e:
                    pass
                try:
                    if untagged_part is not None:
                        untagged_vlan = int(untagged_part.split(':')[-1:][0])
                except Exception as e:
                    pass
            except Exception as e:
                pass

            return port_no, subscriber_vlan, untagged_vlan

        except ValueError:
            pass
        except KeyError:
            pass

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
    def xpon_name(self):
        return self._xpon_name

    @property
    def v_ont_ani(self):
        return self._vont_ani

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
    def upstream_channel_speed(self):
        return self._upstream_channel_speed

    @upstream_channel_speed.setter
    def upstream_channel_speed(self, value):
        assert isinstance(value, (int,float)), 'upstream speed is a numeric value'
        if self._upstream_channel_speed != value:
            self._upstream_channel_speed = value

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
    def onu_vid(self):
        return self._onu_vid

    @property
    def uni_ports(self):
        return self._uni_ports

    @property
    def logical_port(self):
        """Return the logical PORT number of this ONU's UNI"""
        return self._uni_ports[0]

    @property
    def gem_ports(self):
        return self._gem_ports.values()

    @property
    def proxy_address(self):
        if self._proxy_address is None:
            from voltha.protos.device_pb2 import Device

            device_id = self.olt.device_id

            try:
                v_ont_ani = self._vont_ani
                voltha_core = self.olt.adapter_agent.core
                xpon_agent = voltha_core.xpon_agent
                channel_group_id = xpon_agent.get_channel_group_for_vont_ani(v_ont_ani)
                parent_chnl_pair_id = xpon_agent.get_port_num(device_id,
                                                              v_ont_ani.data.preferred_chanpair)
                self._proxy_address = Device.ProxyAddress(
                    device_id=device_id,
                    channel_group_id=channel_group_id,
                    channel_id=parent_chnl_pair_id,
                    channel_termination=v_ont_ani.data.preferred_chanpair,
                    onu_id=self.onu_id,
                    onu_session_id=self.onu_id)
            except Exception:
                pass

        return self._proxy_address

    def _get_v_ont_ani(self, olt):
        onu = None
        try:
            vont_ani = olt.v_ont_anis.get(self.vont_ani)
            ch_pair = olt.channel_pairs.get(vont_ani['preferred-channel-pair'])
            ch_term = next((term for term in olt.channel_terminations.itervalues()
                            if term['channel-pair'] == ch_pair['name']), None)

            pon = olt.pon(ch_term['xgs-ponid'])
            onu = pon.onu(vont_ani['onu-id'])

        except Exception:
            pass

        return onu

    @property
    def channel_id(self):
        return self._channel_id

    @property
    def serial_number_64(self):
        return self._serial_number_base64

    @property
    def serial_number(self):
        return self._serial_number_string

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
    def create(self, tconts, gem_ports, reflow=False):
        """
        Create (or reflow) this ONU to hardware
        :param tconts: (TCont) Current TCONT information
        :param gem_ports: (GemPort) Current GEM Port configuration information
        :param reflow: (boolean) Flag, if True, indicating if this is a reflow ONU
                                 information after an unmanaged OLT hardware reboot
        """
        self.log.debug('create', tconts=tconts, gem_ports=gem_ports, reflow=reflow)
        self._cancel_deferred()

        data = json.dumps({'onu-id': self._onu_id,
                           'serial-number': self._serial_number_base64,
                           'enable': self._enabled})
        uri = AdtranOltHandler.GPON_ONU_CONFIG_LIST_URI.format(self._pon_id)
        name = 'onu-create-{}-{}-{}: {}'.format(self._pon_id, self._onu_id,
                                                self._serial_number_base64, self._enabled)

        if not self._created:
            try:
                yield self.olt.rest_client.request('POST', uri, data=data, name=name)
                self._created = True

            except Exception as e:  # TODO: Add breakpoint here during unexpected reboot test
                self.log.exception('onu-create', e=e)
                # See if it failed due to already being configured
                url = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, self._onu_id)
                url += '/serial-number'

                try:
                    results = yield self.olt.rest_client.request('GET', uri, name=name)
                    self.log.debug('onu-create-check', results=results)
                    if len(results) != 1 or results[0].get('serial-number', '') != self._serial_number_base64:
                        raise e

                except Exception as e:
                    self.log.exception('onu-exists-check', e=e)
                    raise

        # Now set up all tconts & gem-ports
        first_sync = self._sync_tick

        for _, tcont in tconts.items():
            try:
                yield self.add_tcont(tcont, reflow=reflow)

            except Exception as e:
                self.log.exception('add-tcont', tcont=tcont, e=e)
                first_sync = 2    # Expedite first hw-sync

        for _, gem_port in gem_ports.items():
            try:
                gem_port.pon_id = self.pon_id
                gem_port.onu_id = self.onu_id if self.onu_id is not None else -1
                yield self.add_gem_port(gem_port, reflow=reflow)

            except Exception as e:
                self.log.exception('add-gem-port', gem_port=gem_port, reflow=reflow, e=e)
                first_sync = 2    # Expedite first hw-sync

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
        except Exception:
            pass

        dl = []
        for alloc_id in alloc_ids:
            dl.append(self.remove_tcont(alloc_id))

        try:
            yield defer.gatherResults(dl, consumeErrors=True)
        except Exception as e:
             pass

        self._gem_ports.clear()
        self._tconts.clear()

        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, self._onu_id)
        name = 'onu-delete-{}-{}-{}: {}'.format(self._pon_id, self._onu_id,
                                                self._serial_number_base64, self._enabled)
        try:
            yield self.olt.rest_client.request('DELETE', uri, name=name)

        except RestInvalidResponseCode as e:
            if e.code != 404:
                self.log.exception('onu-delete', e=e)

        except Exception as e:
            self.log.exception('onu-delete', e=e)

        self._olt = None
        self._channel_id = None
        returnValue('deleted')

    def start(self):
        self._cancel_deferred()
        self._sync_deferred = reactor.callLater(0, self._sync_hardware)

    def stop(self):
        self._cancel_deferred()
        self._sync_deferred = reactor.callLater(0, self._sync_hardware)

    def restart(self):
        if not self._valid:
            return succeed('Deleting')

        self._cancel_deferred()
        self._sync_deferred = reactor.callLater(0, self._sync_hardware)

        tconts, self._tconts = self._tconts, {}
        gem_ports, self._gem_ports = self._gem_ports, {}

        return self.create(tconts, gem_ports)

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

            except Exception as e:
                self.log.exception('hw-sync-tconts', e=e)

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
                    dl.append(my_tcont.add_to_hardware(self.olt.rest_client,
                                                       self._pon_id,
                                                       self._onu_id))
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
                                                       self.pon.pon_id,
                                                       self.onu_id,
                                                       operation='PATCH'))
            return dl

        def sync_flows():
            from flow.flow_entry import FlowEntry

            reflow, self._resync_flows = self._resync_flows, False
            return FlowEntry.sync_flows_by_onu(self, reflow=reflow)

        def failure(reason):
            # self.log.error('hardware-sync-get-config-failed', reason=reason)
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
            results = yield tcont.add_to_hardware(self.olt.rest_client,
                                                  self._pon_id, self._onu_id)

        except Exception as e:
            self.log.exception('tcont', tcont=tcont, reflow=reflow, e=e)
            # May occur with xPON provisioning, use hw-resync to recover
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def update_tcont_td(self, alloc_id, new_td):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue('not-found')

        tcont.traffic_descriptor = new_td
        try:
            results = yield tcont.add_to_hardware(self.olt.rest_client,
                                                  self._pon_id,
                                                  self._onu_id)
        except Exception as e:
            self.log.exception('tcont', tcont=tcont, e=e)
            # May occur with xPON provisioning, use hw-resync to recover
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def remove_tcont(self, alloc_id):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue('nop')

        del self._tconts[alloc_id]
        try:
            results = yield tcont.remove_from_hardware(self.olt.rest_client,
                                                       self._pon_id,
                                                       self._onu_id)
        except RestInvalidResponseCode as e:
            if e.code != 404:
                self.log.exception('tcont-delete', e=e)

        except Exception as e:
            self.log.exception('delete', e=e)
            raise

        returnValue(results)

    def gem_port(self, gem_id):
        return self._gem_ports.get(gem_id)

    def gem_ids(self, untagged_gem, exception_gems):  # FIXED_ONU
        """Get all GEM Port IDs used by this ONU"""
        if exception_gems:
            gem_ids = sorted([gem_id for gem_id, gem in self._gem_ports.items()
                             if gem.exception and not gem.multicast])
            return gem_ids
        elif untagged_gem:
            gem_ids = sorted([gem_id for gem_id, gem in self._gem_ports.items()
                             if gem.untagged and not gem.exception and not gem.multicast])
            return gem_ids
        else:
            return sorted([gem_id for gem_id, gem in self._gem_ports.items()
                          if not gem.multicast and not gem.exception and not gem.untagged])

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
            results = yield gem_port.add_to_hardware(self.olt.rest_client,
                                                     self._pon_id,
                                                     self.onu_id)
            # May need to update flow tables/evc-maps
            if gem_port.alloc_id in self._tconts:
                from flow.flow_entry import FlowEntry
                # GEM-IDs are a sorted list (ascending). First gemport handles downstream traffic
                # from flow.flow_entry import FlowEntry
                evc_maps = FlowEntry.find_evc_map_flows(self)

                for evc_map in evc_maps:
                    evc_map.add_gem_port(gem_port, reflow=reflow)

        except Exception as e:
            self.log.exception('gem-port', gem_port=gem_port, reflow=reflow, e=e)
            # This can happen with xPON if the ONU has been provisioned, but the PON Discovery
            # has not occurred for the ONU. Rely on hw sync to recover
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def remove_gem_id(self, gem_id):
        from flow.flow_entry import FlowEntry

        gem_port = self._gem_ports.get(gem_id)

        if gem_port is None:
            returnValue('nop')

        del self._gem_ports[gem_id]
        try:

            if gem_port.alloc_id in self._tconts:
                # May need to update flow tables/evc-maps
                # GEM-IDs are a sorted list (ascending). First gemport handles downstream traffic
                evc_maps = FlowEntry.find_evc_map_flows(self)
                for evc_map in evc_maps:
                    evc_map.remove_gem_port(gem_port)

            results = yield gem_port.remove_from_hardware(self.olt.rest_client,
                                                          self._pon_id,
                                                          self.onu_id)
        except RestInvalidResponseCode as e:
            if e.code != 404:
                self.log.exception('onu-delete', e=e)

        except Exception as ex:
            self.log.exception('gem-port-delete', e=ex)
            raise

        for evc_map in FlowEntry.find_evc_map_flows(self):
            try:
                evc_map.remove_gem_port(gem_port)

            except Exception as ex:
                self.log.exception('evc-map-gem-remove', e=ex)

        returnValue('done')

    @staticmethod
    def gem_id_to_gvid(gem_id):
        """Calculate GEM VID for a given GEM port id"""
        return gem_id - 2048
