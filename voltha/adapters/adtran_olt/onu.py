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

# Following is only used in autoactivate/demo mode. Otherwise xPON commands should be used
_VSSN_TO_VENDOR = {
    'ADTN': 'adtran_onu',
    'BCM?': 'broadcom_onu',   # TODO: Get actual VSSN for this vendor
    'DP??': 'dpoe_onu',       # TODO: Get actual VSSN for this vendor
    'PMC?': 'pmcs_onu',       # TODO: Get actual VSSN for this vendor
    'PSMO': 'ponsim_onu',
    'SIM?': 'simulated_onu',  # TODO: Get actual VSSN for this vendor
    'TBIT': 'tibit_onu',
}


class Onu(object):
    """
    Wraps an ONU
    """
    MIN_ONU_ID = 0
    MAX_ONU_ID = 253            # G.984. 0..253, 254=reserved, 255=broadcast
    BROADCAST_ONU_ID = 255
    DEFAULT_PASSWORD = ''

    def __init__(self, onu_info):
        # onu_info = {
        #     'serial-number': serial_number,
        #     'xpon-name': None,
        #     'pon-id': self.pon_id,
        #     'onu-id': None,  # Set later (mandatory)
        #     'enabled': True,
        #     'upstream-channel-speed': 0,
        #     't-conts': get_tconts(self.pon_id, serial_number),
        #     'gem-ports': get_gem_ports(self.pon_id, serial_number),
        # }
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
        self._uni_ports = [onu_info['onu-vid']]
        assert len(self._uni_ports) == 1, 'Only one UNI port supported at this time'
        self._channel_id = onu_info['channel-id']
        self._enabled = onu_info['enabled']
        self._vont_ani = onu_info.get('vont-ani')
        self._rssi = -9999
        self._equalization_delay = 0
        self._fiber_length = 0
        self._valid = True          # Set false during delete/cleanup
        self._proxy_address = None

        self._include_multicast = True        # TODO: May need to add multicast on a per-ONU basis

        self._sync_tick = 60.0
        self._expedite_sync = False
        self._expedite_count = 0
        self._sync_deferred = None     # For sync of ONT config to hardware

        # TODO: enable and upstream-channel-speed not yet supported

        self.log = structlog.get_logger(pon_id=self._pon_id, onu_id=self._onu_id)
        self._vendor_id = _VSSN_TO_VENDOR.get(self._serial_number_string.upper()[:4],
                                              'Unsupported_{}'.format(self._serial_number_string))

    def __del__(self):
        # self.stop()
        pass

    def __str__(self):
        return "Onu-{}-{}, PON ID: {}".format(self._onu_id, self._serial_number_string, self._pon_id)
    
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
    def onu_id(self):
        return self._onu_id

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
            self.set_config('enable', self._enabled)

            if self._enabled:
                self.start()
            else:
                self.stop()

    @property
    def onu_vid(self):
        return self._onu_vid

    @property
    def logical_port(self):
        """Return the logical PORT number of this ONU's UNI"""
        return self._uni_ports[0]

    @property
    def proxy_address(self):
        if self._proxy_address is None:
            from voltha.protos.device_pb2 import Device

            device_id = self.olt.device_id

            if self.olt.autoactivate:
                self._proxy_address = Device.ProxyAddress(device_id=device_id,
                                                          channel_id=self.onu_vid,
                                                          channel_group_id=self.pon.pon_id,
                                                          onu_id=self.onu_id)
            else:
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
    def serial_number(self):
        return self._serial_number_base64

    @property
    def vendor_id(self):
        return self._vendor_id

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

        try:
            yield self.olt.rest_client.request('POST', uri, data=data, name=name)

        except Exception as e:  # TODO: Add breakpoint here during unexpected reboot test
            self.log.exception('onu-create', e=e)
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
                yield self.add_gem_port(gem_port, reflow=reflow)

            except Exception as e:
                self.log.exception('add-gem-port', gem_port=gem_port, reflow=reflow, e=e)
                first_sync = 2    # Expedite first hw-sync

        self._sync_deferred = reactor.callLater(first_sync, self._sync_hardware)

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
        except Exception:
            pass

        self._gem_ports.clear()
        self._tconts.clear()
        self._olt = None
        self._channel_id = None

        returnValue(succeed('deleted'))

    def start(self):
        self._cancel_deferred()
        self._sync_deferred = reactor.callLater(0, self._sync_hardware)

    def stop(self):
        self._cancel_deferred()
        self._sync_deferred = reactor.callLater(0, self._sync_hardware)

    def restart(self):
        if not self._valid:
            return succeed('Deleting')
        tconts, self._tconts = self._tconts, {}
        gem_ports, self._gem_ports = self._gem_ports, {}
        return self.create(tconts, gem_ports)

    def _sync_hardware(self):
        from codec.olt_config import OltConfig
        self.log.debug('sync-hardware')
        def read_config(results):
            self.log.debug('read-config', results=results)

            config = OltConfig.Pon.Onu.decode([results])
            assert self.onu_id in config, 'sync-onu-not-found-{}'.format(self.onu_id)
            config = config[self.onu_id]
            dl = []

            if self._enabled != config.enable:
                dl.append(self.set_config('enable', self._enabled))

            if self.serial_number != config.serial_number:
                dl.append(self.set_config('serial-number', self.serial_number))

            # Sync TCONTs if everything else in sync

            if len(dl) == 0:
                dl.extend(sync_tconts(config.tconts))

            # Sync GEM Ports if everything else in sync

            if len(dl) == 0:
                dl.extend(sync_gem_ports(config.gem_ports))

            # Run h/w sync again a bit faster if we had to sync anything
            self._expedite_sync = len(dl) > 0

            # TODO: do checks
            return defer.gatherResults(dl, consumeErrors=True)

        def sync_tconts(hw_tconts):
            hw_alloc_ids = frozenset(hw_tconts.iterkeys())
            my_alloc_ids = frozenset(self._tconts.iterkeys())
            dl = []

            extra_alloc_ids = hw_alloc_ids - my_alloc_ids
            dl.extend(sync_delete_extra_tconts(extra_alloc_ids))

            missing_alloc_ids = my_alloc_ids - hw_alloc_ids
            dl.extend(sync_add_missing_tconts(missing_alloc_ids))

            matching_alloc_ids = my_alloc_ids & hw_alloc_ids
            matching_hw_tconts = {alloc_id: tcont
                                  for alloc_id, tcont in hw_tconts.iteritems()
                                  if alloc_id in matching_alloc_ids}
            dl.extend(sync_matching_tconts(matching_hw_tconts))

            return dl

        def sync_delete_extra_tconts(alloc_ids):
            return [self.remove_tcont(alloc_id) for alloc_id in alloc_ids]

        def sync_add_missing_tconts(alloc_ids):
            return [self.add_tcont(self._tconts[alloc_id], reflow=True) for alloc_id in alloc_ids]

        def sync_matching_tconts(hw_tconts):
            from tcont import TrafficDescriptor

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
                                                       self._onu_id,
                                                       operation="PATCH"))
            return dl

        def sync_gem_ports(hw_gem_ports):
            hw_gems_ids = frozenset(hw_gem_ports.iterkeys())
            my_gems_ids = frozenset(self._gem_ports.iterkeys())
            dl = []

            extra_gems_ids = hw_gems_ids - my_gems_ids
            dl.extend(sync_delete_extra_gem_ports(extra_gems_ids))

            missing_gem_ids = my_gems_ids - hw_gems_ids
            dl.extend(sync_add_missing_gem_ports(missing_gem_ids))

            matching_gem_ids = my_gems_ids & hw_gems_ids
            matching_hw_gem_ports = {gem_id: gem_port
                                     for gem_id, gem_port in hw_gem_ports.iteritems()
                                     if gem_id in matching_gem_ids}
            dl.extend(sync_matching_gem_ports(matching_hw_gem_ports))

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

        def failure(reason):
            # self.log.error('hardware-sync-get-config-failed', reason=reason)
            pass

        def reschedule(_):
            import random
            delay = self._sync_tick if self._enabled else 5 * self._sync_tick

            # Speed up sequential resync a limited number of times if out of sync
            # With 60 second initial an typical worst case resync of 4 times, this
            # should resync an ONU and all it's gem-ports and tconts within <90 seconds

            if self._expedite_sync:
                self._expedite_count += 1
                if self._expedite_count < 5:
                    delay = 5
            else:
                self._expedite_count = 0

            delay += random.uniform(-delay / 10, delay / 10)
            self._sync_deferred = reactor.callLater(delay, self._sync_hardware)
            self._expedite_sync = False

        # If PON is not enabled, skip hw-sync. If ONU not enabled, do it but less
        # frequently

        if not self.pon.enabled:
            return reschedule('not-enabled')

        self._sync_deferred = self._get_config()
        self._sync_deferred.addCallbacks(read_config, failure)
        self._sync_deferred.addBoth(reschedule)

    def _get_config(self):
        uri = AdtranOltHandler.GPON_ONU_CONFIG_URI.format(self._pon_id, self.onu_id)
        name = 'pon-get-onu_config-{}-{}'.format(self._pon_id, self.onu_id)
        return self.olt.rest_client.request('GET', uri, name=name)

    def set_config(self, leaf, value):
        self.log.debug('set-config', leaf=leaf, value=value)

        data = json.dumps({'onu-id': self._onu_id, leaf: value})
        uri = AdtranOltHandler.GPON_ONU_CONFIG_LIST_URI.format(self._pon_id)
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
            returnValue(succeed('Deleting'))

        if not reflow and tcont.alloc_id in self._tconts:
            returnValue(succeed('already created'))

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
    def update_tcont(self, alloc_id, new_values):
        # TODO: If alloc-id in use by a gemport, should we deny request?
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue(succeed('not-found'))

        # del self._tconts[alloc_id]
        #
        # try:
        #     results = yield tcont.remove_from_hardware()
        #
        # except Exception as e:
        #     self.log.exception('delete', e=e)
        #     raise

        returnValue(succeed('TODO: Not implemented yet'))

    @inlineCallbacks
    def remove_tcont(self, alloc_id):
        # TODO: If alloc-id in use by a gemport, should we deny request?
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue(succeed('nop'))

        del self._tconts[alloc_id]

        try:
            results = yield tcont.remove_from_hardware()

        except Exception as e:
            self.log.exception('delete', e=e)
            raise

        returnValue(succeed(results))

    def gem_ids(self, exception_gems):
        """Get all GEM Port IDs used by this ONU"""
        if exception_gems:
            gem_ids = sorted([gem_id for gem_id, gem in self._gem_ports.items()
                             if gem.exception and not gem.multicast])  # FIXED_ONU
            return gem_ids
        else:
            return sorted([gem_id for gem_id, gem in self._gem_ports.items()
                          if not gem.multicast and not gem.exception])  # FIXED_ONU

    @inlineCallbacks
    def add_gem_port(self, gem_port, reflow=False):
        """
        Add a GEM Port to this ONU

        :param gem_port: (GemPort) GEM Port to add
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            returnValue(succeed('Deleting'))

        if not reflow and gem_port.gem_id in self._gem_ports:
            returnValue(succeed)

        self._gem_ports[gem_port.gem_id] = gem_port

        try:
            results = yield gem_port.add_to_hardware(self.olt.rest_client,
                                                     self._pon_id,
                                                     self.onu_id)

            # May need to update flow tables/evc-maps
            if gem_port.alloc_id in self._tconts:
                # GEM-IDs are a sorted list (ascending). First gemport handles downstream traffic
                # from flow.flow_entry import FlowEntry
                # evc_maps = FlowEntry.find_evc_map_flows(self._device_id, self._pon_id, self._onu_id)
                pass   # TODO: Start here Tuesday

        except Exception as e:
            self.log.exception('gem-port', gem_port=gem_port, reflow=reflow, e=e)
            # This can happen with xPON if the ONU has been provisioned, but the PON Discovery
            # has not occurred for the ONU. Rely on hw sync to recover
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def remove_gem_id(self, gem_id):
        gem_port = self._gem_ports.get(gem_id)

        if gem_port is None:
            returnValue(succeed('nop'))

        del self._gem_ports[gem_id]

        try:
            if gem_port.alloc_id in self._tconts:
                # May need to update flow tables/evc-maps
                # GEM-IDs are a sorted list (ascending). First gemport handles downstream traffic
                pass

            results = yield gem_port.remove_from_hardware(self.olt.rest_client,
                                                          self._pon_id,
                                                          self.onu_id)
        except Exception as e:
            self.log.exception('delete', e=e)
            raise

        returnValue(succeed(results))

    @staticmethod
    def gem_id_to_gvid(gem_id):
        """Calculate GEM VID for a given GEM port id"""
        return gem_id - 2048
