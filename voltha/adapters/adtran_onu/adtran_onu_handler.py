#
# Copyright 2017 the original author or authors.
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
from voltha.adapters.adtran_olt.xpon.adtran_xpon import AdtranXPON
from pon_port import PonPort
from uni_port import UniPort
from heartbeat import HeartBeat
from omci.omci import OMCI

from voltha.extensions.alarms.adapter_alarms import AdapterAlarms
from voltha.extensions.kpi.onu.onu_pm_metrics import OnuPmMetrics
from voltha.extensions.kpi.onu.onu_omci_pm import OnuOmciPmMetrics

from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet.defer import returnValue

from voltha.registry import registry
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from common.utils.indexpool import IndexPool
from voltha.extensions.omci.omci_me import *

import voltha.adapters.adtran_olt.adtranolt_platform as platform

_ = third_party
_MAXIMUM_PORT = 17        # Only one PON and UNI port at this time
_ONU_REBOOT_MIN = 90      # IBONT 602 takes about 3 minutes
_ONU_REBOOT_RETRY = 10
BRDCM_DEFAULT_VLAN = 4091


class AdtranOnuHandler(AdtranXPON):
    def __init__(self, adapter, device_id):
        kwargs = dict()
        super(AdtranOnuHandler, self).__init__(**kwargs)
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.logical_device_id = None
        self.proxy_address = None
        self._event_messages = None
        self._enabled = False
        self.pm_metrics = None
        self.alarms = None
        self._mgmt_gemport_aes = False
        self._upstream_channel_speed = 0

        self._openomci = OMCI(self, adapter.omci_agent)
        self._in_sync_subscription = None
        # TODO: Need to find a way to sync with OLT. It is part of OpenFlow Port number as well
        self._onu_port_number = 0
        self._pon_port_number = 1
        self._port_number_pool = IndexPool(_MAXIMUM_PORT, 0)

        self._unis = dict()         # Port # -> UniPort
        self._pon = PonPort.create(self, self._pon_port_number)
        self._heartbeat = HeartBeat.create(self, device_id)

        self._deferred = None
        self._event_deferred = None

        # Assume no XPON support unless we get an vont-ani/ont-ani/venet create
        self.xpon_support = False    # xPON no longer available

    def __str__(self):
        return "AdtranOnuHandler: {}".format(self.device_id)

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._event_deferred = self._event_deferred, None

        for d in [d1, d2]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        assert isinstance(value, bool), 'enabled is a boolean'
        if self._enabled != value:
            self._enabled = value
            if self._enabled:
                self.start()
            else:
                self.stop()

    @property
    def mgmt_gemport_aes(self):
        return self._mgmt_gemport_aes

    @mgmt_gemport_aes.setter
    def mgmt_gemport_aes(self, value):
        if self._mgmt_gemport_aes != value:
            self._mgmt_gemport_aes = value
            # TODO: Anything else

    @property
    def upstream_channel_speed(self):
        return self._upstream_channel_speed

    @upstream_channel_speed.setter
    def upstream_channel_speed(self, value):
        if self._upstream_channel_speed != value:
            self._upstream_channel_speed = value
            # TODO: Anything else

    @property
    def openomci(self):
        return self._openomci

    @property
    def heartbeat(self):
        return self._heartbeat

    @property
    def uni_ports(self):
        return self._unis.values()

    def uni_port(self, port_no_or_name):
        if isinstance(port_no_or_name, (str, unicode)):
            return next((uni for uni in self.uni_ports
                         if uni.name == port_no_or_name), None)

        assert isinstance(port_no_or_name, int), 'Invalid parameter type'
        return self._unis.get(port_no_or_name)

    @property
    def pon_port(self):
        return self._pon

    @property
    def pon_ports(self):
        return [self._pon]

    @property
    def _next_port_number(self):
        return self._port_number_pool.get_next()

    def _release_port_number(self, number):
        self._port_number_pool.release(number)

    def start(self):
        assert self._enabled, 'Start should only be called if enabled'

        self._cancel_deferred()

        # Handle received ONU event messages   TODO: Deprecate this....
        self._event_messages = DeferredQueue()
        self._event_deferred = reactor.callLater(0, self._handle_onu_events)

        # Register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

        # OpenOMCI Startup
        self._subscribe_to_events()
        self._openomci.enabled = True

        # Port startup
        if self._pon is not None:
            self._pon.enabled = True

        for port in self.uni_ports:
            port.enabled = True

        # Heartbeat
        self._heartbeat.enabled = True

    def stop(self):
        assert not self._enabled, 'Stop should only be called if disabled'

        self._cancel_deferred()

        # Drop registration for adapter messages
        self.adapter_agent.unregister_for_inter_adapter_messages()

        # Heartbeat
        self._heartbeat.stop()

        # OMCI Communications
        self._unsubscribe_to_events()
        self._openomci.enabled = False

        # Port shutdown
        for port in self.uni_ports:
            port.enabled = False

        if self._pon is not None:
            self._pon.enabled = False

        queue, self._event_deferred = self._event_deferred, None
        if queue is not None:
            while queue.pending:
                _ = yield queue.get()

    def receive_message(self, msg):
        if self.enabled:
            # TODO: Have OpenOMCI actually receive the messages
            self.openomci.receive_message(msg)

    def activate(self, device):
        self.log.info('activating')

        try:
            # first we verify that we got parent reference and proxy info
            assert device.parent_id, 'Invalid Parent ID'
            assert device.proxy_address.device_id, 'Invalid Device ID'

            # register for proxied messages right away
            self.proxy_address = device.proxy_address
            self.adapter_agent.register_for_proxied_messages(device.proxy_address)

            # initialize device info
            device.root = True
            device.vendor = 'Adtran Inc.'
            device.model = 'n/a'
            device.hardware_version = 'n/a'
            device.firmware_version = 'n/a'
            device.reason = ''
            device.connect_status = ConnectStatus.UNKNOWN

            # Register physical ports.  Should have at least one of each
            self.adapter_agent.add_port(device.id, self._pon.get_port())

            def xpon_not_found():
                if not self.xpon_support:
                    # Start things up for this ONU Handler.
                    self.enabled = True

            # Schedule xPON 'not found' startup for 10 seconds from now. We will
            # easily get a vONT-ANI create within that time if xPON is being used
            # as this is how we are initially launched and activated in the first
            # place if xPON is in use.
            reactor.callLater(10, xpon_not_found)

            # reference of uni_port is required when re-enabling the device if
            # it was disabled previously
            # Need to query ONU for number of supported uni ports
            # For now, temporarily set number of ports to 1 - port #2
            parent_device = self.adapter_agent.get_device(device.parent_id)
            self.logical_device_id = parent_device.parent_id
            assert self.logical_device_id, 'Invalid logical device ID'
            self.adapter_agent.update_device(device)

            ############################################################################
            # Setup PM configuration for this device
            # Pass in ONU specific options
            kwargs = {
                OnuPmMetrics.DEFAULT_FREQUENCY_KEY: OnuPmMetrics.DEFAULT_ONU_COLLECTION_FREQUENCY,
                'heartbeat': self.heartbeat,
                OnuOmciPmMetrics.OMCI_DEV_KEY: self.openomci.onu_omci_device
            }
            self.pm_metrics = OnuPmMetrics(self.adapter_agent, self.device_id,
                                           self.logical_device_id, grouped=True,
                                           freq_override=False, **kwargs)
            pm_config = self.pm_metrics.make_proto()
            self.openomci.set_pm_config(self.pm_metrics.omci_pm.openomci_interval_pm)
            self.log.info("initial-pm-config", pm_config=pm_config)
            self.adapter_agent.update_device_pm_config(pm_config, init=True)

            ############################################################################
            # Setup Alarm handler
            self.alarms = AdapterAlarms(self.adapter_agent, device.id, self.logical_device_id)

            ############################################################################
            # Start collecting stats from the device after a brief pause
            reactor.callLater(30, self.pm_metrics.start_collector)

        except Exception as e:
            self.log.exception('activate-failure', e=e)
            device.reason = 'Failed to activate: {}'.format(e.message)
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.FAILED
            self.adapter_agent.update_device(device)

    def reconcile(self, device):
        self.log.info('reconciling-ONU-device-starts')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        # assert device.proxy_address.channel_id
        self._cancel_deferred()

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # Register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

        # Set the connection status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)
        self.enabled = True

        # TODO: Verify that the uni, pon and logical ports exists

        # Mark the device as REACHABLE and ACTIVE
        device = self.adapter_agent.get_device(device.id)
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        device.reason = ''
        self.adapter_agent.update_device(device)

        self.log.info('reconciling-ONU-device-ends')

    def update_pm_config(self, device, pm_config):
        # TODO: This has not been tested
        self.log.info('update_pm_config', pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    @inlineCallbacks
    def update_flow_table(self, flows):
        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        self.log.debug('bulk-flow-update', flows=flows)

        import voltha.core.flow_decomposer as fd
        from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC

        def is_downstream(port):
            return port == self._pon_port_number

        def is_upstream(port):
            return not is_downstream(port)

        for flow in flows:
            match = {
                'in_port': None,
                # 'etype': None,            # These remaining key-value
                # 'proto': None,            # pairs are set if found in the
                # 'vlan_vid': None,         # flow information
                # 'inner_vid': None,
                # 'vlan_pcp': None,
                # 'udp_dst': None,
                # 'udp_src': None,
                # 'ipv4_dst': None,
                # 'ipv4_src': None,
            }
            actions = {
                'out_port': None,
                # 'push_tpid': None,        # These remaining key-value
                # 'pop_vlan': None,  (bool) # pairs are set if found in the
                # 'set_vlan_vid': None,     # flow information
            }
            self.log.debug('bulk-flow-update', flow=flow)
            try:
                _out_port = fd.get_out_port(flow)  # may be None
                self.log.debug('out-port', out_port=_out_port)

                for field in fd.get_ofb_fields(flow):
                    if field.type == fd.IN_PORT:
                        assert match['in_port'] is None, \
                            'Only a single input port is supported'
                        match['in_port'] = field.port
                        self.log.debug('field-type-in-port', in_port=field.port)

                    elif field.type == fd.ETH_TYPE:
                        match['etype'] = field.eth_type
                        self.log.debug('field-type-eth-type', eth_type=field.eth_type)

                    elif field.type == fd.IP_PROTO:
                        match['proto'] = field.ip_proto
                        self.log.debug('field-type-ip-proto', ip_proto=field.ip_proto)

                    elif field.type == fd.VLAN_VID:
                        match['vlan_vid'] = field.vlan_vid & 0xfff
                        self.log.debug('field-type-vlan-vid', vlan=field.vlan_vid & 0xfff)

                    elif field.type == fd.VLAN_PCP:
                        match['vlan_pcp'] = field.vlan_pcp
                        self.log.debug('field-type-vlan-pcp', pcp=field.vlan_pcp)

                    elif field.type == fd.UDP_DST:
                        match['udp_dst'] = field.udp_dst
                        self.log.debug('field-type-udp-dst', udp_dst=field.udp_dst)

                    elif field.type == fd.UDP_SRC:
                        match['udp_src'] = field.udp_src
                        self.log.debug('field-type-udp-src', udp_src=field.udp_src)

                    elif field.type == fd.IPV4_DST:
                        match['ipv4_dst'] = field.ipv4_dst
                        self.log.debug('field-type-ipv4-dst', ipv4_dst=field.ipv4_dst)

                    elif field.type == fd.IPV4_SRC:
                        match['ipv4_src'] = field.ipv4_src
                        self.log.debug('field-type-ipv4-src', ipv4_dst=field.ipv4_src)

                    elif field.type == fd.METADATA:
                        match['inner_vid'] = field.table_metadata
                        self.log.debug('field-type-metadata', metadata=field.table_metadata)

                    else:
                        raise NotImplementedError('field.type={}'.format(field.type))

                for action in fd.get_actions(flow):
                    if action.type == fd.OUTPUT:
                        actions['out_port'] = action.output.port
                        self.log.debug('action-type-output', output=action.output.port)

                    elif action.type == fd.POP_VLAN:
                        actions['pop_vlan'] = True
                        self.log.debug('action-type-pop-vlan')

                    elif action.type == fd.PUSH_VLAN:
                        actions['push_tpid'] = action.push.ethertype
                        self.log.debug('action-type-push-vlan',
                                       push_tpid=action.push.ethertype)

                        if action.push.ethertype != 0x8100:
                            self.log.error('unsupported-tpid',
                                           ethertype=action.push.ethertype,
                                           in_port=match['in_port'])

                    elif action.type == fd.SET_FIELD:
                        _field = action.set_field.field.ofb_field
                        self.log.debug('action-type-set-field', field=_field)
                        assert (action.set_field.field.oxm_class == OFPXMC_OPENFLOW_BASIC)

                        if _field.type == fd.VLAN_VID:
                            actions['set_vlan_vid'] = _field.vlan_vid & 0xfff
                            self.log.debug('set-field-type-vlan-vid', actions['set_vlan_vid'])
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type,
                                           in_port=match['in_port'])
                    else:
                        self.log.error('unsupported-action-type', action_type=action.type,
                                       in_port=match['in_port'])

                assert match['in_port'] is not None, 'No input port specified'
                assert actions['out_port'] is not None, 'No output port specified'

                _is_upstream = is_upstream(match['in_port'])

            except Exception as e:
                self.log.exception('failed-to-decode-flow', e=e)
                continue

            # Ignore untagged upstream etherType flows. These are trapped at the
            # OLT and the default flows during initial OMCI service download will
            # send them to the Default VLAN (4091) port for us
            #
            if _is_upstream and match.get('vlan_vid') is None \
                    and match.get('etype') is not None:
                continue

            # Also ignore upstream untagged/priority tag that sets priority tag
            # since that is already installed and any user-data flows for upstream
            # priority tag data will be at a higher level.  Also should ignore the
            # corresponding priority-tagged to priority-tagged flow as well.

            if (match.get('vlan_vid') == 0 and action.get('set_vlan_vid') == 0) or \
                    (match.get('vlan_vid') is None and action.get('set_vlan_vid') == 0
                     and not _is_upstream):
                continue

            from omci.adtn_install_flow import AdtnInstallFlowTask
            task = AdtnInstallFlowTask(self.openomci, self, match, action, _is_upstream)
            self.openomci.onu_omci_device.task_runner.queue_task(task)

    @inlineCallbacks
    def reboot(self):
        self.log.info('rebooting', device_id=self.device_id)
        self._cancel_deferred()

        reregister = True
        try:
            # Drop registration for adapter messages
            self.adapter_agent.unregister_for_inter_adapter_messages()

        except KeyError:
            reregister = False

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE
        device = self.adapter_agent.get_device(self.device_id)

        previous_oper_status = device.oper_status
        previous_conn_status = device.connect_status

        device.oper_status = OperStatus.ACTIVATING
        device.connect_status = ConnectStatus.UNREACHABLE
        device.reason = 'Attempting reboot'
        self.adapter_agent.update_device(device)

        # TODO: send alert and clear alert after the reboot
        try:
            ######################################################
            # MIB Reset
            yield self.openomci.onu_omci_device.reboot(timeout=1)

        except Exception as e:
            self.log.exception('send-reboot', e=e)
            raise

        # Reboot in progress. A reboot may take up to 3 min 30 seconds
        # Go ahead and pause less than that and start to look
        # for it being alive

        device.reason = 'reboot in progress'
        self.adapter_agent.update_device(device)

        # Disable OpenOMCI
        self.omci.enabled = False
        self._deferred = reactor.callLater(_ONU_REBOOT_MIN,
                                           self._finish_reboot,
                                           previous_oper_status,
                                           previous_conn_status,
                                           reregister)

    @inlineCallbacks
    def _finish_reboot(self, previous_oper_status, previous_conn_status,
                       reregister):

        # Restart OpenOMCI
        self.omci.enabled = True

        device = self.adapter_agent.get_device(self.device_id)

        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        device.reason = ''
        self.adapter_agent.update_device(device)

        if reregister:
            self.adapter_agent.register_for_inter_adapter_messages()

        self.log.info('reboot-complete', device_id=self.device_id)

    def self_test_device(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        from voltha.protos.voltha_pb2 import SelfTestResponse
        self.log.info('self-test-device', device=device.id)
        # TODO: Support self test?
        return SelfTestResponse(result=SelfTestResponse.NOT_SUPPORTED)

    def disable(self):
        self.log.info('disabling', device_id=self.device_id)
        self.enabled = False

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        # Update the device operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        device.reason = 'Disabled'
        self.adapter_agent.update_device(device)

        # Remove the uni logical port from the OLT, if still present
        parent_device = self.adapter_agent.get_device(device.parent_id)
        assert parent_device

        for uni in self.uni_ports:
            # port_id = 'uni-{}'.format(uni.port_number)
            port_id = uni.port_id_name()

            try:
                #TODO: there is no logical device if olt disables first
                logical_device_id = parent_device.parent_id
                assert logical_device_id
                port = self.adapter_agent.get_logical_port(logical_device_id,
                                                           port_id)
                self.adapter_agent.delete_logical_port(logical_device_id, port)
            except KeyError:
                self.log.info('logical-port-not-found', device_id=self.device_id,
                              portid=port_id)

        # Remove pon port from parent and disable
        if self._pon is not None:
            self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                                 self._pon.get_port())
            self._pon.enabled = False

        # Unregister for proxied message
        self.adapter_agent.unregister_for_proxied_messages(device.proxy_address)

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('disabled', device_id=device.id)

    def reenable(self):
        self.log.info('re-enabling', device_id=self.device_id)
        try:
            # Get the latest device reference
            device = self.adapter_agent.get_device(self.device_id)
            self._cancel_deferred()

            # First we verify that we got parent reference and proxy info
            assert device.parent_id
            assert device.proxy_address.device_id
            # assert device.proxy_address.channel_id

            # Re-register for proxied messages right away
            self.proxy_address = device.proxy_address
            self.adapter_agent.register_for_proxied_messages(
                device.proxy_address)

            # Re-enable the ports on that device
            self.adapter_agent.enable_all_ports(self.device_id)

            # Add the pon port reference to the parent
            if self._pon is not None:
                self._pon.enabled = True
                self.adapter_agent.add_port_reference_to_parent(device.id,
                                                                self._pon.get_port())
            # Update the connect status to REACHABLE
            device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(device)

            # re-add uni port to logical device
            parent_device = self.adapter_agent.get_device(device.parent_id)
            self.logical_device_id = parent_device.parent_id
            assert self.logical_device_id, 'Invalid logical device ID'

            # reestablish logical ports for each UNI
            for uni in self.uni_ports:
                self.adapter_agent.add_port(device.id, uni.get_port())
                uni.add_logical_port(uni.logical_port_number, subscriber_vlan=uni.subscriber_vlan)

            device = self.adapter_agent.get_device(device.id)
            device.oper_status = OperStatus.ACTIVE
            device.connect_status = ConnectStatus.REACHABLE
            device.reason = ''

            self.enabled = True
            self.adapter_agent.update_device(device)

            self.log.info('re-enabled', device_id=device.id)

        except Exception, e:
            self.log.exception('error-reenabling', e=e)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        for uni in self._unis.itervalues():
            uni.stop()
            uni.delete()

        self._pon.stop()
        self._pon.delete()

        # OpenOMCI cleanup
        self._openomci.delete()

    def on_ont_ani_create(self, ont_ani):
        """
        A new ONT-ani is being created. You can override this method to
        perform custom operations as needed. If you override this method, you can add
        additional items to the item dictionary to track additional implementation
        key/value pairs.

        :param ont_ani: (dict) new ONT-ani
        :return: (dict) Updated ONT-ani dictionary, None if item should be deleted
        """
        self.xpon_support = True

        self.log.info('ont-ani-create', ont_ani=ont_ani)
        self.enabled = ont_ani['enabled']

        return ont_ani   # Implement in your OLT, if needed

    def on_ont_ani_modify(self, ont_ani, update, diffs):
        """
        A existing ONT-ani is being updated. You can override this method to
        perform custom operations as needed. If you override this method, you can add
        additional items to the item dictionary to track additional implementation
        key/value pairs.

        :param ont_ani: (dict) existing ONT-ani item dictionary
        :param update: (dict) updated (changed) ONT-ani
        :param diffs: (dict) collection of items different in the update
        :return: (dict) Updated ONT-ani dictionary, None if item should be deleted
        """
        if not self.xpon_support:
            return

        valid_keys = ['enabled', 'mgnt-gemport-aes']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("ont_ani leaf '{}' is read-only or write-once".format(invalid_key))

        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'enabled':
                self.enabled = update[k]

            elif k == 'mgnt-gemport-aes':
                self.mgmt_gemport_aes = update[k]

        return update

    def on_ont_ani_delete(self, ont_ani):
        """
        A existing ONT-ani is being deleted. You can override this method to
        perform custom operations as needed. If you override this method, you can add
        additional items to the item dictionary to track additional implementation
        key/value pairs.

        :param ont_ani: (dict) ONT-ani to delete
        :return: (dict) None if item should be deleted
        """
        if not self.xpon_support:
            return

        # TODO: Is this ever called or is the iAdapter 'delete' called first?
        return None   # Implement in your OLT, if needed

    def on_vont_ani_create(self, vont_ani):
        self.xpon_support = True
        self.log.info('vont-ani-create', vont_ani=vont_ani)
        # TODO: look up PON port and update 'upstream-channel-speed'
        return vont_ani   # Implement in your OLT, if needed

    def on_vont_ani_modify(self, vont_ani, update, diffs):
        if not self.xpon_support:
            return

        valid_keys = ['upstream-channel-speed']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("vont_ani leaf '{}' is read-only or write-once".format(invalid_key))

        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'upstream-channel-speed':
                self.upstream_channel_speed = update[k]

        return update

    def on_vont_ani_delete(self, vont_ani):
        if not self.xpon_support:
            return

        return self.delete()

    def on_venet_create(self, venet):
        self.xpon_support = True

        self.log.info('venet-create', venet=venet)

        # TODO: This first set is copied over from BroadCOM ONU. For testing, actual work
        #       is the last 7 lines.  The 'test' code below assumes we have not registered
        #       any UNI ports during 'activate' but we want to create them as the vEnet
        #       information comes in.
        # onu_device = self.adapter_agent.get_device(self.device_id)
        # existing_uni_ports = self.adapter_agent.get_ports(onu_device.parent_id, Port.ETHERNET_UNI)
        #
        # parent_port_num = None
        # for uni in existing_uni_ports:
        #     if uni.label == venet['name']:   #  TODO: was -> data.interface.name:
        #         parent_port_num = uni.port_no
        #         break
        #
        # # Create both the physical and logical ports for the UNI now
        # parent_device = self.adapter_agent.get_device(onu_device.parent_id)
        # logical_device_id = parent_device.parent_id
        # assert logical_device_id, 'Invalid logical device ID'
        # # self.add_uni_port(onu_device, logical_device_id, venet['name'], parent_port_num)
        #
        # pon_ports = self.adapter_agent.get_ports(self.device_id, Port.PON_ONU)
        # if pon_ports:
        #     # TODO: Assumed only one PON port and UNI port per ONU.
        #     pon_port = pon_ports[0]
        # else:
        #     self.log.error("No-Pon-port-configured-yet")
        #     return
        #
        # self.adapter_agent.delete_port_reference_from_parent(self.device_id, pon_port)
        # pon_port.peers[0].device_id = onu_device.parent_id
        # pon_port.peers[0].port_no = parent_port_num
        # self.adapter_agent.add_port_reference_to_parent(self.device_id, pon_port)

        #################################################################################
        # Start of actual work (what actually does something)
        # TODO: Clean this up.  Use looked up UNI

        # vlan non-zero if created via legacy method (not xPON). Also
        # Set a random serial number since not xPON based

        ofp_port_no, subscriber_vlan, untagged_vlan = UniPort.decode_venet(venet)

        self._add_uni_port(self, venet['name'], ofp_port_no, subscriber_vlan,
                           untagged_vlan, venet['enabled'])
        return venet

    # SEBA - Below is used by xPON mode
    def _add_uni_port(self, port_name, ofp_port_no, subscriber_vlan, untagged_vlan, enable):
        uni_port = UniPort.create(self, port_name,
                                  self._onu_port_number,  # TODO: self._next_port_number,
                                  ofp_port_no,
                                  subscriber_vlan,
                                  untagged_vlan)

        device = self.adapter_agent.get_device(self.device_id)
        self.adapter_agent.add_port(device.id, uni_port.get_port())

        self._unis[uni_port.port_number] = uni_port

        # If the PON has already synchronized, add the logical port now
        # since we know we have been activated

        if self._pon is not None and self.openomci.connected:
            uni_port.add_logical_port(ofp_port_no, subscriber_vlan=subscriber_vlan)

        # TODO: Next is just for debugging to see what this call returns after
        #       we add a UNI
        # existing_uni_ports = self.adapter_agent.get_ports(onu_device.parent_id, Port.ETHERNET_UNI)

        uni_port.enabled = enable

    def add_uni_ports(self):
        """ Called after in-sync achieved and not in xPON mode"""
        # TODO: Should this be moved to the omci.py module for this ONU?

        # This is only for working WITHOUT xPON
        assert not self.xpon_support
        pptp_entities = self.openomci.onu_omci_device.configuration.pptp_entities

        device = self.adapter_agent.get_device(self.device_id)
        subscriber_vlan = device.vlan
        untagged_vlan = BRDCM_DEFAULT_VLAN          # TODO: Need a better way to define this

        for entity_id, pptp in pptp_entities.items():
            intf_id = self.proxy_address.channel_id
            onu_id = self.proxy_address.onu_id

            uni_no_start = platform.mk_uni_port_num(intf_id, onu_id)

            working_port = self._next_port_number
            uni_no = uni_no_start + working_port        # OpenFlow port number
            uni_name = "uni-{}".format(uni_no)

            mac_bridge_port_num = working_port + 1

            self.log.debug('live-port-number-ready', uni_no=uni_no, uni_name=uni_name)

            uni_port = UniPort.create(self, uni_name, uni_no, uni_name,
                                      subscriber_vlan, untagged_vlan)

            uni_port.entity_id = entity_id
            uni_port.enabled = True
            uni_port.mac_bridge_port_num = mac_bridge_port_num
            uni_port.add_logical_port(uni_port.port_number, subscriber_vlan=subscriber_vlan)

            self.log.debug("created-uni-port", uni=uni_port)

            self.adapter_agent.add_port(device.id, uni_port.get_port())
            parent_device = self.adapter_agent.get_device(device.parent_id)

            parent_adapter_agent = registry('adapter_loader').get_agent(parent_device.adapter)
            if parent_adapter_agent is None:
                self.log.error('olt-adapter-agent-could-not-be-retrieved')

            parent_adapter_agent.add_port(device.parent_id, uni_port.get_port())

            self._unis[uni_port.port_number] = uni_port

            # TODO: this should be in the PonPort class
            pon_port = self._pon.get_port()
            self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                                 pon_port)
            # Find index where this ONU peer is (should almost always be zero)
            d = [i for i, e in enumerate(pon_port.peers) if
                 e.port_no == intf_id and e.device_id == device.parent_id]

            if len(d) > 0:
                pon_port.peers[d[0]].port_no = uni_port.port_number
                self.adapter_agent.add_port_reference_to_parent(self.device_id,
                                                                pon_port)
            self.adapter_agent.update_device(device)

            # TODO: only one uni/pptp for now. flow bug in openolt

    def on_venet_modify(self, venet, update, diffs):
        if not self.xpon_support:
            return

        # Look up the associated UNI port
        uni_port = self.uni_port(venet['name'])

        if uni_port is not None:
            valid_keys = ['enabled']  # Modify of these keys supported

            invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
            if invalid_key is not None:
                raise KeyError("venet leaf '{}' is read-only or write-once".format(invalid_key))

            keys = [k for k in diffs.keys() if k in valid_keys]

            for k in keys:
                if k == 'enabled':
                    uni_port.enabled = update[k]

        return update

    def on_venet_delete(self, venet):
        if not self.xpon_support:
            return

        # Look up the associated UNI port
        uni_port = self.uni_port(venet['name'])

        if uni_port is not None:
            port_no = uni_port.port_number
            del self._unis[port_no]
            uni_port.delete()
            self._release_port_number(port_no)

        return None

    def on_tcont_create(self, tcont):
        from onu_tcont import OnuTCont

        self.log.info('create-tcont')

        td = self.traffic_descriptors.get(tcont.get('td-ref'))
        traffic_descriptor = td['object'] if td is not None else None
        tcont['object'] = OnuTCont.create(self, tcont, traffic_descriptor)

        if self._pon is not None:
            self._pon.add_tcont(tcont['object'])

        return tcont

    def on_tcont_modify(self, tcont, update, diffs):
        valid_keys = ['td-ref']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("TCONT leaf '{}' is read-only or write-once".format(invalid_key))

        tc = tcont.get('object')
        assert tc is not None, 'TCONT not found'

        update['object'] = tc

        if self._pon is not None:
            keys = [k for k in diffs.keys() if k in valid_keys]

            for k in keys:
                if k == 'td-ref':
                    td = self.traffic_descriptors.get(update['td-ref'])
                    if td is not None:
                        self._pon.update_tcont_td(tcont['alloc-id'], td)

        return update

    def on_tcont_delete(self, tcont):
        if self._pon is not None:
            self._pon.remove_tcont(tcont['alloc-id'])

        return None

    def on_td_create(self, traffic_disc):
        from onu_traffic_descriptor import OnuTrafficDescriptor

        traffic_disc['object'] = OnuTrafficDescriptor.create(traffic_disc)
        return traffic_disc

    def on_td_modify(self, traffic_disc, update, diffs):
        from onu_traffic_descriptor import OnuTrafficDescriptor

        valid_keys = ['fixed-bandwidth',
                      'assured-bandwidth',
                      'maximum-bandwidth',
                      'priority',
                      'weight',
                      'additional-bw-eligibility-indicator']
        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("traffic-descriptor leaf '{}' is read-only or write-once".format(invalid_key))

        # New traffic descriptor
        update['object'] = OnuTrafficDescriptor.create(update)

        td_name = traffic_disc['name']
        tconts = {key: val for key, val in self.tconts.iteritems()
                  if val['td-ref'] == td_name and td_name is not None}

        for tcont in tconts.itervalues():
            if self._pon is not None:
                self._pon.update_tcont_td(tcont['alloc-id'], update['object'])

        return update

    def on_td_delete(self, traffic_desc):
        # TD may be used by more than one TCONT. Only delete if the last one

        td_name = traffic_desc['name']
        num_tconts = len([val for val in self.tconts.itervalues()
                          if val['td-ref'] == td_name and td_name is not None])

        return None if num_tconts <= 1 else traffic_desc

    def on_gemport_create(self, gem_port):
        from onu_gem_port import OnuGemPort
        assert self._pon is not None, 'No PON port'

        gem_port['object'] = OnuGemPort.create(self, gem_port,
                                               self._pon.next_gem_entity_id)
        self._pon.add_gem_port(gem_port['object'])
        return gem_port

    def on_gemport_modify(self, gem_port, update, diffs):
        valid_keys = ['encryption',
                      'traffic-class']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("GEM Port leaf '{}' is read-only or write-once".format(invalid_key))

        port = gem_port.get('object')
        assert port is not None, 'GemPort not found'

        keys = [k for k in diffs.keys() if k in valid_keys]
        update['object'] = port

        for k in keys:
            if k == 'encryption':
                port.encryption = update[k]
            elif k == 'traffic-class':
                pass                    # TODO: Implement

        return update

    def on_gemport_delete(self, gem_port):
        if self._pon is not None:
            self._pon.remove_gem_id(gem_port['gemport-id'])

        return None

    def on_mcast_gemport_create(self, mcast_gem_port):
        return mcast_gem_port  # Implement in your OLT, if needed

    def on_mcast_gemport_modify(self, mcast_gem_port, update, diffs):
        return mcast_gem_port  # Implement in your OLT, if needed

    def on_mcast_gemport_delete(self, mcast_gem_port):
        return None  # Implement in your OLT, if needed

    def on_mcast_dist_set_create(self, dist_set):
        return dist_set  # Implement in your OLT, if needed

    def on_mcast_dist_set_modify(self, dist_set, update, diffs):
        return update  # Implement in your OLT, if needed

    def on_mcast_dist_set_delete(self, dist_set):
        return None  # Implement in your OLT, if needed

    def rx_inter_adapter_message(self, msg):
        if self.enabled and self._event_messages is not None:
            self._event_messages.put(msg)

    @inlineCallbacks
    def _handle_onu_events(self):
        #
        # TODO: From broadcom ONU. This is from the 'receive_inter_adapter_message()'
        #       method.
        #
        event_msg = yield self._event_messages.get()

        if self._event_deferred is None:
            returnValue('cancelled')

        if event_msg['event'] == 'activation-completed':
            # if event_msg['event_data']['activation_successful']:
            #     for uni in self.uni_ports:
            #         port_no = self.proxy_address.channel_id + uni
            #         reactor.callLater(1,
            #                           self.message_exchange,
            #                           self.proxy_address.onu_id,
            #                           self.proxy_address.onu_session_id,
            #                           port_no)
            #
            #     device = self.adapter_agent.get_device(self.device_id)
            #     device.oper_status = OperStatus.ACTIVE
            #     self.adapter_agent.update_device(device)
            #
            # else:
            #     device = self.adapter_agent.get_device(self.device_id)
            #     device.oper_status = OperStatus.FAILED
            #     self.adapter_agent.update_device(device)
            pass

        elif event_msg['event'] == 'deactivation-completed':
            # device = self.adapter_agent.get_device(self.device_id)
            # device.oper_status = OperStatus.DISCOVERED
            # self.adapter_agent.update_device(device)
            pass

        elif event_msg['event'] == 'ranging-completed':
            # if event_msg['event_data']['ranging_successful']:
            #     device = self.adapter_agent.get_device(self.device_id)
            #     device.oper_status = OperStatus.ACTIVATING
            #     self.adapter_agent.update_device(device)
            #
            # else:
            #     device = self.adapter_agent.get_device(self.device_id)
            #     device.oper_status = OperStatus.FAILED
            #     self.adapter_agent.update_device(device)
            pass

        # Handle next event (self._event_deferred is None if we got stopped)

        self._event_deferred = reactor.callLater(0, self.handle_onu_events)

    def _subscribe_to_events(self):
        from voltha.extensions.omci.onu_device_entry import OnuDeviceEvents, \
            OnuDeviceEntry

        # OMCI MIB Database sync status
        bus = self.openomci.onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self.device_id,
                                               OnuDeviceEvents.MibDatabaseSyncEvent)
        self._in_sync_subscription = bus.subscribe(topic, self.in_sync_handler)

    def _unsubscribe_to_events(self):
        insync, self._in_sync_subscription = self._in_sync_subscription, None

        if insync is not None:
            bus = self.openomci.onu_omci_device.event_bus
            bus.unsubscribe(insync)

    def in_sync_handler(self, _topic, msg):
        # Create UNI Ports on first In-Sync event

        if self._in_sync_subscription is not None:
            try:
                from voltha.extensions.omci.onu_device_entry import IN_SYNC_KEY

                if msg[IN_SYNC_KEY]:
                    # Do not proceed if we have not got our vENET information yet.

                    if len(self.uni_ports) > 0 or not self.xpon_support:
                        # Drop subscription....
                        insync, self._in_sync_subscription = self._in_sync_subscription, None

                        if insync is not None:
                            bus = self.openomci.onu_omci_device.event_bus
                            bus.unsubscribe(insync)

                        # Set up UNI Ports. The UNI ports are currently created when the xPON
                        # vENET information is created. Once xPON is removed, we need to create
                        # them from the information provided from the MIB upload UNI-G and other
                        # UNI related MEs.
                        if not self.xpon_support:
                            self.add_uni_ports()
                        else:
                            for uni in self.uni_ports:
                                uni.add_logical_port(None, None)
                    else:
                        # SEBA - drop this one once xPON deprecated
                        self._deferred = reactor.callLater(5, self.in_sync_handler, _topic, msg)

            except Exception as e:
                self.log.exception('in-sync', e=e)
