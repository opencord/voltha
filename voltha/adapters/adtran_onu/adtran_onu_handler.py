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

import arrow
import structlog

from voltha.adapters.adtran_olt.xpon.adtran_xpon import AdtranXPON
from pon_port import PonPort
from uni_port import UniPort
from heartbeat import HeartBeat

from voltha.adapters.adtran_olt.alarms.adapter_alarms import AdapterAlarms
from onu_pm_metrics import OnuPmMetrics

from uuid import uuid4
from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet.defer import returnValue

from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from common.utils.indexpool import IndexPool
from voltha.extensions.omci.omci_me import *

_ = third_party
_MAXIMUM_PORT = 128          # PON and UNI ports
_ONU_REBOOT_MIN = 60
_ONU_REBOOT_RETRY = 10


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

        self._unis = dict()         # Port # -> UniPort
        self._pon = None
        self._heartbeat = HeartBeat.create(self, device_id)

        self._deferred = None
        self._event_deferred = None

        self._port_number_pool = IndexPool(_MAXIMUM_PORT, 1)

        self._olt_created = False   # True if deprecated method of OLT creating DA is used
        self._is_mock = False

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
    def is_mock(self):
        return self._is_mock        # Not pointing to real hardware

    @property
    def olt_created(self):
        return self._olt_created    # ONU was created with deprecated 'child_device_detected' call

    @property
    def omci_agent(self):
        return self.adapter.omci_agent

    @property
    def omci(self):
        # TODO: Decrement access to Communications channel at this point?  What about current PM stuff?
        _onu_omci_device = self._pon.onu_omci_device
        return _onu_omci_device.omci_cc if _onu_omci_device is not None else None

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

        # Port startup
        if self._pon is not None:
            self._pon.enabled = True

        for port in self.uni_ports:
            port.enabled = True

        # Heartbeat
        self._heartbeat.enabled = True

    def stop(self):
        assert not self._enabled, 'Stop should only be called if disabled'
        #
        # TODO: Perform common shutdown tasks here
        #
        self._cancel_deferred()

        # Drop registration for adapter messages
        self.adapter_agent.unregister_for_inter_adapter_messages()

        # Heartbeat
        self._heartbeat.stop()

        # OMCI Communications
        # if self._onu_omci_device is not None:
        #     self._onu_omci_device.stop()

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
        if self.omci is not None and self.enabled:
            self.omci.receive_message(msg)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id, 'Invalid Parent ID'
        assert device.proxy_address.device_id, 'Invalid Device ID'

        if device.vlan:
            # vlan non-zero if created via legacy method (not xPON). Also
            # Set a random serial number since not xPON based
            self._olt_created = True

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

        ############################################################################
        # Setup PM configuration for this device

        self.pm_metrics = OnuPmMetrics(self, device, grouped=True, freq_override=False)
        pm_config = self.pm_metrics.make_proto()
        self.log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config, init=True)

        ############################################################################
        # Setup Alarm handler

        self.alarms = AdapterAlarms(self.adapter, device.id)

        # reference of uni_port is required when re-enabling the device if
        # it was disabled previously
        # Need to query ONU for number of supported uni ports
        # For now, temporarily set number of ports to 1 - port #2

        parent_device = self.adapter_agent.get_device(device.parent_id)
        self.logical_device_id = parent_device.parent_id
        assert self.logical_device_id, 'Invalid logical device ID'

        # Register physical ports.  Should have at least one of each

        self._pon = PonPort.create(self, self._next_port_number)
        self.adapter_agent.add_port(device.id, self._pon.get_port())

        if self._olt_created:
            # vlan non-zero if created via legacy method (not xPON). Also
            # Set a random serial number since not xPON based

            uni_port = UniPort.create(self, self._next_port_number, device.vlan,
                                      'deprecated', device.vlan, None)
            self._unis[uni_port.port_number] = uni_port
            self.adapter_agent.add_port(device.id, uni_port.get_port())

            device.serial_number = uuid4().hex
            uni_port.add_logical_port(device.vlan, subscriber_vlan=device.vlan)

            # Start things up for this ONU Handler.
            self.enabled = True

        # Start collecting stats from the device after a brief pause
        reactor.callLater(30, self.start_kpi_collection, device.id)

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

    def start_kpi_collection(self, device_id):
        # TODO: This has not been tested
        def _collect(device_id, prefix):
            from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs

            if self.enabled:
                try:
                    # Step 1: gather metrics from device
                    port_metrics = self.pm_metrics.collect_port_metrics()

                    # Step 2: prepare the KpiEvent for submission
                    # we can time-stamp them here or could use time derived from OLT
                    ts = arrow.utcnow().timestamp
                    kpi_event = KpiEvent(
                        type=KpiEventType.slice,
                        ts=ts,
                        prefixes={
                            prefix + '.{}'.format(k): MetricValuePairs(metrics=port_metrics[k])
                            for k in port_metrics.keys()}
                    )
                    # Step 3: submit
                    self.adapter_agent.submit_kpis(kpi_event)

                except Exception as e:
                    self.log.exception('failed-to-submit-kpis', e=e)

        self.pm_metrics.start_collector(_collect)

    @inlineCallbacks
    def update_flow_table(self, device, flows):
        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        # self.log.info('bulk-flow-update', device_id=device.id, flows=flows)

        import voltha.core.flow_decomposer as fd
        from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC

        def is_downstream(port):
            return port == 100  # Need a better way

        def is_upstream(port):
            return not is_downstream(port)

        omci = self.omci

        for flow in flows:
            _type = None
            _port = None
            _vlan_vid = None
            _udp_dst = None
            _udp_src = None
            _ipv4_dst = None
            _ipv4_src = None
            _metadata = None
            _output = None
            _push_tpid = None
            _field = None
            _set_vlan_vid = None
            self.log.info('bulk-flow-update', device_id=device.id, flow=flow)
            try:
                _in_port = fd.get_in_port(flow)
                assert _in_port is not None

                if is_downstream(_in_port):
                    self.log.info('downstream-flow')
                elif is_upstream(_in_port):
                    self.log.info('upstream-flow')
                else:
                    raise Exception('port should be 1 or 2 by our convention')

                _out_port = fd.get_out_port(flow)  # may be None
                self.log.info('out-port', out_port=_out_port)

                for field in fd.get_ofb_fields(flow):
                    if field.type == fd.ETH_TYPE:
                        _type = field.eth_type
                        self.log.info('field-type-eth-type',
                                      eth_type=_type)

                    elif field.type == fd.IP_PROTO:
                        _proto = field.ip_proto
                        self.log.info('field-type-ip-proto',
                                      ip_proto=_proto)

                    elif field.type == fd.IN_PORT:
                        _port = field.port
                        self.log.info('field-type-in-port',
                                      in_port=_port)

                    elif field.type == fd.VLAN_VID:
                        _vlan_vid = field.vlan_vid & 0xfff
                        self.log.info('field-type-vlan-vid',
                                      vlan=_vlan_vid)

                    elif field.type == fd.VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        self.log.info('field-type-vlan-pcp',
                                      pcp=_vlan_pcp)

                    elif field.type == fd.UDP_DST:
                        _udp_dst = field.udp_dst
                        self.log.info('field-type-udp-dst',
                                      udp_dst=_udp_dst)

                    elif field.type == fd.UDP_SRC:
                        _udp_src = field.udp_src
                        self.log.info('field-type-udp-src',
                                      udp_src=_udp_src)

                    elif field.type == fd.IPV4_DST:
                        _ipv4_dst = field.ipv4_dst
                        self.log.info('field-type-ipv4-dst',
                                      ipv4_dst=_ipv4_dst)

                    elif field.type == fd.IPV4_SRC:
                        _ipv4_src = field.ipv4_src
                        self.log.info('field-type-ipv4-src',
                                      ipv4_dst=_ipv4_src)

                    elif field.type == fd.METADATA:
                        _metadata = field.table_metadata
                        self.log.info('field-type-metadata',
                                      metadata=_metadata)

                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in fd.get_actions(flow):

                    if action.type == fd.OUTPUT:
                        _output = action.output.port
                        self.log.info('action-type-output',
                                      output=_output, in_port=_in_port)

                    elif action.type == fd.POP_VLAN:
                        self.log.info('action-type-pop-vlan',
                                      in_port=_in_port)

                    elif action.type == fd.PUSH_VLAN:
                        _push_tpid = action.push.ethertype
                        self.log.info('action-type-push-vlan',
                                 push_tpid=_push_tpid, in_port=_in_port)
                        if action.push.ethertype != 0x8100:
                            self.log.error('unhandled-tpid',
                                           ethertype=action.push.ethertype)

                    elif action.type == fd.SET_FIELD:
                        _field = action.set_field.field.ofb_field
                        assert (action.set_field.field.oxm_class ==
                                OFPXMC_OPENFLOW_BASIC)
                        self.log.info('action-type-set-field',
                                      field=_field, in_port=_in_port)
                        if _field.type == fd.VLAN_VID:
                            _set_vlan_vid = _field.vlan_vid & 0xfff
                            self.log.info('set-field-type-valn-vid', _set_vlan_vid)
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type)
                    else:
                        self.log.error('unsupported-action-type',
                                       action_type=action.type, in_port=_in_port)
                #
                # All flows created from ONU adapter should be OMCI based
                #
                if _vlan_vid == 0 and _set_vlan_vid != None and _set_vlan_vid != 0:
                    # allow priority tagged packets
                    # Set AR - ExtendedVlanTaggingOperationConfigData
                    #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid

                    results = yield omci.send_delete_vlan_tagging_filter_data(0x2102)

                    # self.send_set_vlan_tagging_filter_data(0x2102, _set_vlan_vid)
                    results = yield omci.send_create_vlan_tagging_filter_data(
                                        0x2102,
                                        _set_vlan_vid)

                    results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(
                                        0x202,
                                        0x1000,
                                        _set_vlan_vid)

                    results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(
                                        0x202,
                                        8,
                                        0,
                                        0,
                                        1,
                                        8,
                                        _set_vlan_vid)

                    # Set AR - ExtendedVlanTaggingOperationConfigData
                    #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
                    '''
                    results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(0x205, 8, 0, 0,
                                                   
                    '''

            except Exception as e:
                self.log.exception('failed-to-install-flow', e=e, flow=flow)

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

        if not self.is_mock:
            from twisted.internet.defer import TimeoutError

            try:
                ######################################################
                # MIB Reset - For ADTRAN ONU, we do not get a response
                #             back (because we are rebooting)
                pass
                yield self.omci.send_reboot(timeout=0.1)

            except TimeoutError:
                # This is expected
                returnValue('reboot-in-progress')

            except Exception as e:
                self.log.exception('send-reboot', e=e)
                raise

        # Reboot in progress. A reboot may take up to 3 min 30 seconds
        # Go ahead and pause less than that and start to look
        # for it being alive

        device.reason = 'reboot in progress'
        self.adapter_agent.update_device(device)

        # Disable OpenOMCI
        self.pon_port.enabled = False

        self._deferred = reactor.callLater(_ONU_REBOOT_MIN,
                                           self._finish_reboot,
                                           previous_oper_status,
                                           previous_conn_status,
                                           reregister)

    @inlineCallbacks
    def _finish_reboot(self, previous_oper_status, previous_conn_status,
                       reregister):
        from common.utils.asleep import asleep

        if not self.is_mock:
            # TODO: Do a simple poll and call this again if we timeout
            # _ONU_REBOOT_RETRY
            yield asleep(180)       # 3 minutes ...

        # Change the operational status back to its previous state.  With a
        # real OLT the operational state should be the state the device is
        # after a reboot.
        # Get the latest device reference

        # Restart OpenOMCI
        self.pon_port.enabled = True

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
            #port_id = 'uni-{}'.format(uni.port_number)
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

        # Send Uni Admin State Down

        # ethernet_uni_entity_id = 0x101
        # omci = self._handler.omci
        # attributes = dict(
        #     administrative_state=1  # - lock
        # )
        # frame = PptpEthernetUniFrame(
        #     ethernet_uni_entity_id,  # Entity ID
        #     attributes=attributes  # See above
        # ).set()
        # results = yield omci.send(frame)
        #
        # status = results.fields['omci_message'].fields['success_code']
        # failed_attributes_mask = results.fields['omci_message'].fields['failed_attributes_mask']
        # unsupported_attributes_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']
        # self.log.debug('set-pptp-ethernet-uni', status=status,
        #                failed_attributes_mask=failed_attributes_mask,
        #                unsupported_attributes_mask=unsupported_attributes_mask)


        # Just updating the port status may be an option as well
        # port.ofp_port.config = OFPPC_NO_RECV
        # yield self.adapter_agent.update_logical_port(logical_device_id,
        #                                             port)
        # Unregister for proxied message
        self.adapter_agent.unregister_for_proxied_messages(
            device.proxy_address)

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

            # Refresh the port reference
            # self.uni_port = self._get_uni_port()   deprecated

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

            if self.olt_created:
                # vlan non-zero if created via legacy method (not xPON)
                self.uni_port('deprecated').add_logical_port(device.vlan, device.vlan,
                                                             subscriber_vlan=device.vlan)
            else:
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
            self._pon._dev_info_loaded = False
            self._bridge_initialized = False
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
        if self.omci_agent is not None:
            self.omci_agent.remove_device(self.device_id, cleanup=True)

    def _check_for_mock_config(self, data):
        # Check for MOCK configuration
        description = data.get('description')
        if description is not None and 'mock' in description.lower():
            self._is_mock = True

    def on_ont_ani_create(self, ont_ani):
        """
        A new ONT-ani is being created. You can override this method to
        perform custom operations as needed. If you override this method, you can add
        additional items to the item dictionary to track additional implementation
        key/value pairs.

        :param ont_ani: (dict) new ONT-ani
        :return: (dict) Updated ONT-ani dictionary, None if item should be deleted
        """
        self.log.info('ont-ani-create', ont_ani=ont_ani)

        self._check_for_mock_config(ont_ani)
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
        # TODO: Is this ever called or is the iAdapter 'delete' called first?
        return None   # Implement in your OLT, if needed

    def on_vont_ani_create(self, vont_ani):
        self.log.info('vont-ani-create', vont_ani=vont_ani)

        self._check_for_mock_config(vont_ani)
        # TODO: look up PON port and update 'upstream-channel-speed'
        return vont_ani   # Implement in your OLT, if needed

    def on_vont_ani_modify(self, vont_ani, update, diffs):
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
        return self.delete()

    def on_venet_create(self, venet):
        self.log.info('venet-create', venet=venet)

        self._check_for_mock_config(venet)

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

        if self._olt_created:
            uni_port = self.uni_port('deprecated')

        else:
            # vlan non-zero if created via legacy method (not xPON). Also
            # Set a random serial number since not xPON based

            device = self.adapter_agent.get_device(self.device_id)
            ofp_port_no, subscriber_vlan, untagged_vlan = UniPort.decode_venet(venet)

            uni_port = UniPort.create(self, venet['name'],
                                      self._next_port_number,
                                      ofp_port_no,
                                      subscriber_vlan,
                                      untagged_vlan)

            self._unis[uni_port.port_number] = uni_port
            self.adapter_agent.add_port(device.id, uni_port.get_port())

            # If the PON has already synchronized, add the logical port now
            # since we know we have been activated

            if self._pon is not None and self._pon.connected:
                uni_port.add_logical_port(ofp_port_no, subscriber_vlan=subscriber_vlan)

        # TODO: Next is just for debugging to see what this call returns after
        #       we add a UNI
        # existing_uni_ports = self.adapter_agent.get_ports(onu_device.parent_id, Port.ETHERNET_UNI)

        uni_port.enabled = venet['enabled']

        return venet

    def on_venet_modify(self, venet, update, diffs):
        # Look up the associated UNI port

        if self._olt_created:
            uni_port = self.uni_port('deprecated')
        else:
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
        # Look up the associated UNI port

        if self._olt_created:
            uni_port = self.uni_port('deprecated')
        else:
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
        tcont['object'] = OnuTCont.create(self, tcont, traffic_descriptor,
                                          is_mock=self.is_mock)

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
                                               self._pon.next_gem_entity_id,
                                               is_mock=self.is_mock)
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
