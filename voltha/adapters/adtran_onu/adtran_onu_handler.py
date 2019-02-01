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
import ast
from pon_port import PonPort
from uni_port import UniPort
from heartbeat import HeartBeat
from omci.omci import OMCI
from onu_traffic_descriptor import OnuTrafficDescriptor
from onu_tcont import OnuTCont
from onu_gem_port import OnuGemPort

from voltha.extensions.alarms.adapter_alarms import AdapterAlarms
from voltha.extensions.kpi.onu.onu_pm_metrics import OnuPmMetrics
from voltha.extensions.kpi.onu.onu_omci_pm import OnuOmciPmMetrics

from twisted.internet import reactor
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet.defer import returnValue

from voltha.registry import registry
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.extensions.omci.omci_me import *
from common.tech_profile.tech_profile import TechProfile
from voltha.core.config.config_backend import ConsulStore
from voltha.core.config.config_backend import EtcdStore

import voltha.adapters.adtran_olt.resources.adtranolt_platform as platform
from voltha.adapters.adtran_onu.flow.flow_entry import FlowEntry
from omci.adtn_install_flow import AdtnInstallFlowTask
from omci.adtn_remove_flow import AdtnRemoveFlowTask
from omci.adtn_tp_service_specific_task import AdtnTpServiceSpecificTask
from common.tech_profile.tech_profile import DEFAULT_TECH_PROFILE_TABLE_ID

_ = third_party
_MAXIMUM_PORT = 17        # Only one PON and UNI port at this time
_ONU_REBOOT_MIN = 90      # IBONT 602 takes about 3 minutes
_ONU_REBOOT_RETRY = 10
_STARTUP_RETRY_WAIT = 20


class AdtranOnuHandler(object):
    def __init__(self, adapter, device_id):
        kwargs = dict()
        super(AdtranOnuHandler, self).__init__(**kwargs)
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.logical_device_id = None
        self.proxy_address = None
        self._enabled = False
        self.pm_metrics = None
        self.alarms = None

        self._openomci = OMCI(self, adapter.omci_agent)
        self._in_sync_subscription = None

        self._pon_port_number = 1

        self._unis = dict()         # Port # -> UniPort
        self._pon = PonPort.create(self, self._pon_port_number)
        self._heartbeat = HeartBeat.create(self, device_id)
        self._deferred = None

        # Flow entries
        self._flows = dict()

        # OMCI resources               # TODO: Some of these could be dynamically chosen
        self.vlan_tcis_1 = 0x900
        self.mac_bridge_service_profile_entity_id = self.vlan_tcis_1
        self.gal_enet_profile_entity_id = 0

        # Technology profile related values
        self.incoming_messages = DeferredQueue()
        self.event_messages = DeferredQueue()
        self._tp_service_specific_task = dict()
        self._tech_profile_download_done = dict()

        # Initialize KV store client
        self.args = registry('main').get_args()
        if self.args.backend == 'etcd':
            host, port = self.args.etcd.split(':', 1)
            self.kv_client = EtcdStore(host, port,
                                       TechProfile.KV_STORE_TECH_PROFILE_PATH_PREFIX)
        elif self.args.backend == 'consul':
            host, port = self.args.consul.split(':', 1)
            self.kv_client = ConsulStore(host, port,
                                         TechProfile.KV_STORE_TECH_PROFILE_PATH_PREFIX)
        else:
            self.log.error('Invalid-backend')
            raise Exception("Invalid-backend-for-kv-store")

        # Handle received ONU event messages
        reactor.callLater(0, self.handle_onu_events)

    def __str__(self):
        return "AdtranOnuHandler: {}".format(self.device_id)

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None
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

    def pon_port(self, port_no=None):
        return self._pon if port_no is None or port_no == self._pon.port_number else None

    @property
    def pon_ports(self):
        return [self._pon]

    def start(self):
        assert self._enabled, 'Start should only be called if enabled'
        self._cancel_deferred()

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
        self._heartbeat.enabled = False

        # OMCI Communications
        self._unsubscribe_to_events()

        # Port shutdown
        for port in self.uni_ports:
            port.enabled = False

        if self._pon is not None:
            self._pon.enabled = False
        self._openomci.enabled = False

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
            device.root = False
            device.vendor = 'Adtran Inc.'
            device.model = 'n/a'
            device.hardware_version = 'n/a'
            device.firmware_version = 'n/a'
            device.reason = ''
            device.connect_status = ConnectStatus.UNKNOWN

            # Register physical ports.  Should have at least one of each
            self.adapter_agent.add_port(device.id, self._pon.get_port())

            def xpon_not_found():
                self.enabled = True

            # Schedule xPON 'not found' startup for 10 seconds from now. We will
            # easily get a vONT-ANI create within that time if xPON is being used
            # as this is how we are initially launched and activated in the first
            # place if xPON is in use.
            reactor.callLater(10, xpon_not_found)   # TODO: Clean up old xPON delay

            # reference of uni_port is required when re-enabling the device if
            # it was disabled previously
            # Need to query ONU for number of supported uni ports
            # For now, temporarily set number of ports to 1 - port #2
            parent_device = self.adapter_agent.get_device(device.parent_id)

            self.logical_device_id = parent_device.parent_id
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
            self.openomci.onu_omci_device.alarm_synchronizer.set_alarm_params(mgr=self.alarms,
                                                                              ani_ports=[self._pon])
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

    @inlineCallbacks
    def handle_onu_events(self):
        # TODO: Add 'shutdown' message to exit loop
        event_msg = yield self.event_messages.get()
        try:
            if event_msg['event'] == 'download_tech_profile':
                tp_path = event_msg['event_data']
                uni_id = event_msg['uni_id']
                self.load_and_configure_tech_profile(uni_id, tp_path)

        except Exception as e:
            self.log.error("exception-handling-onu-event", e=e)

        # Handle next event
        reactor.callLater(0, self.handle_onu_events)

    def _tp_path_to_tp_id(self, tp_path):
        parts = tp_path.split('/')
        if len(parts) > 2:
            try:
                return int(parts[1])
            except ValueError:
                return DEFAULT_TECH_PROFILE_TABLE_ID

    def _create_tcont(self, uni_id, us_scheduler, tech_profile_id):
        """
        Decode Upstream Scheduler and create appropriate TCONT structures

        :param uni_id: (int) UNI ID on the PON
        :param us_scheduler: (Scheduler) Upstream Scheduler with TCONT information
        :param tech_profile_id: (int) Tech Profile ID

        :return (OnuTCont) Created TCONT
        """
        self.log.debug('create-tcont', us_scheduler=us_scheduler, profile_id=tech_profile_id)

        q_sched_policy = {
            'strictpriority': 1,        # Per TCONT (ME #262) values
            'wrr': 2
        }.get(us_scheduler.get('q_sched_policy', 'none').lower(), 0)

        tcont_data = {
            'tech-profile-id': tech_profile_id,
            'uni-id': uni_id,
            'alloc-id': us_scheduler['alloc_id'],
            'q-sched-policy': q_sched_policy
        }
        # TODO: Support TD if shaping on ONU is to be performed
        td = OnuTrafficDescriptor(0, 0, 0)
        tcont = OnuTCont.create(self, tcont_data, td)
        self._pon.add_tcont(tcont)
        return tcont

    # Called when there is an olt up indication, providing the gem port id chosen by the olt handler
    def _create_gemports(self, upstream_ports, downstream_ports, tcont, uni_id, tech_profile_id):
        """
        Create GEM Ports for a specifc tech profile

        The routine will attempt to combine upstream and downstream GEM Ports into bidirectional
        ports where possible

        :param upstream_ports: (list of IGemPortAttribute) Upstream GEM Port attributes
        :param downstream_ports: (list of IGemPortAttribute) Downstream GEM Port attributes
        :param tcont: (OnuTCont) Associated TCONT
        :param uni_id: (int) UNI Instance ID
        :param tech_profile_id: (int) Tech Profile ID
        """
        self.log.debug('create-gemports', upstream=upstream_ports,
                       downstream_ports=downstream_ports,
                       tcont=tcont, tech_id=tech_profile_id)
        # Convert GEM Port lists to dicts with GEM ID as they key
        upstream = {gem['gemport_id']: gem for gem in upstream_ports}
        downstream = {gem['gemport_id']: gem for gem in downstream_ports}

        upstream_ids = set(upstream.keys())
        downstream_ids = set(downstream.keys())
        bidirectional_ids = upstream_ids & downstream_ids

        gem_port_types = {     # Keys are the 'direction' attribute value, value is list of GEM attributes
            OnuGemPort.UPSTREAM: [upstream[gid] for gid in upstream_ids - bidirectional_ids],
            OnuGemPort.DOWNSTREAM: [downstream[gid] for gid in downstream_ids - bidirectional_ids],
            OnuGemPort.BIDIRECTIONAL: [upstream[gid] for gid in bidirectional_ids]
        }
        for direction, gem_list in gem_port_types.items():
            for gem in gem_list:
                gem_data = {
                    'gemport-id': gem['gemport_id'],
                    'direction': direction,
                    'encryption': gem['aes_encryption'].lower() == 'true',
                    'discard-policy': gem['discard_policy'],
                    'max-q-size': gem['max_q_size'],
                    'pbit-map': gem['pbit_map'],
                    'priority-q': gem['priority_q'],
                    'scheduling-policy': gem['scheduling_policy'],
                    'weight': gem['weight'],
                    'uni-id': uni_id,
                    'discard-config': {
                        'max-probability': gem['discard_config']['max_probability'],
                        'max-threshold': gem['discard_config']['max_threshold'],
                        'min-threshold': gem['discard_config']['min_threshold'],
                    },
                }
                gem_port = OnuGemPort.create(self, gem_data, tcont.alloc_id,
                                             tech_profile_id, uni_id,
                                             self._pon.next_gem_entity_id)
                self._pon.add_gem_port(gem_port)

    def _do_tech_profile_configuration(self, uni_id, tp, tech_profile_id):
        us_scheduler = tp['us_scheduler']
        tcont = self._create_tcont(uni_id, us_scheduler, tech_profile_id)

        upstream = tp['upstream_gem_port_attribute_list']
        downstream = tp['downstream_gem_port_attribute_list']
        self._create_gemports(upstream, downstream, tcont, uni_id, tech_profile_id)

    def load_and_configure_tech_profile(self, uni_id, tp_path):
        self.log.debug("loading-tech-profile-configuration", uni_id=uni_id, tp_path=tp_path)

        if uni_id not in self._tp_service_specific_task:
            self._tp_service_specific_task[uni_id] = dict()

        if uni_id not in self._tech_profile_download_done:
            self._tech_profile_download_done[uni_id] = dict()

        if tp_path not in self._tech_profile_download_done[uni_id]:
            self._tech_profile_download_done[uni_id][tp_path] = False

        if not self._tech_profile_download_done[uni_id][tp_path]:
            try:
                if tp_path in self._tp_service_specific_task[uni_id]:
                    self.log.info("tech-profile-config-already-in-progress",
                                  tp_path=tp_path)
                    return

                tp = self.kv_client[tp_path]
                tp = ast.literal_eval(tp)
                self.log.debug("tp-instance", tp=tp)

                tech_profile_id = self._tp_path_to_tp_id(tp_path)
                self._do_tech_profile_configuration(uni_id, tp, tech_profile_id)

                def success(_results):
                    self.log.info("tech-profile-config-done-successfully")
                    device = self.adapter_agent.get_device(self.device_id)
                    device.reason = ''
                    self.adapter_agent.update_device(device)

                    if tp_path in self._tp_service_specific_task[uni_id]:
                        del self._tp_service_specific_task[uni_id][tp_path]

                    self._tech_profile_download_done[uni_id][tp_path] = True

                def failure(_reason):
                    self.log.warn('tech-profile-config-failure-retrying', reason=_reason)
                    device = self.adapter_agent.get_device(self.device_id)
                    device.reason = 'Tech Profile config failed-retrying'
                    self.adapter_agent.update_device(device)

                    if tp_path in self._tp_service_specific_task[uni_id]:
                        del self._tp_service_specific_task[uni_id][tp_path]

                    self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                       self.load_and_configure_tech_profile,
                                                       uni_id, tp_path)

                self.log.info('downloading-tech-profile-configuration')
                tp_task = AdtnTpServiceSpecificTask(self.openomci.omci_agent, self, uni_id)

                self._tp_service_specific_task[uni_id][tp_path] = tp_task
                self._deferred = self.openomci.onu_omci_device.task_runner.queue_task(tp_task)
                self._deferred.addCallbacks(success, failure)

            except Exception as e:
                self.log.exception("error-loading-tech-profile", e=e)
        else:
            self.log.info("tech-profile-config-already-done")

    def update_pm_config(self, _device, pm_config):
        # TODO: This has not been tested
        self.log.info('update_pm_config', pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    @inlineCallbacks
    def update_flow_table(self, flows):
        if len(flows) == 0:
            returnValue('nop')  # TODO:  Do we need to delete all flows if empty?

        self.log.debug('bulk-flow-update', flows=flows)
        valid_flows = set()

        for flow in flows:
            # Decode it
            flow_entry = FlowEntry.create(flow, self)

            # Already handled?
            if flow_entry.flow_id in self._flows:
                valid_flows.add(flow_entry.flow_id)

            if flow_entry is None or flow_entry.flow_direction not in \
                    FlowEntry.upstream_flow_types | FlowEntry.downstream_flow_types:
                continue

            is_upstream = flow_entry.flow_direction in FlowEntry.upstream_flow_types

            # Ignore untagged upstream etherType flows. These are trapped at the
            # OLT and the default flows during initial OMCI service download will
            # send them to the Default VLAN (4091) port for us
            if is_upstream and flow_entry.vlan_vid is None and flow_entry.etype is not None:
                continue

            # Also ignore upstream untagged/priority tag that sets priority tag
            # since that is already installed and any user-data flows for upstream
            # priority tag data will be at a higher level.  Also should ignore the
            # corresponding priority-tagged to priority-tagged flow as well.
            if (flow_entry.vlan_vid == 0 and flow_entry.set_vlan_vid == 0) or \
                    (flow_entry.vlan_vid is None and flow_entry.set_vlan_vid == 0
                     and not is_upstream):
                continue

            # Add it to hardware
            try:
                def failed(_reason, fid):
                    del self._flows[fid]

                task = AdtnInstallFlowTask(self.openomci.omci_agent, self, flow_entry)
                d = self.openomci.onu_omci_device.task_runner.queue_task(task)
                d.addErrback(failed, flow_entry.flow_id)

                valid_flows.add(flow_entry.flow_id)
                self._flows[flow_entry.flow_id] = flow_entry

            except Exception as e:
                self.log.exception('flow-add', e=e, flow=flow_entry)

        # Now check for flows that were missing in the bulk update
        deleted_flows = set(self._flows.keys()) - valid_flows

        for flow_id in deleted_flows:
            try:
                del_flow = self._flows[flow_id]

                task = AdtnRemoveFlowTask(self.openomci.omci_agent, self, del_flow)
                self.openomci.onu_omci_device.task_runner.queue_task(task)
                # TODO: Change to success/failure callback checks later
                # d.addCallback(success, flow_entry.flow_id)
                del self._flows[flow_id]

            except Exception as e:
                self.log.exception('flow-remove', e=e, flow=self._flows[flow_id])

    @inlineCallbacks
    def reboot(self):
        self.log.info('rebooting', device_id=self.device_id)
        self._cancel_deferred()

        reregister = False
        try:
            # Drop registration for adapter messages
            reregister = True
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
        try:
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
                    logical_device_id = parent_device.parent_id
                    assert logical_device_id
                    port = self.adapter_agent.get_logical_port(logical_device_id,port_id)
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

        except Exception as _e:
            pass    # This is expected if OLT has deleted the ONU device handler

        # And disable OMCI as well
        self.enabled = False
        self.log.info('disabled')

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
            multi_uni = len(self.uni_ports) > 1
            for uni in self.uni_ports:
                self.adapter_agent.add_port(device.id, uni.get_port())
                uni.add_logical_port(uni.logical_port_number, multi_uni)

            device = self.adapter_agent.get_device(device.id)
            device.oper_status = OperStatus.ACTIVE
            device.connect_status = ConnectStatus.REACHABLE
            device.reason = ''

            self.enabled = True
            self.adapter_agent.update_device(device)

            self.log.info('re-enabled')

        except Exception, e:
            self.log.exception('error-re-enabling', e=e)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        try:
            for uni in self._unis.values():
                uni.stop()
                uni.delete()

            self._pon.stop()
            self._pon.delete()

        except Exception as _e:
            pass    # Expected if the OLT deleted us from the device handler

        # OpenOMCI cleanup
        omci, self._openomci = self._openomci, None
        omci.delete()

    def add_uni_ports(self):
        """ Called after in-sync achieved and not in xPON mode"""
        # TODO: We have to methods adding UNI ports.  Go to one
        # TODO: Should this be moved to the omci.py module for this ONU?

        # This is only for working WITHOUT xPON
        pptp_entities = self.openomci.onu_omci_device.configuration.pptp_entities
        device = self.adapter_agent.get_device(self.device_id)

        multi_uni = len(pptp_entities) > 1
        uni_id = 0

        for entity_id, pptp in pptp_entities.items():
            intf_id = self.proxy_address.channel_id
            onu_id = self.proxy_address.onu_id
            uni_no = platform.mk_uni_port_num(intf_id, onu_id, uni_id=uni_id)
            uni_name = "uni-{}".format(uni_no)
            mac_bridge_port_num = uni_id + 1

            uni_port = UniPort.create(self, uni_name, uni_no, uni_name)
            uni_port.entity_id = entity_id
            uni_port.enabled = True
            uni_port.mac_bridge_port_num = mac_bridge_port_num
            uni_port.add_logical_port(uni_port.port_number, multi_uni)
            self.log.debug("created-uni-port", uni=uni_port)

            self.adapter_agent.add_port(device.id, uni_port.get_port())
            parent_device = self.adapter_agent.get_device(device.parent_id)

            parent_adapter_agent = registry('adapter_loader').get_agent(parent_device.adapter)
            if parent_adapter_agent is None:
                self.log.error('olt-adapter-agent-could-not-be-retrieved')

            parent_adapter_agent.add_port(device.parent_id, uni_port.get_port())

            self._unis[uni_port.port_number] = uni_port
            self.openomci.onu_omci_device.alarm_synchronizer.set_alarm_params(onu_id=self.proxy_address.onu_id,
                                                                              uni_ports=self._unis.values())
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
            uni_port.enabled = True
            uni_id += 1

    def rx_inter_adapter_message(self, msg):
        raise NotImplemented('Not currently supported')

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

                    if len(self.uni_ports) == 0:
                        # Drop subscription....
                        insync, self._in_sync_subscription = self._in_sync_subscription, None

                        if insync is not None:
                            bus = self.openomci.onu_omci_device.event_bus
                            bus.unsubscribe(insync)

                        # Set up UNI Ports. The UNI ports are currently created when the xPON
                        # vENET information is created. Once xPON is removed, we need to create
                        # them from the information provided from the MIB upload UNI-G and other
                        # UNI related MEs.
                        self.add_uni_ports()

            except Exception as e:
                self.log.exception('in-sync', e=e)
