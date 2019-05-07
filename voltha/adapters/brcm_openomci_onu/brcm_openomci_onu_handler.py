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

"""
Broadcom OpenOMCI OLT/ONU adapter handler.
"""

import json
import ast
import structlog

from collections import OrderedDict

from twisted.internet import reactor, task
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue, TimeoutError

from heartbeat import HeartBeat
from voltha.extensions.alarms.onu.onu_active_alarm import OnuActiveAlarm
from voltha.extensions.kpi.onu.onu_pm_metrics import OnuPmMetrics
from voltha.extensions.kpi.onu.onu_omci_pm import OnuOmciPmMetrics
from voltha.extensions.alarms.adapter_alarms import AdapterAlarms

from common.utils.indexpool import IndexPool
import voltha.core.flow_decomposer as fd
from voltha.registry import registry
from voltha.core.config.config_backend import ConsulStore
from voltha.core.config.config_backend import EtcdStore
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, ConnectStatus, AdminState
from voltha.protos.openflow_13_pb2 import OFPXMC_OPENFLOW_BASIC, ofp_port
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.extensions.omci.onu_configuration import OMCCVersion
from voltha.extensions.omci.onu_device_entry import OnuDeviceEvents, \
    OnuDeviceEntry, IN_SYNC_KEY
from voltha.adapters.brcm_openomci_onu.omci.brcm_mib_download_task import BrcmMibDownloadTask
from voltha.adapters.brcm_openomci_onu.omci.brcm_tp_service_specific_task import BrcmTpServiceSpecificTask
from voltha.adapters.brcm_openomci_onu.omci.brcm_uni_lock_task import BrcmUniLockTask
from voltha.adapters.brcm_openomci_onu.omci.brcm_vlan_filter_task import BrcmVlanFilterTask
from voltha.adapters.brcm_openomci_onu.onu_gem_port import *
from voltha.adapters.brcm_openomci_onu.onu_tcont import *
from voltha.adapters.brcm_openomci_onu.pon_port import *
from voltha.adapters.brcm_openomci_onu.uni_port import *
from voltha.adapters.brcm_openomci_onu.onu_traffic_descriptor import *
from common.tech_profile.tech_profile import TechProfile
from voltha.extensions.omci.tasks.omci_test_request import OmciTestRequest
from voltha.extensions.omci.omci_entities import AniG

OP = EntityOperations
RC = ReasonCodes

_ = third_party
log = structlog.get_logger()

_STARTUP_RETRY_WAIT = 20


class BrcmOpenomciOnuHandler(object):

    def __init__(self, adapter, device_id):
        self.log = structlog.get_logger(device_id=device_id)
        self.log.debug('function-entry')
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.parent_adapter = None
        self.parent_id = None
        self.device_id = device_id
        self.incoming_messages = DeferredQueue()
        self.event_messages = DeferredQueue()
        self.proxy_address = None
        self.tx_id = 0
        self._enabled = False
        self.alarms = None
        self.pm_metrics = None
        self._omcc_version = OMCCVersion.Unknown
        self._total_tcont_count = 0  # From ANI-G ME
        self._qos_flexibility = 0  # From ONT2_G ME

        self._onu_indication = None
        self._unis = dict()  # Port # -> UniPort

        self._pon = None
        # TODO: probably shouldnt be hardcoded, determine from olt maybe?
        self._pon_port_number = 100
        self.logical_device_id = None

        self._heartbeat = HeartBeat.create(self, device_id)

        # Set up OpenOMCI environment
        self._onu_omci_device = None
        self._dev_info_loaded = False
        self._deferred = None

        self._in_sync_subscription = None
        self._connectivity_subscription = None
        self._capabilities_subscription = None

        self.mac_bridge_service_profile_entity_id = 0x201
        self.gal_enet_profile_entity_id = 0x1

        # Stores the list of all the uni_ids for which mid download is completed.
        self._mib_download_done = list()

        # Dictionary with key being uni_id and value being the tp_path for that uni
        self._tech_profile_download_done = dict()

        # Stores information related to 'in progress' tp tasks
        # Dictionary with key being uni_id and value being the tp_path for that uni
        self._in_progress_tp_task = dict()

        # Stores information related to queued tp tasks
        # Dictionary with key being uni_id and value being the tp_path for that uni
        self._queued_tp_task = dict()

        # Stores information related to queued vlan filter tasks
        # Dictionary with key being uni_id and value being flow_cookie, add_tag flag,
        # uni_port and vlan_id
        self._queued_vlan_filter_task = dict()


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

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._enabled != value:
            self._enabled = value

    @property
    def omci_agent(self):
        return self.adapter.omci_agent

    @property
    def omci_cc(self):
        return self._onu_omci_device.omci_cc if self._onu_omci_device is not None else None

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
        return next((uni for uni in self.uni_ports
                    if uni.logical_port_number == port_no_or_name), None)

    @property
    def pon_port(self):
        return self._pon

    def receive_message(self, msg):
        if self.omci_cc is not None:
            self.omci_cc.receive_message(msg)

    # Called once when the adapter creates the device/onu instance
    def activate(self, device):
        self.log.debug('function-entry', device=device)

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)
        self.parent_id = device.parent_id
        parent_device = self.adapter_agent.get_device(self.parent_id)
        if parent_device.type == 'openolt':
            self.parent_adapter = registry('adapter_loader'). \
                get_agent(parent_device.adapter).adapter

        if self.enabled is not True:
            self.log.info('activating-new-onu')
            # populate what we know.  rest comes later after mib sync
            device.root = False
            device.vendor = 'Broadcom'
            device.connect_status = ConnectStatus.REACHABLE
            device.oper_status = OperStatus.DISCOVERED
            device.reason = 'activating-onu'

            # pm_metrics requires a logical device id
            parent_device = self.adapter_agent.get_device(device.parent_id)
            self.logical_device_id = parent_device.parent_id
            assert self.logical_device_id, 'Invalid logical device ID'

            self.adapter_agent.update_device(device)

            self.log.debug('set-device-discovered')

            self._init_pon_state(device)

            ############################################################################
            # Setup PM configuration for this device
            # Pass in ONU specific options
            kwargs = {
                OnuPmMetrics.DEFAULT_FREQUENCY_KEY: OnuPmMetrics.DEFAULT_ONU_COLLECTION_FREQUENCY,
                'heartbeat': self.heartbeat,
                OnuOmciPmMetrics.OMCI_DEV_KEY: self._onu_omci_device
            }
            self.pm_metrics = OnuPmMetrics(self.adapter_agent, self.device_id,
                                           self.logical_device_id, grouped=True,
                                           freq_override=False, **kwargs)
            pm_config = self.pm_metrics.make_proto()
            self._onu_omci_device.set_pm_config(self.pm_metrics.omci_pm.openomci_interval_pm)
            self.log.info("initial-pm-config", pm_config=pm_config)
            self.adapter_agent.update_device_pm_config(pm_config, init=True)

            ############################################################################
            # Setup Alarm handler
            self.alarms = AdapterAlarms(self.adapter_agent, device.id, self.logical_device_id)
            # Note, ONU ID and UNI intf set in add_uni_port method
            self._onu_omci_device.alarm_synchronizer.set_alarm_params(mgr=self.alarms,
                                                                      ani_ports=[self._pon])

            # Start collecting stats from the device after a brief pause
            reactor.callLater(10, self.pm_metrics.start_collector)


            # Code to Run OMCI Test Action

            kwargs_omci_test_action = {
                OmciTestRequest.DEFAULT_FREQUENCY_KEY:
                                OmciTestRequest.DEFAULT_COLLECTION_FREQUENCY
                            }
            device = self.adapter_agent.get_device(self.device_id)
            serial_number = device.serial_number
            test_request = OmciTestRequest(
                self.omci_agent, self.device_id, AniG, serial_number,
                self.logical_device_id, exclusive=False,
                **kwargs_omci_test_action)
            reactor.callLater(10, test_request.start_collector)
            self.enabled = True
        else:
            self.log.info('onu-already-activated')

    # Called once when the adapter needs to re-create device.  usually on vcore restart
    def reconcile(self, device):
        self.log.debug('function-entry', device=device)

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        if self.enabled is not True:
            self.log.info('reconciling-broadcom-onu-device')

            self._init_pon_state(device)

            # need to restart state machines on vcore restart.  there is no indication to do it for us.
            self._onu_omci_device.start()
            device.reason = "restarting-openomci"
            self.adapter_agent.update_device(device)

            # TODO: this is probably a bit heavy handed
            # Force a reboot for now.  We need indications to reflow to reassign tconts and gems given vcore went away
            # This may not be necessary when mib resync actually works
            reactor.callLater(1, self.reboot)

            self.enabled = True
        else:
            self.log.info('onu-already-activated')

    @inlineCallbacks
    def handle_onu_events(self):
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

    def _init_pon_state(self, device):
        self.log.debug('function-entry', device=device)

        self._pon = PonPort.create(self, self._pon_port_number)
        self.adapter_agent.add_port(device.id, self._pon.get_port())

        self.log.debug('added-pon-port-to-agent', pon=self._pon)

        parent_device = self.adapter_agent.get_device(device.parent_id)
        self.logical_device_id = parent_device.parent_id

        self.adapter_agent.update_device(device)

        # Create and start the OpenOMCI ONU Device Entry for this ONU
        self._onu_omci_device = self.omci_agent.add_device(self.device_id,
                                                           self.adapter_agent,
                                                           support_classes=self.adapter.broadcom_omci,
                                                           custom_me_map=self.adapter.custom_me_entities())
        # Port startup
        if self._pon is not None:
            self._pon.enabled = True

    # TODO: move to UniPort
    def update_logical_port(self, logical_device_id, port_id, state):
        try:
            self.log.info('updating-logical-port', logical_port_id=port_id,
                          logical_device_id=logical_device_id, state=state)
            logical_port = self.adapter_agent.get_logical_port(logical_device_id,
                                                               port_id)
            logical_port.ofp_port.state = state
            self.adapter_agent.update_logical_port(logical_device_id,
                                                   logical_port)
        except Exception as e:
            self.log.exception("exception-updating-port", e=e)

    def delete(self, device):
        self.log.info('delete-onu', device=device)
        if self.parent_adapter:
            try:
                self.parent_adapter.delete_child_device(self.parent_id, device)
            except AttributeError:
                self.log.debug('parent-device-delete-child-not-implemented')
        else:
            self.log.debug("parent-adapter-not-available")

    def _create_tconts(self, uni_id, us_scheduler):
        alloc_id = us_scheduler['alloc_id']
        q_sched_policy = us_scheduler['q_sched_policy']
        self.log.debug('create-tcont', us_scheduler=us_scheduler)

        tcontdict = dict()
        tcontdict['alloc-id'] = alloc_id
        tcontdict['q_sched_policy'] = q_sched_policy
        tcontdict['uni_id'] = uni_id

        # TODO: Not sure what to do with any of this...
        tddata = dict()
        tddata['name'] = 'not-sure-td-profile'
        tddata['fixed-bandwidth'] = "not-sure-fixed"
        tddata['assured-bandwidth'] = "not-sure-assured"
        tddata['maximum-bandwidth'] = "not-sure-max"
        tddata['additional-bw-eligibility-indicator'] = "not-sure-additional"

        td = OnuTrafficDescriptor.create(tddata)
        tcont = OnuTCont.create(self, tcont=tcontdict, td=td)

        self._pon.add_tcont(tcont)

        self.log.debug('pon-add-tcont', tcont=tcont)

    # Called when there is an olt up indication, providing the gem port id chosen by the olt handler
    def _create_gemports(self, uni_id, gem_ports, alloc_id_ref, direction):
        self.log.debug('create-gemport',
                       gem_ports=gem_ports, direction=direction)

        for gem_port in gem_ports:
            gemdict = dict()
            gemdict['gemport_id'] = gem_port['gemport_id']
            gemdict['direction'] = direction
            gemdict['alloc_id_ref'] = alloc_id_ref
            gemdict['encryption'] = gem_port['aes_encryption']
            gemdict['discard_config'] = dict()
            gemdict['discard_config']['max_probability'] = \
                gem_port['discard_config']['max_probability']
            gemdict['discard_config']['max_threshold'] = \
                gem_port['discard_config']['max_threshold']
            gemdict['discard_config']['min_threshold'] = \
                gem_port['discard_config']['min_threshold']
            gemdict['discard_policy'] = gem_port['discard_policy']
            gemdict['max_q_size'] = gem_port['max_q_size']
            gemdict['pbit_map'] = gem_port['pbit_map']
            gemdict['priority_q'] = gem_port['priority_q']
            gemdict['scheduling_policy'] = gem_port['scheduling_policy']
            gemdict['weight'] = gem_port['weight']
            gemdict['uni_id'] = uni_id

            gem_port = OnuGemPort.create(self, gem_port=gemdict)

            self._pon.add_gem_port(gem_port)

            self.log.debug('pon-add-gemport', gem_port=gem_port)

    def _do_tech_profile_configuration(self, uni_id, tp):
        us_scheduler = tp['us_scheduler']
        alloc_id = us_scheduler['alloc_id']
        self._create_tconts(uni_id, us_scheduler)
        upstream_gem_port_attribute_list = tp['upstream_gem_port_attribute_list']
        self._create_gemports(uni_id, upstream_gem_port_attribute_list, alloc_id, "UPSTREAM")
        downstream_gem_port_attribute_list = tp['downstream_gem_port_attribute_list']
        self._create_gemports(uni_id, downstream_gem_port_attribute_list, alloc_id, "DOWNSTREAM")

    def _execute_queued_vlan_filter_tasks(self, uni_id):
        # During OLT Reboots, ONU Reboots, ONU Disable/Enable, it is seen that vlan_filter
        # task is scheduled even before tp task. So we queue vlan-filter task if tp_task
        # or initial-mib-download is not done. Once the tp_task is completed, we execute
        # such queued vlan-filter tasks
        try:
            if uni_id in self._queued_vlan_filter_task:
                self.log.info("executing-queued-vlan-filter-task",
                              uni_id=uni_id)
                filter_info = self._queued_vlan_filter_task[uni_id]
                reactor.callLater(0, self._do_vlan_filter_task, filter_info.get("flow_cookie"),
                                  uni_id, filter_info.get("add_tag"),
                                  filter_info.get("uni_port"), filter_info.get("set_vlan_vid"))
                # Now remove the entry from the dictionary
                self._queued_vlan_filter_task[uni_id].clear()
                self.log.debug("executed-queued-vlan-filter-task",
                               uni_id=uni_id)
        except Exception as e:
            self.log.error("vlan-filter-congiuration-failed", uni_id=uni_id, error=e)

    def _execute_queued_tp_task(self):
        # During OLT Reboots, ONU Reboots, ONU Disable/Enable, it is seen that tp_task
        # scheduled even before initial-mib-download task. So we queue tp_task if
        # initial-mib-download is not done. Once the initial-mib-download is completed,
        # we execute such queued tp tasks
        device = self.adapter_agent.get_device(self.device_id)
        for uni_id in self._get_uni_ids(device):
            try:
                if uni_id in self._queued_tp_task:
                    self.log.info("executing-queued-tp-task",
                                  uni_id=uni_id)
                    reactor.callLater(0, self.load_and_configure_tech_profile,
                                      uni_id, self._queued_tp_task[uni_id])
                    self._queued_tp_task[uni_id].clear()
                    self.log.debug("executed-queued-tp-task",
                                   uni_id=uni_id)

            except Exception as e:
                self.log.error("tech-profile-congiuration-failed", uni_id=uni_id, error=e)

    def load_and_configure_tech_profile(self, uni_id, tp_path):
        if uni_id in self._mib_download_done:
            self.log.debug("loading-tech-profile-configuration", uni_id=uni_id, tp_path=tp_path)

            if uni_id not in self._in_progress_tp_task:
                self._in_progress_tp_task[uni_id] = dict()

            if uni_id not in self._tech_profile_download_done:
                self._tech_profile_download_done[uni_id] = dict()

            if tp_path not in self._tech_profile_download_done[uni_id]:
                self._tech_profile_download_done[uni_id][tp_path] = False

            if not self._tech_profile_download_done[uni_id][tp_path]:
                try:
                    if tp_path in self._in_progress_tp_task[uni_id]:
                        self.log.info("tech-profile-config-already-in-progress",
                                       tp_path=tp_path)
                        return

                    tp = self.kv_client[tp_path]
                    tp = ast.literal_eval(tp)
                    self.log.debug("tp-instance", tp=tp)
                    self._do_tech_profile_configuration(uni_id, tp)

                    def success(_results):
                        self.log.info("tech-profile-config-done-successfully")
                        device = self.adapter_agent.get_device(self.device_id)
                        device.reason = 'tech-profile-config-download-success'
                        self.adapter_agent.update_device(device)
                        if tp_path in self._in_progress_tp_task[uni_id]:
                            del self._in_progress_tp_task[uni_id][tp_path]
                        self._tech_profile_download_done[uni_id][tp_path] = True
                        # Now execute any vlan filter tasks that were queued for later
                        self._execute_queued_vlan_filter_tasks(uni_id)

                    def failure(_reason):
                        self.log.warn('tech-profile-config-failure-retrying',
                                       _reason=_reason)
                        device = self.adapter_agent.get_device(self.device_id)
                        device.reason = 'tech-profile-config-download-failure-retrying'
                        self.adapter_agent.update_device(device)
                        if tp_path in self._in_progress_tp_task[uni_id]:
                            del self._in_progress_tp_task[uni_id][tp_path]
                        self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT, self.load_and_configure_tech_profile,
                                                           uni_id, tp_path)

                    self.log.info('downloading-tech-profile-configuration')
                    self._in_progress_tp_task[uni_id][tp_path] = \
                           BrcmTpServiceSpecificTask(self.omci_agent, self, uni_id)
                    self._deferred = \
                           self._onu_omci_device.task_runner.queue_task(self._in_progress_tp_task[uni_id][tp_path])
                    self._deferred.addCallbacks(success, failure)

                except Exception as e:
                    self.log.exception("error-loading-tech-profile", e=e)
            else:
                    self.log.info("tech-profile-config-already-done")
        else:
            self.log.info('mib-download-task-not-done-adding-request-to-local-cache',
                          uni_id=uni_id)
            self._queued_tp_task[uni_id] = tp_path
            self._queued_vlan_filter_task[uni_id].clear()
            self.log.info("cleared-vlan-task-list-as-mib-sync-is-going-to-happen-shortly",
                          uni_id=uni_id, vlan_filter_task_queue=self._queued_vlan_filter_task)

    def update_pm_config(self, device, pm_config):
        # TODO: This has not been tested
        self.log.info('update_pm_config', pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    # Calling this assumes the onu is active/ready and had at least an initial mib downloaded.   This gets called from
    # flow decomposition that ultimately comes from onos
    def update_flow_table(self, device, flows):
        self.log.debug('function-entry', device=device, flows=flows)

        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        # self.log.info('bulk-flow-update', device_id=device.id, flows=flows)

        # no point in pushing omci flows if the device isnt reachable
        if device.connect_status != ConnectStatus.REACHABLE or \
           device.admin_state != AdminState.ENABLED:
            self.log.warn("device-disabled-or-offline-skipping-flow-update",
                          admin=device.admin_state, connect=device.connect_status)
            return

        def is_downstream(port):
            return port == self._pon_port_number

        def is_upstream(port):
            return not is_downstream(port)

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
            self.log.debug('bulk-flow-update', device_id=device.id, flow=flow)
            try:
                _in_port = fd.get_in_port(flow)
                assert _in_port is not None

                _out_port = fd.get_out_port(flow)  # may be None

                if is_downstream(_in_port):
                    self.log.debug('downstream-flow', in_port=_in_port, out_port=_out_port)
                    uni_port = self.uni_port(_out_port)
                    uni_id = self._get_uni_id(device, _out_port)
                elif is_upstream(_in_port):
                    self.log.debug('upstream-flow', in_port=_in_port, out_port=_out_port)
                    uni_port = self.uni_port(_in_port)
                    uni_id = self._get_uni_id(device, _in_port)
                else:
                    raise Exception('port should be 1 or 2 by our convention')

                self.log.debug('flow-ports', in_port=_in_port, out_port=_out_port, uni_port=str(uni_port))

                for field in fd.get_ofb_fields(flow):
                    if field.type == fd.ETH_TYPE:
                        _type = field.eth_type
                        self.log.debug('field-type-eth-type',
                                       eth_type=_type)

                    elif field.type == fd.IP_PROTO:
                        _proto = field.ip_proto
                        self.log.debug('field-type-ip-proto',
                                       ip_proto=_proto)

                    elif field.type == fd.IN_PORT:
                        _port = field.port
                        self.log.debug('field-type-in-port',
                                       in_port=_port)

                    elif field.type == fd.VLAN_VID:
                        _vlan_vid = field.vlan_vid & 0xfff
                        self.log.debug('field-type-vlan-vid',
                                       vlan=_vlan_vid)

                    elif field.type == fd.VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        self.log.debug('field-type-vlan-pcp',
                                       pcp=_vlan_pcp)

                    elif field.type == fd.UDP_DST:
                        _udp_dst = field.udp_dst
                        self.log.debug('field-type-udp-dst',
                                       udp_dst=_udp_dst)

                    elif field.type == fd.UDP_SRC:
                        _udp_src = field.udp_src
                        self.log.debug('field-type-udp-src',
                                       udp_src=_udp_src)

                    elif field.type == fd.IPV4_DST:
                        _ipv4_dst = field.ipv4_dst
                        self.log.debug('field-type-ipv4-dst',
                                       ipv4_dst=_ipv4_dst)

                    elif field.type == fd.IPV4_SRC:
                        _ipv4_src = field.ipv4_src
                        self.log.debug('field-type-ipv4-src',
                                       ipv4_dst=_ipv4_src)

                    elif field.type == fd.METADATA:
                        _metadata = field.table_metadata
                        self.log.debug('field-type-metadata',
                                       metadata=_metadata)

                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in fd.get_actions(flow):

                    if action.type == fd.OUTPUT:
                        _output = action.output.port
                        self.log.debug('action-type-output',
                                       output=_output, in_port=_in_port)

                    elif action.type == fd.POP_VLAN:
                        self.log.debug('action-type-pop-vlan',
                                       in_port=_in_port)

                    elif action.type == fd.PUSH_VLAN:
                        _push_tpid = action.push.ethertype
                        self.log.debug('action-type-push-vlan',
                                       push_tpid=_push_tpid, in_port=_in_port)
                        if action.push.ethertype != 0x8100:
                            self.log.error('unhandled-tpid',
                                           ethertype=action.push.ethertype)

                    elif action.type == fd.SET_FIELD:
                        _field = action.set_field.field.ofb_field
                        assert (action.set_field.field.oxm_class ==
                                OFPXMC_OPENFLOW_BASIC)
                        self.log.debug('action-type-set-field',
                                       field=_field, in_port=_in_port)
                        if _field.type == fd.VLAN_VID:
                            _set_vlan_vid = _field.vlan_vid & 0xfff
                            self.log.debug('set-field-type-vlan-vid',
                                           vlan_vid=_set_vlan_vid)
                        else:
                            self.log.error('unsupported-action-set-field-type',
                                           field_type=_field.type)
                    else:
                        self.log.error('unsupported-action-type',
                                       action_type=action.type, in_port=_in_port)

                # TODO: We only set vlan omci flows.  Handle omci matching ethertypes at some point in another task
                if _type is not None:
                    self.log.warn('ignoring-flow-with-ethType', ethType=_type)
                elif _set_vlan_vid is None or _set_vlan_vid == 0:
                    self.log.warn('ignoring-flow-that-does-not-set-vlanid')
                else:
                    self.log.warn('set-vlanid', uni_id=uni_port.port_number, set_vlan_vid=_set_vlan_vid)
                    self._do_vlan_filter_task(flow.cookie, uni_id, add_tag=True,
                                              uni_port=uni_port, _set_vlan_vid=_set_vlan_vid)

            except Exception as e:
                self.log.exception('failed-to-install-flow', e=e, flow=flow)

    def add_onu_flows(self, device, flows):
        self.log.debug('function-entry', device=device, flows=flows)

        #
        # We need to proxy through the OLT to get to the ONU
        # Configuration from here should be using OMCI
        #
        # self.log.info('bulk-flow-update', device_id=device.id, flows=flows)

        # no point in pushing omci flows if the device isnt reachable
        if device.connect_status != ConnectStatus.REACHABLE or \
           device.admin_state != AdminState.ENABLED:
            self.log.warn("device-disabled-or-offline-skipping-flow-update",
                          admin=device.admin_state, connect=device.connect_status)
            return

        for flow in flows:
            # if incoming flow contains cookie, then add to ONU
            if flow.cookie:
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
                self.log.debug("add-flow", device_id=device.id, flow=flow)

                def is_downstream(port):
                    return port == self._pon_port_number

                def is_upstream(port):
                    return not is_downstream(port)

                try:
                    _in_port = fd.get_in_port(flow)
                    assert _in_port is not None

                    _out_port = fd.get_out_port(flow)  # may be None

                    if is_downstream(_in_port):
                        self.log.debug('downstream-flow', in_port=_in_port, out_port=_out_port)
                        uni_port = self.uni_port(_out_port)
                        uni_id = self._get_uni_id(device, _out_port)
                    elif is_upstream(_in_port):
                        self.log.debug('upstream-flow', in_port=_in_port, out_port=_out_port)
                        uni_port = self.uni_port(_in_port)
                        uni_id = self._get_uni_id(device, _in_port)
                    else:
                        raise Exception('port should be 1 or 2 by our convention')

                    self.log.debug('flow-ports', in_port=_in_port, out_port=_out_port, uni_port=str(uni_port))

                    for field in fd.get_ofb_fields(flow):
                        if field.type == fd.ETH_TYPE:
                            _type = field.eth_type
                            self.log.debug('field-type-eth-type',
                                           eth_type=_type)

                        elif field.type == fd.IP_PROTO:
                            _proto = field.ip_proto
                            self.log.debug('field-type-ip-proto',
                                           ip_proto=_proto)

                        elif field.type == fd.IN_PORT:
                            _port = field.port
                            self.log.debug('field-type-in-port',
                                           in_port=_port)

                        elif field.type == fd.VLAN_VID:
                            _vlan_vid = field.vlan_vid & 0xfff
                            self.log.debug('field-type-vlan-vid',
                                           vlan=_vlan_vid)

                        elif field.type == fd.VLAN_PCP:
                            _vlan_pcp = field.vlan_pcp
                            self.log.debug('field-type-vlan-pcp',
                                           pcp=_vlan_pcp)

                        elif field.type == fd.UDP_DST:
                            _udp_dst = field.udp_dst
                            self.log.debug('field-type-udp-dst',
                                           udp_dst=_udp_dst)

                        elif field.type == fd.UDP_SRC:
                            _udp_src = field.udp_src
                            self.log.debug('field-type-udp-src',
                                           udp_src=_udp_src)

                        elif field.type == fd.IPV4_DST:
                            _ipv4_dst = field.ipv4_dst
                            self.log.debug('field-type-ipv4-dst',
                                           ipv4_dst=_ipv4_dst)

                        elif field.type == fd.IPV4_SRC:
                            _ipv4_src = field.ipv4_src
                            self.log.debug('field-type-ipv4-src',
                                           ipv4_dst=_ipv4_src)

                        elif field.type == fd.METADATA:
                            _metadata = field.table_metadata
                            self.log.debug('field-type-metadata',
                                           metadata=_metadata)

                        else:
                            raise NotImplementedError('field.type={}'.format(
                                field.type))

                    for action in fd.get_actions(flow):

                        if action.type == fd.OUTPUT:
                            _output = action.output.port
                            self.log.debug('action-type-output',
                                           output=_output, in_port=_in_port)

                        elif action.type == fd.POP_VLAN:
                            self.log.debug('action-type-pop-vlan',
                                           in_port=_in_port)

                        elif action.type == fd.PUSH_VLAN:
                            _push_tpid = action.push.ethertype
                            self.log.debug('action-type-push-vlan',
                                           push_tpid=_push_tpid, in_port=_in_port)
                            if action.push.ethertype != 0x8100:
                                self.log.error('unhandled-tpid',
                                               ethertype=action.push.ethertype)

                        elif action.type == fd.SET_FIELD:
                            _field = action.set_field.field.ofb_field
                            assert (action.set_field.field.oxm_class ==
                                    OFPXMC_OPENFLOW_BASIC)
                            self.log.debug('action-type-set-field',
                                           field=_field, in_port=_in_port)
                            if _field.type == fd.VLAN_VID:
                                _set_vlan_vid = _field.vlan_vid & 0xfff
                                self.log.debug('set-field-type-vlan-vid',
                                               vlan_vid=_set_vlan_vid)
                            else:
                                self.log.error('unsupported-action-set-field-type',
                                               field_type=_field.type)
                        else:
                            self.log.error('unsupported-action-type',
                                           action_type=action.type, in_port=_in_port)

                    # TODO: We only set vlan omci flows.  Handle omci matching ethertypes at some point in another task
                    if _type is not None:
                        self.log.warn('ignoring-flow-with-ethType', ethType=_type)
                    elif _set_vlan_vid is None or _set_vlan_vid == 0:
                        self.log.warn('ignoring-flow-that-does-not-set-vlanid')
                    else:
                        self.log.warn('set-vlanid', uni_id=uni_port.port_number, set_vlan_vid=_set_vlan_vid)
                        self._do_vlan_filter_task(flow.cookie, uni_id, add_tag=True,
                                                  uni_port=uni_port, _set_vlan_vid=_set_vlan_vid)

                except Exception as e:
                    self.log.exception('failed-to-install-flow', e=e, flow=flow)

    def remove_onu_flows(self, device, flows):
        self.log.debug('function-entry', device=device, flows=flows)

        # no point in removing omci flows if the device isnt reachable
        if device.connect_status != ConnectStatus.REACHABLE or \
           device.admin_state != AdminState.ENABLED:
            self.log.warn("device-disabled-or-offline-skipping-remove-flow",
                          admin=device.admin_state, connect=device.connect_status)
            return

        for flow in flows:
            # if incoming flow contains cookie, then remove from ONU
            if flow.cookie:
                self.log.debug("remove-flow", device_id=device.id, flow=flow)

                def is_downstream(port):
                    return port == self._pon_port_number

                def is_upstream(port):
                    return not is_downstream(port)

                try:
                    _in_port = fd.get_in_port(flow)
                    assert _in_port is not None

                    _out_port = fd.get_out_port(flow)  # may be None

                    if is_downstream(_in_port):
                        self.log.debug('downstream-flow', in_port=_in_port, out_port=_out_port)
                        uni_port = self.uni_port(_out_port)
                        uni_id = self._get_uni_id(device, _out_port)
                    elif is_upstream(_in_port):
                        self.log.debug('upstream-flow', in_port=_in_port, out_port=_out_port)
                        uni_port = self.uni_port(_in_port)
                        uni_id = self._get_uni_id(device, _in_port)
                    else:
                        raise Exception('port should be 1 or 2 by our convention')

                    self.log.debug('flow-ports', in_port=_in_port, out_port=_out_port, uni_port=str(uni_port))
                    _set_vlan_vid = None
                    for action in fd.get_actions(flow):

                        if action.type == fd.SET_FIELD:
                            _field = action.set_field.field.ofb_field
                            assert (action.set_field.field.oxm_class ==
                                    OFPXMC_OPENFLOW_BASIC)
                            self.log.debug('action-type-set-field',
                                           field=_field, in_port=_in_port)
                            if _field.type == fd.VLAN_VID:
                                _set_vlan_vid = _field.vlan_vid & 0xfff
                                self.log.debug('set-field-type-vlan-vid',
                                               vlan_vid=_set_vlan_vid)
                            else:
                                self.log.error('unsupported-action-set-field-type',
                                               field_type=_field.type)

                    # Deleting flow from ONU.
                    if _set_vlan_vid is not None and _set_vlan_vid != 0:
                        self._do_vlan_filter_task(flow.cookie, uni_id, add_tag=False, uni_port=uni_port,
                                                  _set_vlan_vid=_set_vlan_vid)
                except Exception as e:
                    self.log.exception('failed-to-remove-flow', e=e)

    def _get_uni_id(self, device, port):
       # TODO: This knowledge is locked away in openolt.
       # and it assumes one onu equals one uni...
       parent_device = self.adapter_agent.get_device(device.parent_id)
       parent_adapter_agent = registry('adapter_loader').get_agent(parent_device.adapter)
       if parent_adapter_agent is None:
           self.log.error('parent-adapter-could-not-be-retrieved')

       parent_adapter = parent_adapter_agent.adapter.devices[parent_device.id]
       return parent_adapter.platform.uni_id_from_port_num(port)

    def _get_uni_ids(self, device):
        uni_ids = list()
        ports = self.adapter_agent.get_ports(device.id, Port.ETHERNET_UNI)
        uni_ports = map((lambda port: port.port_no), ports)
        for uni_port in uni_ports:
            uni_ids.append(self._get_uni_id(device, uni_port))
        self.log.debug("uni-ids", uni_ids=uni_ids)
        return uni_ids

    def _do_vlan_filter_task(self, flow_cookie, uni_id, add_tag=True, uni_port=None, _set_vlan_vid=None):
        self.log.debug("Starting-vlan-filter-task", flow_cookie=flow_cookie, uni_id=uni_id, add_tag=add_tag,
                       uni_port=uni_port, set_vlan_vid=_set_vlan_vid)

        if uni_id in self._tech_profile_download_done and self._tech_profile_download_done[uni_id] != {}:
            task_name = 'removing-vlan-tag'
            if add_tag:
                assert uni_port is not None
                task_name = 'setting-vlan-tag'

            def success(_results):
                device = self.adapter_agent.get_device(self.device_id)
                if add_tag:
                    self.log.info('vlan-tagging-success', _results=_results)
                    device.reason = 'omci-flows-pushed'
                    self.log.debug('Flow-addition-success', cookie=flow_cookie)
                else:
                    self.log.info('vlan-untagging-success', _results=_results)
                    device.reason = 'omci-flows-deleted'
                    self.log.debug('Flow-removal-success', cookie=flow_cookie)

                self.adapter_agent.update_device(device)
                self._vlan_filter_task = None

            def failure(_reason):
                device = self.adapter_agent.get_device(self.device_id)
                if add_tag:
                    self.log.warn('vlan-tagging-failure', _reason=_reason)
                    device.reason = 'omci-flows-addition-failed-retrying'
                    self._vlan_filter_task = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                               self._do_vlan_filter_task, flow_cookie,
                                                               uni_id, add_tag=True, uni_port=uni_port,
                                                               _set_vlan_vid=_set_vlan_vid)
                else:
                    self.log.warn('vlan-untagging-failure', _reason=_reason)
                    device.reason = 'omci-flows-deletion-failed-retrying'
                    self._vlan_filter_task = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                               self._do_vlan_filter_task, flow_cookie,
                                                               uni_id, add_tag=False)
                self.adapter_agent.update_device(device)

            self.log.info(task_name)
            self._vlan_filter_task = BrcmVlanFilterTask(self.omci_agent, self.device_id, uni_port, _set_vlan_vid,
                                                        add_tag=add_tag)
            self._deferred = self._onu_omci_device.task_runner.queue_task(self._vlan_filter_task)
            self._deferred.addCallbacks(success, failure)

            if add_tag == False:
                # The flow is going to get deleted eventually.
                # Let TP download happen again
                for uni_id in self._in_progress_tp_task:
                    self._in_progress_tp_task[uni_id].clear()
                for uni_id in self._tech_profile_download_done:
                    self._tech_profile_download_done[uni_id].clear()

        else:
            self.log.info('tp-service-specific-task-not-done-adding-request-to-local-cache',
                          uni_id=uni_id)
            self._queued_vlan_filter_task[uni_id]= {"flow_cookie": flow_cookie, \
                "add_tag": add_tag, "uni_port": uni_port, "set_vlan_vid": _set_vlan_vid}

    def get_tx_id(self):
        self.log.debug('function-entry')
        self.tx_id += 1
        return self.tx_id

    # TODO: Actually conform to or create a proper interface.
    # this and the other functions called from the olt arent very clear.
    # Called each time there is an onu "up" indication from the olt handler
    def create_interface(self, data):
        self.log.debug('function-entry', data=data)
        self._onu_indication = data

        onu_device = self.adapter_agent.get_device(self.device_id)

        self.log.debug('starting-openomci-statemachine')
        self._subscribe_to_events()
        reactor.callLater(1, self._onu_omci_device.start)
        onu_device.reason = "starting-openomci"
        self.adapter_agent.update_device(onu_device)
        self._heartbeat.enabled = True

    # Currently called each time there is an onu "down" indication from the olt handler
    # TODO: possibly other reasons to "update" from the olt?
    def update_interface(self, data):
        self.log.debug('function-entry', data=data)
        oper_state = data.get('oper_state', None)

        onu_device = self.adapter_agent.get_device(self.device_id)

        if oper_state == 'down':
            self.log.debug('stopping-openomci-statemachine')
            reactor.callLater(0, self._onu_omci_device.stop)

            # Clear mib_download_done list as OMCI SM is going to reset
            for uni_id in self._get_uni_ids(onu_device):
                try:
                    self._mib_download_done.remove(uni_id)
                except ValueError:
                    pass

            # Let TP download happen again
            for uni_id in self._in_progress_tp_task:
                self._in_progress_tp_task[uni_id].clear()
            for uni_id in self._tech_profile_download_done:
                self._tech_profile_download_done[uni_id].clear()

            self.disable_ports(onu_device)
            onu_device.reason = "stopping-openomci"
            onu_device.connect_status = ConnectStatus.UNREACHABLE
            onu_device.oper_status = OperStatus.DISCOVERED
            self.adapter_agent.update_device(onu_device)
        else:
            self.log.debug('not-changing-openomci-statemachine')

    # Not currently called by olt or anything else
    def remove_interface(self, data):
        self.log.debug('function-entry', data=data)

        onu_device = self.adapter_agent.get_device(self.device_id)

        self.log.debug('stopping-openomci-statemachine')
        reactor.callLater(0, self._onu_omci_device.stop)

        # Clear mib_download_done list as OMCI SM is going to reset
        for uni_id in self._get_uni_ids(onu_device):
            self._mib_download_done.remove(uni_id)
        # Let TP download happen again
        for uni_id in self._in_progress_tp_task:
            self._in_progress_tp_task[uni_id].clear()
        for uni_id in self._tech_profile_download_done:
            self._tech_profile_download_done[uni_id].clear()

        self.disable_ports(onu_device)
        onu_device.reason = "stopping-openomci"
        self.adapter_agent.update_device(onu_device)

        # TODO: im sure there is more to do here

    # Not currently called.  Would be called presumably from the olt handler
    def remove_gemport(self, data):
        self.log.debug('remove-gemport', data=data)
        gem_port = GemportsConfigData()
        gem_port.CopyFrom(data)
        device = self.adapter_agent.get_device(self.device_id)
        if device.connect_status != ConnectStatus.REACHABLE:
            self.log.error('device-unreachable')
            return

    # Not currently called.  Would be called presumably from the olt handler
    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        self.log.debug('remove-tcont', tcont_data=tcont_data, traffic_descriptor_data=traffic_descriptor_data)
        device = self.adapter_agent.get_device(self.device_id)
        if device.connect_status != ConnectStatus.REACHABLE:
            self.log.error('device-unreachable')
            return

        # TODO: Create some omci task that encompases this what intended

    # Not currently called.  Would be called presumably from the olt handler
    def create_multicast_gemport(self, data):
        self.log.debug('function-entry', data=data)

        # TODO: create objects and populate for later omci calls

    def disable(self, device):
        self.log.debug('function-entry', device=device)
        try:
            self.log.info('sending-uni-lock-towards-device', device=device)

            def stop_anyway(reason):
                # proceed with disable regardless if we could reach the onu. for example onu is unplugged
                self.log.debug('stopping-openomci-statemachine')
                reactor.callLater(0, self._onu_omci_device.stop)

                # Clear mib_download_done list as OMCI SM is going to reset
                for uni_id in self._get_uni_ids(device):
                    self._mib_download_done.remove(uni_id)
                # Let TP download happen again
                for uni_id in self._in_progress_tp_task:
                    self._in_progress_tp_task[uni_id].clear()
                for uni_id in self._tech_profile_download_done:
                    self._tech_profile_download_done[uni_id].clear()
                self.log.debug('cleared-tech-profile-cache',
                               tp_service_specific_task=self._in_progress_tp_task,
                               tech_profile_download_done=self._tech_profile_download_done)

                self.disable_ports(device)
                device.oper_status = OperStatus.UNKNOWN
                device.reason = "omci-admin-lock"
                self.adapter_agent.update_device(device)

            # lock all the unis
            task = BrcmUniLockTask(self.omci_agent, self.device_id, lock=True)
            self._deferred = self._onu_omci_device.task_runner.queue_task(task)
            self._deferred.addCallbacks(stop_anyway, stop_anyway)
        except Exception as e:
            log.exception('exception-in-onu-disable', exception=e)

    def reenable(self, device):
        self.log.debug('function-entry', device=device)
        try:
            # Start up OpenOMCI state machines for this device
            # this will ultimately resync mib and unlock unis on successful redownloading the mib
            self.log.debug('restarting-openomci-statemachine')
            self._subscribe_to_events()
            device.reason = "restarting-openomci"
            self.adapter_agent.update_device(device)
            reactor.callLater(1, self._onu_omci_device.start)
            self._heartbeat.enabled = True
        except Exception as e:
            log.exception('exception-in-onu-reenable', exception=e)

    def reboot(self):
        self.log.info('reboot-device')
        device = self.adapter_agent.get_device(self.device_id)
        if device.connect_status != ConnectStatus.REACHABLE:
            self.log.error("device-unreachable")
            return

        def success(_results):
            self.log.info('reboot-success', _results=_results)
            self.disable_ports(device)
            device.connect_status = ConnectStatus.UNREACHABLE
            device.oper_status = OperStatus.DISCOVERED
            device.reason = "rebooting"
            self.adapter_agent.update_device(device)

        def failure(_reason):
            self.log.info('reboot-failure', _reason=_reason)

        self._deferred = self._onu_omci_device.reboot()
        self._deferred.addCallbacks(success, failure)

    def disable_ports(self, onu_device):
        self.log.info('disable-ports', device_id=self.device_id,
                      onu_device=onu_device)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        parent_device = self.adapter_agent.get_device(onu_device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        ports = self.adapter_agent.get_ports(onu_device.id, Port.ETHERNET_UNI)
        for port in ports:
            port_id = 'uni-{}'.format(port.port_no)
            # TODO: move to UniPort
            self.update_logical_port(logical_device_id, port_id, OFPPS_LINK_DOWN)

    def enable_ports(self, onu_device):
        self.log.info('enable-ports', device_id=self.device_id, onu_device=onu_device)

        # Disable all ports on that device
        self.adapter_agent.enable_all_ports(self.device_id)

        parent_device = self.adapter_agent.get_device(onu_device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        ports = self.adapter_agent.get_ports(onu_device.id, Port.ETHERNET_UNI)
        for port in ports:
            port_id = 'uni-{}'.format(port.port_no)
            # TODO: move to UniPort
            self.update_logical_port(logical_device_id, port_id, OFPPS_LIVE)

    # Called just before openomci state machine is started.  These listen for events from selected state machines,
    # most importantly, mib in sync.  Which ultimately leads to downloading the mib
    def _subscribe_to_events(self):
        self.log.debug('function-entry')

        # OMCI MIB Database sync status
        bus = self._onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self.device_id,
                                               OnuDeviceEvents.MibDatabaseSyncEvent)
        self._in_sync_subscription = bus.subscribe(topic, self.in_sync_handler)

        # OMCI Capabilities
        bus = self._onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self.device_id,
                                               OnuDeviceEvents.OmciCapabilitiesEvent)
        self._capabilities_subscription = bus.subscribe(topic, self.capabilties_handler)

    # Called when the mib is in sync
    def in_sync_handler(self, _topic, msg):
        self.log.debug('function-entry', _topic=_topic, msg=msg)
        if self._in_sync_subscription is not None:
            try:
                in_sync = msg[IN_SYNC_KEY]

                if in_sync:
                    # Only call this once
                    bus = self._onu_omci_device.event_bus
                    bus.unsubscribe(self._in_sync_subscription)
                    self._in_sync_subscription = None

                    # Start up device_info load
                    self.log.debug('running-mib-sync')
                    reactor.callLater(0, self._mib_in_sync)

            except Exception as e:
                self.log.exception('in-sync', e=e)

    def capabilties_handler(self, _topic, _msg):
        self.log.debug('function-entry', _topic=_topic, msg=_msg)
        if self._capabilities_subscription is not None:
            self.log.debug('capabilities-handler-done')

    # Mib is in sync, we can now query what we learned and actually start pushing ME (download) to the ONU.
    # Currently uses a basic mib download task that create a bridge with a single gem port and uni, only allowing EAP
    # Implement your own MibDownloadTask if you wish to setup something different by default
    def _mib_in_sync(self):
        self.log.debug('function-entry')

        omci = self._onu_omci_device
        in_sync = omci.mib_db_in_sync

        device = self.adapter_agent.get_device(self.device_id)
        device.reason = 'discovery-mibsync-complete'
        self.adapter_agent.update_device(device)

        if not self._dev_info_loaded:
            self.log.info('loading-device-data-from-mib', in_sync=in_sync, already_loaded=self._dev_info_loaded)

            omci_dev = self._onu_omci_device
            config = omci_dev.configuration

            # TODO: run this sooner somehow. shouldnt have to wait for mib sync to push an initial download
            # In Sync, we can register logical ports now. Ideally this could occur on
            # the first time we received a successful (no timeout) OMCI Rx response.
            try:

                # sort the lists so we get consistent port ordering.
                ani_list = sorted(config.ani_g_entities) if config.ani_g_entities else []
                uni_list = sorted(config.uni_g_entities) if config.uni_g_entities else []
                pptp_list = sorted(config.pptp_entities) if config.pptp_entities else []
                veip_list = sorted(config.veip_entities) if config.veip_entities else []

                if ani_list is None or (pptp_list is None and veip_list is None):
                    device.reason = 'onu-missing-required-elements'
                    self.log.warn("no-ani-or-unis")
                    self.adapter_agent.update_device(device)
                    raise Exception("onu-missing-required-elements")

                # Currently logging the ani, pptp, veip, and uni for information purposes.
                # Actually act on the veip/pptp as its ME is the most correct one to use in later tasks.
                # And in some ONU the UNI-G list is incomplete or incorrect...
                for entity_id in ani_list:
                    ani_value = config.ani_g_entities[entity_id]
                    self.log.debug("discovered-ani", entity_id=entity_id, value=ani_value)
                    # TODO: currently only one OLT PON port/ANI, so this works out.  With NGPON there will be 2..?
                    self._total_tcont_count = ani_value.get('total-tcont-count')
                    self.log.debug("set-total-tcont-count", tcont_count=self._total_tcont_count)

                for entity_id in uni_list:
                    uni_value = config.uni_g_entities[entity_id]
                    self.log.debug("discovered-uni", entity_id=entity_id, value=uni_value)

                uni_entities = OrderedDict()
                for entity_id in pptp_list:
                    pptp_value = config.pptp_entities[entity_id]
                    self.log.debug("discovered-pptp", entity_id=entity_id, value=pptp_value)
                    uni_entities[entity_id] = UniType.PPTP

                for entity_id in veip_list:
                    veip_value = config.veip_entities[entity_id]
                    self.log.debug("discovered-veip", entity_id=entity_id, value=veip_value)
                    uni_entities[entity_id] = UniType.VEIP

                uni_id = 0
                for entity_id, uni_type in uni_entities.iteritems():
                    try:
                        self._add_uni_port(entity_id, uni_id, uni_type)
                        uni_id += 1
                    except AssertionError as e:
                        self.log.warn("could not add UNI", entity_id=entity_id, uni_type=uni_type, e=e)

                multi_uni = len(self._unis) > 1
                for uni_port in self._unis.itervalues():
                    uni_port.add_logical_port(uni_port.port_number, multi_uni)

                self.adapter_agent.update_device(device)

                self._qos_flexibility = config.qos_configuration_flexibility or 0
                self._omcc_version = config.omcc_version or OMCCVersion.Unknown

                if self._unis:
                    self._dev_info_loaded = True
                else:
                    device.reason = 'no-usable-unis'
                    self.adapter_agent.update_device(device)
                    self.log.warn("no-usable-unis")
                    raise Exception("no-usable-unis")

            except Exception as e:
                self.log.exception('device-info-load', e=e)
                self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT, self._mib_in_sync)

        else:
            self.log.info('device-info-already-loaded', in_sync=in_sync, already_loaded=self._dev_info_loaded)

        if self._dev_info_loaded:
            if device.admin_state == AdminState.ENABLED:
                def success(_results):
                    self.log.info('mib-download-success', _results=_results)
                    device = self.adapter_agent.get_device(self.device_id)
                    device.reason = 'initial-mib-downloaded'
                    device.oper_status = OperStatus.ACTIVE
                    device.connect_status = ConnectStatus.REACHABLE
                    self.enable_ports(device)
                    self.adapter_agent.update_device(device)
                    self._mib_download_task = None
                    self._mib_download_done.extend(self._get_uni_ids(device))
                    self._execute_queued_tp_task()

                    # raise onu activated alarm
                    self.onu_active_alarm()

                def failure(_reason):
                    self.log.warn('mib-download-failure-retrying', _reason=_reason)
                    device.reason = 'initial-mib-download-failure-retrying'
                    self.adapter_agent.update_device(device)
                    self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT, self._mib_in_sync)

                # Download an initial mib that creates simple bridge that can pass EAP.  On success (above) finally set
                # the device to active/reachable.   This then opens up the handler to openflow pushes from outside
                self.log.info('downloading-initial-mib-configuration')
                self._mib_download_task = BrcmMibDownloadTask(self.omci_agent, self)
                self._deferred = self._onu_omci_device.task_runner.queue_task(self._mib_download_task)
                self._deferred.addCallbacks(success, failure)
            else:
                self.log.info('admin-down-disabling')
                self.disable(device)
        else:
            self.log.info('device-info-not-loaded-skipping-mib-download')


    def _add_uni_port(self, entity_id, uni_id, uni_type=UniType.PPTP):
        self.log.debug('function-entry')

        device = self.adapter_agent.get_device(self.device_id)
        parent_device = self.adapter_agent.get_device(device.parent_id)

        parent_adapter_agent = registry('adapter_loader').get_agent(parent_device.adapter)
        if parent_adapter_agent is None:
            self.log.error('parent-adapter-could-not-be-retrieved')

        # TODO: This knowledge is locked away in openolt.  and it assumes one onu equals one uni...
        parent_device = self.adapter_agent.get_device(device.parent_id)
        parent_adapter = parent_adapter_agent.adapter.devices[parent_device.id]
        uni_no = parent_adapter.platform.mk_uni_port_num(
            self._onu_indication.intf_id, self._onu_indication.onu_id, uni_id)

        # TODO: Some or parts of this likely need to move to UniPort. especially the format stuff
        uni_name = "uni-{}".format(uni_no)

        mac_bridge_port_num = uni_id + 1 # TODO +1 is only to test non-zero index

        self.log.debug('uni-port-inputs', uni_no=uni_no, uni_id=uni_id, uni_name=uni_name, uni_type=uni_type,
                       entity_id=entity_id, mac_bridge_port_num=mac_bridge_port_num)

        uni_port = UniPort.create(self, uni_name, uni_id, uni_no, uni_name, uni_type)
        uni_port.entity_id = entity_id
        uni_port.enabled = True
        uni_port.mac_bridge_port_num = mac_bridge_port_num

        self.log.debug("created-uni-port", uni=uni_port)

        self.adapter_agent.add_port(device.id, uni_port.get_port())
        parent_adapter_agent.add_port(device.parent_id, uni_port.get_port())

        self._unis[uni_port.port_number] = uni_port

        self._onu_omci_device.alarm_synchronizer.set_alarm_params(onu_id=self._onu_indication.onu_id,
                                                                  uni_ports=self._unis.values())
        # TODO: this should be in the PonPortclass
        pon_port = self._pon.get_port()

        # Delete reference to my own UNI as peer from parent.
        # TODO why is this here, add_port_reference_to_parent already prunes duplicates
        me_as_peer = Port.PeerPort(device_id=device.parent_id, port_no=uni_port.port_number)
        partial_pon_port = Port(port_no=pon_port.port_no, label=pon_port.label,
                                type=pon_port.type, admin_state=pon_port.admin_state,
                                oper_status=pon_port.oper_status,
                                peers=[me_as_peer]) # only list myself as a peer to avoid deleting all other UNIs from parent
        self.adapter_agent.delete_port_reference_from_parent(self.device_id, partial_pon_port)

        pon_port.peers.extend([me_as_peer])

        self._pon._port = pon_port

        self.adapter_agent.add_port_reference_to_parent(self.device_id,
                                                        pon_port)

    def onu_active_alarm(self):
        self.log.debug('function-entry')
        try:
            device = self.adapter_agent.get_device(self.device_id)
            parent_device = self.adapter_agent.get_device(self.parent_id)
            olt_serial_number = parent_device.serial_number
            datapath_id = self.get_datapath_id()
        except Exception as e:
            self.log.exception("error-handling-onu-active-alarm", e=e)
            return

        self.log.debug("onu-indication-context-data",
                       pon_id=self._onu_indication.intf_id,
                       registration_id=self._onu_indication.registration_id,
                       device_id=self.device_id,
                       onu_serial_number=device.serial_number,
                       olt_serial_number=olt_serial_number)
        try:
            OnuActiveAlarm(self.alarms, self.device_id,
                           self._onu_indication.intf_id,
                           device.serial_number,
                           self._onu_indication.registration_id,
                           olt_serial_number,onu_id=self._onu_indication.onu_id,
                           datapath_id=datapath_id).raise_alarm()
        except Exception as active_alarm_error:
            self.log.exception('onu-activated-alarm-error',
                               errmsg=active_alarm_error.message)

    def get_datapath_id(self):
        datapath_hex_id = None
        try:
            logical_device = self.adapter_agent.get_logical_device(
                self.logical_device_id)
            datapath_hex_id = format(logical_device.datapath_id, '016x')
            self.log.debug("datapath-hex-id", datapath_hex_id=datapath_hex_id)
        except Exception as e:
            self.log.exception('datapath-id-error:', e=e)
        return datapath_hex_id

