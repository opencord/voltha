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
Fully simulated OLT/ONU adapter.
"""

import arrow
import sys
import structlog
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from common.utils.asleep import asleep

from twisted.internet.task import LoopingCall
from voltha.adapters.iadapter import OnuAdapter
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos import third_party
from voltha.protos.common_pb2 import OperStatus, ConnectStatus, AdminState
from voltha.protos.device_pb2 import Port, PmConfig, PmConfigs
from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD
from voltha.protos.openflow_13_pb2 import ofp_port
from voltha.protos.ponsim_pb2 import FlowTable, PonSimMetricsRequest, PonSimMetrics
from voltha.protos.ponsim_pb2 import InterfaceConfig
from voltha.protos.bbf_fiber_base_pb2 import OntaniConfig, VOntaniConfig, \
    VEnetConfig
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import \
    TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_multicast_gemport_body_pb2 import \
    MulticastGemportsConfigData
from voltha.protos.bbf_fiber_multicast_distribution_set_body_pb2 import \
    MulticastDistributionSetData

_ = third_party
log = structlog.get_logger()

xpon_ponsim_onu_itfs = {
    'create_interface': {
        'log': 'create-interface'},
    'update_interface': {
        'log': 'update-interface'},
    'remove_interface': {
        'log': 'remove-interface'},
    'create_tcont': {
        'log': 'create-tconts-config-data'},
    'update_tcont': {
        'log': 'update-tconts-config-data'},
    'remove_tcont': {
        'log': 'remove-tconts-config-data'},
    'create_gemport': {
        'log': 'create-gemports-config-data'},
    'update_gemport': {
        'log': 'update-gemports-config-data'},
    'remove_gemport': {
        'log': 'remove-gemports-config-data'},
    'create_multicast_gemport': {
        'log': 'create-multicast-gemports-config-data'},
    'update_multicast_gemport': {
        'log': 'update-multicast-gemports-config-data'},
    'remove_multicast_gemport': {
        'log': 'remove-multicast-gemports-config-data'},
    'create_multicast_distribution_set': {
        'log': 'create-multicast-distribution-set-data'},
    'update_multicast_distribution_set': {
        'log': 'update-multicast-distribution-set-data'},
    'remove_multicast_distribution_set': {
        'log': 'remove-multicast-distribution-set-data'},
}

class AdapterPmMetrics:
    def __init__(self, device):
        self.pm_names = {'tx_64_pkts', 'tx_65_127_pkts', 'tx_128_255_pkts',
                         'tx_256_511_pkts', 'tx_512_1023_pkts',
                         'tx_1024_1518_pkts', 'tx_1519_9k_pkts',
                         'rx_64_pkts', 'rx_65_127_pkts',
                         'rx_128_255_pkts', 'rx_256_511_pkts',
                         'rx_512_1023_pkts', 'rx_1024_1518_pkts',
                         'rx_1519_9k_pkts'}
        self.device = device
        self.id = device.id
        self.name = 'ponsim_onu'
        # self.id = "abc"
        self.default_freq = 150
        self.grouped = False
        self.freq_override = False
        self.pon_metrics_config = dict()
        self.uni_metrics_config = dict()
        self.lc = None
        for m in self.pm_names:
            self.pon_metrics_config[m] = PmConfig(name=m,
                                                  type=PmConfig.COUNTER,
                                                  enabled=True)
            self.uni_metrics_config[m] = PmConfig(name=m,
                                                  type=PmConfig.COUNTER,
                                                  enabled=True)

    def update(self, pm_config):
        if self.default_freq != pm_config.default_freq:
            # Update the callback to the new frequency.
            self.default_freq = pm_config.default_freq
            self.lc.stop()
            self.lc.start(interval=self.default_freq / 10)
        for m in pm_config.metrics:
            self.pon_metrics_config[m.name].enabled = m.enabled
            self.uni_metrics_config[m.name].enabled = m.enabled

    def make_proto(self):
        pm_config = PmConfigs(
            id=self.id,
            default_freq=self.default_freq,
            grouped=False,
            freq_override=False)
        for m in sorted(self.pon_metrics_config):
            pm = self.pon_metrics_config[m]  # Either will do they're the same
            pm_config.metrics.extend([PmConfig(name=pm.name,
                                               type=pm.type,
                                               enabled=pm.enabled)])
        return pm_config

    def extract_metrics(self, stats):
        rtrn_port_metrics = dict()
        rtrn_port_metrics['pon'] = self.extract_pon_metrics(stats)
        rtrn_port_metrics['uni'] = self.extract_uni_metrics(stats)
        return rtrn_port_metrics

    def extract_pon_metrics(self, stats):
        rtrn_pon_metrics = dict()
        for m in stats.metrics:
            if m.port_name == "pon":
                for p in m.packets:
                    if self.pon_metrics_config[p.name].enabled:
                        rtrn_pon_metrics[p.name] = p.value
                return rtrn_pon_metrics

    def extract_uni_metrics(self, stats):
        rtrn_pon_metrics = dict()
        for m in stats.metrics:
            if m.port_name == "uni":
                for p in m.packets:
                    if self.pon_metrics_config[p.name].enabled:
                        rtrn_pon_metrics[p.name] = p.value
                return rtrn_pon_metrics

    def start_collector(self, callback):
        log.info("starting-pm-collection", device_name=self.name,
                 device_id=self.device.id)
        prefix = 'voltha.{}.{}'.format(self.name, self.device.id)
        self.lc = LoopingCall(callback, self.device.id, prefix)
        self.lc.start(interval=self.default_freq / 10)

    def stop_collector(self):
        log.info("stopping-pm-collection", device_name=self.name,
                 device_id=self.device.id)
        self.lc.stop()


class PonSimOnuAdapter(OnuAdapter):
    def __init__(self, adapter_agent, config):
        # DeviceType of ONU should be same as VENDOR ID of ONU Serial Number as specified by standard
        # requires for identifying correct adapter or ranged ONU
        super(PonSimOnuAdapter, self).__init__(adapter_agent=adapter_agent,
                                               config=config,
                                               device_handler_class=PonSimOnuHandler,
                                               name='ponsim_onu',
                                               vendor='Voltha project',
                                               version='0.4',
                                               device_type='ponsim_onu',
                                               vendor_id='PSMO',
                                               accepts_bulk_flow_update=True,
                                               accepts_add_remove_flow_updates=False)

    def xpon_ponsim_onu_adapter_interface(self, method_name, device, data,
                                          data2=None):
        log.info('{}'.format(xpon_ponsim_onu_itfs[method_name]['log']),
                 device_id=device.id)
        if device.id in self.devices_handlers:
            handler = self.devices_handlers[device.id]
            if handler is not None:
                _method = getattr(handler, method_name)
                if isinstance(data, TcontsConfigData):
                    _method(data, data2)
                else:
                    _method(data)

    def update_pm_config(self, device, pm_config):
        log.info("adapter-update-pm-config", device=device,
                 pm_config=pm_config)
        handler = self.devices_handlers[device.id]
        handler.update_pm_config(device, pm_config)

    def create_interface(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def update_interface(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def remove_interface(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device,
                                               tcont_data,
                                               traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device,
                                               tcont_data,
                                               traffic_descriptor_data)

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device,
                                               tcont_data,
                                               traffic_descriptor_data)

    def create_gemport(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def update_gemport(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def remove_gemport(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def create_multicast_gemport(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def update_multicast_gemport(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def remove_multicast_gemport(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def create_multicast_distribution_set(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def update_multicast_distribution_set(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)

    def remove_multicast_distribution_set(self, device, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_adapter_interface(_method_name, device, data)


class PonSimOnuHandler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.incoming_messages = DeferredQueue()
        self.proxy_address = None
        # reference of uni_port is required when re-enabling the device if
        # it was disabled previously
        self.uni_port = None
        self.pon_port = None

    def receive_message(self, msg):
        if isinstance(msg, PonSimMetrics):
            # Message is a reply to an ONU statistics request. Push it out to Kafka via adapter.submit_kpis().
            if self.pm_metrics:
                self.log.debug('Handling incoming ONU metrics')
                prefix = 'voltha.{}.{}'.format("ponsim_onu", self.device_id)
                port_metrics = self.pm_metrics.extract_metrics(msg)
                try:
                    ts = arrow.utcnow().timestamp
                    kpi_event = KpiEvent(
                        type=KpiEventType.slice,
                        ts=ts,
                        prefixes={
                            # OLT NNI port
                            prefix + '.uni': MetricValuePairs(
                                metrics=port_metrics['uni']),
                            # OLT PON port
                            prefix + '.pon': MetricValuePairs(
                                metrics=port_metrics['pon'])
                        }
                    )

                    self.log.debug('Submitting KPI for incoming ONU metrics')

                    # Step 3: submit
                    self.adapter_agent.submit_kpis(kpi_event)
                except Exception as e:
                   log.exception('failed-to-submit-kpis', e=e)
            else:
                # We received a statistics message, but we don't have pm_metrics set up. This shouldn't happen.
                self.log.warning('received unexpected PonSimMetrics')
        else:
            # The message is probably a reply to a FlowTable update. self.update_flow_table() will pop it off this
            # queue and return it to its caller.
            self.incoming_messages.put(msg)

    def activate(self, device):
        self.log.info('activating')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # populate device info
        device.root = False
        device.vendor = 'ponsim'
        device.model = 'n/a'
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Now set the initial PM configuration for this device
        self.pm_metrics = AdapterPmMetrics(device)
        pm_config = self.pm_metrics.make_proto()
        log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config, init=True)

        # register physical ports
        self.uni_port = Port(
            port_no=2,
            label='UNI facing Ethernet port',
            type=Port.ETHERNET_UNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.pon_port = Port(
            port_no=1,
            label='PON port',
            type=Port.PON_ONU,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE,
            peers=[
                Port.PeerPort(
                    device_id=device.parent_id,
                    port_no=device.parent_port_no
                )
            ]
        )
        self.adapter_agent.add_port(device.id, self.uni_port)
        self.adapter_agent.add_port(device.id, self.pon_port)

        # add uni port to logical device
        parent_device = self.adapter_agent.get_device(device.parent_id)
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
            id='uni-{}'.format(port_no),
            ofp_port=ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name=device.serial_number,
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=device.id,
            device_port_no=self.uni_port.port_no
        ))

        device = self.adapter_agent.get_device(device.id)
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        # Start collecting stats from the device after a brief pause
        self.start_kpi_collection(device.id)

    def _get_uni_port(self):
        ports = self.adapter_agent.get_ports(self.device_id, Port.ETHERNET_UNI)
        if ports:
            # For now, we use on one uni port
            return ports[0]

    def _get_pon_port(self):
        ports = self.adapter_agent.get_ports(self.device_id, Port.PON_ONU)
        if ports:
            # For now, we use on one uni port
            return ports[0]

    def reconcile(self, device):
        self.log.info('reconciling-ONU-device-starts')

        # first we verify that we got parent reference and proxy info
        assert device.parent_id
        assert device.proxy_address.device_id
        assert device.proxy_address.channel_id

        # register for proxied messages right away
        self.proxy_address = device.proxy_address
        self.adapter_agent.register_for_proxied_messages(device.proxy_address)

        # Set the connection status to REACHABLE
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

        # Now set the initial PM configuration for this device
        self.pm_metrics = AdapterPmMetrics(device)
        pm_config = self.pm_metrics.make_proto()
        log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config, init=True)

        # TODO: Verify that the uni, pon and logical ports exists

        # Mark the device as REACHABLE and ACTIVE
        device = self.adapter_agent.get_device(device.id)
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        # Start collecting stats from the device after a brief pause
        self.start_kpi_collection(device.id)

        self.log.info('reconciling-ONU-device-ends')

    @inlineCallbacks
    def update_flow_table(self, flows):

        # we need to proxy through the OLT to get to the ONU

        # reset response queue
        while self.incoming_messages.pending:
            yield self.incoming_messages.get()

        msg = FlowTable(
            port=self.proxy_address.channel_id,
            flows=flows
        )
        self.adapter_agent.send_proxied_message(self.proxy_address, msg)

        yield self.incoming_messages.get()

    def remove_from_flow_table(self, flows):
        self.log.debug('remove-from-flow-table', flows=flows)
        # TODO: Update PONSIM code to accept incremental flow changes.
        # Once completed, the accepts_add_remove_flow_updates for this
        # device type can be set to True

    def add_to_flow_table(self, flows):
        self.log.debug('add-to-flow-table', flows=flows)
        # TODO: Update PONSIM code to accept incremental flow changes
        # Once completed, the accepts_add_remove_flow_updates for this
        # device type can be set to True

    def update_pm_config(self, device, pm_config):
        log.info("handler-update-pm-config", device=device,
                 pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    @inlineCallbacks
    def reboot(self):
        self.log.info('rebooting', device_id=self.device_id)

        # Update the operational status to ACTIVATING and connect status to
        # UNREACHABLE
        device = self.adapter_agent.get_device(self.device_id)
        previous_oper_status = device.oper_status
        previous_conn_status = device.connect_status
        device.oper_status = OperStatus.ACTIVATING
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Sleep 10 secs, simulating a reboot
        # TODO: send alert and clear alert after the reboot
        yield asleep(10)

        # Change the operational status back to its previous state.  With a
        # real OLT the operational state should be the state the device is
        # after a reboot.
        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)
        device.oper_status = previous_oper_status
        device.connect_status = previous_conn_status
        self.adapter_agent.update_device(device)
        self.log.info('rebooted', device_id=self.device_id)

    def self_test_device(self, device):
        """
        This is called to Self a device based on a NBI call.
        :param device: A Voltha.Device object.
        :return: Will return result of self test
        """
        log.info('self-test-device', device=device.id)
        raise NotImplementedError()

    def disable(self):
        self.log.info('disabling', device_id=self.device_id)

        self.stop_kpi_collection()

        # Get the latest device reference
        device = self.adapter_agent.get_device(self.device_id)

        # Disable all ports on that device
        self.adapter_agent.disable_all_ports(self.device_id)

        # Update the device operational status to UNKNOWN
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the uni logical port from the OLT, if still present
        parent_device = self.adapter_agent.get_device(device.parent_id)
        assert parent_device
        logical_device_id = parent_device.parent_id
        assert logical_device_id
        port_no = device.proxy_address.channel_id
        port_id = 'uni-{}'.format(port_no)
        try:
            port = self.adapter_agent.get_logical_port(logical_device_id,
                                                       port_id)
            self.adapter_agent.delete_logical_port(logical_device_id, port)
        except KeyError:
            self.log.info('logical-port-not-found', device_id=self.device_id,
                          portid=port_id)

        # Remove pon port from parent
        self.pon_port = self._get_pon_port()
        self.adapter_agent.delete_port_reference_from_parent(self.device_id,
                                                             self.pon_port)

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

            # First we verify that we got parent reference and proxy info
            assert device.parent_id
            assert device.proxy_address.device_id
            assert device.proxy_address.channel_id

            # Re-register for proxied messages right away
            self.proxy_address = device.proxy_address
            self.adapter_agent.register_for_proxied_messages(
                device.proxy_address)

            # Re-enable the ports on that device
            self.adapter_agent.enable_all_ports(self.device_id)

            # Refresh the port reference
            self.uni_port = self._get_uni_port()
            self.pon_port = self._get_pon_port()

            # Add the pon port reference to the parent
            self.adapter_agent.add_port_reference_to_parent(device.id,
                                                            self.pon_port)

            # Update the connect status to REACHABLE
            device.connect_status = ConnectStatus.REACHABLE
            self.adapter_agent.update_device(device)

            # re-add uni port to logical device
            parent_device = self.adapter_agent.get_device(device.parent_id)
            logical_device_id = parent_device.parent_id
            assert logical_device_id
            port_no = device.proxy_address.channel_id
            cap = OFPPF_1GB_FD | OFPPF_FIBER
            self.adapter_agent.add_logical_port(logical_device_id, LogicalPort(
                id='uni-{}'.format(port_no),
                ofp_port=ofp_port(
                    port_no=port_no,
                    hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                    name=device.serial_number,
                    config=0,
                    state=OFPPS_LIVE,
                    curr=cap,
                    advertised=cap,
                    peer=cap,
                    curr_speed=OFPPF_1GB_FD,
                    max_speed=OFPPF_1GB_FD
                ),
                device_id=device.id,
                device_port_no=self.uni_port.port_no
            ))

            device = self.adapter_agent.get_device(device.id)
            device.oper_status = OperStatus.ACTIVE
            self.adapter_agent.update_device(device)

            self.start_kpi_collection(device.id)

            self.log.info('re-enabled', device_id=device.id)
        except Exception, e:
            self.log.exception('error-reenabling', e=e)

    def delete(self):
        self.log.info('deleting', device_id=self.device_id)

        # A delete request may be received when an OLT is dsiabled

        # TODO:
        # 1) Remove all flows from the device
        # 2) Remove the device from ponsim

        self.log.info('deleted', device_id=self.device_id)

    def start_kpi_collection(self, device_id):
        def _collect(device_id, prefix):
            # Proxy a message to ponsim_olt. The OLT will then query the ONU for statistics. The reply will
            # arrive proxied back to us in self.receive_message().
            msg = PonSimMetricsRequest(port=self.proxy_address.channel_id)
            self.adapter_agent.send_proxied_message(self.proxy_address, msg)

        self.pm_metrics.start_collector(_collect)

    def stop_kpi_collection(self):
        self.pm_metrics.stop_collector()


    def get_interface_config(self, data):
        interfaceConfig = InterfaceConfig()
        if isinstance(data, OntaniConfig):
            interfaceConfig.ont_ani_config.CopyFrom(data)
        elif isinstance(data, VOntaniConfig):
            interfaceConfig.vont_ani_config.CopyFrom(data)
        elif isinstance(data, VEnetConfig):
            interfaceConfig.venet_config.CopyFrom(data)
        elif isinstance(data, TrafficDescriptorProfileData):
            interfaceConfig.traffic_descriptor_profile_config_data.CopyFrom(
                data)
        elif isinstance(data, TcontsConfigData):
            interfaceConfig.tconts_config_data.CopyFrom(data)
        elif isinstance(data, GemportsConfigData):
            interfaceConfig.gemports_config_data.CopyFrom(data)
        elif isinstance(data, MulticastGemportsConfigData):
            interfaceConfig.multicast_gemports_config_data.CopyFrom(data)
        elif isinstance(data, MulticastDistributionSetData):
            interfaceConfig.multicast_distribution_set_data.CopyFrom(data)
        else:
            return None
        return interfaceConfig

    def xpon_ponsim_onu_interface(self, method_name, data, data2=None):
        interfaceConfig = self.get_interface_config(data)
        if interfaceConfig is not None:
            self.log.info('forwarding-{}-request-to-onu-for-interface-type'
                          .format(xpon_ponsim_onu_itfs[method_name]['log']),
                          interface_type=type(data))
            if data2 is not None:
                self.log.info(interface_type=type(data2))

    def create_interface(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def update_interface(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def remove_interface(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def create_tcont(self, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, tcont_data,
                                       traffic_descriptor_data)

    def update_tcont(self, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, tcont_data,
                                       traffic_descriptor_data)

    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, tcont_data,
                                       traffic_descriptor_data)

    def create_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def update_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def remove_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def create_multicast_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def update_multicast_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def remove_multicast_gemport(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def create_multicast_distribution_set(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def update_multicast_distribution_set(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)

    def remove_multicast_distribution_set(self, data):
        _method_name = sys._getframe().f_code.co_name
        self.xpon_ponsim_onu_interface(_method_name, data)
