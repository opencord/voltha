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
Mock device adapter for testing.
"""
from uuid import uuid4

import arrow
import structlog
import datetime
import random
from klein import Klein
from scapy.layers.l2 import Ether, EAPOL, Padding
from twisted.internet import endpoints
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import LoopingCall
from twisted.web.server import Site
from zope.interface import implementer

from common.utils.asleep import asleep
from voltha.adapters.interface import IAdapterInterface
from voltha.core.flow_decomposer import *
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Device, Port, \
     PmConfigs, PmConfig, Image, ImageDownload
from voltha.protos.voltha_pb2 import SelfTestResponse
from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.common_pb2 import LogLevel, OperStatus, ConnectStatus, \
    AdminState
from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_port, OFPPF_1GB_FD, \
    OFPPF_FIBER, OFPPS_LIVE, ofp_switch_features, OFPC_PORT_STATS, \
    OFPC_GROUP_STATS, OFPC_TABLE_STATS, OFPC_FLOW_STATS
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory

log = structlog.get_logger()


class AdapterPmMetrics:
    class Metrics:
        def __init__(self, config, value):
            self.config = config
            self.value = value

    def __init__(self,device):
        self.pm_names = {'tx_64_pkts','tx_65_127_pkts', 'tx_128_255_pkts',
                         'tx_256_511_pkts', 'tx_512_1023_pkts',
                         'tx_1024_1518_pkts', 'tx_1519_9k_pkts', 'rx_64_pkts',
                         'rx_65_127_pkts', 'rx_128_255_pkts', 'rx_256_511_pkts',
                         'rx_512_1023_pkts', 'rx_1024_1518_pkts',
                         'rx_1519_9k_pkts', 'tx_pkts', 'rx_pkts',
                         'tx_bytes', 'rx_bytes'}
        # This is just to generate more realistic looking values. This would
        # not be implemented in a normal adapter.
        self.rand_ranges = dict (
            tx_64_pkts=[50, 55],
            tx_65_127_pkts=[55,60],
            tx_128_255_pkts=[60,65],
            tx_256_511_pkts=[85,90],
            tx_512_1023_pkts=[90,95],
            tx_1024_1518_pkts=[60,65],
            tx_1519_9k_pkts=[50,55],
            rx_64_pkts=[50, 55],
            rx_65_127_pkts=[55,60],
            rx_128_255_pkts=[60,65],
            rx_256_511_pkts=[85,90],
            rx_512_1023_pkts=[90,95],
            rx_1024_1518_pkts=[60,65],
            rx_1519_9k_pkts=[50,55],
            tx_pkts=[90,100],
            rx_pkts=[90,100],
            rx_bytes=[90000,100000],
            tx_bytes=[90000,100000]
        )
        self.device = device
        self.id = device.id
        self.default_freq = 150
        self.grouped = False
        self.freq_override = False
        self.pon_metrics = dict()
        self.nni_metrics = dict()
        self.lc = None
        for m in self.pm_names:
            self.pon_metrics[m] = \
                    self.Metrics(config = PmConfig(name=m,
                                                   type=PmConfig.COUNTER,
                                                   enabled=True), value = 0)
            self.nni_metrics[m] = \
                    self.Metrics(config = PmConfig(name=m,
                                                   type=PmConfig.COUNTER,
                                                   enabled=True), value = 0)

    def update(self, pm_config):
        if self.default_freq != pm_config.default_freq:
            # Update the callback to the new frequency.
            self.default_freq = pm_config.default_freq
            self.lc.stop()
            self.lc.start(interval=self.default_freq/10)
        for m in pm_config.metrics:
            self.pon_metrics[m.name].config.enabled = m.enabled
            self.nni_metrics[m.name].config.enabled = m.enabled

    def make_proto(self):
        pm_config = PmConfigs(
            id=self.id,
            default_freq=self.default_freq,
            grouped = False,
            freq_override = False)
        for m in sorted(self.pon_metrics):
            pm=self.pon_metrics[m]
            pm_config.metrics.extend([PmConfig(name=pm.config.name,
                                               type=pm.config.type,
                                               enabled=pm.config.enabled)])
        return pm_config

    def collect_pon_metrics(self):
        import random
        rtrn_pon_metrics = dict()
        for m in self.pm_names:
            if self.pon_metrics[m].config.enabled:
                self.pon_metrics[m].value += \
                random.randint(self.rand_ranges[m][0], self.rand_ranges[m][1])
                rtrn_pon_metrics[m] = self.pon_metrics[m].value
        return rtrn_pon_metrics

    def collect_nni_metrics(self):
        import random
        rtrn_nni_metrics = dict()
        for m in self.pm_names:
            if self.nni_metrics[m].config.enabled:
                self.nni_metrics[m].value += \
                random.randint(self.rand_ranges[m][0], self.rand_ranges[m][1])
                rtrn_nni_metrics[m] = self.nni_metrics[m].value
        return rtrn_nni_metrics

    def start_collector(self, device_name, device_id, callback):
        prefix = 'voltha.{}.{}'.format(device_name, device_id)
        self.lc = LoopingCall(callback, device_id, prefix)
        self.lc.start(interval=self.default_freq/10)


@implementer(IAdapterInterface)
class SimulatedOltAdapter(object):
    name = 'simulated_olt'

    supported_device_types = [
        DeviceType(
            id='simulated_olt',
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    app = Klein()

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Voltha project',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.control_endpoint = None
        # Faked PM metrics for testing PM functionality
        self.pm_metrics = None

    def start(self):
        log.debug('starting')

        # setup a basic web server for test control
        self.control_endpoint = endpoints.TCP4ServerEndpoint(reactor, 18880)
        self.control_endpoint.listen(self.get_test_control_site())

        log.info('started')

    def stop(self):
        log.debug('stopping')
        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        # We kick of a simulated activation scenario
        reactor.callLater(0.2, self._simulate_device_activation, device)
        return device

    def reconcile_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        raise NotImplementedError()

    def disable_device(self, device):
        device.oper_status = OperStatus.UNKNOWN
        device.connect_status = ConnectStatus.UNREACHABLE
        self.adapter_agent.update_device(device)

        # Remove the logical device
        logical_device = self.adapter_agent.get_logical_device(device.parent_id)
        self.adapter_agent.delete_logical_device(logical_device)

        # Disable all child devices first
        self.adapter_agent.update_child_devices_state(device.id,
                                                      admin_state=AdminState.DISABLED)

        # Remove the peer references from this device
        self.adapter_agent.delete_all_peer_references(device.id)

        # Set all ports to disabled
        self.adapter_agent.disable_all_ports(device.id)

        log.info('disabled', device_id=device.id)

    def reenable_device(self, device):
        raise NotImplementedError()

    def reboot_device(self, device):
        raise NotImplementedError()

    def delete_device(self, device):
        raise NotImplementedError()

    def download_image(self, device, request):
        log.info('download-image', device=device, request=request)
        try:
            # initiate requesting software download to device
            log.info('device.image_downloads', img_dnld=device.image_downloads)
            pass
        except Exception as e:
            log.exception(e.message)

    def get_image_download_status(self, device, request):
        log.info('get-image-download-status', device=device,\
                request=request)
        try:
            download_completed = False
            # initiate query for progress of download to device
            request.state = random.choice([ImageDownload.DOWNLOAD_SUCCEEDED,
                                           ImageDownload.DOWNLOAD_STARTED,
                                           ImageDownload.DOWNLOAD_FAILED])
            if request.state != ImageDownload.DOWNLOAD_STARTED:
                download_completed = True
            request.downloaded_bytes = random.choice(range(1024,65536))
            # update status based on query output
            self.adapter_agent.update_image_download(request)
            if download_completed == True:
                # restore admin state to enabled
                device.admin_state = AdminState.ENABLED
                self.adapter_agent.update_device(device)
                # TODO:
                # the device admin state will also restore
                # when adapter receiving event notification
                # this will be handled in event handler
        except Exception as e:
            log.exception(e.message)

    def cancel_image_download(self, device, request):
        log.info('cancel-sw-download', device=device,
                request=request)
        try:
            # intiate cancelling software download to device
            # at success delete image download record
            self.adapter_agent.delete_image_download(request)
            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)
        except Exception as e:
            log.exception(e.message)

    def activate_image_update(self, device, request):
        log.info('activate-image-update', device=device, request=request)
        try:
            # initiate activating software update to device
            # at succcess, update image state
            request.image_state = ImageDownload.IMAGE_ACTIVE
            self.adapter_agent.update_image_download(request)
            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)
        except Exception as e:
            log.exception(e.message)

    def revert_image_update(self, device, request):
        log.info('revert-image-updade', device=device, request=request)
        try:
            # initiate reverting software update to device
            # at succcess, update image state
            request.image_state = ImageDownload.IMAGE_INACTIVE
            self.adapter_agent.update_image_download(request)
            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)
        except Exception as e:
            log.exception(e.message)

    def get_device_details(self, device):
        raise NotImplementedError()

    def update_pm_config(self, device, pm_config):
        log.info("adapter-update-pm-config", device=device, pm_config=pm_config)
        self.pm_metrics.update(pm_config)

    def self_test_device(self, device):
        log.info("run-self-test-on-device", device=device.id)
        result = SelfTestResponse(result = random.choice([
            SelfTestResponse.SUCCESS,
            SelfTestResponse.FAILURE,
            SelfTestResponse.NOT_SUPPORTED,
            SelfTestResponse.UNKNOWN_ERROR]))
        return result

    @inlineCallbacks
    def _simulate_device_activation(self, device):

        # first we pretend that we were able to contact the device and obtain
        # additional information about it
        device.root = True
        device.vendor = 'simulated'
        device.model = 'n/a'
        device.hardware_version = 'n/a'
        device.firmware_version = 'n/a'
        device.serial_number = uuid4().hex
        device.connect_status = ConnectStatus.REACHABLE

        image1 = Image(name="olt_candidate1",
                       version="1.0",
                       hash="",
                       install_datetime=datetime.datetime.utcnow().isoformat(),
                       is_active=True,
                       is_committed=True,
                       is_valid=True)

        image2 = Image(name="olt_candidate2",
                       version="1.0",
                       hash="",
                       install_datetime=datetime.datetime.utcnow().isoformat(),
                       is_active=False,
                       is_committed=False,
                       is_valid=True)

        device.images.image.extend([image1, image2])

        self.adapter_agent.update_device(device)

        # Now set the initial PM configuration for this device
        self.pm_metrics=AdapterPmMetrics(device)
        pm_config = self.pm_metrics.make_proto()
        log.info("initial-pm-config", pm_config=pm_config)
        self.adapter_agent.update_device_pm_config(pm_config,init=True)

        # then shortly after we create some ports for the device
        yield asleep(0.05)
        nni_port = Port(
            port_no=2,
            label='NNI facing Ethernet port',
            type=Port.ETHERNET_NNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.adapter_agent.add_port(device.id, nni_port)
        self.adapter_agent.add_port(device.id, Port(
            port_no=1,
            label='PON port',
            type=Port.PON_OLT,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        ))


        # then shortly after we create the logical device with one port
        # that will correspond to the NNI port
        yield asleep(0.05)
        logical_device_id = uuid4().hex[:12]
        dpid = device.mac_address if device.mac_address else \
                ':'.join([a+b for a,b in zip(logical_device_id[::2], logical_device_id[1::2])])
        ld = LogicalDevice(
            # not setting id and datapth_id will let the adapter agent pick id
            desc=ofp_desc(
                hw_desc='simulated pon',
                sw_desc='simulated pon',
                serial_num=uuid4().hex,
                dp_desc='n/a'
            ),
            switch_features=ofp_switch_features(
                n_buffers=256,  # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    OFPC_FLOW_STATS
                    | OFPC_TABLE_STATS
                    | OFPC_PORT_STATS
                    | OFPC_GROUP_STATS
                )
            ),
            root_device_id=device.id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld, dpid=dpid)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=129,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
                name='nni',
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=device.id,
            device_port_no=nni_port.port_no,
            root_port=True
        ))

        # and finally update to active
        device = self.adapter_agent.get_device(device.id)
        device.parent_id = ld_initialized.id
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)

        reactor.callLater(0.1, self._simulate_detection_of_onus, device.id)
        self.start_kpi_collection(device.id)

        self.start_alarm_simulation(device.id)

    @inlineCallbacks
    def _simulate_detection_of_onus(self, device_id):
        try:
            for i in xrange(1, 5):
                log.info('activate-olt-for-onu-{}'.format(i))
                vlan_id = self._olt_side_onu_activation(i)
                yield asleep(0.05)
                self.adapter_agent.child_device_detected(
                    parent_device_id=device_id,
                    parent_port_no=1,
                    child_device_type='simulated_onu',
                    proxy_address=Device.ProxyAddress(
                        device_id=device_id,
                        channel_id=vlan_id
                    ),
                    admin_state=AdminState.ENABLED,
                    vlan=vlan_id
                )
        except Exception as e:
            log.exception('error', e=e)

    def _olt_side_onu_activation(self, seq):
        """
        This is where if this was a real OLT, the OLT-side activation for
        the new ONU should be performed. By the time we return, the OLT shall
        be able to provide tunneled (proxy) communication to the given ONU,
        using the returned information.
        """
        vlan_id = seq + 100
        return vlan_id

    #def update_pm_collection(self, device, pm_collection_config):
        # This is where the metrics to be collected are configured and where
        # the sampling frequency is set.
        #TODO: Here.
    #    pass

    def update_flows_bulk(self, device, flows, groups):
        log.debug('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

        # sample code that analyzes the incoming flow table
        assert len(groups.items) == 0, "Cannot yet deal with groups"

        for flow in flows.items:
            in_port = get_in_port(flow)
            assert in_port is not None

            if in_port == 2:

                # Downstream rule

                for field in get_ofb_fields(flow):
                    if field.type == ETH_TYPE:
                        _type = field.eth_type
                        pass  # construct ether type based condition here

                    elif field.type == IP_PROTO:
                        _proto = field.ip_proto
                        pass  # construct ip_proto based condition here

                    elif field.type == IN_PORT:
                        _port = field.port
                        pass  # construct in_port based condition here

                    elif field.type == VLAN_VID:
                        _vlan_vid = field.vlan_vid
                        pass  # construct VLAN ID based filter condition here

                    elif field.type == VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        pass  # construct VLAN PCP based filter condition here

                    elif field.type == METADATA:
                        pass  # safe to ignore

                    # TODO
                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in get_actions(flow):

                    if action.type == OUTPUT:
                        pass  # construct packet emit rule here

                    elif action.type == PUSH_VLAN:
                        if action.push.ethertype != 0x8100:
                            log.error('unhandled-ether-type',
                                      ethertype=action.push.ethertype)
                        pass  # construct vlan push command here

                    elif action.type == POP_VLAN:
                        pass  # construct vlan pop command here

                    elif action.type == SET_FIELD:
                        assert (action.set_field.field.oxm_class ==
                                ofp.OFPXMC_OPENFLOW_BASIC)
                        field = action.set_field.field.ofb_field
                        if field.type == VLAN_VID:
                            pass  # construct vlan_id set command here
                        else:
                            log.error('unsupported-action-set-field-type',
                                      field_type=field.type)

                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type)

                # final assembly of low level device flow rule and pushing it
                # down to device
                pass

            elif in_port == 1:

                # Upstream rule

                for field in get_ofb_fields(flow):

                    if field.type == ETH_TYPE:
                        _type = field.eth_type
                        pass  # construct ether type based condition here

                    elif field.type == IP_PROTO:
                        _proto = field.ip_proto
                        pass  # construct ip_proto based condition here

                    elif field.type == IN_PORT:
                        _port = field.port
                        pass  # construct in_port based condition here

                    elif field.type == VLAN_VID:
                        _vlan_vid = field.vlan_vid
                        pass  # construct VLAN ID based filter condition here

                    elif field.type == VLAN_PCP:
                        _vlan_pcp = field.vlan_pcp
                        pass  # construct VLAN PCP based filter condition here

                    elif field.type == UDP_SRC:
                        _udp_src = field.udp_src
                        pass  # construct UDP SRC based filter here

                    elif field.type == UDP_DST:
                        _udp_dst = field.udp_dst
                        pass  # construct UDP DST based filter here

                    # TODO
                    else:
                        raise NotImplementedError('field.type={}'.format(
                            field.type))

                for action in get_actions(flow):

                    if action.type == OUTPUT:
                        pass  # construct packet emit rule here

                    elif action.type == PUSH_VLAN:
                        if action.push.ethertype != 0x8100:
                            log.error('unhandled-ether-type',
                                      ethertype=action.push.ethertype)
                        pass  # construct vlan push command here

                    elif action.type == SET_FIELD:
                        assert (action.set_field.field.oxm_class ==
                                ofp.OFPXMC_OPENFLOW_BASIC)
                        field = action.set_field.field.ofb_field
                        if field.type == VLAN_VID:
                            pass  # construct vlan_id set command here
                        else:
                            log.error('unsupported-action-set-field-type',
                                      field_type=field.type)

                    else:
                        log.error('unsupported-action-type',
                                  action_type=action.type)

                # final assembly of low level device flow rule and pushing it
                # down to device
                pass

            else:
                raise Exception('Port should be 1 or 2 by our convention')

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.info('send-proxied-message', proxy_address=proxy_address, msg=msg)
        # we mimic a response by sending the same message back in a short time
        reactor.callLater(
            0.2,
            self.adapter_agent.receive_proxied_message,
            proxy_address,
            msg
        )

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()

    def receive_packet_out(self, logical_device_id, egress_port_no, msg):
        log.info('packet-out', logical_device_id=logical_device_id,
                 egress_port_no=egress_port_no, msg_len=len(msg))

    def receive_inter_adapter_message(self, msg):
        raise NotImplementedError()

    def suppress_alarm(self, filter):
        raise NotImplementedError()

    def unsuppress_alarm(self, filter):
        raise NotImplementedError()

    def start_kpi_collection(self, device_id):

        """Simulate periodic KPI metric collection from the device"""
        import random

        @inlineCallbacks  # pretend that we need to do async calls
        def _collect(device_id, prefix):

            try:
                # Step 1: gather metrics from device (pretend it here) - examples
                # upgraded the metrics to include packet statistics for
                # testing.
                nni_port_metrics = self.pm_metrics.collect_nni_metrics()
                pon_port_metrics = self.pm_metrics.collect_pon_metrics()

                olt_metrics = yield dict(
                    cpu_util=20 + 5 * random.random(),
                    buffer_util=10 + 10 * random.random()
                )

                # Step 2: prepare the KpiEvent for submission
                # we can time-stamp them here (or could use time derived from OLT
                ts = arrow.utcnow().timestamp
                kpi_event = KpiEvent(
                    type=KpiEventType.slice,
                    ts=ts,
                    prefixes={
                        # OLT-level
                        prefix: MetricValuePairs(metrics=olt_metrics),
                        # OLT NNI port
                        prefix + '.nni': MetricValuePairs(
                            metrics=nni_port_metrics),
                        # OLT PON port
                        prefix + '.pon': MetricValuePairs(
                            metrics=pon_port_metrics)
                    }
                )

                # Step 3: submit
                self.adapter_agent.submit_kpis(kpi_event)

            except Exception as e:
                log.exception('failed-to-submit-kpis', e=e)

        self.pm_metrics.start_collector(self.name, device_id ,_collect)
        #prefix = 'voltha.{}.{}'.format(self.name, device_id)
        #lc = LoopingCall(_collect, device_id, prefix)
        #lc.start(interval=15)  # TODO make this configurable

    def start_alarm_simulation(self, device_id):

        """Simulate periodic device alarms"""
        import random

        def _generate_alarm(device_id):

            try:
                # Randomly choose values for each enum types
                severity = random.choice(list(
                    v for k, v in
                    AlarmEventSeverity.DESCRIPTOR.enum_values_by_name.items()))

                state = random.choice(list(
                    v for k, v in
                    AlarmEventState.DESCRIPTOR.enum_values_by_name.items()))

                type = random.choice(list(
                    v for k, v in
                    AlarmEventType.DESCRIPTOR.enum_values_by_name.items()))

                category = random.choice(list(
                    v for k, v in
                    AlarmEventCategory.DESCRIPTOR.enum_values_by_name.items()))

                description = "Simulated alarm - " \
                              "device:{} " \
                              "type:{} " \
                              "severity:{} " \
                              "state:{} " \
                              "category:{}".format(device_id,
                                                   type.name,
                                                   severity.name,
                                                   state.name,
                                                   category.name)

                current_context = {}
                for key, value in self.__dict__.items():
                    current_context[key] = str(value)

                alarm_event = self.adapter_agent.create_alarm(
                    resource_id=device_id,
                    type=type.number,
                    category=category.number,
                    severity=severity.number,
                    state=state.number,
                    description=description,
                    context=current_context)

                self.adapter_agent.submit_alarm(device_id, alarm_event)

            except Exception as e:
                log.exception('failed-to-submit-alarm', e=e)

        alarm_lc = LoopingCall(_generate_alarm, device_id)
        alarm_lc.start(30)

    def create_interface(self, device, data):
        raise NotImplementedError()

    def update_interface(self, device, data):
        raise NotImplementedError()

    def remove_interface(self, device, data):
        raise NotImplementedError()

    def receive_onu_detect_state(self, device_id, state):
        raise NotImplementedError()

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        raise NotImplementedError()

    def create_gemport(self, device, data):
        raise NotImplementedError()

    def update_gemport(self, device, data):
        raise NotImplementedError()

    def remove_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def update_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def remove_multicast_gemport(self, device, data):
        raise NotImplementedError()

    def create_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def update_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    def remove_multicast_distribution_set(self, device, data):
        raise NotImplementedError()

    # ~~~~~~~~~~~~~~~~~~~~ Embedded test Klein rest server ~~~~~~~~~~~~~~~~~~~~

    def get_test_control_site(self):
        return Site(self.app.resource())

    @app.route('/devices/<string:device_id>/detect_onus')
    def detect_onus(self, request, device_id):
        log.info('detect-onus', request=request, device_id=device_id)
        self._simulate_detection_of_onus(device_id)
        return '{"status": "OK"}'

    @app.route('/devices/<string:device_id>/test_eapol_in')
    def test_eapol_in(self, request, device_id):
        """Simulate a packet in message posted upstream"""
        log.info('test_eapol_in', request=request, device_id=device_id)
        eapol_start = str(
            Ether(src='00:11:22:33:44:55') /
            EAPOL(type=1, len=0) /
            Padding(load=42 * '\x00')
        )
        device = self.adapter_agent.get_device(device_id)
        self.adapter_agent.send_packet_in(logical_device_id=device.parent_id,
                                          logical_port_no=1,
                                          packet=eapol_start)
        return '{"status": "sent"}'
