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
Agent to play gateway between CORE and an individual adapter.
"""
from uuid import uuid4

import arrow
import structlog
from google.protobuf.json_format import MessageToJson
from scapy.packet import Packet
from twisted.internet.defer import inlineCallbacks, returnValue
from zope.interface import implementer

from common.event_bus import EventBusClient
from common.frameio.frameio import hexify
from common.utils.id_generation import create_cluster_logical_device_ids
from voltha.adapters.interface import IAdapterAgent
from voltha.protos import third_party
from voltha.core.flow_decomposer import OUTPUT
from voltha.protos.device_pb2 import Device, Port, PmConfigs
from voltha.protos.events_pb2 import AlarmEvent, AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory
from voltha.protos.events_pb2 import KpiEvent, KpiEvent2
from voltha.protos.voltha_pb2 import DeviceGroup, LogicalDevice, \
    LogicalPort, AdminState, OperStatus, AlarmFilterRuleKey
from voltha.registry import registry
from common.utils.id_generation import create_cluster_device_id
import re


class MacAddressError(BaseException):
    def __init__(self, error):
        self.error = error


class IDError(BaseException):
    def __init__(self, error):
        self.error = error


@implementer(IAdapterAgent)
class AdapterAgent(object):
    """
    Gate-keeper between CORE and device adapters.

    On one side it interacts with Core's internal model and update/dispatch
    mechanisms.

    On the other side, it interacts with the adapters standard interface as
    defined in
    """

    def __init__(self, adapter_name, adapter_cls):
        self.adapter_name = adapter_name
        self.adapter_cls = adapter_cls
        self.core = registry('core')
        self.adapter = None
        self.adapter_node_proxy = None
        self.root_proxy = self.core.get_proxy('/')
        self._rx_event_subscriptions = {}
        self._tx_event_subscriptions = {}
        self.event_bus = EventBusClient()
        self.packet_out_subscriptions = {}
        self.log = structlog.get_logger(adapter_name=adapter_name)
        self._onu_detect_event_subscriptions = {}

    @property
    def name(self):
        return self.adapter_name

    @inlineCallbacks
    def start(self):
        self.log.debug('starting')
        config = self._get_adapter_config()  # this may be None
        try:
            adapter = self.adapter_cls(self, config)
            yield adapter.start()
            self.adapter = adapter
            self.adapter_node_proxy = self._update_adapter_node()
            self._update_device_types()
        except Exception, e:
            self.log.exception(e)
        self.log.info('started')
        returnValue(self)

    @inlineCallbacks
    def stop(self):
        self.log.debug('stopping')
        if self.adapter is not None:
            yield self.adapter.stop()
            self.adapter = None
        self.log.info('stopped')

    def _get_adapter_config(self):
        """
        Opportunistically load persisted adapter configuration.
        Return None if no configuration exists yet.
        """
        proxy = self.core.get_proxy('/')
        try:
            config = proxy.get('/adapters/' + self.adapter_name)
            return config
        except KeyError:
            return None

    def _update_adapter_node(self):
        """
        Creates or updates the adapter node object based on self
        description from the adapter.
        """

        adapter_desc = self.adapter.adapter_descriptor()
        assert adapter_desc.id == self.adapter_name
        path = self._make_up_to_date(
            '/adapters', self.adapter_name, adapter_desc)
        return self.core.get_proxy(path)

    def _update_device_types(self):
        """
        Make sure device types are registered in Core
        """
        device_types = self.adapter.device_types()
        for device_type in device_types.items:
            key = device_type.id
            self._make_up_to_date('/device_types', key, device_type)

    def _make_up_to_date(self, container_path, key, data):
        full_path = container_path + '/' + str(key)
        root_proxy = self.core.get_proxy('/')
        try:
            root_proxy.get(full_path)
            root_proxy.update(full_path, data)
        except KeyError:
            root_proxy.add(container_path, data)
        return full_path

    def _remove_node(self, container_path, key):
        """
        Remove a node from the data model
        :param container_path: path to node
        :param key: node
        :return: None
        """
        full_path = container_path + '/' + str(key)
        root_proxy = self.core.get_proxy('/')
        try:
            root_proxy.get(full_path)
            root_proxy.remove(full_path)
        except KeyError:
            # Node does not exist
            pass

    # ~~~~~~~~~~~~~~~~~~~~~ Core-Facing Service ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def adopt_device(self, device):
        return self.adapter.adopt_device(device)

    def reconcile_device(self, device):
        return self.adapter.reconcile_device(device)

    def abandon_device(self, device):
        return self.adapter.abandon_device(device)

    def disable_device(self, device):
        return self.adapter.disable_device(device)

    def reenable_device(self, device):
        return self.adapter.reenable_device(device)

    def reboot_device(self, device):
        return self.adapter.reboot_device(device)

    def download_image(self, device, request):
        return self.adapter.download_image(device, request)

    def get_image_download_status(self, device, request):
        return self.adapter.get_image_download_status(device, request)

    def cancel_image_download(self, device, request):
        return self.adapter.cancel_image_download(device, request)

    def activate_image_update(self, device, request):
        return self.adapter.activate_image_update(device, request)

    def revert_image_update(self, device, request):
        return self.adapter.revert_image_update(device, request)

    def self_test(self, device):
        return self.adapter.self_test_device(device)

    def delete_device(self, device):
        # Remove all child devices
        self.delete_all_child_devices(device.id)
        # Removing device
        return self.adapter.delete_device(device)

    def get_device_details(self, device):
        return self.adapter.get_device_details(device)

    def update_flows_bulk(self, device, flows, groups):
        return self.adapter.update_flows_bulk(device, flows, groups)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        return self.adapter.update_flows_incrementally(device, flow_changes, group_changes)

    def suppress_alarm(self, filter):
        return self.adapter.suppress_alarm(filter)

    def unsuppress_alarm(self, filter):
        return self.adapter.unsuppress_alarm(filter)

    # def update_pm_collection(self, device, pm_collection_config):
    #    return self.adapter.update_pm_collection(device, pm_collection_config)

    def create_interface(self, device, data):
        return self.adapter.create_interface(device, data)

    def update_interface(self, device, data):
        return self.adapter.update_interface(device, data)

    def remove_interface(self, device, data):
        return self.adapter.remove_interface(device, data)

    def create_tcont(self, device, tcont_data, traffic_descriptor_data):
        return self.adapter.create_tcont(device, tcont_data,
                                         traffic_descriptor_data)

    def update_tcont(self, device, tcont_data, traffic_descriptor_data):
        return self.adapter.update_tcont(device, tcont_data,
                                         traffic_descriptor_data)

    def remove_tcont(self, device, tcont_data, traffic_descriptor_data):
        return self.adapter.remove_tcont(device, tcont_data,
                                         traffic_descriptor_data)

    def create_gemport(self, device, data):
        return self.adapter.create_gemport(device, data)

    def update_gemport(self, device, data):
        return self.adapter.update_gemport(device, data)

    def remove_gemport(self, device, data):
        return self.adapter.remove_gemport(device, data)

    def create_multicast_gemport(self, device, data):
        return self.adapter.create_multicast_gemport(device, data)

    def update_multicast_gemport(self, device, data):
        return self.adapter.update_multicast_gemport(device, data)

    def remove_multicast_gemport(self, device, data):
        return self.adapter.remove_multicast_gemport(device, data)

    def create_multicast_distribution_set(self, device, data):
        return self.adapter.create_multicast_distribution_set(device, data)

    def update_multicast_distribution_set(self, device, data):
        return self.adapter.update_multicast_distribution_set(device, data)

    def remove_multicast_distribution_set(self, device, data):
        return self.adapter.remove_multicast_distribution_set(device, data)

    def simulate_alarm(self, device, request):
        return self.adapter.simulate_alarm(device, request)

    # ~~~~~~~~~~~~~~~~~~~ Adapter-Facing Service ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def get_device(self, device_id):
        return self.root_proxy.get('/devices/{}'.format(device_id))

    def get_child_device(self, parent_device_id, **kwargs):
        """
        Retrieve a child device object belonging
        to the specified parent device based on some match
        criteria. The first child device that matches the
        provided criteria is returned.
        :param parent_device_id: parent's device id
        :param **kwargs: arbitrary list of match criteria
        :return: Child Device Object or None
        """
        # Get all arguments to be used for comparison
        # Note that for now we are only matching on the
        # PON Interface Id (parent_port_no), ONU ID & SERIAL NUMBER
        # Other matching fields can be added as required in the future
        parent_port_no = kwargs.pop('parent_port_no', None)
        onu_id = kwargs.pop('onu_id', None)
        serial_number = kwargs.pop('serial_number', None)
        if onu_id is None and serial_number is None: return None

        # Get all devices
        devices = self.root_proxy.get('/devices')

        # Get all child devices with the same parent ID
        children_ids = set(
            d.id for d in devices if d.parent_id == parent_device_id)

        # Loop through all the child devices with this parent ID
        for child_id in children_ids:
            found = True
            device = self.get_device(child_id)

            # Does this child device match the passed in ONU ID?
            found_onu_id = False
            if onu_id is not None:
                if device.proxy_address.onu_id == onu_id:
                    # Does the ONU ID belong to the right PON port?
                    # (ONU IDs are not unique across PON ports)
                    if parent_port_no is not None:
                        if device.parent_port_no ==  parent_port_no:
                            found_onu_id = True
                    else:
                        found_onu_id = True

            # Does this child device match the passed in SERIAL NUMBER?
            found_serial_number = False
            if serial_number is not None:
                if device.serial_number == serial_number:
                    found_serial_number = True
            # Match ONU ID and SERIAL NUMBER
            if onu_id is not None and serial_number is not None:
                found = found_onu_id & found_serial_number
            # Otherwise ONU ID or SERIAL NUMBER
            else:
                found = found_onu_id | found_serial_number

            # Return the matched child device
            if found is True:
                return device

        return None

    def add_device(self, device):
        assert isinstance(device, Device)
        self._make_up_to_date('/devices', device.id, device)

        # Ultimately, assign devices to device grpups.
        # see https://jira.opencord.org/browse/CORD-838

        dg = DeviceGroup(id='1')
        self._make_up_to_date('/device_groups', dg.id, dg)

        # add device to device group
        # see https://jira.opencord.org/browse/CORD-838

    def update_device(self, device):
        assert isinstance(device, Device)

        # we run the update through the device_agent so that the change
        # does not loop back to the adapter unnecessarily
        device_agent = self.core.get_device_agent(device.id)
        device_agent.update_device(device)

    def update_device_pm_config(self, device_pm_config, init=False):
        assert isinstance(device_pm_config, PmConfigs)

        # we run the update through the device_agent so that the change
        # does not loop back to the adapter unnecessarily
        device_agent = self.core.get_device_agent(device_pm_config.id)
        device_agent.update_device_pm_config(device_pm_config, init)

    def update_adapter_pm_config(self, device_id, device_pm_config):
        device = self.get_device(device_id)
        self.adapter.update_pm_config(device, device_pm_config)

    def update_image_download(self, img_dnld):
        self.log.info('update-image-download', img_dnld=img_dnld)
        try:
            # we run the update through the device_agent so that the change
            # does not loop back to the adapter unnecessarily
            device_agent = self.core.get_device_agent(img_dnld.id)
            device_agent.update_device_image_download(img_dnld)
        except Exception as e:
            self.log.exception(e.message)

    def delete_image_download(self, img_dnld):
        self.log.info('delete-image-download', img_dnld=img_dnld)
        try:
            root_proxy = self.core.get_proxy('/')
            path = '/devices/{}/image_downloads/{}'. \
                format(img_dnld.id, img_dnld.name)
            root_proxy.get(path)
            root_proxy.remove(path)
            device_agent = self.core.get_device_agent(img_dnld.id)
            device_agent.unregister_device_image_download(img_dnld.name)
        except Exception as e:
            self.log.exception(e.message)

    def _add_peer_reference(self, device_id, port):
        # for referential integrity, add/augment references
        port.device_id = device_id
        me_as_peer = Port.PeerPort(device_id=device_id, port_no=port.port_no)
        for peer in port.peers:
            peer_port_path = '/devices/{}/ports/{}'.format(
                peer.device_id, peer.port_no)
            peer_port = self.root_proxy.get(peer_port_path)
            if me_as_peer not in peer_port.peers:
                new = peer_port.peers.add()
                new.CopyFrom(me_as_peer)
            self.root_proxy.update(peer_port_path, peer_port)

    def _del_peer_reference(self, device_id, port):
        me_as_peer = Port.PeerPort(device_id=device_id, port_no=port.port_no)
        for peer in port.peers:
            try:
                peer_port_path = '/devices/{}/ports/{}'.format(
                    peer.device_id, peer.port_no)
                peer_port = self.root_proxy.get(peer_port_path)
                if me_as_peer in peer_port.peers:
                    peer_port.peers.remove(me_as_peer)
                self.root_proxy.update(peer_port_path, peer_port)
            except Exception:
                # if the device on the other side was already remove
                # the key cannot be found under /devices/<device_id>
                pass

    def add_port(self, device_id, port):
        assert isinstance(port, Port)

        # for referential integrity, add/augment references
        self._add_peer_reference(device_id, port)

        # Add port
        self._make_up_to_date('/devices/{}/ports'.format(device_id),
                              port.port_no, port)

    def get_ports(self, device_id, port_type=None):
        # assert Port.PortType.DESCRIPTOR.values_by_name[port_type]
        ports = self.root_proxy.get('/devices/{}/ports'.format(device_id))
        if port_type is None:
            return ports
        else:
            return [p for p in ports if p.type == port_type]

    def get_port(self, device_id, port_no=None, label=None):
        ports = self.root_proxy.get('/devices/{}/ports'.format(device_id))
        for p in ports:
            if p.label == label or p.port_no == port_no:
                return p
        return None

    def delete_port(self, device_id, port):
        assert isinstance(port, Port)
        # for referential integrity, add/augment references
        self._del_peer_reference(device_id, port)
        # Delete port
        self._remove_node('/devices/{}/ports'.format(device_id), port.port_no)

    def disable_all_ports(self, device_id):
        """
        Disable all ports on that device, i.e. change the admin status to
        disable and operational status to UNKNOWN.
        :param device_id: device id
        :return: None
        """

        # get all device ports
        ports = self.root_proxy.get('/devices/{}/ports'.format(device_id))
        for port in ports:
            port.admin_state = AdminState.DISABLED
            port.oper_status = OperStatus.UNKNOWN
            self._make_up_to_date('/devices/{}/ports'.format(device_id),
                                  port.port_no, port)

    def enable_all_ports(self, device_id):
        """
        Re-enable all ports on that device, i.e. change the admin status to
        enabled and operational status to ACTIVE
        :param device_id: device id
        :return: None
        """

        # get all device ports
        ports = self.root_proxy.get('/devices/{}/ports'.format(device_id))
        for port in ports:
            port.admin_state = AdminState.ENABLED
            port.oper_status = OperStatus.ACTIVE
            self._make_up_to_date('/devices/{}/ports'.format(device_id),
                                  port.port_no, port)

    def update_operstatus_all_ports(self, device_id, oper_status):
        ports = self.root_proxy.get('/devices/{}/ports'.format(device_id))
        for port in ports:
            port.oper_status = oper_status
            self._make_up_to_date('/devices/{}/ports'.format(device_id),
                                  port.port_no, port)

    def delete_all_peer_references(self, device_id):
        """
        Remove all peer port references for that device
        :param device_id: device_id of device
        :return: None
        """
        ports = self.root_proxy.get('/devices/{}/ports'.format(device_id))
        for port in ports:
            port_path = '/devices/{}/ports/{}'.format(device_id, port.port_no)
            for peer in port.peers:
                port.peers.remove(peer)
            self.root_proxy.update(port_path, port)

    def delete_port_reference_from_parent(self, device_id, port):
        """
        Delete the port reference from the parent device
        :param device_id: id of device containing the port
        :param port: port to remove
        :return: None
        """
        assert isinstance(port, Port)
        self.log.debug('delete-port-reference', device_id=device_id, port=port)
        self._del_peer_reference(device_id, port)

        # update child port details
        self._make_up_to_date('/devices/{}/ports'.format(device_id),
                              port.port_no, port)

    def add_port_reference_to_parent(self, device_id, port):
        """
        Add the port reference to the parent device
        :param device_id: id of device containing the port
        :param port: port to add
        :return: None
        """
        assert isinstance(port, Port)
        self.log.debug('add-port-reference', device_id=device_id, port=port)
        self._add_peer_reference(device_id, port)
        # update child port details
        self._make_up_to_date('/devices/{}/ports'.format(device_id),
                              port.port_no, port)

    def get_logical_device(self, logical_device_id):
        return self.root_proxy.get('/logical_devices/{}'.format(
            logical_device_id))

    def get_logical_port(self, logical_device_id, port_id):
        return self.root_proxy.get('/logical_devices/{}/ports/{}'.format(
            logical_device_id, port_id))

    def get_meter_band(self, logical_device_id, meter_id):
        meters = list(self.root_proxy.get('/logical_devices/{}/meters'.format(
            logical_device_id)).items)
        for meter in meters:
            if meter.config.meter_id == meter_id:
                '''
                # Returns
                message ofp_meter_config {
                    uint32        flags = 1;
                    uint32        meter_id = 2;
                    repeated ofp_meter_band_header bands = 3;
                };
                '''
                return meter.config
        return None

    def _create_cluster_ids_from_dpid(self, dpid):
        """
        Create a logical device id using a datapath id.
        :param dpid: Must be present and formatted as a mac address
        :return: a unique logical device id and a formatted datapath id.   If
        the dpid was already registered then an exception will be raised.
        """
        switch_id = int(dpid.replace(':', ''), 16)
        logical_devices = self.root_proxy.get('/logical_devices')
        existing_ids = set(ld.id for ld in logical_devices)
        existing_datapath_ids = set(ld.datapath_id for ld in logical_devices)
        core_id = registry('core').core_store_id

        ld_id, dp_id = create_cluster_logical_device_ids(core_id, switch_id)
        ids_exist = dp_id in existing_datapath_ids or \
                    ld_id in existing_ids
        if not ids_exist:
            return ld_id, dp_id
        else:
            self.log.error('ID-already-registered', logical_id=ld_id,
                           dpid=dpid)
            raise IDError('ID-already-registered')

    def _is_valid_mac_address(self, data):
        return re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                        data)

    def create_logical_device(self, logical_device, dpid=None):
        """
        Allow the adapters to provide their own datapath id.  This must
        be the OLT MAC address.  If the dpid is None or is not a mac
        address then an exception will be raised.
        :param logical_device: logical device
        :param dpid: OLT MAC address.  dpid default param is None just to be
        backward compatible with existing adapters.
        :return: updated logical device
        """
        assert isinstance(logical_device, LogicalDevice)

        # Validate the dpid - it needs to be present and formatted as a mac
        # address
        if dpid:
            dpid = dpid.lower()
            if not self._is_valid_mac_address(dpid):
                self.log.error('DPID-not-a-mac-address', dpid=dpid)
                raise MacAddressError('DPID-not-a-mac-address')
        else:
            self.log.error('DPID-cannot-be-none')
            raise MacAddressError("DPID-cannot-be-none")

        if not logical_device.id:
            ld_id, dp_id = self._create_cluster_ids_from_dpid(dpid)
            logical_device.id = ld_id
            logical_device.datapath_id = dp_id

        if not logical_device.desc.mfr_desc:
            logical_device.desc.mfr_desc = "VOLTHA Project"

        self._make_up_to_date('/logical_devices',
                              logical_device.id, logical_device)

        # Keep a reference to the packet out subscription as it will be
        # referred during removal
        self.packet_out_subscriptions[logical_device.id] = self.event_bus.subscribe(
            topic='packet-out:{}'.format(logical_device.id),
            callback=lambda _, p: self.receive_packet_out(logical_device.id, p)
        )

        return logical_device

    def reconcile_logical_device(self, logical_device_id):
        """
        This is called by the adapter to reconcile the physical device with
        the logical device.  For now, we only set the packet-out subscription
        :param logical_device_id:
        :return:
        """
        # Keep a reference to the packet out subscription as it will be
        # referred during removal
        self.packet_out_subscriptions[logical_device_id] = self.event_bus.subscribe(
            topic='packet-out:{}'.format(logical_device_id),
            callback=lambda _, p: self.receive_packet_out(logical_device_id, p)
        )

    def delete_logical_device(self, logical_device):
        """
        This will remove the logical device as well as all logical ports
        associated with it
        :param logical_device: The logical device to remove
        :return: None
        """
        assert isinstance(logical_device, LogicalDevice)

        # Remove packet out subscription
        self.event_bus.unsubscribe(self.packet_out_subscriptions[logical_device.id])
        del self.packet_out_subscriptions[logical_device.id]

        # Remove node from the data model - this will trigger the logical
        # device 'remove callbacks' as well as logical ports 'remove
        # callbacks' if present
        self._remove_node('/logical_devices', logical_device.id)

    def receive_packet_out(self, logical_device_id, ofp_packet_out):

        def get_port_out(opo):
            for action in opo.actions:
                if action.type == OUTPUT:
                    return action.output.port

        out_port = get_port_out(ofp_packet_out)
        frame = ofp_packet_out.data
        self.log.debug('rcv-packet-out', logical_device_id=logical_device_id,
                       egress_port_no=out_port, adapter_name=self.adapter_name,
                       data=hexify(ofp_packet_out.data))
        self.adapter.receive_packet_out(logical_device_id, out_port, frame)

    def add_logical_port(self, logical_device_id, port):
        assert isinstance(port, LogicalPort)
        self._make_up_to_date(
            '/logical_devices/{}/ports'.format(logical_device_id),
            port.id, port)

    def delete_logical_port(self, logical_device_id, port):
        assert isinstance(port, LogicalPort)
        self._remove_node('/logical_devices/{}/ports'.format(
            logical_device_id), port.id)

    def delete_logical_port_by_id(self, logical_device_id, port_id):
        self._remove_node('/logical_devices/{}/ports'.format(
            logical_device_id), port_id)

    def update_logical_port(self, logical_device_id, port):
        assert isinstance(port, LogicalPort)
        self.log.debug('update-logical-port',
                       logical_device_id=logical_device_id,
                       port=port)
        self._make_up_to_date(
            '/logical_devices/{}/ports'.format(logical_device_id),
            port.id, port)

    def get_child_devices(self, parent_device_id):
        try:
            devices = self.root_proxy.get('/devices')
            children = [d for d in devices if d.parent_id == parent_device_id]
            return children
        except Exception, e:
            self.log.exception('failure', e=e)

    def subscribe_to_proxy_child_messages(self, proxy_address):
        topic = self._gen_tx_proxy_address_topic(proxy_address)
        self._tx_event_subscriptions[topic] = self.event_bus.subscribe(
            topic, lambda t, m: self._send_proxied_message(proxy_address, m))

    def reconcile_child_devices(self, parent_device_id):
        children = self.get_child_devices(parent_device_id)
        for child in children:
            # First subscribe to proxy messages from a chile device
            self.subscribe_to_proxy_child_messages(child.proxy_address)

            # Then trigger the reconciliation of the existing child device
            device_agent = self.core.get_device_agent(child.id)
            device_agent.reconcile_existing_device(child)

    # Obselete API - discouraged to be decommissioned after
    # adapters are align to new APIs
    def child_device_detected(self,
                              parent_device_id,
                              parent_port_no,
                              child_device_type,
                              proxy_address,
                              admin_state,
                              **kw):
        # we create new ONU device objects and insert them into the config
        device = Device(
            id=create_cluster_device_id(self.core.core_store_id),
            # id=uuid4().hex[:12],
            type=child_device_type,
            parent_id=parent_device_id,
            parent_port_no=parent_port_no,
            proxy_address=proxy_address,
            admin_state=admin_state,
            **kw
        )
        self._make_up_to_date(
            '/devices', device.id, device)

        topic = self._gen_tx_proxy_address_topic(proxy_address)
        self._tx_event_subscriptions[topic] = self.event_bus.subscribe(
            topic, lambda t, m: self._send_proxied_message(proxy_address, m))

    def add_onu_device(self,
                       parent_device_id,
                       parent_port_no,
                       vendor_id,
                       proxy_address,
                       admin_state,
                       **kw):

        device_type = None

        for dt in self.root_proxy.get('/device_types'):
            if (dt.vendor_id == vendor_id or vendor_id in dt.vendor_ids) and \
                    dt.id.endswith("_onu"):
                device_type = dt

        assert device_type is not None

        # we create new ONU device objects and insert them into the config
        device = Device(
            id=create_cluster_device_id(self.core.core_store_id),
            # id=uuid4().hex[:12],
            type=device_type.id,
            vendor_id=vendor_id,
            parent_id=parent_device_id,
            parent_port_no=parent_port_no,
            proxy_address=proxy_address,
            admin_state=admin_state,
            adapter=device_type.adapter,
            **kw
        )
        self._make_up_to_date('/devices', device.id, device)

        topic = self._gen_tx_proxy_address_topic(proxy_address)
        self._tx_event_subscriptions[topic] = self.event_bus.subscribe(
            topic, lambda t, m: self._send_proxied_message(proxy_address, m))

    def get_child_device_with_proxy_address(self, proxy_address):
        # Proxy address is defined as {parent id, channel_id}
        devices = self.root_proxy.get('/devices')
        children_ids = set(d.id for d in devices if d.parent_id ==
                           proxy_address.device_id)
        for child_id in children_ids:
            device = self.get_device(child_id)
            if device.proxy_address == proxy_address:
                return device

    def remove_all_logical_ports(self, logical_device_id):
        """ Remove all logical ports from a given logical device"""
        ports = self.root_proxy.get('/logical_devices/{}/ports')
        for port in ports:
            self._remove_node('/logical_devices/{}/ports', port.id)

    def delete_all_child_devices(self, parent_device_id):
        """ Remove all ONUs from a given OLT """
        devices = self.root_proxy.get('/devices')
        children_ids = set()
        for device in devices:
            if device.parent_id == parent_device_id:
                children_ids.add(device.id)
                topic = self._gen_tx_proxy_address_topic(device.proxy_address)
                self.event_bus.unsubscribe(self._tx_event_subscriptions[topic])
                del self._tx_event_subscriptions[topic]

        self.log.debug('devices-to-delete',
                       parent_id=parent_device_id,
                       children_ids=children_ids)
        for child_id in children_ids:
            self._remove_node('/devices', child_id)

    def update_child_devices_state(self,
                                   parent_device_id,
                                   oper_status=None,
                                   connect_status=None,
                                   admin_state=None):
        """ Update status of all child devices """
        devices = self.root_proxy.get('/devices')
        children_ids = set(
            d.id for d in devices if d.parent_id == parent_device_id)
        self.log.debug('update-devices',
                       parent_id=parent_device_id,
                       children_ids=children_ids,
                       oper_status=oper_status,
                       connect_status=connect_status,
                       admin_state=admin_state)

        for child_id in children_ids:
            device = self.get_device(child_id)
            if oper_status is not None:
                device.oper_status = oper_status
            if connect_status:
                device.connect_status = connect_status
            if admin_state:
                device.admin_state = admin_state
            self._make_up_to_date(
                '/devices', device.id, device)

    def delete_child_device(self, parent_device_id, child_device_id,
                            onu_device=None):
        if onu_device is None:
            onu_device = self.root_proxy.get('/devices/{}'.format(child_device_id))
        if onu_device is not None:
            assert isinstance(onu_device, Device)
            if onu_device.parent_id == parent_device_id:
                self.log.debug('deleting-child-device',
                               parent_device_id=parent_device_id,
                               child_device_id=child_device_id)
                topic = self._gen_tx_proxy_address_topic(
                    onu_device.proxy_address)
                self.event_bus.unsubscribe(self._tx_event_subscriptions[topic])
                del self._tx_event_subscriptions[topic]
                try:
                    self._remove_node('/devices', child_device_id)
                except Exception:
                    pass

    def _gen_rx_proxy_address_topic(self, proxy_address):
        """Generate unique topic name specific to this proxy address for rx"""
        topic = 'rx:' + MessageToJson(proxy_address)
        return topic

    def _gen_tx_proxy_address_topic(self, proxy_address):
        """Generate unique topic name specific to this proxy address for tx"""
        topic = 'tx:' + MessageToJson(proxy_address)
        return topic

    def register_for_proxied_messages(self, proxy_address):
        topic = self._gen_rx_proxy_address_topic(proxy_address)
        self._rx_event_subscriptions[topic] = self.event_bus.subscribe(
            topic,
            lambda t, m: self._receive_proxied_message(proxy_address, m))

    def unregister_for_proxied_messages(self, proxy_address):
        topic = self._gen_rx_proxy_address_topic(proxy_address)
        self.event_bus.unsubscribe(self._rx_event_subscriptions[topic])
        del self._rx_event_subscriptions[topic]

    def _receive_proxied_message(self, proxy_address, msg):
        self.adapter.receive_proxied_message(proxy_address, msg)

    def send_proxied_message(self, proxy_address, msg):
        topic = self._gen_tx_proxy_address_topic(proxy_address)
        self.event_bus.publish(topic, msg)

    def _send_proxied_message(self, proxy_address, msg):
        self.adapter.send_proxied_message(proxy_address, msg)

    def receive_proxied_message(self, proxy_address, msg):
        topic = self._gen_rx_proxy_address_topic(proxy_address)
        self.event_bus.publish(topic, msg)

    def register_for_inter_adapter_messages(self):
        self.event_bus.subscribe(self.adapter_name,
                                 lambda t,
                                        m: self.adapter.receive_inter_adapter_message(
                                     m))

    def unregister_for_inter_adapter_messages(self):
        self.event_bus.unsubscribe(self.adapter_name)

    def publish_inter_adapter_message(self, device_id, msg):
        # Get the device from the device_id
        device = self.get_device(device_id)
        assert device is not None

        # Publish a message to the adapter that is responsible
        # for managing this device
        self.event_bus.publish(device.type, msg)

    # ~~~~~~~~~~~~~~~~~~ Handling packet-in and packet-out ~~~~~~~~~~~~~~~~~~~~

    def send_packet_in(self, logical_device_id, logical_port_no, packet):
        self.log.debug('send-packet-in', logical_device_id=logical_device_id,
                       logical_port_no=logical_port_no, packet=hexify(packet))

        if isinstance(packet, Packet):
            packet = str(packet)

        topic = 'packet-in:' + logical_device_id
        self.event_bus.publish(topic, (logical_port_no, packet))

    # ~~~~~~~~~~~~~~~~~~~ Handling KPI metric submissions ~~~~~~~~~~~~~~~~~~~~~

    def submit_kpis(self, kpi_event_msg):
        try:
            assert isinstance(kpi_event_msg, (KpiEvent, KpiEvent2))
            self.event_bus.publish('kpis', kpi_event_msg)
        except Exception as e:
            self.log.exception('failed-kpi-submission',
                               type=type(kpi_event_msg))

    # # ~~~~~~~~~~~~~~~~~~~~~~~~~~ Handle flow stats ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def update_flow_stats(self, logical_device_id, flow_id, packet_count=0,
                          byte_count=0):
        flows = self.root_proxy.get(
            'logical_devices/{}/flows'.format(logical_device_id))
        flow_to_update = None
        for flow in flows:
            if flow.id == flow_id:
                flow_to_update = flow
                flow_to_update.packet_count = packet_count
                flow_to_update.byte_count = byte_count
                break
        if flow_to_update is not None:
            self._make_up_to_date(
                'logical_devices/{}/flows'.format(logical_device_id),
                flow_to_update.id, flow_to_update)
        else:
            self.log.warn('flow-to-update-not-found',
                          logical_device_id=logical_device_id, flow_id=flow_id)

    # ~~~~~~~~~~~~~~~~~~~ Handle alarm submissions ~~~~~~~~~~~~~~~~~~~~~

    def create_alarm(self, id=None, resource_id=None, description=None,
                     raised_ts=0, changed_ts=0,
                     type=AlarmEventType.EQUIPMENT,
                     category=AlarmEventCategory.PON,
                     severity=AlarmEventSeverity.MINOR,
                     state=AlarmEventState.RAISED,
                     context=None,
                     logical_device_id=None,
                     alarm_type_name=None):

        # Construct the ID if it is not provided
        if id is None:
            id = 'voltha.{}.{}'.format(self.adapter_name, resource_id)

        return AlarmEvent(
            id=id,
            resource_id=resource_id,
            type=type,
            category=category,
            severity=severity,
            state=state,
            description=description,
            reported_ts=arrow.utcnow().timestamp,
            raised_ts=raised_ts,
            changed_ts=changed_ts,
            context=context,
            logical_device_id=logical_device_id,
            alarm_type_name=alarm_type_name
        )

    def filter_alarm(self, device_id, alarm_event):
        alarm_filters = self.root_proxy.get('/alarm_filters')

        rule_values = {
            'id': alarm_event.id,
            'type': AlarmEventType.AlarmEventType.Name(alarm_event.type),
            'category': AlarmEventCategory.AlarmEventCategory.Name(
                alarm_event.category),
            'severity': AlarmEventSeverity.AlarmEventSeverity.Name(
                alarm_event.severity),
            'resource_id': alarm_event.resource_id,
            'device_id': device_id
        }

        for alarm_filter in alarm_filters:
            if alarm_filter.rules:
                exclude = True
                for rule in alarm_filter.rules:
                    self.log.debug("compare-alarm-event",
                                   key=AlarmFilterRuleKey.AlarmFilterRuleKey.Name(
                                       rule.key),
                                   actual=rule_values[
                                       AlarmFilterRuleKey.AlarmFilterRuleKey.Name(
                                           rule.key)].lower(),
                                   expected=rule.value.lower())
                    exclude = exclude and \
                              (rule_values[
                                   AlarmFilterRuleKey.AlarmFilterRuleKey.Name(
                                       rule.key)].lower() == rule.value.lower())
                    if not exclude:
                        break

                if exclude:
                    self.log.info("filtered-alarm-event", alarm=alarm_event)
                    return True

        return False

    def submit_alarm(self, device_id, alarm_event_msg):
        try:
            assert isinstance(alarm_event_msg, AlarmEvent)
            if not self.filter_alarm(device_id, alarm_event_msg):
                self.event_bus.publish('alarms', alarm_event_msg)

        except Exception as e:
            self.log.exception('failed-alarm-submission',
                               type=type(alarm_event_msg))

    # ~~~~~~~~~~~~~~~~~~~ Handle ONU detect ~~~~~~~~~~~~~~~~~~~~~

    def _gen_onu_detect_proxy_address_topic(self, device_id):
        """Generate unique topic name specific to this device id for onu detect"""
        topic = str('onu_detect:{}'.format(device_id))
        return topic

    def register_for_onu_detect_state(self, device_id):
        topic = self._gen_onu_detect_proxy_address_topic(device_id)
        self._onu_detect_event_subscriptions[topic] = self.event_bus.subscribe(
            topic,
            lambda t, m: self._forward_onu_detect_state(device_id, m))

    def unregister_for_onu_detect_state(self, device_id):
        topic = self._gen_onu_detect_proxy_address_topic(device_id)
        self.event_bus.unsubscribe(self._onu_detect_event_subscriptions[topic])
        del self._onu_detect_event_subscriptions[topic]

    def _forward_onu_detect_state(self, device_id, state):
        self.adapter.receive_onu_detect_state(device_id, state)

    def forward_onu_detect_state(self, device_id, state):
        topic = self._gen_onu_detect_proxy_address_topic(device_id)
        self.event_bus.publish(topic, state)
