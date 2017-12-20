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

import datetime
import random
import json
import xmltodict

from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks, succeed

from adtran_device_handler import AdtranDeviceHandler
from download import Download
from xpon.adtran_olt_xpon import AdtranOltXPON
from codec.olt_state import OltState
from flow.flow_entry import FlowEntry
from net.adtran_zmq import AdtranZmqClient
from voltha.extensions.omci.omci import *
from voltha.protos.common_pb2 import AdminState, OperStatus
from voltha.protos.device_pb2 import ImageDownload

FIXED_ONU = True  # Enhanced ONU support
ATT_NETWORK = True  # Use AT&T cVlan scheme


class AdtranOltHandler(AdtranDeviceHandler, AdtranOltXPON):
    """
    The OLT Handler is used to wrap a single instance of a 10G OLT 1-U pizza-box
    """
    MIN_OLT_HW_VERSION = datetime.datetime(2017, 1, 5)

    # Full table output

    GPON_OLT_HW_URI = '/restconf/data/gpon-olt-hw'
    GPON_OLT_HW_STATE_URI = GPON_OLT_HW_URI + ':olt-state'
    GPON_OLT_HW_CONFIG_URI = GPON_OLT_HW_URI + ':olt'
    GPON_PON_CONFIG_LIST_URI = GPON_OLT_HW_CONFIG_URI + '/pon'

    # Per-PON info

    GPON_PON_STATE_URI = GPON_OLT_HW_STATE_URI + '/pon={}'        # .format(pon-id)
    GPON_PON_CONFIG_URI = GPON_PON_CONFIG_LIST_URI + '={}'        # .format(pon-id)

    GPON_ONU_CONFIG_LIST_URI = GPON_PON_CONFIG_URI + '/onus/onu'  # .format(pon-id)
    GPON_ONU_CONFIG_URI = GPON_ONU_CONFIG_LIST_URI + '={}'        # .format(pon-id,onu-id)

    GPON_TCONT_CONFIG_LIST_URI = GPON_ONU_CONFIG_URI + '/t-conts/t-cont'  # .format(pon-id,onu-id)
    GPON_TCONT_CONFIG_URI = GPON_TCONT_CONFIG_LIST_URI + '={}'            # .format(pon-id,onu-id,alloc-id)

    GPON_GEM_CONFIG_LIST_URI = GPON_ONU_CONFIG_URI + '/gem-ports/gem-port'  # .format(pon-id,onu-id)
    GPON_GEM_CONFIG_URI = GPON_GEM_CONFIG_LIST_URI + '={}'                  # .format(pon-id,onu-id,gem-id)

    GPON_PON_DISCOVER_ONU = '/restconf/operations/gpon-olt-hw:discover-onu'

    BASE_ONU_OFFSET = 64

    def __init__(self, **kwargs):
        super(AdtranOltHandler, self).__init__(**kwargs)

        self.status_poll = None
        self.status_poll_interval = 5.0
        self.status_poll_skew = self.status_poll_interval / 10
        self.zmq_client = None
        self.ssh_deferred = None
        self._system_id = None
        self._download_protocols = None
        self._download_deferred = None
        self._downloads = {}        # name -> Download obj

    def __del__(self):
        # OLT Specific things here.
        #
        # If you receive this during 'enable' of the object, you probably threw an
        # uncaught exception which trigged an errback in the VOLTHA core.

        d, self.status_poll = self.status_poll, None

        # TODO Any OLT device specific cleanup here
        #     def get_channel(self):
        #         if self.channel is None:
        #             device = self.adapter_agent.get_device(self.device_id)
        #         return self.channel
        #
        # Clean up base class as well

        AdtranDeviceHandler.__del__(self)

    def _cancel_deferred(self):
        d1, self.status_poll = self.status_poll, None
        d2, self.ssh_deferred = self.ssh_deferred, None
        d3, self._download_deferred = self._download_deferred, None

        for d in [d1, d2, d3]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def __str__(self):
        return "AdtranOltHandler: {}".format(self.ip_address)

    @property
    def system_id(self):
        return self._system_id

    @system_id.setter
    def system_id(self, value):
        if self._system_id != value:
            self._system_id = value

            data = json.dumps({'olt-id': str(value)})
            uri = AdtranOltHandler.GPON_OLT_HW_CONFIG_URI
            self.rest_client.request('PATCH', uri, data=data, name='olt-system-id')

    @inlineCallbacks
    def get_device_info(self, device):
        """
        Perform an initial network operation to discover the device hardware
        and software version. Serial Number would be helpful as well.

        Upon successfully retrieving the information, remember to call the
        'start_heartbeat' method to keep in contact with the device being managed

        :param device: A voltha.Device object, with possible device-type
                specific extensions. Such extensions shall be described as part of
                the device type specification returned by device_types().
        """
        from codec.physical_entities_state import PhysicalEntitiesState
        # TODO: After a CLI 'reboot' command, the device info may get messed up (prints labels and not values)  Enter device and type 'show'
        device = {
            'model': 'n/a',
            'hardware_version': 'n/a',
            'serial_number': 'n/a',
            'vendor': 'Adtran, Inc.',
            'firmware_version': 'n/a',
            'running-revision': 'n/a',
            'candidate-revision': 'n/a',
            'startup-revision': 'n/a',
        }
        if self.is_virtual_olt:
            returnValue(device)

        try:
            pe_state = PhysicalEntitiesState(self.netconf_client)
            self.startup = pe_state.get_state()
            results = yield self.startup

            if results.ok:
                modules = pe_state.get_physical_entities('adtn-phys-mod:module')

                if isinstance(modules, list):
                    module = modules[0]

                    name = str(module.get('model-name', 'n/a')).translate(None, '?')
                    model = str(module.get('model-number', 'n/a')).translate(None, '?')

                    device['model'] = '{} - {}'.format(name, model) if len(name) > 0 else \
                        module.get('parent-entity', 'n/a')
                    device['hardware_version'] = str(module.get('hardware-revision',
                                                                'n/a')).translate(None, '?')
                    device['serial_number'] = str(module.get('serial-number',
                                                             'n/a')).translate(None, '?')
                    device['firmware_version'] = str(device.get('firmware-revision',
                                                                'unknown')).translate(None, '?')
                    if 'software' in module:
                        if 'software' in module['software']:
                            software = module['software']['software']
                            device['running-revision'] = str(software.get('running-revision',
                                                                          'n/a')).translate(None, '?')
                            device['candidate-revision'] = str(software.get('candidate-revision',
                                                                            'n/a')).translate(None, '?')
                            device['startup-revision'] = str(software.get('startup-revision',
                                                                          'n/a')).translate(None, '?')
        except Exception as e:
            self.log.exception('get-pe-state', e=e)

        returnValue(device)

    @inlineCallbacks
    def enumerate_northbound_ports(self, device):
        """
        Enumerate all northbound ports of this device.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
        from net.rcmd import RCmd
        try:
            # Also get the MAC Address for the OLT
            command = "ip -o link | grep eth0 | sed -n -e 's/^.*ether //p' | awk '{ print $1 }'"
            rcmd = RCmd(self.ip_address, self.netconf_username, self.netconf_password,
                        command)
            self.default_mac_addr = yield rcmd.execute()
            self.log.info("mac-addr", mac_addr=self.default_mac_addr)

        except Exception as e:
            log.exception('mac-address', e=e)
            raise

        try:
            from codec.ietf_interfaces import IetfInterfacesState
            from nni_port import MockNniPort

            ietf_interfaces = IetfInterfacesState(self.netconf_client)

            if self.is_virtual_olt:
                results = MockNniPort.get_nni_port_state_results()
            else:
                self.startup = ietf_interfaces.get_state()
                results = yield self.startup

            ports = ietf_interfaces.get_nni_port_entries(results)
            yield returnValue(ports)

        except Exception as e:
            log.exception('enumerate_northbound_ports', e=e)
            raise

    def process_northbound_ports(self, device, results):
        """
        Process the results from the 'enumerate_northbound_ports' method.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :param results: Results from the 'enumerate_northbound_ports' method that
                you implemented. The type and contents are up to you to
        :return: (Deferred or None).
        """
        from nni_port import NniPort, MockNniPort

        for port in results:
            port_no = port['port_no']
            self.log.info('processing-nni', port_no=port_no, name=port['port_no'])
            assert port_no, 'Port number not found'
            assert port_no not in self.northbound_ports, 'Port number is not a northbound port'
            self.northbound_ports[port_no] = NniPort(self, **port) if not self.is_virtual_olt \
                else MockNniPort(self, **port)

            # TODO: For now, limit number of NNI ports to make debugging easier
            if len(self.northbound_ports) >= self.max_nni_ports:
                break

        self.num_northbound_ports = len(self.northbound_ports)

    @inlineCallbacks
    def enumerate_southbound_ports(self, device):
        """
        Enumerate all southbound ports of this device.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
        ###############################################################################
        # Determine number of southbound ports. We know it is 16, but this keeps this
        # device adapter generic for our other OLTs up to this point.

        self.startup = self.rest_client.request('GET', self.GPON_PON_CONFIG_LIST_URI, 'pon-config')
        results = yield self.startup
        returnValue(results)

    def process_southbound_ports(self, device, results):
        """
        Process the results from the 'enumerate_southbound_ports' method.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :param results: Results from the 'enumerate_southbound_ports' method that
                you implemented. The type and contents are up to you to
        :return: (Deferred or None).
        """
        from pon_port import PonPort

        for pon in results:
            # Number PON Ports after the NNI ports
            pon_id = pon['pon-id']
            log.info('processing-pon-port', pon_id=pon_id)
            assert pon_id not in self.southbound_ports,\
                'Pon ID not found in southbound ports'

            self.southbound_ports[pon_id] = PonPort(pon_id,
                                                    self._pon_id_to_port_number(pon_id),
                                                    self)
            if self.autoactivate:
                self.southbound_ports[pon_id].downstream_fec_enable = True
                self.southbound_ports[pon_id].upstream_fec_enable = True

        self.num_southbound_ports = len(self.southbound_ports)

    def pon(self, pon_id):
        return self.southbound_ports.get(pon_id)

    def complete_device_specific_activation(self, device, reconciling):
        """
        Perform an initial network operation to discover the device hardware
        and software version. Serial Number would be helpful as well.

        This method is called from within the base class's activate generator.

        :param device: A voltha.Device object, with possible device-type
                specific extensions. Such extensions shall be described as part of
                the device type specification returned by device_types().

        :param reconciling: (boolean) True if taking over for another VOLTHA
        """
        # Make sure configured for ZMQ remote access
        self._ready_zmq()

        # ZeroMQ client
        self.zmq_client = AdtranZmqClient(self.ip_address, rx_callback=self.rx_packet, port=self.zmq_port)

        # Download support
        self._download_deferred = reactor.callLater(0, self._get_download_protocols)

        # Register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

        # PON Status
        self.status_poll = reactor.callLater(5, self.poll_for_status)
        return succeed('Done')

    def on_heatbeat_alarm(self, active):
        if not active:
            self._ready_zmq()

    @inlineCallbacks
    def _get_download_protocols(self):
        if self._download_protocols is None:
            try:
                config = '<filter>' + \
                          '<file-servers-state xmlns="http://www.adtran.com/ns/yang/adtran-file-servers">' + \
                           '<profiles>' + \
                            '<supported-protocol/>' + \
                           '</profiles>' + \
                          '</file-servers-state>' + \
                         '</filter>'

                results = yield self.netconf_client.get(config)

                result_dict = xmltodict.parse(results.data_xml)
                entries = result_dict['data']['file-servers-state']['profiles']['supported-protocol']
                self._download_protocols = [entry['#text'].split(':')[-1] for entry in entries
                                            if '#text' in entry]

            except Exception as e:
                self.log.exception('protocols', e=e)
                self._download_protocols = None
                self._download_deferred = reactor.callLater(10, self._get_download_protocols)

    @inlineCallbacks
    def _ready_zmq(self):
        from net.rcmd import RCmd
        # Check for port status
        command = 'netstat -pan | grep -i 0.0.0.0:{} |  wc -l'.format(self.zmq_port)
        rcmd = RCmd(self.ip_address, self.netconf_username, self.netconf_password, command)

        try:
            self.log.debug('check-request', command=command)
            results = yield rcmd.execute()
            self.log.info('check-results', results=results, result_type=type(results))
            create_it = int(results) != 1

        except Exception as e:
            self.log.exception('find', e=e)
            create_it = True

        if create_it:
            next_run = 15
            command = 'mkdir -p /etc/pon_agent; touch /etc/pon_agent/debug.conf; '
            command += 'ps -ae | grep -i ngpon2_agent; '
            command += 'service_supervisor stop ngpon2_agent; service_supervisor start ngpon2_agent; '
            command += 'ps -ae | grep -i ngpon2_agent'

            rcmd = RCmd(self.ip_address, self.netconf_username, self.netconf_password, command)

            try:
                self.log.debug('create-request', command=command)
                results = yield rcmd.execute()
                self.log.info('create-results', results=results, result_type=type(results))

            except Exception as e:
                self.log.exception('mkdir', e=e)
        else:
            next_run = 0

        if next_run > 0:
            self.ssh_deferred = reactor.callLater(next_run, self._ready_zmq)

    def disable(self):
        self._cancel_deferred()

        # Drop registration for adapter messages
        self.adapter_agent.unregister_for_inter_adapter_messages()

        c, self.zmq_client = self.zmq_client, None
        if c is not None:
            try:
                c.shutdown()
            except:
                pass

        super(AdtranOltHandler, self).disable()

    def reenable(self, done_deferred=None):
        super(AdtranOltHandler, self).reenable(done_deferred=done_deferred)

        self._ready_zmq()
        self.zmq_client = AdtranZmqClient(self.ip_address, rx_callback=self.rx_packet,
                                          port=self.zmq_port)
        # Register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

        self.status_poll = reactor.callLater(1, self.poll_for_status)

    def reboot(self):
        self._cancel_deferred()

        c, self.zmq_client = self.zmq_client, None
        if c is not None:
            c.shutdown()

        # Drop registration for adapter messages
        self.adapter_agent.unregister_for_inter_adapter_messages()

        # Download supported protocols may change (if new image gets activated)
        self._download_protocols = None

        super(AdtranOltHandler, self).reboot()

    def _finish_reboot(self, timeout, previous_oper_status, previous_conn_status):
        super(AdtranOltHandler, self)._finish_reboot(timeout, previous_oper_status, previous_conn_status)

        self._ready_zmq()

        # Download support
        self._download_deferred = reactor.callLater(0, self._get_download_protocols)

        # Register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

        self.zmq_client = AdtranZmqClient(self.ip_address, rx_callback=self.rx_packet, port=self.zmq_port)
        self.status_poll = reactor.callLater(5, self.poll_for_status)

    def delete(self):
        self._cancel_deferred()

        # Drop registration for adapter messages
        self.adapter_agent.unregister_for_inter_adapter_messages()

        c, self.zmq_client = self.zmq_client, None
        if c is not None:
            c.shutdown()

        super(AdtranOltHandler, self).delete()

    def rx_packet(self, message):
        try:
            self.log.debug('rx_packet')

            pon_id, onu_id, msg_bytes, is_omci = AdtranZmqClient.decode_packet(message,
                                                                               self.is_async_control)
            if is_omci:
                proxy_address = self._pon_onu_id_to_proxy_address(pon_id, onu_id)
                self.adapter_agent.receive_proxied_message(proxy_address, msg_bytes)
            else:
                pass  # TODO: Packet in support not yet supported
                # self.adapter_agent.send_packet_in(logical_device_id=logical_device_id,
                #                                   logical_port_no=cvid,  # C-VID encodes port no
                #                                   packet=str(msg))
        except Exception as e:
            self.log.exception('rx_packet', e=e)

    def poll_for_status(self):
        self.log.debug('Initiating-status-poll')

        device = self.adapter_agent.get_device(self.device_id)

        if device.admin_state == AdminState.ENABLED and\
                device.oper_status != OperStatus.ACTIVATING and\
                self.rest_client is not None:
            uri = AdtranOltHandler.GPON_OLT_HW_STATE_URI
            name = 'pon-status-poll'
            self.status_poll = self.rest_client.request('GET', uri, name=name)
            self.status_poll.addBoth(self.status_poll_complete)
        else:
            self.status_poll = reactor.callLater(0, self.status_poll_complete, 'inactive')

    def status_poll_complete(self, results):
        """
        Results of the status poll
        :param results:
        """
        from pon_port import PonPort

        if isinstance(results, dict) and 'pon' in results:
            try:
                self.log.debug('status-success')
                for pon_id, pon in OltState(results).pons.iteritems():
                    pon_port = self.southbound_ports.get(pon_id, None)

                    if pon_port is not None and pon_port.state == PonPort.State.RUNNING:
                        pon_port.process_status_poll(pon)

            except Exception as e:
                self.log.exception('PON-status-poll', e=e)

        # Reschedule

        delay = self.status_poll_interval
        delay += random.uniform(-delay / 10, delay / 10)

        self.status_poll = reactor.callLater(delay, self.poll_for_status)

    @inlineCallbacks
    def update_flow_table(self, flows, device):
        """
        Update the flow table on the OLT.  If an existing flow is not in the list, it needs
        to be removed from the device.

        :param flows: List of flows that should be installed upon completion of this function
        :param device: A voltha.Device object, with possible device-type
                       specific extensions.
        """
        self.log.debug('bulk-flow-update', num_flows=len(flows),
                       device_id=device.id, flows=flows)

        valid_flows = []

        for flow in flows:
            try:
                # Try to create an EVC.
                #
                # The first result is the flow entry that was created. This could be a match to an
                # existing flow since it is a bulk update.  None is returned only if no match to
                # an existing entry is found and decode failed (unsupported field)
                #
                # The second result is the EVC this flow should be added to. This could be an
                # existing flow (so your adding another EVC-MAP) or a brand new EVC (no existing
                # EVC-MAPs).  None is returned if there are not a valid EVC that can be created YET.

                valid_flow, evc = FlowEntry.create(flow, self)

                if valid_flow is not None:
                    valid_flows.append(valid_flow.flow_id)

                if evc is not None:
                    try:
                        evc.schedule_install()
                        self.add_evc(evc)

                    except Exception as e:
                        evc.status = 'EVC Install Exception: {}'.format(e.message)
                        self.log.exception('EVC-install', e=e)

            except Exception as e:
                self.log.exception('bulk-flow-update-add', e=e)

        # Now drop all flows from this device that were not in this bulk update
        try:
            yield FlowEntry.drop_missing_flows(device.id, valid_flows)

        except Exception as e:
            self.log.exception('bulk-flow-update-remove', e=e)

    # @inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        self.log.debug('sending-proxied-message', msg=msg)

        if isinstance(msg, Packet):
            msg = str(msg)

        if self.zmq_client is not None:
            pon_id, onu_id = self._proxy_address_to_pon_onu_id(proxy_address)

            pon = self.southbound_ports.get(pon_id)

            if pon is not None and pon.enabled:
                onu = pon.onu(onu_id)

                if onu is not None and onu.enabled:
                    data = AdtranZmqClient.encode_omci_message(msg, pon_id, onu_id,
                                                               self.is_async_control)
                    try:
                        self.zmq_client.send(data)

                    except Exception as e:
                        self.log.exception('zmqClient-send', pon_id=pon_id, onu_id=onu_id, e=e)
                else:
                    self.log.debug('onu-invalid-or-disabled', pon_id=pon_id, onu_id=onu_id)
            else:
                self.log.debug('pon-invalid-or-disabled', pon_id=pon_id)

    def get_channel_id(self, pon_id, onu_id):
        from pon_port import PonPort
        if ATT_NETWORK:
            if FIXED_ONU:
                return (onu_id * 120) + 2
            return 1 + onu_id + (pon_id * 120)

        if FIXED_ONU:
            return self._onu_offset(onu_id)
        return self._onu_offset(onu_id) + (pon_id * PonPort.MAX_ONUS_SUPPORTED)

    def _onu_offset(self, onu_id):
        # Start ONU's just past the southbound PON port numbers. Since ONU ID's start
        # at zero, add one
        assert AdtranOltHandler.BASE_ONU_OFFSET > (self.num_northbound_ports + self.num_southbound_ports + 1)
        return AdtranOltHandler.BASE_ONU_OFFSET + onu_id

    def _pon_onu_id_to_proxy_address(self, pon_id, onu_id):
        if pon_id in self.southbound_ports:
            pon = self.southbound_ports[pon_id]
            onu = pon.onu(onu_id)
            proxy_address = onu.proxy_address if onu is not None else None

        else:
            proxy_address = None

        return proxy_address

    def _proxy_address_to_pon_onu_id(self, proxy_address):
        """
        Convert the proxy address to the PON-ID and ONU-ID
        :param proxy_address: (ProxyAddress)
        :return: (tuple) pon-id, onu-id
        """
        onu_id = proxy_address.onu_id

        if self.autoactivate:
            # Legacy method
            pon_id = proxy_address.channel_group_id
        else:
            # xPON method
            pon_id = self._port_number_to_pon_id(proxy_address.channel_id)

        return pon_id, onu_id

    def _pon_id_to_port_number(self, pon_id):
        return pon_id + 1 + self.num_northbound_ports

    def _port_number_to_pon_id(self, port):
        return port - 1 - self.num_northbound_ports

    def is_pon_port(self, port):
        return self._port_number_to_pon_id(port) in self.southbound_ports

    def is_uni_port(self, port):
        return port >= self._onu_offset(0)  # TODO: Really need to rework this one...

    def get_southbound_port(self, port):
        pon_id = self._port_number_to_pon_id(port)
        return self.southbound_ports.get(pon_id, None)

    def get_port_name(self, port):
        if self.is_nni_port(port):
            return self.northbound_ports[port].name

        if self.is_pon_port(port):
            return self.get_southbound_port(port).name

        if self.is_uni_port(port):
            return self.northbound_ports[port].name

        if self.is_logical_port(port):
            raise NotImplemented('TODO: Logical ports not yet supported')

    def _update_download_status(self, request, download):
        if download is not None:
            request.state = download.download_state
            request.reason = download.failure_reason
            request.image_state = download.image_state
            request.additional_info = download.additional_info
            request.downloaded_bytes = download.downloaded_bytes
        else:
            request.state = ImageDownload.DOWNLOAD_UNKNOWN
            request.reason = ImageDownload.UNKNOWN_ERROR
            request.image_state = ImageDownload.IMAGE_UNKNOWN
            request.additional_info = "Download request '{}' not found".format(request.name)
            request.downloaded_bytes = 0

        self.adapter_agent.update_image_download(request)

    def start_download(self, device, request, done):
        """
        This is called to request downloading a specified image into
        the standby partition of a device based on a NBI call.

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done
        :return: (Deferred) Shall be fired to acknowledge the download.
        """
        log.info('image_download', request=request)

        try:
            if request.name in self._downloads:
                raise Exception("Download request with name '{}' already exists".
                                format(request.name))
            try:
                download = Download.create(self, request, self._download_protocols)

            except Exception:
                request.additional_info = 'Download request creation failed due to exception'
                raise

            try:
                self._downloads[download.name] = download
                self._update_download_status(request, download)
                done.callback('started')
                return done

            except Exception:
                request.additional_info = 'Download request startup failed due to exception'
                del self._downloads[download.name]
                download.cancel_download(request)
                raise

        except Exception as e:
            self.log.exception('create', e=e)

            request.reason = ImageDownload.UNKNOWN_ERROR
            request.state = ImageDownload.DOWNLOAD_FAILED
            if not request.additional_info:
                request.additional_info = e.message

            self.adapter_agent.update_image_download(request)

            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)
            raise

    def download_status(self, device, request, done):
        """
        This is called to inquire about a requested image download status based
        on a NBI call.

        The adapter is expected to update the DownloadImage DB object with the
        query result

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) Shall be fired to acknowledge
        """
        log.info('download_status', request=request)
        download = self._downloads.get(request.name)

        self._update_download_status(request, download)

        if request.state != ImageDownload.DOWNLOAD_STARTED:
            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)

        done.callback(request.state)
        return done

    def cancel_download(self, device, request, done):
        """
        This is called to cancel a requested image download based on a NBI
        call.  The admin state of the device will not change after the
        download.

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) Shall be fired to acknowledge
        """
        log.info('cancel_download', request=request)

        download = self._downloads.get(request.name)

        if download is not None:
            del self._downloads[request.name]
            result = download.cancel_download(request)
            self._update_download_status(request, download)
            done.callback(result)
        else:
            self._update_download_status(request, download)
            done.errback(KeyError('Download request not found'))

        if device.admin_state == AdminState.DOWNLOADING_IMAGE:
            device.admin_state = AdminState.ENABLED
            self.adapter_agent.update_device(device)

        return done

    def activate_image(self, device, request, done):
        """
        This is called to activate a downloaded image from a standby partition
        into active partition.

        Depending on the device implementation, this call may or may not
        cause device reboot. If no reboot, then a reboot is required to make
        the activated image running on device

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) OperationResponse object.
        """
        log.info('activate_image', request=request)

        download = self._downloads.get(request.name)
        if download is not None:
            del self._downloads[request.name]
            result = download.activate_image()
            self._update_download_status(request, download)
            done.callback(result)
        else:
            self._update_download_status(request, download)
            done.errback(KeyError('Download request not found'))

        # restore admin state to enabled
        device.admin_state = AdminState.ENABLED
        self.adapter_agent.update_device(device)
        return done

    def revert_image(self, device, request, done):
        """
        This is called to deactivate the specified image at active partition,
        and revert to previous image at standby partition.

        Depending on the device implementation, this call may or may not
        cause device reboot. If no reboot, then a reboot is required to
        make the previous image running on device

        :param device: A Voltha.Device object.
        :param request: A Voltha.ImageDownload object.
        :param done: (Deferred) Deferred to fire when done

        :return: (Deferred) OperationResponse object.
        """
        log.info('revert_image', request=request)

        download = self._downloads.get(request.name)
        if download is not None:
            del self._downloads[request.name]
            result = download.revert_image()
            self._update_download_status(request, download)
            done.callback(result)
        else:
            self._update_download_status(request, download)
            done.errback(KeyError('Download request not found'))

        # restore admin state to enabled
        device.admin_state = AdminState.ENABLED
        self.adapter_agent.update_device(device)
        return done

    def on_channel_group_modify(self, cgroup, update, diffs):
        valid_keys = ['enable',
                      'polling-period',
                      'system-id']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("channel-group leaf '{}' is read-only or write-once".format(invalid_key))

        pons = self.get_related_pons(cgroup)
        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'enabled':
                pass  # TODO: ?

            elif k == 'polling-period':
                for pon in pons:
                    pon.discovery_tick = update[k]

            elif k == 'system-id':
                self.system_id(update[k])

        return update

    def on_channel_partition_modify(self, cpartition, update, diffs):
        valid_keys = ['enabled', 'fec-downstream', 'mcast-aes', 'differential-fiber-distance']

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("channel-partition leaf '{}' is read-only or write-once".format(invalid_key))

        pons = self.get_related_pons(cpartition)
        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'enabled':
                pass  # TODO: ?

            elif k == 'fec-downstream':
                for pon in pons:
                    pon.downstream_fec_enable = update[k]

            elif k == 'mcast-aes':
                for pon in pons:
                    pon.mcast_aes = update[k]

            elif k == 'differential-fiber-distance':
                for pon in pons:
                    pon.deployment_range = update[k] * 1000  # pon-agent uses meters
        return update

    def on_channel_pair_modify(self, cpair, update, diffs):
        valid_keys = ['enabled', 'line-rate']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("channel-pair leaf '{}' is read-only or write-once".format(invalid_key))

        pons = self.get_related_pons(cpair)
        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'enabled':
                pass                        # TODO: ?

            elif k == 'line-rate':
                for pon in pons:
                    pon.line_rate = update[k]
        return update

    def on_channel_termination_create(self, ct, pon_type='xgs-ponid'):
        pons = self.get_related_pons(ct, pon_type=pon_type)
        pon_port = pons[0] if len(pons) == 1 else None

        if pon_port is None:
            raise ValueError('Unknown PON port. PON-ID: {}'.format(ct[pon_type]))

        assert ct['channel-pair'] in self.channel_pairs, \
            '{} is not a channel-pair'.format(ct['channel-pair'])
        cpair = self.channel_pairs[ct['channel-pair']]

        assert cpair['channel-group'] in self.channel_groups, \
            '{} is not a -group'.format(cpair['channel-group'])
        assert cpair['channel-partition'] in self.channel_partitions, \
            '{} is not a channel-partition'.format(cpair('channel-partition'))
        cg = self.channel_groups[cpair['channel-group']]
        cpart = self.channel_partitions[cpair['channel-partition']]

        polling_period = cg['polling-period']
        system_id = cg['system-id']
        authentication_method = cpart['authentication-method']
        # line_rate = cpair['line-rate']
        downstream_fec = cpart['fec-downstream']
        deployment_range = cpart['differential-fiber-distance']
        mcast_aes = cpart['mcast-aes']
        # TODO: Support BER calculation period

        pon_port.xpon_name = ct['name']
        pon_port.discovery_tick = polling_period
        pon_port.authentication_method = authentication_method
        pon_port.deployment_range = deployment_range * 1000  # pon-agent uses meters
        pon_port.downstream_fec_enable = downstream_fec
        pon_port.mcast_aes = mcast_aes
        # pon_port.line_rate = line_rate            # TODO: support once 64-bits
        self.system_id = system_id

        # Enabled 'should' be a logical 'and' of all referenced items but
        # there is no easy way to detected changes in referenced items.
        # enabled = ct['enabled'] and cpair['enabled'] and cg['enabled'] and cpart['enabled']
        enabled = ct['enabled']
        pon_port.admin_state = AdminState.ENABLED if enabled else AdminState.DISABLED
        return ct

    def on_channel_termination_modify(self, ct, update, diffs, pon_type='xgs-ponid'):
        valid_keys = ['enabled']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("channel-termination leaf '{}' is read-only or write-once".format(invalid_key))

        pons = self.get_related_pons(ct, pon_type=pon_type)
        pon_port = pons[0] if len(pons) == 1 else None

        if pon_port is None:
            raise ValueError('Unknown PON port. PON-ID: {}'.format(ct[pon_type]))

        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'enabled':
                enabled = update[k]
                pon_port.admin_state = AdminState.ENABLED if enabled else AdminState.DISABLED
        return update

    def on_channel_termination_delete(self, ct, pon_type='xgs-ponid'):
        pons = self.get_related_pons(ct, pon_type=pon_type)
        pon_port = pons[0] if len(pons) == 1 else None

        if pon_port is None:
            raise ValueError('Unknown PON port. PON-ID: {}'.format(ct[pon_type]))

        pon_port.admin_state = AdminState.DISABLED
        return None

    def on_ont_ani_modify(self, ont_ani, update, diffs):
        valid_keys = ['enabled', 'upstream-fec']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("ont-ani leaf '{}' is read-only or write-once".format(invalid_key))

        onus = self.get_related_onus(ont_ani)
        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'enabled':
                pass      # TODO: Have only ONT use this value?

            elif k == 'upstream-fec':
                for onu in onus:
                    onu.upstream_fec_enable = update[k]
        return update

    def on_vont_ani_modify(self, vont_ani, update, diffs):
        valid_keys = ['enabled',
                      'expected-serial-number',
                      'upstream-channel-speed'
                      ]  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("vont-ani leaf '{}' is read-only or write-once".format(invalid_key))

        onus = self.get_related_onus(vont_ani)
        keys = [k for k in diffs.keys() if k in valid_keys]

        for k in keys:
            if k == 'enabled':
                for onu in onus:
                    onu.enabled = update[k]
            elif k == 'expected-serial-number':
                for onu in onus:
                    if onu.serial_number != update[k]:
                        onu.pon.delete_onu(onu.onu_id)
            elif k == 'upstream-channel-speed':
                for onu in onus:
                    onu.upstream_channel_speed = update[k]
        return update

    def on_vont_ani_delete(self, vont_ani):
        onus = self.get_related_onus(vont_ani)

        for onu in onus:
            try:
                onu.pon.delete_onu(onu.onu_id)

            except Exception as e:
                self.log.exception('onu', onu=onu, e=e)

        return None

    def _get_tcont_onu(self, vont_ani):
        onu = None
        try:
            vont_ani = self.v_ont_anis.get(vont_ani)
            ch_pair = self.channel_pairs.get(vont_ani['preferred-channel-pair'])
            ch_term = next((term for term in self.channel_terminations.itervalues()
                            if term['channel-pair'] == ch_pair['name']), None)

            pon = self.pon(ch_term['xgs-ponid'])
            onu = pon.onu(vont_ani['onu-id'])

        except Exception:
            pass

        return onu

    def on_tcont_create(self, tcont):
        from xpon.olt_tcont import OltTCont

        td = self.traffic_descriptors.get(tcont.get('td-ref'))
        traffic_descriptor = td['object'] if td is not None else None

        tcont['object'] = OltTCont.create(tcont, traffic_descriptor)

        # Look up any ONU associated with this TCONT (should be only one if any)
        onu = self._get_tcont_onu(tcont['vont-ani'])

        if onu is not None:                 # Has it been discovered yet?
            onu.add_tcont(tcont['object'])

        return tcont

    def on_tcont_modify(self, tcont, update, diffs):
        valid_keys = ['td-ref']  # Modify of these keys supported

        invalid_key = next((key for key in diffs.keys() if key not in valid_keys), None)
        if invalid_key is not None:
            raise KeyError("TCONT leaf '{}' is read-only or write-once".format(invalid_key))

        tc = tcont.get('object')
        assert tc is not None, 'TCONT not found'

        update['object'] = tc

        # Look up any ONU associated with this TCONT (should be only one if any)
        onu = self._get_tcont_onu(tcont['vont-ani'])

        if onu is not None:                 # Has it been discovered yet?
            keys = [k for k in diffs.keys() if k in valid_keys]

            for k in keys:
                if k == 'td-ref':
                    td = self.traffic_descriptors.get(update['td-ref'])
                    if td is not None:
                        onu.update_tcont_td(tcont['alloc-id'], td)

        return update

    def on_tcont_delete(self, tcont):
        onu = self._get_tcont_onu(tcont['vont-ani'])

        if onu is not None:
            onu.remove_tcont(tcont['alloc-id'])

        return None

    def on_td_create(self, traffic_disc):
        from xpon.olt_traffic_descriptor import OltTrafficDescriptor
        traffic_disc['object'] = OltTrafficDescriptor.create(traffic_disc)
        return traffic_disc

    def on_td_modify(self, traffic_disc, update, diffs):
        from xpon.olt_traffic_descriptor import OltTrafficDescriptor

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
        update['object'] = OltTrafficDescriptor.create(update)

        td_name = traffic_disc['name']
        tconts = {key: val for key, val in self.tconts.iteritems()
                  if val['td-ref'] == td_name and td_name is not None}

        for tcont in tconts.itervalues():
            # Look up any ONU associated with this TCONT (should be only one if any)
            onu = self._get_tcont_onu(tcont['vont-ani'])
            if onu is not None:
                onu.update_tcont_td(tcont['alloc-id'], update['object'])

        return update

    def on_td_delete(self, traffic_desc):
        # TD may be used by more than one TCONT. Only delete if the last one
        td_name = traffic_desc['name']
        num_tconts = len([val for val in self.tconts.itervalues()
                          if val['td-ref'] == td_name and td_name is not None])
        return None if num_tconts <= 1 else traffic_desc

    def on_gemport_create(self, gem_port):
        from xpon.olt_gem_port import OltGemPort
        # Create an GemPort object to wrap the dictionary
        gem_port['object'] = OltGemPort.create(self, gem_port)

        onus = self.get_related_onus(gem_port)
        assert len(onus) <= 1, 'Too many ONUs: {}'.format(len(onus))

        if len(onus) == 1:
            onus[0].add_gem_port(gem_port['object'])

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
        onus = self.get_related_onus(gem_port)
        assert len(onus) <= 1, 'Too many ONUs: {}'.format(len(onus))
        if len(onus) == 1:
            onus[0].remove_gem_id(gem_port['gemport-id'])
        return None
