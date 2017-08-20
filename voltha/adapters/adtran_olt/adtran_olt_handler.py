# Copyright 2017-present Open Networking Foundation
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

from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks, succeed

from adtran_device_handler import AdtranDeviceHandler
from codec.olt_state import OltState
from flow.flow_entry import FlowEntry
from net.adtran_zmq import AdtranZmqClient
from voltha.extensions.omci.omci import *
from voltha.protos.common_pb2 import AdminState, OperStatus
from voltha.protos.device_pb2 import Device
from voltha.protos.bbf_fiber_base_pb2 import \
    ChannelgroupConfig, ChannelpartitionConfig, ChannelpairConfig, ChannelterminationConfig, \
    OntaniConfig, VOntaniConfig, VEnetConfig


class AdtranOltHandler(AdtranDeviceHandler):
    """
    The OLT Handler is used to wrap a single instance of a 10G OLT 1-U pizza-box
    """
    MIN_OLT_HW_VERSION = datetime.datetime(2017, 1, 5)

    # Full table output

    GPON_OLT_HW_URI = '/restconf/data/gpon-olt-hw'
    GPON_OLT_HW_STATE_URI = GPON_OLT_HW_URI + ':olt-state'
    GPON_PON_CONFIG_LIST_URI = GPON_OLT_HW_URI + ':olt/pon'

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

    def __init__(self, adapter, device_id, timeout=20):
        super(AdtranOltHandler, self).__init__(adapter, device_id, timeout=timeout)
        self.gpon_olt_hw_revision = None
        self.status_poll = None
        self.status_poll_interval = 5.0
        self.status_poll_skew = self.status_poll_interval / 10

        self.zmq_client = None

        # xPON config dictionaries

        self._channel_groups = {}         #  Name -> dict
        self._channel_partitions = {}     #  Name -> dict
        self._channel_pairs = {}          #  Name -> dict
        self._channel_terminations = {}   #  Name -> dict
        self._v_ont_anis = {}             #  Name -> dict
        self._ont_anis = {}               #  Name -> dict
        self._v_enets = {}                #  Name -> dict

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

    def __str__(self):
        return "AdtranOltHandler: {}".format(self.ip_address)

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

        device = {}

        if self.is_virtual_olt:
            returnValue(device)

        pe_state = PhysicalEntitiesState(self.netconf_client)
        self.startup = pe_state.get_state()
        results = yield self.startup

        if results.ok:
            modules = pe_state.get_physical_entities('adtn-phys-mod:module')
            if isinstance(modules, list):
                module = modules[0]
                name = str(module['model-name']).translate(None, '?')
                model = str(module['model-number']).translate(None, '?')

                device['model'] = '{} - {}'.format(name, model) if len(name) > 0 else \
                    module['parent-entity']
                device['hardware_version'] = str(module['hardware-revision']).translate(None, '?')
                device['serial_number'] = str(module['serial-number']).translate(None, '?')
                device['vendor'] = 'Adtran, Inc.'
                device['firmware_version'] = str(device.get('firmware-revision', 'unknown')).translate(None, '?')
                software = module['software']['software']
                device['running-revision'] = str(software['running-revision']).translate(None, '?')
                device['candidate-revision'] = str(software['candidate-revision']).translate(None, '?')
                device['startup-revision'] = str(software['startup-revision']).translate(None, '?')

        returnValue(device)

    @inlineCallbacks
    def enumerate_northbound_ports(self, device):
        """
        Enumerate all northbound ports of this device.

        :param device: A voltha.Device object, with possible device-type
                specific extensions.
        :return: (Deferred or None).
        """
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
            assert port_no
            assert port_no not in self.northbound_ports
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
            log.info('Processing-pon-port', pon_id=pon_id)
            assert pon_id not in self.southbound_ports

            admin_state = AdminState.ENABLED if pon.get('enabled',
                                                        PonPort.DEFAULT_ENABLED) else AdminState.DISABLED

            self.southbound_ports[pon_id] = PonPort(pon_id,
                                                    self._pon_id_to_port_number(pon_id),
                                                    self,
                                                    admin_state=admin_state)

            # TODO: For now, limit number of PON ports to make debugging easier
            if self.autoactivate and len(self.southbound_ports) >= self.max_pon_ports:
                break

        self.num_southbound_ports = len(self.southbound_ports)

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
        # For the pizzabox OLT, periodically query the OLT state of all PONs. This
        # is simpler then having each PON port do its own poll.  From this, we can:
        #
        # o Discover any new or missing ONT/ONUs
        #
        # o TODO Discover any LOS for any ONT/ONUs
        #
        # o TODO Update some PON level statistics

        self.zmq_client = AdtranZmqClient(self.ip_address, rx_callback=self.rx_packet, port=self.zmq_port)
        self.status_poll = reactor.callLater(5, self.poll_for_status)
        return succeed('Done')

    def disable(self):
        c, self.zmq_client = self.zmq_client, None
        if c is not None:
            try:
                c.shutdown()
            except:
                pass

        d, self.status_poll = self.status_poll, None
        if d is not None and not d.called:
            try:
                d.cancel()
            except:
                pass

        super(AdtranOltHandler, self).disable()

    def reenable(self):
        super(AdtranOltHandler, self).reenable()

        self.zmq_client = AdtranZmqClient(self.ip_address, rx_callback=self.rx_packet, port=self.zmq_port)
        self.status_poll = reactor.callLater(1, self.poll_for_status)

    def reboot(self):
        c, self.zmq_client = self.zmq_client, None
        if c is not None:
            c.shutdown()

        d, self.status_poll = self.status_poll, None
        if d is not None and not d.called:
            d.cancel()

        super(AdtranOltHandler, self).reboot()

    def _finish_reboot(self, timeout, previous_oper_status, previous_conn_status):
        super(AdtranOltHandler, self)._finish_reboot(timeout, previous_oper_status, previous_conn_status)

        self.zmq_client = AdtranZmqClient(self.ip_address, rx_callback=self.rx_packet, port=self.zmq_port)
        self.status_poll = reactor.callLater(1, self.poll_for_status)

    def delete(self):
        c, self.zmq_client = self.zmq_client, None
        if c is not None:
            c.shutdown()

        d, self.status_poll = self.status_poll, None
        if d is not None and not d.called:
            d.cancel()

        super(AdtranOltHandler, self).delete()

    def rx_packet(self, message):
        try:
            self.log.debug('rx_packet')

            pon_id, onu_id, msg, is_omci = AdtranZmqClient.decode_packet(message)

            if is_omci:
                proxy_address = Device.ProxyAddress(device_id=self.device_id,
                                                    channel_id=self.get_channel_id(pon_id, onu_id),
                                                    onu_id=onu_id)

                self.adapter_agent.receive_proxied_message(proxy_address, msg)
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
    def deactivate(self, device):
        # OLT Specific things here

        d, self.startup = self.startup, None
        if d is not None and not d.called:
            d.cancel()

        # self.pons.clear()

        # TODO: Any other? OLT specific deactivate steps

        # Call into base class and have it clean up as well
        super(AdtranOltHandler, self).deactivate(device)

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
            FlowEntry.drop_missing_flows(device.id, valid_flows)

        except Exception as e:
            self.log.exception('bulk-flow-update-remove', e=e)

    # @inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        self.log.debug('sending-proxied-message', msg=msg)

        if isinstance(msg, Packet):
            msg = str(msg)

        if self.zmq_client is not None:
            pon_id = self._channel_id_to_pon_id(proxy_address.channel_id, proxy_address.onu_id)
            onu_id = proxy_address.onu_id

            data = AdtranZmqClient.encode_omci_message(msg, pon_id, onu_id)

            try:
                self.zmq_client.send(data)

            except Exception as e:
                self.log.exception('zmqClient.send', e=e)
                raise

    @staticmethod
    def is_gpon_olt_hw(content):
        """
        If the hello content

        :param content: (dict) Results of RESTCONF adtran-hello GET request
        :return: (string) GPON OLT H/w RESTCONF revision number or None on error/not GPON
        """
        for item in content.get('module-info', None):
            if item.get('module-name') == 'gpon-olt-hw':
                return AdtranDeviceHandler.parse_module_revision(item.get('revision', None))
        return None

    def get_channel_id(self, pon_id, onu_id):
        from pon_port import PonPort
        return self._onu_offset(onu_id) + (pon_id * PonPort.MAX_ONUS_SUPPORTED)

    def _onu_offset(self, onu_id):
        # Start ONU's just past the southbound PON port numbers. Since ONU ID's start
        # at zero, add one
        assert AdtranOltHandler.BASE_ONU_OFFSET > (self.num_northbound_ports + self.num_southbound_ports + 1)
        return AdtranOltHandler.BASE_ONU_OFFSET + onu_id

    def _channel_id_to_pon_id(self, channel_id, onu_id):
        from pon_port import PonPort
        return (channel_id - self._onu_offset(onu_id)) / PonPort.MAX_ONUS_SUPPORTED

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

    def get_xpon_info(self, pon_id, pon_id_type='xgs-ponid'):
        """
        Lookup all xPON configuraiton data for a specific pon-id / channel-termination
        :param pon_id: (int) PON Identifier
        :return: (dict) reduced xPON information for the specific PON port
        """
        terminations = {key: val for key, val in self._channel_terminations.iteritems()
                        if val[pon_id_type] == pon_id}

        pair_names = set([term['channel-pair'] for term in terminations.itervalues()])

        pairs = {key: val for key, val in self._channel_pairs.iteritems()
                 if key in pair_names}

        partition_names = set([pair['channel-partition'] for pair in pairs.itervalues()])

        partitions = {key: val for key, val in self._channel_partitions.iteritems()
                      if key in partition_names}

        v_ont_anis = {key: val for key, val in self._v_ont_anis.iteritems()
                      if val['preferred-channel-pair'] in pair_names}

        return {
            'channel-terminations': terminations,
            'channel-pairs': pairs,
            'channel-partitions': partitions,
            'v_ont_anis': v_ont_anis
        }

    def create_interface(self, device, data):
        """
        Create XPON interfaces
        :param device: (Device)
        :param data: (ChannelgroupConfig) Channel Group configuration
        """
        name = data.name
        interface = data.interface
        inst_data = data.data

        if isinstance(data, ChannelgroupConfig):
            self.log.debug('create_interface-channel-group', interface=interface, data=inst_data)
            self._channel_groups[name] = {
                'name': name,
                'enabled': interface.enabled,
                'system-id': inst_data.system_id,
                'polling-period': inst_data.polling_period
            }

        elif isinstance(data, ChannelpartitionConfig):
            self.log.debug('create_interface-channel-partition', interface=interface, data=inst_data)

            def _auth_method_enum_to_string(value):
                from voltha.protos.bbf_fiber_types_pb2 import SERIAL_NUMBER, LOID, \
                    REGISTRATION_ID, OMCI, DOT1X
                return {
                    SERIAL_NUMBER: 'serial-number',
                    LOID: 'loid',
                    REGISTRATION_ID: 'registation-id',
                    OMCI: 'omci',
                    DOT1X: 'don1x'
                }.get(value, 'unknown')

            self._channel_partitions[name] = {
                'name': name,
                'enabled': interface.enabled,
                'authentication-method': _auth_method_enum_to_string(inst_data.authentication_method),
                'channel-group': inst_data.channelgroup_ref,
                'fec-downstream': inst_data.fec_downstream,
                'mcast-aes': inst_data.multicast_aes_indicator,
                'differential-fiber-distance': inst_data.differential_fiber_distance
            }

        elif isinstance(data, ChannelpairConfig):
            self.log.debug('create_interface-channel-pair', interface=interface, data=inst_data)
            self._channel_pairs[name] = {
                'name': name,
                'enabled': interface.enabled,
                'channel-group': inst_data.channelgroup_ref,
                'channel-partition': inst_data.channelpartition_ref,
                'line-rate': inst_data.channelpair_linerate
            }

        elif isinstance(data, ChannelterminationConfig):
            self.log.debug('create_interface-channel-termination', interface=interface, data=inst_data)
            self._channel_terminations[name] = {
                'name': name,
                'enabled': interface.enabled,
                'xgs-ponid': inst_data.xgs_ponid,
                'xgpon-ponid': inst_data.xgpon_ponid,
                'channel-pair': inst_data.channelpair_ref,
                'ber-calc-period': inst_data.ber_calc_period
            }
            self.on_channel_termination_config(name, 'create')

        elif isinstance(data, OntaniConfig):
            self.log.debug('create_interface-ont-ani', interface=interface, data=inst_data)
            self._ont_anis[name] = {
                'name': name,
                'enabled': interface.enabled,
                'upstream-fec': inst_data.upstream_fec_indicator,
                'mgnt-gemport-aes': inst_data.mgnt_gemport_aes_indicator
            }

        elif isinstance(data, VOntaniConfig):
            self.log.debug('create_interface-v-ont-ani', interface=interface, data=inst_data)
            self._v_ont_anis[name] = {
                'name': name,
                'enabled': interface.enabled,
                'onu-id': inst_data.onu_id,
                'expected-serial-number': inst_data.expected_serial_number,
                'preferred-channel-pair': inst_data.preferred_chanpair,
                'channel-partition': inst_data.parent_ref,
                'upstream-channel-speed': inst_data.upstream_channel_speed
            }

        elif isinstance(data, VEnetConfig):
            self.log.debug('create_interface-v-enet', interface=interface, data=inst_data)
            self._v_enets[name] = {
                'name': name,
                'enabled': interface.enabled,
                'v-ont-ani': inst_data.v_ontani_ref
            }

        else:
            raise NotImplementedError('Unknown data type')

    def on_channel_termination_config(self, name, operation, pon_type='xgs-ponid'):
        supported_operations = ['create']

        assert operation in supported_operations
        assert name in self._channel_terminations
        ct = self._channel_terminations[name]

        pon_id = ct[pon_type]
        # Look up the southbound PON port

        pon_port = self.southbound_ports.get(pon_id, None)
        if pon_port is None:
            raise ValueError('Unknown PON port. PON-ID: {}'.format(pon_id))

        assert ct['channel-pair'] in self._channel_pairs
        cpair = self._channel_pairs[ct['channel-pair']]

        assert cpair['channel-group'] in self._channel_groups
        assert cpair['channel-partition'] in self._channel_partitions
        cg = self._channel_groups[cpair['channel-group']]
        cpart = self._channel_partitions[cpair['channel-partition']]

        enabled = ct['enabled']
        
        polling_period = cg['polling-period']
        authentication_method = cpart['authentication-method']
        # line_rate = cpair['line-rate']
        # downstream_fec = cpart['fec-downstream']
        # deployment_range = cpart['differential-fiber-distance']
        # mcast_aes = cpart['mcast-aes']

        # TODO: Support BER calculation period
        # TODO support FEC, and MCAST AES settings
        # TODO Support setting of line rate

        if operation == 'create':
            pon_port.xpon_name = name
            pon_port.discovery_tick = polling_period
            pon_port.authentication_method = authentication_method
            # pon_port.deployment_range = deployment_range
            # pon_port.fec_enable = downstream_fec
            # pon_port.mcast_aes = mcast_aes

            if enabled:
                pon_port.start()
            else:
                pon_port.stop()
