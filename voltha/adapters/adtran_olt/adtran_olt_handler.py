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
import xmltodict

from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks, succeed

from adtran_device_handler import AdtranDeviceHandler
from voltha.adapters.adtran_olt.resources import adtranolt_platform as platform
from download import Download
from codec.olt_state import OltState
from flow.flow_entry import FlowEntry
from resources.adtran_olt_resource_manager import AdtranOltResourceMgr
from net.pio_zmq import PioClient
from net.pon_zmq import PonClient
from voltha.core.flow_decomposer import *
from voltha.extensions.omci.omci import *
from voltha.protos.common_pb2 import AdminState, OperStatus
from voltha.protos.device_pb2 import ImageDownload, Image
from voltha.protos.openflow_13_pb2 import OFPP_MAX
from common.tech_profile.tech_profile import *
from voltha.protos.device_pb2 import Port


class AdtranOltHandler(AdtranDeviceHandler):
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
        self._pon_agent = None
        self._pio_agent = None
        self._ssh_deferred = None
        self._system_id = None
        self._download_protocols = None
        self._download_deferred = None
        self._downloads = {}        # name -> Download obj
        self._pio_exception_map = []

        self.downstream_shapping_supported = True      # 1971320F1-ML-4154 and later

        # FIXME:  Remove once we containerize.  Only exists to keep BroadCom OpenOMCI ONU Happy
        #         when it reaches up our rear and tries to yank out a UNI port number
        self.platform_class = None

        # To keep broadcom ONU happy
        from voltha.adapters.adtran_olt.resources.adtranolt_platform import adtran_platform
        self.platform = adtran_platform()           # TODO: Remove once tech-profiles & containerization is done !!!


    def __del__(self):
        # OLT Specific things here.
        #
        # If you receive this during 'enable' of the object, you probably threw an
        # uncaught exception which triggered an errback in the VOLTHA core.
        d, self.status_poll = self.status_poll, None

        # Clean up base class as well
        AdtranDeviceHandler.__del__(self)

    def _cancel_deferred(self):
        d1, self.status_poll = self.status_poll, None
        d2, self._ssh_deferred = self._ssh_deferred, None
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
    def get_device_info(self, _device):
        """
        Perform an initial network operation to discover the device hardware
        and software version. Serial Number would be helpful as well.

        Upon successfully retrieving the information, remember to call the
        'start_heartbeat' method to keep in contact with the device being managed

        :param _device: A voltha.Device object, with possible device-type
                specific extensions. Such extensions shall be described as part of
                the device type specification returned by device_types().
        """
        from codec.physical_entities_state import PhysicalEntitiesState
        # TODO: After a CLI 'reboot' command, the device info may get messed up (prints labels and not values)
        # #     Enter device and type 'show'
        device = {
            'model': 'n/a',
            'hardware_version': 'unknown',
            'serial_number': 'unknown',
            'vendor': 'ADTRAN, Inc.',
            'firmware_version': 'unknown',
            'running-revision': 'unknown',
            'candidate-revision': 'unknown',
            'startup-revision': 'unknown',
            'software-images': []
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
                    if 'software' in module:
                        if 'software' in module['software']:
                            software = module['software']['software']
                            if isinstance(software, dict):
                                device['running-revision'] = str(software.get('running-revision',
                                                                              'n/a')).translate(None, '?')
                                device['candidate-revision'] = str(software.get('candidate-revision',
                                                                                'n/a')).translate(None, '?')
                                device['startup-revision'] = str(software.get('startup-revision',
                                                                              'n/a')).translate(None, '?')
                            elif isinstance(software, list):
                                for sw_item in software:
                                    sw_type = sw_item.get('name', '').lower()
                                    if sw_type == 'firmware':
                                        device['firmware_version'] = str(sw_item.get('running-revision',
                                                                                     'unknown')).translate(None, '?')
                                    elif sw_type == 'software':
                                        for rev_type in ['startup-revision',
                                                         'running-revision',
                                                         'candidate-revision']:
                                            if rev_type in sw_item:
                                                image = Image(name=rev_type,
                                                              version=sw_item[rev_type],
                                                              is_active=(rev_type == 'running-revision'),
                                                              is_committed=True,
                                                              is_valid=True,
                                                              install_datetime='Not Available',
                                                              hash='Not Available')
                                                device['software-images'].append(image)

                    # Update features based on version
                    # Format expected to be similar to:  1971320F1-ML-4154

                    running_version = next((image.version for image in device.get('software-images', list())
                                           if image.is_active), '').split('-')
                    if len(running_version) > 2:
                        try:
                            self.downstream_shapping_supported = int(running_version[-1]) >= 4154
                        except ValueError:
                            pass

        except Exception as e:
            self.log.exception('dev-info-failure', e=e)
            raise

        returnValue(device)

    def initialize_resource_manager(self):
        # Initialize the resource and tech profile managers
        extra_args = '--olt_model {}'.format(self.resource_manager_key)
        self.resource_mgr = AdtranOltResourceMgr(self.device_id,
                                                 self.host_and_port,
                                                 extra_args,
                                                 self.default_resource_mgr_device_info)
        self._populate_tech_profile_per_pon_port()

    @property
    def default_resource_mgr_device_info(self):
        class AdtranOltDevInfo(object):
            def __init__(self, pon_ports):
                self.technology = "xgspon"
                self.onu_id_start = 0
                self.onu_id_end = platform.MAX_ONUS_PER_PON
                self.alloc_id_start = platform.MIN_TCONT_ALLOC_ID
                self.alloc_id_end = platform.MAX_TCONT_ALLOC_ID
                self.gemport_id_start = platform.MIN_GEM_PORT_ID
                self.gemport_id_end = platform.MAX_GEM_PORT_ID
                self.pon_ports = len(pon_ports)
                self.max_tconts = platform.MAX_TCONTS_PER_ONU
                self.max_gem_ports = platform.MAX_GEM_PORTS_PER_ONU
                self.intf_ids = pon_ports.keys()    # PON IDs

        return AdtranOltDevInfo(self.southbound_ports)

    def _populate_tech_profile_per_pon_port(self):
        self.tech_profiles = {intf_id: self.resource_mgr.resource_managers[intf_id].tech_profile
                              for intf_id in self.resource_mgr.device_info.intf_ids}

        # Make sure we have as many tech_profiles as there are pon ports on
        # the device
        assert len(self.tech_profiles) == self.resource_mgr.device_info.pon_ports

    def get_tp_path(self, intf_id, ofp_port_name):
        # TODO: Should get Table id form the flow, as of now hardcoded to DEFAULT_TECH_PROFILE_TABLE_ID (64)
        # 'tp_path' contains the suffix part of the tech_profile_instance path.
        # The prefix to the 'tp_path' should be set to \
        # TechProfile.KV_STORE_TECH_PROFILE_PATH_PREFIX by the ONU adapter.
        return self.tech_profiles[intf_id].get_tp_path(DEFAULT_TECH_PROFILE_TABLE_ID,
                                                       ofp_port_name)

    def delete_tech_profile_instance(self, intf_id, onu_id, logical_port):
        # Remove the TP instance associated with the ONU
        ofp_port_name = self.get_ofp_port_name(intf_id, onu_id, logical_port)
        tp_path = self.get_tp_path(intf_id, ofp_port_name)
        return self.tech_profiles[intf_id].delete_tech_profile_instance(tp_path)

    def get_ofp_port_name(self, pon_id, onu_id, logical_port_number):
        parent_port_no = self.pon_id_to_port_number(pon_id)
        child_device = self.adapter_agent.get_child_device(self.device_id,
                                                           parent_port_no=parent_port_no, onu_id=onu_id)
        if child_device is None:
            self.log.error("could-not-find-child-device", parent_port_no=pon_id, onu_id=onu_id)
            return None, None

        ports = self.adapter_agent.get_ports(child_device.id, Port.ETHERNET_UNI)
        port = next((port for port in ports if port.port_no == logical_port_number), None)
        logical_port = self.adapter_agent.get_logical_port(self.logical_device_id,
                                                           port.label)
        ofp_port_name = (logical_port.ofp_port.name, logical_port.ofp_port.port_no)

        return ofp_port_name

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
            command = "ip link | grep -A1 eth0 | sed -n -e 's/^.*ether //p' | awk '{ print $1 }'"
            rcmd = RCmd(self.ip_address, self.netconf_username, self.netconf_password,
                        command)
            address = yield rcmd.execute()
            self.mac_address = address.replace('\n', '')
            self.log.info("mac-addr", mac_addr=self.mac_address)

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

            ports = ietf_interfaces.get_port_entries(results, 'ethernet')
            returnValue(ports)

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

        for port in results.itervalues():
            port_no = port.get('port_no')
            assert port_no, 'Port number not found'

            # May already exist if device was not fully reachable when first enabled
            if port_no not in self.northbound_ports:
                self.log.info('processing-nni', port_no=port_no, name=port['port_no'])
                self.northbound_ports[port_no] = NniPort(self, **port) if not self.is_virtual_olt \
                    else MockNniPort(self, **port)

            if len(self.northbound_ports) >= self.max_nni_ports: # TODO: For now, limit number of NNI ports to make debugging easier
                break

        self.num_northbound_ports = len(self.northbound_ports)

    def _olt_version(self):
        #  Version
        #     0     Unknown
        #     1     V1 OMCI format
        #     2     V2 OMCI format
        #     3     2018-01-11 or later
        version = 0
        info = self._rest_support.get('module-info', [dict()])
        hw_mod_ver_str = next((mod.get('revision') for mod in info
                               if mod.get('module-name', '').lower() == 'gpon-olt-hw'), None)

        if hw_mod_ver_str is not None:
            try:
                from datetime import datetime
                hw_mod_dt = datetime.strptime(hw_mod_ver_str, '%Y-%m-%d')
                version = 2 if hw_mod_dt >= datetime(2017, 9, 21) else 2

            except Exception as e:
                self.log.exception('ver-str-check', e=e)

        return version

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

        self.startup = self.rest_client.request('GET', self.GPON_PON_CONFIG_LIST_URI,
                                                'pon-config')
        try:
            from codec.ietf_interfaces import IetfInterfacesState
            from nni_port import MockNniPort

            results = yield self.startup

            ietf_interfaces = IetfInterfacesState(self.netconf_client)

            if self.is_virtual_olt:
                nc_results = MockNniPort.get_pon_port_state_results()
            else:
                self.startup = ietf_interfaces.get_state()
                nc_results = yield self.startup

            ports = ietf_interfaces.get_port_entries(nc_results, 'xpon')
            if len(ports) == 0:
                ports = ietf_interfaces.get_port_entries(nc_results,
                                                         'channel-termination')
            for data in results:
                pon_id = data['pon-id']
                port = ports[pon_id + 1]
                port['pon-id'] = pon_id
                port['admin_state'] = AdminState.ENABLED \
                    if data.get('enabled', True)\
                    else AdminState.DISABLED

        except Exception as e:
            log.exception('enumerate_southbound_ports', e=e)
            raise

        returnValue(ports)

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

        for pon in results.itervalues():
            pon_id = pon.get('pon-id')
            assert pon_id is not None, 'PON ID not found'
            if pon['ifIndex'] is None:
                pon['port_no'] = self.pon_id_to_port_number(pon_id)
            else:
                pass        # Need to adjust ONU numbering !!!!

            # May already exist if device was not fully reachable when first enabled
            if pon_id not in self.southbound_ports:
                self.southbound_ports[pon_id] = PonPort(self, **pon)

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
        # ZeroMQ clients
        self._zmq_startup()

        # Download support
        self._download_deferred = reactor.callLater(0, self._get_download_protocols)

        # Register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()

        # PON Status
        self.status_poll = reactor.callLater(5, self.poll_for_status)
        return succeed('Done')

    def on_heatbeat_alarm(self, active):
        if not active:
            self.ready_network_access()

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
    def ready_network_access(self):
        from net.rcmd import RCmd

        # Check for port status
        command = 'netstat -pan | grep -i 0.0.0.0:{} |  wc -l'.format(self.pon_agent_port)
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
            def v1_method():
                command = 'mkdir -p /etc/pon_agent; touch /etc/pon_agent/debug.conf; '
                command += 'ps -ae | grep -i ngpon2_agent; '
                command += 'service_supervisor stop ngpon2_agent; service_supervisor start ngpon2_agent; '
                command += 'ps -ae | grep -i ngpon2_agent'

                self.log.debug('create-request', command=command)
                return RCmd(self.ip_address, self.netconf_username, self.netconf_password, command)

            def v2_v3_method():
                # Old V2 method
                # For V2 images, want -> export ZMQ_LISTEN_ON_ANY_ADDRESS=1
                # For V3+ images, want -> export AGENT_LISTEN_ON_ANY_ADDRESS=1

                # V3 unifies listening port, compatible with v2
                cmd = "sed --in-place '/add feature/aexport ZMQ_LISTEN_ON_ANY_ADDRESS=1' " \
                      "/etc/ngpon2_agent/ngpon2_agent_feature_flags; "
                cmd += "sed --in-place '/add feature/aexport AGENT_LISTEN_ON_ANY_ADDRESS=1' " \
                      "/etc/ngpon2_agent/ngpon2_agent_feature_flags; "

                # Note: 'ps' commands are to help decorate the logfile with useful info
                cmd += 'ps -ae | grep -i ngpon2_agent; '
                cmd += 'service_supervisor stop ngpon2_agent; service_supervisor start ngpon2_agent; '
                cmd += 'ps -ae | grep -i ngpon2_agent'

                self.log.debug('create-request', command=cmd)
                return RCmd(self.ip_address, self.netconf_username, self.netconf_password, cmd)

            # Look for version
            next_run = 15
            version = v2_v3_method    # NOTE: Only v2 or later supported.

            if version is not None:
                try:
                    rcmd = version()
                    results = yield rcmd.execute()
                    self.log.info('create-results', results=results, result_type=type(results))

                except Exception as e:
                    self.log.exception('mkdir-and-restart', e=e)
        else:
            next_run = 0

        if next_run > 0:
            self._ssh_deferred = reactor.callLater(next_run, self.ready_network_access)

        returnValue('retrying' if next_run > 0 else 'ready')

    def _zmq_startup(self):
        # ZeroMQ clients
        self._pon_agent = PonClient(self.ip_address,
                                    port=self.pon_agent_port,
                                    rx_callback=self.rx_pa_packet)

        try:
            self._pio_agent = PioClient(self.ip_address,
                                        port=self.pio_port,
                                        rx_callback=self.rx_pio_packet)
        except Exception as e:
            self._pio_agent = None
            self.log.exception('pio-agent', e=e)

    def _zmq_shutdown(self):
        pon, self._pon_agent = self._pon_agent, None
        pio, self._pio_agent = self._pio_agent, None

        for c in [pon, pio]:
            if c is not None:
                try:
                    c.shutdown()
                except:
                    pass

    def _unregister_for_inter_adapter_messages(self):
        try:
            self.adapter_agent.unregister_for_inter_adapter_messages()
        except:
            pass

    def disable(self):
        self._cancel_deferred()

        # Drop registration for adapter messages
        self._unregister_for_inter_adapter_messages()
        self._zmq_shutdown()
        self._pio_exception_map = []

        # Remove any UNI ports that were created for any activated ONUs
        uni_ports = self.adapter_agent.get_ports(self.device_id, Port.ETHERNET_UNI)
        for uni_port in uni_ports:
            self.adapter_agent.delete_port(self.device_id, uni_port)

        super(AdtranOltHandler, self).disable()

    def reenable(self, done_deferred=None):
        super(AdtranOltHandler, self).reenable(done_deferred=done_deferred)

        # Only do the re-enable if we fully came up on the very first enable attempt.
        # If we had not, the base class will have initiated the 'activate' for us

        if self._initial_enable_complete:
            self._zmq_startup()
            self.adapter_agent.register_for_inter_adapter_messages()
            self.status_poll = reactor.callLater(1, self.poll_for_status)

    def reboot(self):
        if not self._initial_enable_complete:
            # Never contacted the device on the initial startup, do 'activate' steps instead
            return

        self._cancel_deferred()

        # Drop registration for adapter messages
        self._unregister_for_inter_adapter_messages()
        self._zmq_shutdown()

        # Download supported protocols may change (if new image gets activated)
        self._download_protocols = None

        super(AdtranOltHandler, self).reboot()

    def _finish_reboot(self, timeout, previous_oper_status, previous_conn_status):
        super(AdtranOltHandler, self)._finish_reboot(timeout, previous_oper_status, previous_conn_status)

        self.ready_network_access()

        # Download support
        self._download_deferred = reactor.callLater(0, self._get_download_protocols)

        # Register for adapter messages
        self.adapter_agent.register_for_inter_adapter_messages()
        self._zmq_startup()

        self.status_poll = reactor.callLater(5, self.poll_for_status)

    def delete(self):
        self._cancel_deferred()

        # Drop registration for adapter messages
        self._unregister_for_inter_adapter_messages()
        self._zmq_shutdown()

        super(AdtranOltHandler, self).delete()

    def rx_pa_packet(self, packets):
        if self._pon_agent is not None:
            for packet in packets:
                try:
                    pon_id, onu_id, msg_bytes, is_omci = self._pon_agent.decode_packet(packet)

                    if is_omci:
                        proxy_address = self._pon_onu_id_to_proxy_address(pon_id, onu_id)

                        if proxy_address is not None:
                            self.adapter_agent.receive_proxied_message(proxy_address, msg_bytes)

                except Exception as e:
                    self.log.exception('rx-pon-agent-packet', e=e)

    def _compute_logical_port_no(self, port_no, evc_map, packet):
        logical_port_no = None

        # Upstream direction?
        if self.is_pon_port(port_no):
            #TODO: Validate the evc-map name
            from flow.evc_map import EVCMap
            map_info = EVCMap.decode_evc_map_name(evc_map)
            logical_port_no = int(map_info.get('ingress-port'))

            if logical_port_no is None:
                # Get PON
                pon = self.get_southbound_port(port_no)

                # Examine Packet and decode gvid
                if packet is not None:
                    pass

        elif self.is_nni_port(port_no):
            nni = self.get_northbound_port(port_no)
            logical_port = nni.get_logical_port() if nni is not None else None
            logical_port_no = logical_port.ofp_port.port_no if logical_port is not None else None

        # TODO: Need to decode base on port_no & evc_map
        return logical_port_no

    def rx_pio_packet(self, packets):
        self.log.debug('rx-packet-in', type=type(packets), data=packets)
        assert isinstance(packets, list), 'Expected a list of packets'

        # TODO self._pio_agent.socket.socket.closed might be a good check here as well
        if self.logical_device_id is not None and self._pio_agent is not None:
            for packet in packets:
                url_type = self._pio_agent.get_url_type(packet)
                if url_type == PioClient.UrlType.EVCMAPS_RESPONSE:
                    exception_map = self._pio_agent.decode_query_response_packet(packet)
                    self.log.debug('rx-pio-packet', exception_map=exception_map)
                    # update latest pio exception map
                    self._pio_exception_map = exception_map

                elif url_type == PioClient.UrlType.PACKET_IN:
                    try:
                        from scapy.layers.l2 import Ether, Dot1Q
                        ifindex, evc_map, packet = self._pio_agent.decode_packet(packet)

                        # convert ifindex to physical port number
                        # pon port numbers start at 60001 and end at 600016 (16 pons)
                        if ifindex > 60000 and ifindex < 60017:
                            port_no = (ifindex - 60000) + 4
                        # nni port numbers start at 1401 and end at 1404 (16 nnis)
                        elif ifindex > 1400 and ifindex < 1405:
                            port_no = ifindex - 1400
                        else:
                            raise ValueError('Unknown physical port. ifindex: {}'.format(ifindex))

                        logical_port_no = self._compute_logical_port_no(port_no, evc_map, packet)

                        if logical_port_no is not None:
                            if self.is_pon_port(port_no) and packet.haslayer(Dot1Q):
                                # Scrub g-vid
                                inner_pkt = packet.getlayer(Dot1Q)
                                assert inner_pkt.haslayer(Dot1Q), 'Expected a C-Tag'
                                packet = Ether(src=packet.src, dst=packet.dst, type=inner_pkt.type)\
                                    / inner_pkt.payload

                            self.adapter_agent.send_packet_in(logical_device_id=self.logical_device_id,
                                                              logical_port_no=logical_port_no,
                                                              packet=str(packet))
                        else:
                            self.log.warn('logical-port-not-found', port_no=port_no, evc_map=evc_map)

                    except Exception as e:
                        self.log.exception('rx-pio-packet', e=e)

                else:
                    self.log.warn('packet-in-unknown-url-type', url_type=url_type)

    def packet_out(self, egress_port, msg):
        """
        Pass a packet_out message content to adapter so that it can forward it
        out to the device. This is only called on root devices.

        :param egress_port: egress logical port number
        :param msg: actual message
        :return: None        """

        if self.pio_port is not None:
            from scapy.layers.l2 import Ether, Dot1Q
            from scapy.layers.inet import UDP
            from common.frameio.frameio import hexify

            self.log.debug('sending-packet-out', egress_port=egress_port,
                           msg=hexify(msg))
            pkt = Ether(msg)

            # Remove any extra tags
            while pkt.type == 0x8100:
                msg_hex = hexify(msg)
                msg_hex = msg_hex[:24] + msg_hex[32:]
                bytes = []
                msg_hex = ''.join(msg_hex.split(" "))
                for i in range(0, len(msg_hex), 2):
                    bytes.append(chr(int(msg_hex[i:i+2], 16)))

                msg = ''.join(bytes)
                pkt = Ether(msg)

            if self._pio_agent is not None:
                port, ctag, vlan_id, evcmapname = FlowEntry.get_packetout_info(self, egress_port)
                exceptiontype = None
                if pkt.type == FlowEntry.EtherType.EAPOL:
                    exceptiontype = 'eapol'
                    ctag = self.utility_vlan
                elif pkt.type == 2:
                    exceptiontype = 'igmp'
                elif pkt.type == FlowEntry.EtherType.IPv4:
                    if UDP in pkt and pkt[UDP].sport == 67 and pkt[UDP].dport == 68:
                        exceptiontype = 'dhcp'

                if exceptiontype is None:
                    self.log.warn('packet-out-exceptiontype-unknown', eEtherType=pkt.type)

                elif port is not None and ctag is not None and vlan_id is not None and \
                     evcmapname is not None and self.pio_exception_exists(evcmapname, exceptiontype):

                    self.log.debug('sending-pio-packet-out', port=port, ctag=ctag, vlan_id=vlan_id,
                                   evcmapname=evcmapname, exceptiontype=exceptiontype)
                    out_pkt = (
                        Ether(src=pkt.src, dst=pkt.dst) /
                        Dot1Q(vlan=vlan_id) /
                        Dot1Q(vlan=ctag, type=pkt.type) /
                        pkt.payload
                    )
                    data = self._pio_agent.encode_packet(port, str(out_pkt), evcmapname, exceptiontype)
                    self.log.debug('pio-packet-out', message=data)
                    try:
                        self._pio_agent.send(data)

                    except Exception as e:
                        self.log.exception('pio-send', egress_port=egress_port, e=e)
                else:
                    self.log.warn('packet-out-flow-not-found', egress_port=egress_port)

    def pio_exception_exists(self, name, exp):
        # verify exception is in the OLT's reported exception map for this evcmap name
        if exp is None:
            return False
        entry = next((entry for entry in self._pio_exception_map if entry['evc-map-name'] == name), None)
        if entry is None:
            return False
        if exp not in entry['exception-types']:
            return False
        return True

    def send_packet_exceptions_request(self):
        if self._pio_agent is not None:
            request = self._pio_agent.query_request_packet()
            try:
                self._pio_agent.send(request)

            except Exception as e:
                self.log.exception('pio-send', e=e)

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

    def _create_utility_flow(self):
        nni_port = self.northbound_ports.get(1).port_no
        pon_port = self.southbound_ports.get(0).port_no

        return mk_flow_stat(
            priority=200,
            match_fields=[
                in_port(nni_port),
                vlan_vid(ofp.OFPVID_PRESENT + self.utility_vlan)
            ],
            actions=[output(pon_port)]
        )

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

        if flows:
            # Special helper egress Packet In/Out flows
            special_flow = self._create_utility_flow()
            valid_flow, evc = FlowEntry.create(special_flow, self)

            if valid_flow is not None:
                valid_flows.append(valid_flow.flow_id)

            if evc is not None:
                try:
                    evc.schedule_install()
                    self.add_evc(evc)

                except Exception as e:
                    evc.status = 'EVC Install Exception: {}'.format(e.message)
                    self.log.exception('EVC-install', e=e)

        # verify exception flows were installed by OLT PET process
        reactor.callLater(5, self.send_packet_exceptions_request)

        # Now process bulk flows
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
            yield FlowEntry.drop_missing_flows(self, valid_flows)

        except Exception as e:
            self.log.exception('bulk-flow-update-remove', e=e)

    # @inlineCallbacks
    def send_proxied_message(self, proxy_address, msg):
        self.log.debug('sending-proxied-message', msg=msg)

        if isinstance(msg, Packet):
            msg = str(msg)

        if self._pon_agent is not None:
            pon_id, onu_id = self._proxy_address_to_pon_onu_id(proxy_address)

            pon = self.southbound_ports.get(pon_id)

            if pon is not None and pon.enabled:
                onu = pon.onu(onu_id)

                if onu is not None and onu.enabled:
                    data = self._pon_agent.encode_omci_packet(msg, pon_id, onu_id)
                    try:
                        self._pon_agent.send(data)

                    except Exception as e:
                        self.log.exception('pon-agent-send', pon_id=pon_id, onu_id=onu_id, e=e)
                else:
                    self.log.debug('onu-invalid-or-disabled', pon_id=pon_id, onu_id=onu_id)
            else:
                self.log.debug('pon-invalid-or-disabled', pon_id=pon_id)

    def _onu_offset(self, onu_id):
        # Start ONU's just past the southbound PON port numbers. Since ONU ID's start
        # at zero, add one
        # assert AdtranOltHandler.BASE_ONU_OFFSET > (self.num_northbound_ports + self.num_southbound_ports + 1)
        assert AdtranOltHandler.BASE_ONU_OFFSET > (4 + self.num_southbound_ports + 1)  # Skip over uninitialized ports
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
        pon_id = self._port_number_to_pon_id(proxy_address.channel_id)

        return pon_id, onu_id

    def pon_id_to_port_number(self, pon_id):
        return pon_id + 1 + 4   # Skip over uninitialized ports

    def _port_number_to_pon_id(self, port):
        if self.is_uni_port(port):
            # Convert to OLT device port
            port = platform.intf_id_from_uni_port_num(port)

        return port - 1 - 4  # Skip over uninitialized ports

    def is_pon_port(self, port):
        return self._port_number_to_pon_id(port) in self.southbound_ports

    def is_uni_port(self, port):
            return OFPP_MAX >= port >= (5 << 11)

    def get_southbound_port(self, port):
        pon_id = self._port_number_to_pon_id(port)
        return self.southbound_ports.get(pon_id, None)

    def get_northbound_port(self, port):
        return self.northbound_ports.get(port, None)

    def get_port_name(self, port, logical_name=False):
        """
        Get the name for a port

        Port names are used in various ways within and outside of VOLTHA.
        Typically, the physical port name will be used during device handler conversations
        with the hardware (REST, NETCONF, ...) while the logical port name is what the
        outside world (ONOS, SEBA, ...) uses.

        All ports have a physical port name, but only ports exposed through VOLTHA
        as a logical port will have a logical port name
        """
        if self.is_nni_port(port):
            port = self.get_northbound_port(port)
            return port.logical_port_name if logical_name else port.physical_port_name

        if self.is_pon_port(port):
            port = self.get_southbound_port(port)
            return port.logical_port_name if logical_name else port.physical_port_name

        if self.is_uni_port(port):
            return 'uni-{}'.format(port)

        if self.is_logical_port(port):
            raise NotImplemented('Logical OpenFlow ports are not supported')

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
            if not self._initial_enable_complete:
                # Never contacted the device on the initial startup, do 'activate' steps instead
                raise Exception('Device has not finished initial activation')

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

            request.reason = ImageDownload.UNKNOWN_ERROR if self._initial_enable_complete\
                else ImageDownload.DEVICE_BUSY
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

        if request.state not in [ImageDownload.DOWNLOAD_STARTED,
                                 ImageDownload.DOWNLOAD_SUCCEEDED,
                                 ImageDownload.DOWNLOAD_FAILED]:
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

    def add_onu_device(self, pon_id, onu_id, serial_number):
        onu_device = self.adapter_agent.get_child_device(self.device_id,
                                                         serial_number=serial_number)
        if onu_device is not None:
            return onu_device

        try:
            from voltha.protos.voltha_pb2 import Device
            # NOTE - channel_id of onu is set to pon_id
            pon_port = self.pon_id_to_port_number(pon_id)
            proxy_address = Device.ProxyAddress(device_id=self.device_id,
                                                channel_id=pon_port,
                                                onu_id=onu_id,
                                                onu_session_id=onu_id)

            self.log.debug("added-onu", port_no=pon_id,
                           onu_id=onu_id, serial_number=serial_number,
                           proxy_address=proxy_address)

            self.adapter_agent.add_onu_device(
                parent_device_id=self.device_id,
                parent_port_no=pon_port,
                vendor_id=serial_number[:4],
                proxy_address=proxy_address,
                root=True,
                serial_number=serial_number,
                admin_state=AdminState.ENABLED,
            )

        except Exception as e:
            self.log.exception('onu-activation-failed', e=e)
            return None

    def setup_onu_tech_profile(self, pon_id, onu_id, logical_port_number):
        # Send ONU Adapter related tech profile information.
        self.log.debug('add-tech-profile-info')

        uni_id = self.platform.uni_id_from_uni_port(logical_port_number)
        parent_port_no = self.pon_id_to_port_number(pon_id)
        onu_device = self.adapter_agent.get_child_device(self.device_id,
                                                         onu_id=onu_id,
                                                         parent_port_no=parent_port_no)

        ofp_port_name, ofp_port_no = self.get_ofp_port_name(pon_id, onu_id,
                                                            logical_port_number)
        if ofp_port_name is None:
            self.log.error("port-name-not-found")
            return

        tp_path = self.get_tp_path(pon_id, ofp_port_name)

        self.log.debug('Load-tech-profile-request-to-onu-handler', tp_path=tp_path)

        msg = {'proxy_address': onu_device.proxy_address, 'uni_id': uni_id,
               'event': 'download_tech_profile', 'event_data': tp_path}

        # Send the event message to the ONU adapter
        self.adapter_agent.publish_inter_adapter_message(onu_device.id, msg)
