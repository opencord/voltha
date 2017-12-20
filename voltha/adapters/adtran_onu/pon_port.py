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

import structlog
from twisted.internet.defer import inlineCallbacks, returnValue, succeed, TimeoutError
from twisted.internet import reactor

from voltha.protos.common_pb2 import AdminState
from voltha.protos.device_pb2 import Port

from voltha.protos.common_pb2 import OperStatus, ConnectStatus

from omci.omci_me import *

_STARTUP_RETRY_WAIT = 5
BRDCM_DEFAULT_VLAN = 4091       # TODO: Deprecate later...

# abbreviations
OP = EntityOperations


class PonPort(object):
    """Wraps northbound-port / vlan bridge support for ONU"""

    def __init__(self, handler, port_no):
        self._enabled = False
        self._valid = True
        self._handler = handler
        self._deferred = None
        self._port = None
        self._port_number = port_no
        self._bridge_initialized = False
        self.log = structlog.get_logger(device_id=handler.device_id, port_no=port_no)

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        self._gem_ports = {}                           # gem-id -> GemPort
        self._tconts = {}                              # alloc-id -> TCont

        # TODO: Add stats, alarm reference, ...

        pass

    def __str__(self):
        return "PonPort"      # TODO: Encode current state

    @staticmethod
    def create(handler, port_no):
        port = PonPort(handler, port_no)
        return port

    def _start(self):
        self._cancel_deferred()

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        self._update_adapter_agent()

        # Begin ONU Activation sequence
        self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT, self.message_exchange)

        # TODO: start h/w sync
        pass

    def _stop(self):
        self._cancel_deferred()

        self._bridge_initialized = False
        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()
        # TODO: stop h/w sync
        pass

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None

        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def delete(self):
        self.enabled = False
        self._valid = False
        self._handler = None
        # TODO: anything else

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._enabled != value:
            self._enabled = value

            if value:
                self._start()
            else:
                self._stop()

    @property
    def bridge_initialized(self):
        return self._bridge_initialized

    @property
    def port_number(self):
            return self._port_number

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self._port is None:
            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            self._port = Port(port_no=self.port_number,
                              label='PON port',
                              type=Port.PON_ONU,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status,
                              peers = [Port.PeerPort(device_id=device.parent_id,
                                                     port_no=device.parent_port_no)])
        return self._port

    def _update_adapter_agent(self):
        # TODO: Currently does the adapter_agent allow 'update' of port status
        # self.adapter_agent.update_port(self.olt.device_id, self.get_port())
        pass

    @inlineCallbacks
    def message_exchange(self):
        self.log.info('message-exchange')
        self._deferred = None

        if self._handler.device_id is None or not self.enabled:
            returnValue(succeed('deleted'))

        elif not self.enabled:
            # Wait until enabled
            returnValue('not-enabled')

        omci = self._handler.omci

        try:
            # reset incoming message queue
            omci.flush()

            ####################################################
            # Start by getting some useful device information

            device = self._handler.adapter_agent.get_device(self._handler.device_id)
            device.oper_status = OperStatus.ACTIVATING
            device.connect_status = ConnectStatus.UNREACHABLE

        except Exception as e:
            self.log.exception('top-of-msg-exch', e=e)
            device = None

        if device is None:
            # Wait until enabled
            returnValue('no-device')

        try:
            # May timeout to ONU not fully discovered (can happen in xPON case)
            # or other errors.
            # Decode fields in response and update device info

            response = yield omci.send_get_OntG('vendor_id')

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            vendor = data["vendor_id"]
            assert vendor == 'ADTN', \
                "Invalid Device/Wrong device adapter assigned: '{}'".format(vendor)

            response = yield omci.send(OntGFrame('vendor_id').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            vendor = data["vendor_id"]
            assert vendor == 'ADTN', \
                "Invalid Device/Wrong device adapter assigned: '{}'".format(vendor)

            # TODO: Get serial number and validate!

            # Mark as reachable if at least first message gets through
            device.connect_status = ConnectStatus.REACHABLE
            self._handler.adapter_agent.update_device(device)

            # response = yield omci.send_get_cardHolder('actual_plugin_unit_type', 257)
            response = yield omci.send(CardholderFrame(True, 1,
                                                       'actual_plugin_unit_type').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            # device.type = str(data["actual_plugin_unit_type"])

            # response = yield omci.send_get_circuit_pack('number_of_ports', 257)
            response = yield omci.send(CircuitPackFrame(257, 'number_of_ports').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            num_ports = data["number_of_ports"]
            assert num_ports == 1, 'Invalid number of ports: {}'.format(num_ports)

            # response = yield omci.send_get_IpHostConfigData('mac_address', 515)
            response = yield omci.send(IpHostConfigDataFrame(515, 'mac_address').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.mac_address = str(data["mac_address"])

            # response = yield omci.send_get_Ont2G('equipment_id', 0)
            response = yield omci.send(Ont2GFrame('equipment_id').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            eqptId_bootVersion = str(data["equipment_id"])
            eqptId = eqptId_bootVersion[0:10]          # ie) BVMDZ10DRA
            bootVersion = eqptId_bootVersion[12:20]    # ie) CML.D55~

            # response = yield omci.send_get_Ont2G('omcc_version', 0)
            response = yield omci.send(Ont2GFrame('omcc_version').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            # decimal version
            omciVersion = str(data["omcc_version"])

            # response = yield omci.send_get_Ont2G('vendor_product_code', 0)
            response = yield omci.send(Ont2GFrame('vendor_product_code').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            # decimal value
            vendorProductCode = str(data["vendor_product_code"])

            # response = yield omci.send(OntGFrame('version').get())
            response = yield omci.send(OntGFrame('version').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.model = str(data["version"])             # such as 1287800F1

            # Possibility of bug in ONT Firmware. uncomment this code after it is fixed.
            # response = yield omci.send_get_SoftwareImage('version', 0)
            #
            # omci_response = response.getfieldval("omci_message")
            # data = omci_response.getfieldval("data")
            # device.firmware_version = str(data["version"])
            # is_committed = data["is_committed"]
            # is_active = data["is_active"]
            # is_valid = data["is_valid"]

            # TODO: May have some issue with the next one...
            # response = yield omci.send_set_adminState(257)

            # device.hardware_version = 'TODO: to be filled'
            # TODO: Support more versions as needed
            # images = Image(version=results.get('software_version', 'unknown'))
            # device.images.image.extend([images])

            # self.adapter_agent.update_device(device)
            device.oper_status = OperStatus.ACTIVE
            device.connect_status = ConnectStatus.REACHABLE
            self._handler.adapter_agent.update_device(device)

            # Start up non-critical message exchange
            self._deferred = reactor.callLater(0, self.message_exchange_part_2)
            self.log.info('onu-activated')

        # These exceptions are not recoverable
        except (AssertionError, TypeError, ValueError, AttributeError) as e:
            self.log.exception('Failed', e=e)
            device.oper_status = OperStatus.FAILED
            device.reason = e.message
            self._handler.adapter_agent.update_device(device)

        except TimeoutError as e:
            self.log.debug('Failed', e=e)
            self._handler.adapter_agent.update_device(device)
            # Try again later. May not have been discovered
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self.message_exchange)

        except Exception as e:
            self.log.exception('Failed', e=e)
            self._handler.adapter_agent.update_device(device)
            # Try again later. May not have been discovered
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self.message_exchange)

    @inlineCallbacks
    def message_exchange_part_2(self):
        """ Called after basic OMCI message startup/exchange """

        self.log.info('message-exchange-part-2')
        self._deferred = None

        if self._handler.device_id is None or not self.enabled:
            returnValue('not-enabled')

        omci = self._handler.omci

        try:
            # reset incoming message queue
            omci.flush()
            device = self._handler.adapter_agent.get_device(self._handler.device_id)

        except Exception as e:
            self.log.exception('top-of-msg-exch', e=e)
            device = None

        if not self.enabled or device is None:
            returnValue('not-enabled')

        try:
            cvid = BRDCM_DEFAULT_VLAN           # TODO: What should this be?

            # construct message
            # MIB Reset - OntData - 0
            # results = yield omci.send_mib_reset()

            # Create AR - GalEthernetProfile - 1
            results = yield omci.send_create_gal_ethernet_profile(
                                                    1,   # Entity ID
                                                    48)  # Max GEM Payload size

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            # Port 2
            # Extended VLAN Tagging Operation config
            # TODO: add entry here for additional UNI interfaces
            results = yield omci.send_create_extended_vlan_tagging_operation_configuration_data(
                                                    0x202,  # Entity ID
                                                    2,      # Assoc Type
                                                    0x102)  # Assoc ME

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            # Set AR - ExtendedVlanTaggingOperationConfigData - 514 - 8100 - 8100
            results = yield omci.send_set_extended_vlan_tagging_operation_tpid_configuration_data(
                                                    0x202,   # Entity ID
                                                    0x8100,  # input TPID
                                                    0x8100)  # output TPID

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # unsupported_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']
            # failed_mask = results.fields['omci_message'].fields['failed_attributes_mask']

            # MAC Bridge Service config
            results = yield omci.send_create_mac_bridge_service_profile(0x201)   # Entity ID

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            # Create AR - MacBridgePortConfigData
            results = yield omci.send_create_mac_bridge_port_configuration_data(
                                            0x201,   # Entity ID
                                            0x201,   # Bridge ID
                                            2,       # Port ID
                                            1,       # TP Type
                                            0x102)   # TP ID

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            # Mapper Service config
            results = yield omci.send_create_8021p_mapper_service_profile(0x8001)   # Entity ID

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            # MAC Bridge Port config
            results = yield omci.send_create_mac_bridge_port_configuration_data(
                                            0x2102,  # Entity ID
                                            0x201,   # Bridge ID
                                            3,       # Port ID
                                            3,       # TP Type
                                            0x8001)  # TP ID

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            # VLAN Tagging Filter config
            # TODO: Probably need to get VLAN ID from device.vlan
            results = yield omci.send_create_vlan_tagging_filter_data(0x2102,  # Entity ID
                                                                      cvid)    # VLAN ID

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
            # results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(
            #                                 0x202,  # Entity ID
            #                                 8,      # Filter Inner Priority
            #                                 0,      # Filter Inner VID
            #                                 0,      # Filter Inner TPID DE
            #                                 1,      # Treatment tags to remove
            #                                 8,      # Treatment inner priority
            #                                 cvid)   # Treatment inner VID
            #
            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to untagged pkts - c-vid
            results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(
                                            0x202,   # Entity ID
                                            0x1000,  # Filter Inner VID
                                            cvid)    # Treatment inner VID

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            ######################################################################
            # If here, we can add TCONTs/GEM Ports as needed

            self._bridge_initialized = True
            self._deferred = reactor.callLater(0, self.sync_existing_xpon)
            #       that xPON may have already sent us

            # ###############################################################################
            # # Multicast related MEs
            # # Set AR - MulticastOperationsProfile - Dynamic Access Control List table
            # # Create AR - MacBridgePortConfigData - 9000 - 513 - 6 - 6 - 6
            # results = yield omci.send_create_mac_bridge_port_configuration_data(
            #                                 0x2328,
            #                                 0x201,
            #                                 6,
            #                                 6,
            #                                 6)
            #
            # # Multicast Operation Profile config
            # # Create AR - MulticastOperationsProfile
            # results = yield omci.send_create_multicast_operations_profile(
            #                                 0x201,
            #                                 3)
            #
            # # Multicast Subscriber config
            # # Create AR - MulticastSubscriberConfigInfo
            # results = yield omci.send_create_multicast_subscriber_config_info(
            #                                 0x201,
            #                                 0,
            #                                 0x201)
            #
            # # Create AR - GemPortNetworkCtp - 260 - 4000 - 0 Multicast
            # results = yield omci.send_create_gem_port_network_ctp(
            #                                 0x104,
            #                                 0x0FA0,
            #                                 0,
            #                                 "downstream",
            #                                 0)
            #
            # # Multicast GEM Interworking config Multicast
            # # Create AR - MulticastGemInterworkingTp - 6 - 260
            # results = yield omci.send_create_multicast_gem_interworking_tp(0x6, 0x104)
            #
            # results = yield omci.send_set_multicast_operations_profile_acl_row0(
            #                                 0x201,
            #                                 'dynamic',
            #                                 0,
            #                                 0x0fa0,
            #                                 0x0fa0,
            #                                 '0.0.0.0',
            #                                 '224.0.0.0',
            #                                 '239.255.255.255')
            #
            # # Multicast Operation Profile config
            # # Set AR - MulticastOperationsProfile - Downstream IGMP Multicast TCI
            # results = yield omci.send_set_multicast_operations_profile_ds_igmp_mcast_tci(
            #                                 0x201,
            #                                 4,
            #                                 cvid)

        except AssertionError as e:
            self.log.exception('Failed', e=e)
            # TODO: get message and report back
            # TODO: get message and report back

        except Exception as e:
            self.log.debug('Failed', e=e)
            self._handler.adapter_agent.update_device(device)
            # Try again later. TODO: Do we want to restart at part 1 here ?
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self.message_exchange_part_2)

    @inlineCallbacks
    def sync_existing_xpon(self):
        """
        Run through existing TCONT and GEM Ports and push into hardware
        """
        for tcont in self._tconts.itervalues():
            try:
                yield self.add_tcont(tcont, reflow=True)
            except Exception as e:
                self.log.exception('tcont-reflow', e=e, tcont=tcont)

        for gem_port in self._gem_ports.itervalues():
            try:
                yield self.add_gem_port(gem_port, reflow=True)

            except Exception as e:
                self.log.exception('gem-port-reflow', e=e, gem_port=gem_port)

        returnValue('Done')

    @inlineCallbacks
    def add_tcont(self, tcont, reflow=False):
        """
        Creates/ a T-CONT with the given alloc-id

        :param tcont: (TCont) Object that maintains the TCONT properties
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            returnValue('Deleting')

        if not reflow and tcont.alloc_id in self._tconts:
            returnValue('already created')

        self.log.info('add', tcont=tcont, reflow=reflow)
        self._tconts[tcont.alloc_id] = tcont

        if not self.bridge_initialized:
            returnValue('Bridge Not Initialized')

        try:
            results = yield tcont.add_to_hardware(self._handler.omci)

        except Exception as e:
            self.log.exception('tcont', tcont=tcont, reflow=reflow, e=e)
            # May occur with xPON provisioning, use hw-resync to recover
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def update_tcont_td(self, alloc_id, new_td):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue('not-found')

        tcont.traffic_descriptor = new_td

        if not self.bridge_initialized:
            returnValue('Bridge Not Initialized')

        try:
            results = yield tcont.add_to_hardware(self._handler.omci)

        except Exception as e:
            self.log.exception('tcont', tcont=tcont, e=e)
            # May occur with xPON provisioning, use hw-resync to recover
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def remove_tcont(self, alloc_id):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue('nop')

        del self._tconts[alloc_id]

        if not self.bridge_initialized:
            returnValue('Bridge Not Initialized')

        try:
            results = yield tcont.remove_from_hardware(self._handler.omci)

        except Exception as e:
            self.log.exception('delete', e=e)
            results = e
        #     raise

        returnValue(results)

    def gem_port(self, gem_id):
        return self._gem_ports.get(gem_id)

    @property
    def gem_ids(self):
        """Get all GEM Port IDs used by this ONU"""
        return sorted([gem_id for gem_id, gem in self._gem_ports.items()])

    @inlineCallbacks
    def add_gem_port(self, gem_port, reflow=False):
        """
        Add a GEM Port to this ONU

        :param gem_port: (GemPort) GEM Port to add
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            returnValue('Deleting')

        if not reflow and gem_port.gem_id in self._gem_ports:
            returnValue('nop')

        self.log.info('add', gem_port=gem_port, reflow=reflow)
        self._gem_ports[gem_port.gem_id] = gem_port

        if not self.bridge_initialized:
            returnValue('Bridge Not Initialized')

        try:
            results = yield gem_port.add_to_hardware(self._handler.omci)
            # TODO: Are flows affected by this change?

        except Exception as e:
            self.log.exception('gem-port', gem_port=gem_port, reflow=reflow, e=e)
            # This can happen with xPON if the ONU has been provisioned, but the PON Discovery
            # has not occurred for the ONU. Rely on hw sync to recover
            results = 'resync needed'

        returnValue(results)

    @inlineCallbacks
    def remove_gem_id(self, gem_id):
        gem_port = self._gem_ports.get(gem_id)

        if gem_port is None:
            returnValue('nop')

        del self._gem_ports[gem_id]

        if not self.bridge_initialized:
            returnValue('Bridge Not Initialized')

        try:
            results = yield gem_port.remove_from_hardware(self._handler.omci)
            # TODO: Are flows affected by this change?

        except Exception as ex:
            self.log.exception('gem-port-delete', e=ex)
            raise

        returnValue(results)











