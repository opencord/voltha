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
from omci.deprecated import *       # TODO: Remove this once OMCI_CC and ME_Frame refactoring is complete

###################################################################################
#
# TODO: Notes -> This version is the fifth attempt. All calls converted with the
#                exception of the mib-reset and upload.
#
#                Saving this off before moving things around.
#
#
###################################################################################


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

        # TODO: Until we have an external database, just save it here
        self.mib_data_store = dict()  # TODO: Improve and make class attribute/property
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
        self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                           self._initial_message_exchange)
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
                              peers=[Port.PeerPort(device_id=device.parent_id,
                                                   port_no=device.parent_port_no)])
        return self._port

    def _update_adapter_agent(self):
        # TODO: Currently does the adapter_agent allow 'update' of port status
        # self.adapter_agent.update_port(self.olt.device_id, self.get_port())
        pass

    @inlineCallbacks
    def _initial_message_exchange(self):
        """
        Perform a MIB Reset and then collect some basic (read-only) attributes.
        Upon success, begin MIB upload sequence
        """
        self.log.info('initial-message-exchange')
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
            device.reason = 'Initial OMCI message exchange in progress'

        except Exception as e:
            self.log.exception('top-of-msg-exch', e=e)
            device = None

        if device is None:
            # Wait until enabled
            returnValue('no-device')

        try:
            # Note: May timeout to ONU not fully discovered (can happen in xPON case)
            # or other errors.
            # Decode fields in response and update device info

            response = yield omci.send(OntGFrame('vendor_id').get())
            # TODO: Get status for this and others below before getting other values...
            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            vendor = data["vendor_id"]
            assert vendor == 'ADTN', \
                "Invalid Device/Wrong device adapter assigned: '{}'".format(vendor)

            # TODO: Get serial number and validate!

            # Mark as reachable if at least first message gets through
            device.connect_status = ConnectStatus.REACHABLE
            self._handler.adapter_agent.update_device(device)

            response = yield omci.send(CardholderFrame(True, 1,
                                                       'actual_plugin_unit_type').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            # device.type = str(data["actual_plugin_unit_type"])

            response = yield omci.send(CircuitPackFrame(257, 'number_of_ports').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            num_ports = data["number_of_ports"]
            assert num_ports == 1, 'Invalid number of ports: {}'.format(num_ports)

            response = yield omci.send(IpHostConfigDataFrame(515, 'mac_address').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.mac_address = str(data["mac_address"])

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

            response = yield omci.send(Ont2GFrame('vendor_product_code').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            # decimal value
            vendorProductCode = str(data["vendor_product_code"])

            response = yield omci.send(OntGFrame('version').get())

            omci_response = response.getfieldval("omci_message")
            data = omci_response.getfieldval("data")
            device.model = str(data["version"])             # such as 1287800F1

            # TODO: Combine ONTG calls into a single call with multiple attributes
            # TODO: Combine ONT2G calls into a single call with multiple attributes

            # TODO: Look into ONTG and ONT2G to see if we can get other items of interest
            #       such as max tconts, max gem ports, and so on. Make use of them

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
            device.reason = 'Initial OMCI message exchange complete'
            self._handler.adapter_agent.update_device(device)

            # Start MIB synchronization
            self._deferred = reactor.callLater(0, self._perform_mib_upload)
            self.log.info('onu-activated')

        # These exceptions are not recoverable
        except (TypeError, ValueError) as e:
            self.log.exception('Failed', e=e)
            device.oper_status = OperStatus.FAILED
            device.reason = 'Initial message sequence failure: ' + e.message
            self._handler.adapter_agent.update_device(device)

        except TimeoutError as e:
            self.log.debug('Failed', e=e)
            self._handler.adapter_agent.update_device(device)
            # Try again later. May not have been discovered
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self._initial_message_exchange)

        except Exception as e:
            self.log.exception('Failed', e=e)
            device.reason = 'Initial message sequence failure: ' + e.message
            self._handler.adapter_agent.update_device(device)
            # Try again later. May not have been discovered
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self._initial_message_exchange)

    @inlineCallbacks
    def _perform_mib_upload(self):
        """
        Called after basic OMCI MIB RESET message startup/exchange.

        Upon successful completion, proceed to establish a few basic structures
        that we know will be required.  Once OpenOMCI is created, this sequence
        should be skipped (go directly to MIB upload) and this info is available
        from the uploaded MIB.

        On failure, restart the initial message exchange
        """
        self.log.info('perform-mib-upload')
        self._deferred = None

        if self._handler.device_id is None or not self.enabled:
            returnValue('not-enabled')

        device = None
        omci = self._handler.omci

        if self._handler.is_mock:
            self._deferred = reactor.callLater(0, self._perform_mib_download)
            returnValue('is-mock')

        try:
            device = self._handler.adapter_agent.get_device(self._handler.device_id)
            device.reason = 'Performing MIB Synchronization'
            self._handler.adapter_agent.update_device(device)

            #########################################
            # MIB Reset
            results = yield omci.send_mib_reset()
            status = results.fields['omci_message'].fields['success_code']
            assert status == 0, 'Unexpected MIB reset response status: {}'.format(status)

            # TODO: On a real system, need to flush the external MIB database
            # TODO: Also would need to watch for any AVC being handled between the MIB reset and the DB flush
            self.mib_data_store = dict()

            ########################################
            # Begin MIB Upload
            results = yield omci.send_mib_upload()
            number_of_commands = results.fields['omci_message'].fields['number_of_commands']

            for seq_no in xrange(number_of_commands):
                results = yield omci.send_mib_upload_next(seq_no)

                object_entity_class = results.fields['omci_message'].fields['object_entity_class']
                object_entity_id = results.fields['omci_message'].fields['object_entity_id']
                object_attributes_mask = results.fields['omci_message'].fields['object_attributes_mask']
                object_data = results.fields['omci_message'].fields['object_data']

                key = (object_entity_class, object_entity_id)

                if key not in self.mib_data_store:
                    self.mib_data_store[key] = (object_attributes_mask, object_data)
                else:
                    pass

            # Successful if here

            device.reason = 'MIB Synchronization Complete'
            self._handler.adapter_agent.update_device(device)

            # Start up non-critical message exchange
            self._deferred = reactor.callLater(0, self._perform_mib_download)
            self.log.info('mib-synchronized')

        except TimeoutError as e:
            self.log.warn('mib-upload', e=e)

            if device is not None:
                device.reason = 'mib-upload-failure: Response Timeout'
                self._handler.adapter_agent.update_device(device)

            # Try again later
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self._initial_message_exchange)

        except Exception as e:
            self.log.exception('mib-upload', e=e)
            device.reason = 'MIB upload sequence failure: ' + e.message
            self._handler.adapter_agent.update_device(device)

            # Try again later
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self._initial_message_exchange)

    @inlineCallbacks
    def _perform_mib_download(self):
        """
        Called after basic OMCI Synchronization (MIB upload). Begin to set up
        some basic OMCI settings common for most expected configurations

        Upon successful completion, any xPON information received so far will be
        acted upon.

        On failure, restart the initial message exchange
        """
        self.log.info('mib-download-start')
        self._deferred = None

        if self._handler.device_id is None or not self.enabled:
            returnValue('not-enabled')

        omci = self._handler.omci

        if self._handler.is_mock:
            self._bridge_initialized = True
            self._deferred = reactor.callLater(0, self._sync_existing_xpon)
            returnValue('is-mock')

        # reset incoming message queue
        omci.flush()
        device = self._handler.adapter_agent.get_device(self._handler.device_id)

        device.reason = 'Performing MIB Download'
        self._handler.adapter_agent.update_device(device)

        if not self.enabled or device is None:
            returnValue('not-enabled')

        #############################################
        #  All our variables here
        #  TODO: Move elsewhere in future version of this software
        frame = None
        gal_enet_profile_entity_id = 0x100       # Any Unique Entity ID BP: old value 1
        ieee_mapper_service_profile_entity_id = 0x100         # Entity ID BP: old value 0x8001
        mac_bridge_service_profile_entity_id = 0x100  # Entity ID BP: old value 0x201
        mac_bridge_port_ani_entity_id = 0x100       # BP: oldvalue 0x201
        ethernet_uni_entity_id = 0x101
        vlan_tcis_1 = 0x900
        cvid = 2            # TODO: Get from xPON and/or device adapter
        tcont_entity_id = 0x100   # Entity ID, ONT is set to 0x100
        tcont_alloc_id = 0x400    # Alloc ID, 1024 - Tcont
        gem_entity_id = 0x4900          # Entity ID, unique Id
        gem_port_id = 0x400             # Port ID, 2304 - Gem Id
        gem_interworking_entity_id = 0x4900
        vlan_config_entity_id = vlan_tcis_1               # Entity ID       BP: Oldvalue 0x202

        try:
            ################################################################################
            #
            #
            #  EntityID will be referenced by:
            #            -
            #            -
            #            -
            #            -
            #  References:
            #            -
            #            -

            frame = TcontFrame(tcont_entity_id, tcont_alloc_id).set()
            results = yield omci.send(frame)
            # results = yield send_set_tcont(omci, 0x100,  # Entity ID, ONT is set to 0x100
            #                                0x400)  # Alloc ID, 1024 - Tcont

            status = results.fields['omci_message'].fields['success_code']
            failed_attributes_mask = results.fields['omci_message'].fields['failed_attributes_mask']
            unsupported_attributes_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']
            self.log.debug('set-tcont', status=status,
                           failed_attributes_mask=failed_attributes_mask,
                           unsupported_attributes_mask=unsupported_attributes_mask)

            ################################################################################
            direction = "bi-directional"

            # TODO: For TM, is this the entity ID for a traffic descriptor?
            frame = GemPortNetworkCtpFrame(
                    gem_entity_id,
                    port_id=gem_port_id,       # Port ID, 2304 - Gem ID
                    tcont_id=tcont_entity_id,  # TCONT Entity ID, as set in TCONT set
                    direction=direction,       # Direction, bidirectional
                    upstream_tm=0x8000         # TM ID, 32768 unique ID set in TD set  TODO: Parameterize
            ).create()
            results = yield omci.send(frame)
            # results = yield send_create_gem_port_network_ctp(omci, 0x4900,    # Entity ID, unique Id
            #                                                  0x400,     # Port ID, 2304 - Gem Id
            #                                                  0x100,     # TCONT Entity ID, as set in TCONT set
            #                                                  direction, # Direction, bidirectional
            #                                                  0x8000)    # TM ID, 32768 unique Id set in TD set

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-gem-port-network-ctp', status=status, error_mask=error_mask)

            ################################################################################
            # GEM Interworking config
            #
            #
            #  EntityID will be referenced by:
            #            -
            #            -
            #            -
            #            -
            #  References:
            #            -
            #            -
            # TODO: for the service_profile_pointer=0x100, is this create/set somewhere later

            frame = GemInterworkingTpFrame(
                gem_interworking_entity_id,
                gem_port_network_ctp_pointer=gem_entity_id,  # GEMPort NET CTP ID, as set in CTP create
                interworking_option=5,                             # IEEE 802.1
                service_profile_pointer=ieee_mapper_service_profile_entity_id,
                interworking_tp_pointer=0x0,
                pptp_counter=1,
                gal_profile_pointer=0   # TODO:  make? -> gal_enet_profile_entity_id     # BP: HACK old value 0x1  (TODO: Balaji had this set to 0 in his test sequence)
            ).create()
            results = yield omci.send(frame)
            # results = yield send_create_gem_inteworking_tp(omci, 0x4900, # any Unique Entity ID
            #                                                0x4900, # GEMPort NET CTP ID, as set in CTP create
            #                                                0x100)  # 802.1p mapper Service Mapper Profile ID

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-gem-interworking-tp', status=status, error_mask=error_mask)

            ########################################################################################
            # Create GalEthernetProfile - Once per ONU/PON interface
            #
            #  EntityID will be referenced by:
            #            - GEM Interworking TPs when a new GEM Port is created
            #  References:
            #            - Nothing

            frame = GalEthernetProfileFrame(gal_enet_profile_entity_id,
                                            max_gem_payload_size=1518).create()  # Max GEM Payload size
            results = yield omci.send(frame)
            # results = yield send_create_gal_ethernet_profile(omci,
            #                                         0x100,   # Any Unique Entity ID BP: old value 1
            #                                         1518)    # Max GEM Payload size

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-gal-ethernet-profile', status=status, error_mask=error_mask)

            ################################################################################
            # MAC Bridge Service Profile - Once per UNI
            #
            #  EntityID will be referenced by:
            #            - MAC Bridge Port Configuration Data
            #  References:
            #            - Nothing

            attributes = {
                'spanning_tree_ind': False,
                #  TODO: CB: see if we need or can use any of the following...
                # 'learning_ind': True,
                # 'priority': 0x8000,
                # 'max_age': 20 * 256,
                # 'hello_time': 2 * 256,
                # 'forward_delay': 15 * 256,
                # 'unknown_mac_address_discard': True
            }
            frame = MacBridgeServiceProfileFrame(mac_bridge_service_profile_entity_id,
                                                 attributes).create()
            results = yield omci.send(frame)
            # results = yield send_create_mac_bridge_service_profile(omci, 0x100)   # Entity ID BP: old value 0x201

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-mac-bridge-service-profile', status=status, error_mask=error_mask)

            ################################################################################
            # IEEE 802.1 Mapper Service config - Once per PON
            #
            #  EntityID will be referenced by:
            #            - MAC Bridge Port Configuration Data for the PON port
            #  References:
            #            - Nothing at this point. When a GEM port is created, this entity will
            #              be updated to reference the GEM Interworking TP

            frame = Ieee8021pMapperServiceProfileFrame(ieee_mapper_service_profile_entity_id).create()
            results = yield omci.send(frame)
            # results = yield send_create_8021p_mapper_service_profile(omci, 0x100)   # Entity ID BP: old value 0x8001

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-8021p-mapper-service-profile', status=status, error_mask=error_mask)

            ################################################################################
            # Create MAC Bridge Port Configuration Data for the PON port via IEEE 802.1
            # mapper service. Upon receipt by the ONU, the ONU will create an instance
            # of the following before returning the response.
            #
            #     - MAC bridge port designation data
            #     - MAC bridge port filter table data
            #     - MAC bridge port bridge table data
            #
            #  EntityID will be referenced by:
            #            - Implicitly by the VLAN tagging filter data
            #            -
            #            -
            #            -
            #  References:
            #            - MAC Bridge Service Profile (the bridge)
            #            - IEEE 802.1p mapper service profile for PON port

            frame = MacBridgePortConfigurationDataFrame(
                mac_bridge_port_ani_entity_id,                           # Entity ID
                bridge_id_pointer=mac_bridge_service_profile_entity_id,  # Bridge Entity ID BP: oldvalue 0x201
                # TODO: The PORT number for this port and the UNI port are the same. Is this correct?
                port_num=0,                                              # Port ID          BP: oldvalue 2
                tp_type=3,                                               # TP Type (IEEE 802.1p mapper service)  BP: oldvalue 1, 802.1 mapper GPON intf
                tp_pointer=ieee_mapper_service_profile_entity_id         # TP ID, 8021p mapper ID   BP: oldvalue 0x102
            ).create()
            results = yield omci.send(frame)
            # results = yield send_create_mac_bridge_port_configuration_data(omci,
            #                                 0x100,   # Entity ID   BP: oldvalue 0x201
            #                                 0x100,   # Bridge Entity ID   BP: oldvalue 0x201
            #                                 0,       # Port ID     BP: oldvalue 2
            #                                 3,       # TP Type    BP: oldvalue  1, 802.1 mapper GPON interface
            #                                 0x100)   # TP ID, 8021p mapper Id      BP: oldvalue 0x102

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-mac-bridge-port-configuration-data-part-1', status=status, error_mask=error_mask)

            ################################################################################
            # MAC Bridge Port config
            # This configuration is for Ethernet UNI
            #
            #  EntityID will be referenced by:
            #            -
            #            -
            #            -
            #            -
            #  References:
            #            - MAC Bridge Service Profile (the bridge)
            #            - PPTP Ethernet UNI

            frame = MacBridgePortConfigurationDataFrame(
                0x000,                             # Entity ID                BP: oldvalue 0x201
                bridge_id_pointer=mac_bridge_service_profile_entity_id,  # Bridge Entity ID BP: oldvalue 0x201
                port_num=0,                        # Port ID                  BP: oldvalue 3
                tp_type=1,                         # PPTP Ethernet UNI        BP: oldvalue 3
                tp_pointer=ethernet_uni_entity_id  # TP ID, 8021p mapper Id   BP: oldvalue 0x8001
            ).create()
            results = yield omci.send(frame)
            # results = yield send_create_mac_bridge_port_configuration_data(omci,
            #                                 0x000,   # Entity ID     BP: oldvalue 0x2102
            #                                 0x100,   # Bridge Entity ID     BP: oldvalue 0x201
            #                                 0,       # Port ID     BP: oldvalue 3
            #                                 1,       # TP Type, Ethernet UNI     BP: oldvalue 3
            #                                 0x101)   # TP ID, PPTP UNI Entity Id     BP: oldvalue 0x8001

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-mac-bridge-port-configuration-data-part-2', status=status, error_mask=error_mask)

            ################################################################################
            # VLAN Tagging Filter config
            #
            #  EntityID will be referenced by:
            #            - Nothing
            #  References:
            #            - Implicitly linked to an instance of the MAC bridge port configuration data
            #              for the PON port
            # TODO: Probably need to get VLAN ID from device.vlan
            # Set anything, this request will not be used when using Extended Vlan

            frame = VlanTaggingFilterDataFrame(
                mac_bridge_port_ani_entity_id,       # Entity ID   BP: Oldvalue 0x2102
                vlan_tcis=[vlan_tcis_1],             # VLAN IDs     BP: cvid
                forward_operation=0x10
            ).create()
            results = yield omci.send(frame)
            # results = yield send_create_vlan_tagging_filter_data(omci, 0x100,  # Entity ID   BP: Oldvalue 0x2102
            #                                                      0x900)        # VLAN ID     BP: cvid

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-vlan-tagging-filter-data', status=status, error_mask=error_mask)

            ################################################################################
            # Update the IEEE 802.1p Mapper Service Profile config
            #
            #  EntityID was created prior to this call
            #  References:
            #            -
            #            -
            # TODO: All p-bits currently go to the one and only GEMPORT ID for now

            frame = Ieee8021pMapperServiceProfileFrame(
                ieee_mapper_service_profile_entity_id,      # 802.1p mapper Service Mapper Profile ID
                interwork_tp_pointers=[gem_entity_id]  # Interworking TP IDs  BP: oldvalue self.gemid
            ).set()
            results = yield omci.send(frame)
            # results = yield send_set_8021p_mapper_service_profile(omci, 0x100, 0x4900)

            status = results.fields['omci_message'].fields['success_code']
            failed_attributes_mask = results.fields['omci_message'].fields['failed_attributes_mask']
            unsupported_attributes_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']
            self.log.debug('set-8021p-mapper-service-profile', status=status,
                           failed_attributes_mask=failed_attributes_mask,
                           unsupported_attributes_mask=unsupported_attributes_mask)

            ################################################################################
            #  Unlock UNI
            #
            #  EntityID will be referenced by:
            #            - MAC bridge port configuration data for the UNI side
            #  References:
            #            - Nothing

            attributes = dict(
                administrative_state=0  # 0 - Unlock
            )
            frame = PptpEthernetUniFrame(
                ethernet_uni_entity_id,  # Entity ID
                attributes=attributes    # See above
            ).set()
            results = yield omci.send(frame)
            #results = yield send_set_pptp_ethernet_uni(omci, 0x101)  # Entity ID

            status = results.fields['omci_message'].fields['success_code']
            failed_attributes_mask = results.fields['omci_message'].fields['failed_attributes_mask']
            unsupported_attributes_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']
            self.log.debug('set-pptp-ethernet-uni', status=status,
                           failed_attributes_mask=failed_attributes_mask,
                           unsupported_attributes_mask=unsupported_attributes_mask)

            ################################################################################
            # Create Extended VLAN Tagging Operation config
            #
            #  EntityID relates to the VLAN TCIS
            #  References:
            #            - VLAN TCIS from previously created VLAN Tagging filter data
            #            - PPTP Ethernet UNI
            #
            # TODO: add entry here for additional UNI interfaces

            attributes = dict(
                association_type=2,                           # Assoc Type, PPTP Ethernet UNI   BP: Oldvalue 2
                associated_me_pointer=ethernet_uni_entity_id  # Assoc ME, PPTP Entity Id        BP: Oldvalue 0x102
            )

            frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                vlan_config_entity_id,
                attributes=attributes     # See above
            ).create()
            results = yield omci.send(frame)
            # results = yield send_create_extended_vlan_tagging_operation_configuration_data(omci,
            #                                         0x900,  # Entity ID       BP: Oldvalue 0x202
            #                                         2,      # Assoc Type, PPTP Ethernet UNI   BP: Oldvalue 2
            #                                         0x101)  # Assoc ME, PPTP Entity Id   BP: Oldvalue 0x102

            status = results.fields['omci_message'].fields['success_code']
            error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
            self.log.debug('create-extended-vlan-tagging-operation-configuration-data', status=status, error_mask=error_mask)

            ################################################################################
            # Update Extended VLAN Tagging Operation Config Data
            #
            # Specifies the TPIDs in use and that operations in the downstream direction are
            # inverse to the operations in the upstream direction
            # TODO: Downstream mode may need to be modified once we work more on the flow rules

            attributes = dict(
                input_tpid=0x8100,   # input TPID
                output_tpid=0x8100,  # output TPID
                downstream_mode=0,   # inverse of upstream
            )
            frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                vlan_config_entity_id,    # Entity ID       BP: Oldvalue 0x202
                attributes=attributes     # See above
            ).set()
            results = yield omci.send(frame)
            # results = yield send_set_extended_vlan_tagging_operation_tpid_configuration_data(omci,
            #                                         0x900,   # Entity ID      BP: Oldvalue 0x202
            #                                         0x8100,  # input TPID
            #                                         0x8100)  # output TPID

            status = results.fields['omci_message'].fields['success_code']
            failed_attributes_mask = results.fields['omci_message'].fields['failed_attributes_mask']
            unsupported_attributes_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']
            self.log.debug('set-extended-vlan-tagging-operation-configuration-data', status=status,
                           failed_attributes_mask=failed_attributes_mask,
                           unsupported_attributes_mask=unsupported_attributes_mask)

            ################################################################################
            # Update Extended VLAN Tagging Operation Config Data
            #
            # parameters: Entity Id ( 0x900), Filter Inner Vlan Id(0x1000-4096,do not filter on Inner vid,
            #             Treatment Inner Vlan Id : 2

            attributes = dict(
                received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,       # This entry is not a double-tag rule
                    filter_outer_vid=4096,          # Do not filter on the outer VID value
                    filter_outer_tpid_de=0,         # Do not filter on the outer TPID field

                    filter_inner_priority=15,       # This is a no-tag rule, ignore all other VLAN tag filter fields
                    filter_inner_vid=0x1000,        # Do not filter on the inner VID
                    filter_inner_tpid_de=0,         # Do not filter on inner TPID field
                    filter_ether_type=0,            # Do not filter on EtherType

                    treatment_tags_to_remove=0,     # Remove 0 tags
                    treatment_outer_priority=15,    # Do not add an outer tag
                    treatment_outer_vid=0,          # n/a
                    treatment_outer_tpid_de=0,      # n/a

                    treatment_inner_priority=0,     # Add an inner tag and insert this value as the priority
                    treatment_inner_vid=cvid,       # use this value as the VID in the inner VLAN tag
                    treatment_inner_tpid_de=4       # set TPID = 0x8100
                )
            )
            frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                vlan_config_entity_id,    # Entity ID       BP: Oldvalue 0x202
                attributes=attributes     # See above
            ).set()
            results = yield omci.send(frame)
            # results = yield send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(omci, 0x900,
            #                                                                                           0x1000,
            #                                                                                           2)
            status = results.fields['omci_message'].fields['success_code']
            failed_attributes_mask = results.fields['omci_message'].fields['failed_attributes_mask']
            unsupported_attributes_mask = results.fields['omci_message'].fields['unsupported_attributes_mask']
            self.log.debug('set-extended-vlan-tagging-operation-configuration-data-untagged', status=status,
                           failed_attributes_mask=failed_attributes_mask,
                           unsupported_attributes_mask=unsupported_attributes_mask)

            # BP: This is for AT&T RG's
            #
            #   TODO: CB: NOTE: TRY THIS ONCE OTHER SEQUENCES WORK
            #
            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
            # results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(
            #                                 0x900,  # Entity ID
            #                                 8,      # Filter Inner Priority, do not filter on Inner Priority
            #                                 0,    # Filter Inner VID, this will be 0 in CORD
            #                                 0,      # Filter Inner TPID DE
            #                                 1,      # Treatment tags, number of tags to remove
            #                                 8,      # Treatment inner priority, copy Inner Priority
            #                                 2)   # Treatment inner VID, this will be 2 in CORD

            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to priority tagged pkts - c-vid
            # results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(
            #                                 0x200,  # Entity ID
            #                                 8,      # Filter Inner Priority
            #                                 0,      # Filter Inner VID
            #                                 0,      # Filter Inner TPID DE
            #                                 1,      # Treatment tags to remove
            #                                 8,      # Treatment inner priority
            #                                 cvid)   # Treatment inner VID
            #
            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to untagged pkts - c-vid
            #results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(
            #                                0x100,   # Entity ID            BP: Oldvalue 0x202
            #                                0x1000,  # Filter Inner VID     BP: Oldvalue 0x1000
            #                                cvid)    # Treatment inner VID  BP: cvid

            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            ###############################################################################
            # If here, we are done
            device.reason = ''
            self._handler.adapter_agent.update_device(device)

            ######################################################################
            # If here, we can add TCONTs/GEM Ports/... as needed

            self._bridge_initialized = True
            self._deferred = reactor.callLater(0, self._sync_existing_xpon)

        except TimeoutError as e:
            self.log.warn('rx-timeout', frame=frame)
            # Try again later. May not have been discovered
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self._initial_message_exchange)
            returnValue('retry-pending')

        except Exception as e:
            self.log.exception('mib-download', e=e)
            device.reason = 'MIB download sequence failure: ' + e.message
            self._handler.adapter_agent.update_device(device)

            # Try again later
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self._initial_message_exchange)

    @inlineCallbacks
    def _sync_existing_xpon(self):
        """
        Run through existing TCONT and GEM Ports and push into hardware
        """
        # for tcont in self._tconts.itervalues():
        #     try:
        #         yield self.add_tcont(tcont, reflow=True)
        #     except Exception as e:
        #         self.log.exception('tcont-reflow', e=e, tcont=tcont)
        #
        # for gem_port in self._gem_ports.itervalues():
        #     try:
        #         yield self.add_gem_port(gem_port, reflow=True)
        #
        #     except Exception as e:
        #         self.log.exception('gem-port-reflow', e=e, gem_port=gem_port)

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
