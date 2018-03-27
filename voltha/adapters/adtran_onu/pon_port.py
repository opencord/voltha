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
from twisted.internet.defer import inlineCallbacks, returnValue, TimeoutError
from twisted.internet import reactor

from voltha.protos.common_pb2 import AdminState
from voltha.protos.device_pb2 import Port

from voltha.protos.common_pb2 import OperStatus, ConnectStatus

from omci.omci_entities import onu_custom_me_entities
from voltha.extensions.omci.omci_me import *

_STARTUP_RETRY_WAIT = 5
# abbreviations
OP = EntityOperations


class PonPort(object):
    """Wraps northbound-port / vlan bridge support for ONU"""
    MIN_GEM_ENTITY_ID = 0x4900
    MAX_GEM_ENTITY_ID = 0x4AFF

    def __init__(self, handler, port_no):
        self._enabled = False
        self._valid = True
        self._handler = handler
        self._deferred = None
        self._resync_deferred = None    # For TCont/GEM use
        self._port = None
        self._port_number = port_no
        self._connected = False
        self._dev_info_loaded = False
        self._bridge_initialized = False
        self._next_entity_id = PonPort.MIN_GEM_ENTITY_ID
        self.log = structlog.get_logger(device_id=handler.device_id, port_no=port_no)

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        self._gem_ports = {}                           # gem-id -> GemPort
        self._tconts = {}                              # alloc-id -> TCont
        self._in_sync_subscription = None
        self._connectivity_subscription = None

        self._onu_omci_device = handler.omci_agent.add_device(handler.device_id,
                                                              handler.adapter_agent,
                                                              onu_custom_me_entities())
        # TODO: Add stats, alarm reference, ...

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

        # Subscriber to events of interest in OpenOMCI
        self._subscribe_to_events()
        self._onu_omci_device.start()

        # Begin ONU Activation sequence if already in sync
        if self._onu_omci_device.mib_db_in_sync:
            self._deferred = reactor.callLater(0, self._mib_in_sync)
        else:
            device = self._handler.adapter_agent.get_device(self._handler.device_id)
            device.reason = 'Waiting for MIB upload completion'
            self._handler.adapter_agent.update_device(device)

    def _stop(self):
        self._cancel_deferred()
        # Unsubscribe to OpenOMCI Events
        self._unsubscribe_to_events()
        self._onu_omci_device.stop()

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()
        # TODO: stop h/w sync
        pass

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._resync_deferred = self._resync_deferred, None

        for d in [d1, d2]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def _cancel_resync_deferred(self):
        d, self._resync_deferred = self._resync_deferred, None
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
    def connected(self):
        return self._connected

    @property
    def port_number(self):
            return self._port_number

    @property
    def next_gem_entity_id(self):
        entity_id = self._next_entity_id

        self._next_entity_id = self._next_entity_id + 1
        if self._next_entity_id > PonPort.MAX_GEM_ENTITY_ID:
            self._next_entity_id = PonPort.MIN_GEM_ENTITY_ID

        return entity_id

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

    @property
    def onu_omci_device(self):
        return self._onu_omci_device

    def _mib_in_sync(self):
        if self._handler.is_mock:
            return  # Done, Mock has no bridge support

        if not self._dev_info_loaded:
            # Here if in sync. But verify first

            omci = self._onu_omci_device
            in_sync = omci.mib_db_in_sync
            self.log.info('mib-in-sync', in_sync=in_sync, already_loaded=self._dev_info_loaded)

            device = self._handler.adapter_agent.get_device(self._handler.device_id)
            device.oper_status = OperStatus.ACTIVE
            device.connect_status = ConnectStatus.REACHABLE
            device.reason = 'MIB Synchronization complete'
            self._handler.adapter_agent.update_device(device)

            # In Sync, we can register logical ports now. Ideally this could occur on
            # the first time we received a successful (no timeout) OMCI Rx response.
            try:
                for uni in self._handler.uni_ports:
                    uni.add_logical_port(None, None)

                vendor = omci.query_mib_single_attribute(OntG.class_id, 0, 'vendor_id') or 'ADTN'
                assert vendor == 'ADTN', \
                    "Invalid Device/Wrong device adapter assigned: '{}'".format(vendor)

                # TODO: Get serial number and validate!
                num_ports = omci.query_mib_single_attribute(CircuitPack.class_id,
                                                            257, 'number_of_ports') or 1
                assert num_ports == 1, 'Invalid number of ports: {}'.format(num_ports)

                mac_address = omci.query_mib_single_attribute(IpHostConfigData.class_id,
                                                              0, 'mac_address') or 'unknown'
                device.mac_address = str(mac_address)

                ont2_attributes = omci.query_mib(Ont2G.class_id, 0, ['equipment_id',
                                                                     'omcc_version',
                                                                     'vendor_product_code'])
                equipment_id = ont2_attributes.get('equipment_id') or " unknown    unknown "
                eqptId_bootVersion = str(equipment_id)
                eqptId = eqptId_bootVersion[0:10]          # ie) BVMDZ10DRA
                bootVersion = eqptId_bootVersion[12:20]    # ie) CML.D55~

                omcc_version = str(ont2_attributes.get('omcc_version', 'unknown'))
                vendorProductCode = str(ont2_attributes.get('vendor_product_code', 'unknown'))

                version = omci.query_mib_single_attribute(OntG.class_id, 0, 'version') or 'unknown'
                device.model = str(version)
                # # TODO: Combine ONTG calls into a single call with multiple attributes
                # # TODO: Look into ONTG and ONT2G to see if we can get other items of interest
                # #       such as max tconts, max gem ports, and so on. Make use of them

                sw_version = omci.query_mib_single_attribute(SoftwareImage.class_id, 0, 'version') or 'unknown'
                device.firmware_version = str(sw_version)
                # # is_committed = data["is_committed"]
                # # is_active = data["is_active"]
                # # is_valid = data["is_valid"]
                # # device.hardware_version = 'TODO: to be filled'
                # # TODO: Support more versions as needed
                # # images = Image(version=results.get('software_version', 'unknown'))
                # # device.images.image.extend([images])

                self._handler.adapter_agent.update_device(device)
                self._dev_info_loaded = True

            except Exception as e:
                self.log.exception('device-info-load', e=e)
                self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT, self._mib_in_sync())

            self._deferred = reactor.callLater(0, self.resync_omci_settings)

    @inlineCallbacks
    def resync_omci_settings(self):
        self._cancel_resync_deferred()

        if not self._bridge_initialized:
            self.log.info('resync-omci-settings', initialized=self._bridge_initialized)
            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            if not self.enabled or device is None:
                returnValue('not-enabled')

            device.reason = 'Performing OMCI Setup'
            self._handler.adapter_agent.update_device(device)

            omci = self._handler.omci

            #############################################
            #  All our variables here
            #  TODO: Move elsewhere in future version of this software
            #  TODO: Make as many entity IDs dynamic/discovered as possible
            frame = None
            gal_enet_profile_entity_id = 0x100
            ieee_mapper_service_profile_entity_id = 0x100
            mac_bridge_service_profile_entity_id = 0x100
            mac_bridge_port_ani_entity_id = 0x100
            ethernet_uni_entity_id = 0x101
            vlan_tcis_1 = 0x900
            vlan_config_entity_id = vlan_tcis_1
            cvid = device.vlan

            try:
                ################################################################################
                # TCONTS
                # get tconts in database
                omci_dev = self._onu_omci_device
                tcont_idents = omci_dev.query_mib(Tcont.class_id)
                self.log.debug('tcont-idents', tcont_idents=tcont_idents)

                for tcont in self._tconts.itervalues():
                    free_entity_id = next((k for k, v in tcont_idents.items()
                                          if isinstance(k, int) and v.get('alloc_id', 0) == 0xFFFF), None)
                    if free_entity_id is None:
                        self.log.error('no-available-tconts')
                        break
                    results = yield tcont.add_to_hardware(omci, free_entity_id)

                ################################################################################
                # GEMS
                for gem_port in self._gem_ports.itervalues():
                    tcont = gem_port.tcont
                    if tcont is None:
                        self.log.error('unknown-tcont-reference', gem_id=gem_port.gem_id)
                        continue

                    results = yield gem_port.add_to_hardware(omci,
                                                             tcont.entity_id,
                                                             ieee_mapper_service_profile_entity_id,
                                                             gal_enet_profile_entity_id)

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

                gem_entity_ids = []
                for gem_port in self._gem_ports.itervalues():
                    gem_entity_ids.append(gem_port.entity_id)

                frame = Ieee8021pMapperServiceProfileFrame(
                    ieee_mapper_service_profile_entity_id,      # 802.1p mapper Service Mapper Profile ID
                    interwork_tp_pointers=gem_entity_ids  # Interworking TP IDs  BP: oldvalue self.gemid
                ).set()
                results = yield omci.send(frame)

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
                    association_type=2,                           # Assoc Type, PPTP Ethernet UNI
                    associated_me_pointer=ethernet_uni_entity_id  # Assoc ME, PPTP Entity Id
                )

                frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                    vlan_config_entity_id,
                    attributes=attributes
                ).create()
                results = yield omci.send(frame)

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
                    vlan_config_entity_id,
                    attributes=attributes
                ).set()
                results = yield omci.send(frame)

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
                self._bridge_initialized = True
                device.reason = ''
                self._handler.adapter_agent.update_device(device)

            except TimeoutError as e:
                self.log.warn('rx-timeout', frame=frame)
                self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                   self.resync_omci_settings)
                returnValue('retry-pending')

            except Exception as e:
                self.log.exception('omci-setup', e=e)
                device.reason = 'OMCI setup sequence failure: ' + e.message
                self._handler.adapter_agent.update_device(device)

                # Try again later
                self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                   self.resync_omci_settings)

    def add_tcont(self, tcont, reflow=False):
        """
        Creates/ a T-CONT with the given alloc-id

        :param tcont: (TCont) Object that maintains the TCONT properties
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            return      # Deleting

        if not reflow and tcont.alloc_id in self._tconts:
            return      # already created

        self.log.info('add', tcont=tcont, reflow=reflow)
        self._tconts[tcont.alloc_id] = tcont

        # only start setting sequence if there are at least one gem add
        if len(self._gem_ports) > 0 and self._bridge_initialized:
            self._cancel_resync_deferred()
            self._bridge_initialized = False
            self._resync_deferred = reactor.callLater(0, self.resync_omci_settings)

    def update_tcont_td(self, alloc_id, new_td):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            return  # not-found

        tcont.traffic_descriptor = new_td

        # TODO: Not yet implemented
        #TODO: How does this affect ONU tcont settings?
        #try:
        #    results = yield tcont.add_to_hardware(self._handler.omci)
        #except Exception as e:
        #    self.log.exception('tcont', tcont=tcont, e=e)
        #    # May occur with xPON provisioning, use hw-resync to recover
        #    results = 'resync needed'
        # returnValue(results)

    @inlineCallbacks
    def remove_tcont(self, alloc_id):
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            returnValue('nop')

        try:
            del self._tconts[alloc_id]

            results = yield tcont.remove_from_hardware(self._handler.omci)
            returnValue(results)

        except Exception as e:
            self.log.exception('delete', e=e)
            raise

    def gem_port(self, gem_id):
        return self._gem_ports.get(gem_id)

    @property
    def gem_ids(self):
        """Get all GEM Port IDs used by this ONU"""
        return sorted([gem_id for gem_id, gem in self._gem_ports.items()])

    def add_gem_port(self, gem_port, reflow=False):
        """
        Add a GEM Port to this ONU

        :param gem_port: (GemPort) GEM Port to add
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """
        if not self._valid:
            return  # Deleting

        if not reflow and gem_port.gem_id in self._gem_ports:
            return  # nop

        self.log.info('add', gem_port=gem_port, reflow=reflow)
        self._gem_ports[gem_port.gem_id] = gem_port

        # assuming tcont was already added to start start settings sequence
        if self._bridge_initialized:
            self._cancel_resync_deferred()
            self._bridge_initialized = False
            self._resync_deferred = reactor.callLater(0, self.resync_omci_settings)

    @inlineCallbacks
    def remove_gem_id(self, gem_id):
        """
        Remove a GEM Port from this ONU

        :param gem_port: (GemPort) GEM Port to remove
        :return: deferred
        """
        gem_port = self._gem_ports.get(gem_id)

        if gem_port is None:
            returnValue('nop')

        try:
            del self._gem_ports[gem_id]

            results = yield gem_port.remove_from_hardware(self._handler.omci)
            returnValue(results)

        except Exception as ex:
            self.log.exception('gem-port-delete', e=ex)
            raise

    def _subscribe_to_events(self):
        from voltha.extensions.omci.onu_device_entry import OnuDeviceEvents, \
            OnuDeviceEntry, IN_SYNC_KEY
        from voltha.extensions.omci.omci_cc import OMCI_CC, OmciCCRxEvents, \
            CONNECTED_KEY

        def in_sync_handler(_topic, msg):
            if self._in_sync_subscription is not None:
                try:
                    in_sync = msg[IN_SYNC_KEY]

                    if in_sync:
                        # Only call this once as well
                        bus = self._onu_omci_device.event_bus
                        bus.unsubscribe(self._in_sync_subscription)
                        self._in_sync_subscription = None

                        # Start up device_info load
                        reactor.callLater(0, self._mib_in_sync)

                except Exception as e:
                    self.log.exception('in-sync', e=e)

        def onu_is_reachable(_topic, msg):
            """
            Reach-ability change event
            :param msg: (dict) 'connected' key holds True if reachable
            """
            if self._connectivity_subscription is not None:
                try:
                    connected = msg[CONNECTED_KEY]

                    # TODO: For now, only care about the first.
                    # Later we could use this for a heartbeat, but may want some hysteresis
                    # Cancel any 'reachable' subscriptions
                    if connected:
                        evt_bus = self._onu_omci_device.omci_cc.event_bus
                        evt_bus.unsubscribe(self._connectivity_subscription)
                        self._connectivity_subscription = None
                        self._connected = True

                        device = self._handler.adapter_agent.get_device(self._handler.device_id)
                        device.connect_status = ConnectStatus.REACHABLE
                        self._handler.adapter_agent.update_device(device)

                except Exception as e:
                    self.log.exception('onu-reachable', e=e)

        # OMCI MIB Database sync status
        bus = self._onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self._handler.device_id,
                                               OnuDeviceEvents.MibDatabaseSyncEvent)
        self._in_sync_subscription = bus.subscribe(topic, in_sync_handler)

        # OMCI-CC Connectivity Events (for reachbility/heartbeat)
        bus = self._onu_omci_device.omci_cc.event_bus
        topic = OMCI_CC.event_bus_topic(self._handler.device_id,
                                        OmciCCRxEvents.Connectivity)
        self._connectivity_subscription = bus.subscribe(topic, onu_is_reachable)

    def _unsubscribe_to_events(self):
        if self._in_sync_subscription is not None:
            bus = self._onu_omci_device.event_bus
            bus.unsubscribe(self._in_sync_subscription)
            self._in_sync_subscription = None

        if self._connectivity_subscription is not None:
            bus = self._onu_omci_device.omci_cc.event_bus
            bus.unsubscribe(self._connectivity_subscription)
            self._connectivity_subscription = None

