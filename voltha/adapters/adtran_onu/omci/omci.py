# Copyright 2018-present Adtran, Inc.
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

from voltha.protos.device_pb2 import Image

from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.extensions.omci.onu_configuration import OMCCVersion

from omci_entities import onu_custom_me_entities
from voltha.extensions.omci.omci_me import *

_STARTUP_RETRY_WAIT = 5
# abbreviations
OP = EntityOperations


class OMCI(object):
    """
    OpenOMCI Support
    """
    def __init__(self, handler, omci_agent):
        self.log = structlog.get_logger(device_id=handler.device_id)
        self._handler = handler
        self._openomci_agent = omci_agent
        self._enabled = False
        self._connected = False
        self._deferred = None
        self._resync_deferred = None    # For TCont/GEM use
        self._bridge_initialized = False
        self._in_sync_reached = False

        self._omcc_version = OMCCVersion.Unknown
        self._total_tcont_count = 0                    # From ANI-G ME
        self._qos_flexibility = 0                      # From ONT2_G ME

        self._in_sync_subscription = None
        self._connectivity_subscription = None
        self._capabilities_subscription = None

        self._mib_download_task = None
        self._mib_download_deferred = None

        self._onu_omci_device = omci_agent.add_device(handler.device_id,
                                                      handler.adapter_agent,
                                                      onu_custom_me_entities(),
                                                      support_classes=handler.adapter.adtran_omci)

    def __str__(self):
        return "OMCI"

    @property
    def omci_agent(self):
        return self._openomci_agent

    @property
    def omci_cc(self):
        # TODO: Decrement access to Communications channel at this point?  What about current PM stuff?
        return self.onu_omci_device.omci_cc if self._onu_omci_device is not None else None

    def receive_message(self, msg):
        if self.enabled:
            # TODO: Have OpenOMCI actually receive the messages
            self.omci_cc.receive_message(msg)

    def _start(self):
        self._cancel_deferred()

        # Subscriber to events of interest in OpenOMCI
        self._subscribe_to_events()
        self._onu_omci_device.start()

        if self._onu_omci_device.mib_db_in_sync:
            self._deferred = reactor.callLater(0, self._mib_in_sync)

    def _stop(self):
        self._cancel_deferred()

        # Unsubscribe to OpenOMCI Events
        self._unsubscribe_to_events()
        self._onu_omci_device.stop()        # Will also cancel any running tasks/state-machines

        self._mib_download_task = None
        self._bridge_initialized = False
        self._in_sync_reached = False

        # TODO: stop h/w sync

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._resync_deferred = self._resync_deferred, None
        d3, self._mib_download_deferred = self._mib_download_deferred, None

        for d in [d1, d2, d3]:
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

        agent, self._openomci_agent = self._openomci_agent, None
        device_id = self._handler.device_id
        self._onu_omci_device = None
        self._handler = None

        if agent is not None:
            agent(device_id, cleanup=True)

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
    def onu_omci_device(self):
        return self._onu_omci_device

    def _mib_in_sync(self):
        """
        This method is ran whenever the ONU MIB database is in-sync. This is often after
        the initial MIB Upload during ONU startup, or after it has gone out-of-sync and
        then back in. This second case could be due a reboot of the ONU and a new version
        of firmware is running on the ONU hardware.
        """
        self.log.info('mib-in-sync')

        device = self._handler.adapter_agent.get_device(self._handler.device_id)
        device.oper_status = OperStatus.ACTIVE
        device.connect_status = ConnectStatus.REACHABLE
        device.reason = 'MIB Synchronization complete'
        self._handler.adapter_agent.update_device(device)

        omci_dev = self._onu_omci_device
        config = omci_dev.configuration

        # In Sync, we can register logical ports now. Ideally this could occur on
        # the first time we received a successful (no timeout) OMCI Rx response.
        try:
            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            ani_g = config.ani_g_entities
            uni_g = config.uni_g_entities
            pon_ports = len(ani_g) if ani_g is not None else 0
            uni_ports = len(uni_g) if uni_g is not None else 0

            assert pon_ports == 1, 'Expected one PON/ANI port, got {}'.format(pon_ports)
            assert uni_ports == 1, 'Expected one UNI port, got {}'.format(uni_ports)

            self._total_tcont_count = ani_g.get('total-tcont-count')
            self._qos_flexibility = config.qos_configuration_flexibility or 0
            self._omcc_version = config.omcc_version or OMCCVersion.Unknown

            # vendorProductCode = str(config.vendor_product_code or 'unknown').rstrip('\0')

            host_info = omci_dev.query_mib(IpHostConfigData.class_id)
            mgmt_mac_address = next((host_info[inst].get('attributes').get('mac_address')
                                     for inst in host_info
                                     if isinstance(inst, int)), 'unknown')
            device.mac_address = str(mgmt_mac_address)
            device.model = str(config.version or 'unknown').rstrip('\0')

            equipment_id = config.equipment_id or " unknown    unknown "
            eqpt_boot_version = str(equipment_id).rstrip('\0')
            # eqptId = eqpt_boot_version[:10]         # ie) BVMDZ10DRA
            boot_version = eqpt_boot_version[12:]     # ie) CML.D55~

            images = [Image(name='boot-code',
                            version=boot_version.rstrip('\0'),
                            is_active=False,
                            is_committed=True,
                            is_valid=True,
                            install_datetime='Not Available',
                            hash='Not Available')] + \
                config.software_images

            del (device.images.image[:])       # Clear previous entries
            device.images.image.extend(images)

            # Save our device information
            self._handler.adapter_agent.update_device(device)

            # Start MIB download  TODO: This will be replaced with a MIB Download task soon
            self._in_sync_reached = True
            self._deferred = reactor.callLater(0, self.resync_omci_settings)

        except Exception as e:
            self.log.exception('device-info-load', e=e)
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT, self._mib_in_sync())

    def gem_or_tcont_added(self):
        if self._in_sync_reached:
            self._cancel_resync_deferred()
            self._resync_deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                      self.resync_omci_settings)

    @inlineCallbacks
    def resync_omci_settings(self):
        #
        # TODO: All of these steps below are being moved into an OpenOMCI Task.  !!!!
        #
        #  This will first be the AdtnMibDownloadTask task. As more ONUs are converted
        #  to OpenOMCI, I am hoping to come up with a shared/generic version all can use
        #
        #  Note also that this sets up everything for the user right now. It will be refactored
        #  once Service Tech Profiles are available.
        #
        self._cancel_resync_deferred()
        self.log.debug('resync-omci-settings', initialized=self._bridge_initialized)

        if not self.enabled:
            returnValue('not-enabled')

        device = self._handler.adapter_agent.get_device(self._handler.device_id)

        def resources_available():
            return (device.vlan > 0 and
                    len(self._handler.uni_ports) > 0 and
                    len(self._handler.pon_port.tconts) and
                    len(self._handler.pon_port.gem_ports))

        if not self._bridge_initialized and self._in_sync_reached and resources_available():
            device.reason = 'Performing OMCI Download'
            self._handler.adapter_agent.update_device(device)

            omci = self.omci_cc

            #############################################
            #  All our variables here
            #  TODO: Move elsewhere in future version of this software
            #  TODO: Make as many entity IDs dynamic/discovered as possible

            frame = None
            gal_enet_profile_entity_id = 0x100
            ieee_mapper_service_profile_entity_id = 0x100
            mac_bridge_service_profile_entity_id = 0x100
            mac_bridge_port_ani_entity_id = 0x100
            ethernet_uni_entity_id = 0x101          # TODO: This can be retrieved from the UNI-G instance_id
            vlan_tcis_1 = 0x900
            vlan_config_entity_id = vlan_tcis_1
            cvid = device.vlan

            try:
                ################################################################################
                # TCONTS
                #
                #  EntityID will be referenced by:
                #            - GemPortNetworkCtp
                #  References:
                #            - ONU created TCONT (created on ONU startup)

                omci_dev = self._onu_omci_device
                tcont_idents = omci_dev.query_mib(Tcont.class_id)
                self.log.debug('tcont-idents', tcont_idents=tcont_idents)

                for tcont in self._handler.pon_port.tconts.itervalues():
                    free_entity_id = next((k for k, v in tcont_idents.items()
                                          if isinstance(k, int) and
                                           v.get('attributes', {}).get('alloc_id', 0) == 0xFFFF), None)
                    if free_entity_id is None:
                        self.log.error('no-available-tconts')
                        break

                    yield tcont.add_to_hardware(omci, free_entity_id)

                ################################################################################
                # GEMS  (GemPortNetworkCtp and GemInterworkingTp)
                #
                #  For both of these MEs, the entity_id is the GEM Port ID. The entity id of the
                #  GemInterworkingTp ME could be different since it has an attribute to specify
                #  the GemPortNetworkCtp entity id.
                #
                #  TODO: In the GEM Port routine to add, it has a hardcoded upstream TM ID of 0x8000
                #        for the GemPortNetworkCtp ME
                #
                #  GemPortNetworkCtp
                #    EntityID will be referenced by:
                #              - GemInterworkingTp
                #    References:
                #              - TCONT
                #              - Hardcoded upstream TM Entity ID
                #              - (Possibly in Future) Upstream Traffic descriptor profile pointer
                #
                #  GemInterworkingTp
                #    EntityID will be referenced by:
                #              - Ieee8021pMapperServiceProfile
                #    References:
                #              - GemPortNetworkCtp
                #              - Ieee8021pMapperServiceProfile
                #              - GalEthernetProfile
                #
                for gem_port in self._handler.pon_port.gem_ports.itervalues():
                    tcont = gem_port.tcont
                    if tcont is None:
                        self.log.error('unknown-tcont-reference', gem_id=gem_port.gem_id)
                        continue

                    yield gem_port.add_to_hardware(omci,
                                                   tcont.entity_id,
                                                   ieee_mapper_service_profile_entity_id,
                                                   gal_enet_profile_entity_id)

                ########################################################################################
                # Create GalEthernetProfile - Once per ONU/PON interface
                #
                #  EntityID will be referenced by:
                #            - GemInterworkingTp
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
                #  References:
                #            - MAC Bridge Service Profile (the bridge)
                #            - IEEE 802.1p mapper service profile for PON port

                frame = MacBridgePortConfigurationDataFrame(
                    mac_bridge_port_ani_entity_id,                           # Entity ID
                    bridge_id_pointer=mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                    # TODO: The PORT number for this port and the UNI port are the same. Is this correct?
                    port_num=0,                                              # Port ID
                    tp_type=3,                                               # TP Type (IEEE 802.1p mapper service)
                    tp_pointer=ieee_mapper_service_profile_entity_id         # TP ID, 8021p mapper ID
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
                #            - Nothing
                #  References:
                #            - MAC Bridge Service Profile (the bridge)
                #            - PPTP Ethernet UNI

                frame = MacBridgePortConfigurationDataFrame(
                    0x000,                             # Entity ID - This is read-only/set-by-create !!!
                    bridge_id_pointer=mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                    port_num=0,                        # Port ID
                    tp_type=1,                         # PPTP Ethernet UNI
                    tp_pointer=ethernet_uni_entity_id  # TP ID, 8021p mapper Id
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
                #            - MacBridgePortConfigurationData for the ANI/PON side
                #
                # Set anything, this request will not be used when using Extended Vlan

                frame = VlanTaggingFilterDataFrame(
                    mac_bridge_port_ani_entity_id,       # Entity ID
                    vlan_tcis=[vlan_tcis_1],             # VLAN IDs
                    forward_operation=0x10
                ).create()
                results = yield omci.send(frame)

                status = results.fields['omci_message'].fields['success_code']
                error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']
                self.log.debug('create-vlan-tagging-filter-data', status=status, error_mask=error_mask)

                ################################################################################
                # Update the IEEE 802.1p Mapper Service Profile config
                #
                #  EntityID was created prior to this call. This is a set
                #
                #  References:
                #            - Gem Interwork TPs are set here
                #
                # TODO: All p-bits currently go to the one and only GEMPORT ID for now
                gem_ports = self._handler.pon_port.gem_ports
                gem_entity_ids = [gem_port.entity_id for _, gem_port in gem_ports.items()] \
                    if len(gem_ports) else [OmciNullPointer]

                frame = Ieee8021pMapperServiceProfileFrame(
                    ieee_mapper_service_profile_entity_id,   # 802.1p mapper Service Mapper Profile ID
                    interwork_tp_pointers=gem_entity_ids     # Interworking TP IDs
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
        else:
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                               self.resync_omci_settings)

    def _subscribe_to_events(self):
        from voltha.extensions.omci.onu_device_entry import OnuDeviceEvents, \
            OnuDeviceEntry
        from voltha.extensions.omci.omci_cc import OMCI_CC, OmciCCRxEvents

        # OMCI MIB Database sync status

        bus = self._onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self._handler.device_id,
                                               OnuDeviceEvents.MibDatabaseSyncEvent)
        self._in_sync_subscription = bus.subscribe(topic, self.in_sync_handler)

        # OMCI Capabilities (MEs and Message Types

        bus = self._onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self._handler.device_id,
                                               OnuDeviceEvents.OmciCapabilitiesEvent)
        self._capabilities_subscription = bus.subscribe(topic, self.capabilties_handler)

        # OMCI-CC Connectivity Events (for reachability/heartbeat)

        bus = self._onu_omci_device.omci_cc.event_bus
        topic = OMCI_CC.event_bus_topic(self._handler.device_id,
                                        OmciCCRxEvents.Connectivity)
        self._connectivity_subscription = bus.subscribe(topic, self.onu_is_reachable)

    def _unsubscribe_to_events(self):
        insync, self._in_sync_subscription = self._in_sync_subscription, None
        connect, self._connectivity_subscription = self._connectivity_subscription, None
        caps, self._capabilities_subscription = self._capabilities_subscription, None

        if insync is not None:
            bus = self._onu_omci_device.event_bus
            bus.unsubscribe(insync)

        if connect is not None:
            bus = self._onu_omci_device.omci_cc.event_bus
            bus.unsubscribe(connect)

        if caps is not None:
            bus = self._onu_omci_device.event_bus
            bus.unsubscribe(caps)

    def in_sync_handler(self, _topic, msg):
        if self._in_sync_subscription is not None:
            try:
                from voltha.extensions.omci.onu_device_entry import IN_SYNC_KEY

                if msg[IN_SYNC_KEY]:
                    # Start up device_info load from MIB DB
                    reactor.callLater(0, self._mib_in_sync)
                else:
                    # Cancel any running/scheduled MIB download task
                    try:
                        d, self._mib_download_deferred = self._mib_download_deferred, None
                        d.cancel()
                    except:
                        pass

            except Exception as e:
                self.log.exception('in-sync', e=e)

    def capabilties_handler(self, _topic, _msg):
        """
        This event occurs after an ONU reaches the In-Sync state and the OMCI ME has
        been queried for supported ME and message types.

        At this point, we can act upon any download device and/or service Technology
        profiles (when they exist).  For now, just run our somewhat fixed script
        """
        if self._capabilities_subscription is not None:
            from adtn_mib_download_task import AdtnMibDownloadTask

            def success(_results):
                self._mib_download_task = None
                pass   # TODO.  What's next...

            def failure(_reason):
                self._mib_download_task = None
                # TODO: Handle failure, retry for now?
                self._mib_download_deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                                self.capabilties_handler)
            self._mib_download_task = AdtnMibDownloadTask(self.omci_agent, self._handler.device_id)
            self._mib_download_deferred = self._onu_omci_device.task_runner.queue_task(self._mib_download_task)
            self._mib_download_deferred.addCallbacks(success, failure)

    def onu_is_reachable(self, _topic, msg):
        """
        Reach-ability change event
        :param _topic: (str) subscription topic, not used
        :param msg: (dict) 'connected' key holds True if reachable
        """
        from voltha.extensions.omci.omci_cc import CONNECTED_KEY
        if self._connectivity_subscription is not None:
            try:
                connected = msg[CONNECTED_KEY]

                # TODO: For now, only care about the first connect occurrence.
                # Later we could use this for a heartbeat, but may want some hysteresis
                # Cancel any 'reachable' subscriptions
                if connected:
                    evt_bus = self._onu_omci_device.omci_cc.event_bus
                    evt_bus.unsubscribe(self._connectivity_subscription)
                    self._connectivity_subscription = None
                    self._connected = True

                    device = self._handler.adapter_agent.get_device(self._handler.device_id)
                    device.oper_status = OperStatus.ACTIVE
                    device.connect_status = ConnectStatus.REACHABLE
                    self._handler.adapter_agent.update_device(device)

            except Exception as e:
                self.log.exception('onu-reachable', e=e)
