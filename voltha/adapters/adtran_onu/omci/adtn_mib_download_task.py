#
# Copyright 2018 the original author or authors.
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
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, TimeoutError, failure
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.tasks.task import Task
from voltha.extensions.omci.omci_defs import *

OP = EntityOperations
RC = ReasonCodes


class MibDownloadFailure(Exception):
    """
    This error is raised by default when the download fails
    """


class MibResourcesFailure(Exception):
    """
    This error is raised by when one or more resources required is not available
    """


class AdtnMibDownloadTask(Task):
    """
    OpenOMCI MIB Download Example

    This task takes the legacy OMCI 'script' for provisioning the Adtran ONU
    and converts it to run as a Task on the OpenOMCI Task runner.  This is
    in order to begin to decompose service instantiation in preparation for
    Technology Profile work.

    Once technology profiles are ready, some of this task may hang around or
    be moved into OpenOMCI if there are any very common settings/configs to do
    for any profile that may be provided in the v2.0 release

    Currently, the only service tech profiles expected by v2.0 will be for AT&T
    residential data service and DT residential data service.
    """
    task_priority = Task.DEFAULT_PRIORITY + 10
    default_tpid = 0x8100
    default_gem_payload = 1518

    name = "ADTRAN MIB Download Example Task"

    def __init__(self, omci_agent, handler):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        super(AdtnMibDownloadTask, self).__init__(AdtnMibDownloadTask.name,
                                                  omci_agent,
                                                  handler.device_id,
                                                  priority=AdtnMibDownloadTask.task_priority)
        self._handler = handler
        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None

        # Frame size
        self._max_gem_payload = AdtnMibDownloadTask.default_gem_payload

        # Port numbers
        self._pon_port_num = 0
        self._uni_port_num = 0  # TODO Both port numbers are the same, is this correct?  See MacBridgePortConfigurationDataFrame

        self._vlan_tcis_1 = 0x900
        self._input_tpid = AdtnMibDownloadTask.default_tpid
        self._output_tpid = AdtnMibDownloadTask.default_tpid

        device = self._handler.adapter_agent.get_device(self.device_id)
        self._cvid = device.vlan

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set

        self._mac_bridge_service_profile_entity_id = 0x100
        self._ieee_mapper_service_profile_entity_id = 0x100
        self._mac_bridge_port_ani_entity_id = 0x100
        self._gal_enet_profile_entity_id = 0x100

        # Next to are specific
        self._ethernet_uni_entity_id = self._handler.uni_ports[0].entity_id
        self._vlan_config_entity_id = self._vlan_tcis_1

    def cancel_deferred(self):
        super(AdtnMibDownloadTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start the MIB Download
        """
        super(AdtnMibDownloadTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_mib_download)

    def stop(self):
        """
        Shutdown MIB Synchronization tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(AdtnMibDownloadTask, self).stop()

    def check_status_and_state(self, results, operation=''):
        """
        Check the results of an OMCI response.  An exception is thrown
        if the task was cancelled or an error was detected.

        :param results: (OmciFrame) OMCI Response frame
        :param operation: (str) what operation was being performed
        :return: True if successful, False if the entity existed (already created)
        """
        if not self.running:
            raise MibDownloadFailure('Download Task was cancelled')

        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')

        self.log.debug(operation, status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            return True

        elif status == RC.InstanceExists:
            return False

        raise MibDownloadFailure('{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'
                                 .format(operation, status, error_mask, failed_mask, unsupported_mask))

    @inlineCallbacks
    def perform_mib_download(self):
        """
        Send the commands to minimally configure the PON, Bridge, and
        UNI ports for this device. The application of any service flows
        and other characteristics are done as needed.
        """
        self.log.info('perform-download')

        device = self._handler.adapter_agent.get_device(self.device_id)

        def resources_available():
            return (device.vlan > 0 and
                    len(self._handler.uni_ports) > 0 and
                    len(self._handler.pon_port.tconts) and
                    len(self._handler.pon_port.gem_ports))

        if self._handler.enabled and resources_available():
            device.reason = 'Performing OMCI Download'
            self._handler.adapter_agent.update_device(device)

            try:
                # Lock the UNI ports to prevent any alarms during initial configuration
                # of the ONU
                yield self.enable_unis(self._handler.uni_ports, True)

                # Provision the initial bridge configuration
                yield self.perform_initial_bridge_setup()

                # And not all the service specific work
                yield self.perform_service_specific_steps()

                # And re-enable the UNIs if needed
                yield self.enable_unis(self._handler.uni_ports, False)

                # If here, we are done
                device = self._handler.adapter_agent.get_device(self.device_id)

                device.reason = ''
                self._handler.adapter_agent.update_device(device)
                self.deferred.callback('TODO: What should we return to the caller?')

            except TimeoutError as e:
                self.deferred.errback(failure.Failure(e))

        else:
            # TODO: Provide better error reason, what was missing...
            e = MibResourcesFailure('Required resources are not available')
            self.deferred.errback(failure.Failure(e))

    @inlineCallbacks
    def perform_initial_bridge_setup(self):
        omci_cc = self._onu_device.omci_cc
        frame = None

        try:
            ################################################################################
            # Common - PON and/or UNI                                                      #
            ################################################################################
            # MAC Bridge Service Profile
            #
            #  EntityID will be referenced by:
            #            - MAC Bridge Port Configuration Data (PON & UNI)
            #  References:
            #            - Nothing

            attributes = {
                'spanning_tree_ind': False
            }
            frame = MacBridgeServiceProfileFrame(
                self._mac_bridge_service_profile_entity_id,
                attributes
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-mac-bridge-service-profile')

            ################################################################################
            # PON Specific                                                                 #
            ################################################################################
            # IEEE 802.1 Mapper Service config - Once per PON
            #
            #  EntityID will be referenced by:
            #            - MAC Bridge Port Configuration Data for the PON port
            #  References:
            #            - Nothing at this point. When a GEM port is created, this entity will
            #              be updated to reference the GEM Interworking TP

            frame = Ieee8021pMapperServiceProfileFrame(self._ieee_mapper_service_profile_entity_id).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-8021p-mapper-service-profile')

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
                self._mac_bridge_port_ani_entity_id,                    # Entity ID
                bridge_id_pointer=self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                # TODO: The PORT number for this port and the UNI port are the same. Is this correct?
                port_num=self._pon_port_num,                            # Port ID
                tp_type=3,                                              # TP Type (IEEE 802.1p mapper service)
                tp_pointer=self._ieee_mapper_service_profile_entity_id  # TP ID, 8021p mapper ID
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-mac-bridge-port-configuration-data-part-1')

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
                self._mac_bridge_port_ani_entity_id,  # Entity ID
                vlan_tcis=[self._vlan_tcis_1],        # VLAN IDs
                forward_operation=0x10
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-vlan-tagging-filter-data')

            ########################################################################################
            # Create GalEthernetProfile - Once per ONU/PON interface
            #
            #  EntityID will be referenced by:
            #            - GemInterworkingTp
            #  References:
            #            - Nothing

            frame = GalEthernetProfileFrame(
                self._gal_enet_profile_entity_id,
                max_gem_payload_size=self._max_gem_payload
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-gal-ethernet-profile')

            ################################################################################
            # UNI Specific                                                                 #
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
                0x000,                                   # Entity ID - This is read-only/set-by-create !!!
                bridge_id_pointer=self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                port_num=self._uni_port_num,             # Port ID
                tp_type=1,                               # PPTP Ethernet UNI
                tp_pointer=self._ethernet_uni_entity_id  # TP ID, 8021p mapper Id
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-mac-bridge-port-configuration-data-part-2')

        except TimeoutError as e:
            self.log.warn('rx-timeout-1', frame=frame)
            raise

        except Exception as e:
            self.log.exception('omci-setup-1', e=e)
            raise

        returnValue(None)

    @inlineCallbacks
    def perform_service_specific_steps(self):
        omci_cc = self._onu_device.omci_cc
        frame = None

        try:
            ################################################################################
            # TCONTS
            #
            #  EntityID will be referenced by:
            #            - GemPortNetworkCtp
            #  References:
            #            - ONU created TCONT (created on ONU startup)

            tcont_idents = self._onu_device.query_mib(Tcont.class_id)
            self.log.debug('tcont-idents', tcont_idents=tcont_idents)

            for tcont in self._handler.pon_port.tconts.itervalues():
                free_entity_id = next((k for k, v in tcont_idents.items()
                                       if isinstance(k, int) and
                                       v.get('attributes', {}).get('alloc_id', 0) == 0xFFFF), None)
                if free_entity_id is None:
                    self.log.error('no-available-tconts')
                    break
                # TODO: Need to restore on failure.  Need to check status/results
                yield tcont.add_to_hardware(omci_cc, free_entity_id)

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
                # TODO: Need to restore on failure.  Need to check status/results
                yield gem_port.add_to_hardware(omci_cc,
                                               tcont.entity_id,
                                               self._ieee_mapper_service_profile_entity_id,
                                               self._gal_enet_profile_entity_id)

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
                self._ieee_mapper_service_profile_entity_id,  # 802.1p mapper Service Mapper Profile ID
                interwork_tp_pointers=gem_entity_ids          # Interworking TP IDs
            ).set()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-8021p-mapper-service-profile')

            ################################################################################
            # Create Extended VLAN Tagging Operation config (PON-side)
            #
            #  EntityID relates to the VLAN TCIS
            #  References:
            #            - VLAN TCIS from previously created VLAN Tagging filter data
            #            - PPTP Ethernet UNI
            #
            # TODO: add entry here for additional UNI interfaces

            attributes = dict(
                association_type=2,                                 # Assoc Type, PPTP Ethernet UNI
                associated_me_pointer=self._ethernet_uni_entity_id  # Assoc ME, PPTP Entity Id
            )

            frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._vlan_config_entity_id,
                attributes=attributes
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-extended-vlan-tagging-operation-configuration-data')

            ################################################################################
            # Update Extended VLAN Tagging Operation Config Data
            #
            # Specifies the TPIDs in use and that operations in the downstream direction are
            # inverse to the operations in the upstream direction
            # TODO: Downstream mode may need to be modified once we work more on the flow rules

            attributes = dict(
                input_tpid=self._input_tpid,    # input TPID
                output_tpid=self._output_tpid,  # output TPID
                downstream_mode=0,              # inverse of upstream
            )
            frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._vlan_config_entity_id,
                attributes=attributes
            ).set()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data')

            ################################################################################
            # Update Extended VLAN Tagging Operation Config Data
            #
            # parameters: Entity Id ( 0x900), Filter Inner Vlan Id(0x1000-4096,do not filter on Inner vid,
            #             Treatment Inner Vlan Id : 2

            attributes = dict(
                received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,  # This entry is not a double-tag rule
                    filter_outer_vid=4096,     # Do not filter on the outer VID value
                    filter_outer_tpid_de=0,    # Do not filter on the outer TPID field

                    filter_inner_priority=15,  # This is a no-tag rule, ignore all other VLAN tag filter fields
                    filter_inner_vid=0x1000,   # Do not filter on the inner VID
                    filter_inner_tpid_de=0,    # Do not filter on inner TPID field

                    filter_ether_type=0,         # Do not filter on EtherType
                    treatment_tags_to_remove=0,  # Remove 0 tags

                    treatment_outer_priority=15,  # Do not add an outer tag
                    treatment_outer_vid=0,        # n/a
                    treatment_outer_tpid_de=0,    # n/a

                    treatment_inner_priority=0,      # Add an inner tag and insert this value as the priority
                    treatment_inner_vid=self._cvid,  # use this value as the VID in the inner VLAN tag
                    treatment_inner_tpid_de=4,       # set TPID
                )
            )
            frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._vlan_config_entity_id,  # Entity ID
                attributes=attributes         # See above
            ).set()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data-untagged')

            ################################################################################
            ################################################################################
            ################################################################################
            # BP: This is for AT&T RG's                #
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
            # Set AR - ExtendedVlanTaggingOperationConfigData
            #          514 - RxVlanTaggingOperationTable - add VLAN <cvid> to untagged pkts - c-vid
            # results = yield omci.send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(
            #                                0x100,   # Entity ID            BP: Oldvalue 0x202
            #                                0x1000,  # Filter Inner VID     BP: Oldvalue 0x1000
            #                                cvid)    # Treatment inner VID  BP: cvid
            # success = results.fields['omci_message'].fields['success_code'] == 0
            # error_mask = results.fields['omci_message'].fields['parameter_error_attributes_mask']

            ###############################################################################

        except TimeoutError as e:
            self.log.warn('rx-timeout-2', frame=frame)
            raise

        except Exception as e:
            self.log.exception('omci-setup-2', e=e)
            raise

        returnValue(None)

    @inlineCallbacks
    def enable_unis(self, unis, force_lock):
        """
        Lock or unlock one or more UNI ports

        :param unis: (list) of UNI objects
        :param force_lock: (boolean) If True, force lock regardless of enabled state
        """
        omci_cc = self._onu_device.omci_cc
        frame = None

        for uni in unis:
            ################################################################################
            #  Lock/Unlock UNI  -  0 to Unlock, 1 to lock
            #
            #  EntityID is referenced by:
            #            - MAC bridge port configuration data for the UNI side
            #  References:
            #            - Nothing
            try:
                state = 1 if force_lock or not uni.enabled else 0
                frame = PptpEthernetUniFrame(uni.entity_id,
                                             attributes=dict(administrative_state=state)).set()
                results = yield omci_cc.send(frame)
                self.check_status_and_state(results, 'set-pptp-ethernet-uni-lock-restore')

            except TimeoutError:
                self.log.warn('rx-timeout', frame=frame)
                raise

            except Exception as e:
                self.log.exception('omci-failure', e=e)
                raise

        returnValue(None)
