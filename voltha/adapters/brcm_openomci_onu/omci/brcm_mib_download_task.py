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

import structlog
from common.frameio.frameio import hexify
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, TimeoutError, failure
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.tasks.task import Task
from voltha.extensions.omci.omci_defs import *
from voltha.adapters.brcm_openomci_onu.uni_port import *

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


class BrcmMibDownloadTask(Task):
    """
    OpenOMCI MIB Download Example

    This task takes the legacy OMCI 'script' for provisioning the Broadcom ONU
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
    default_gem_payload = 48
    BRDCM_DEFAULT_VLAN = 4091

    name = "Broadcom MIB Download Example Task"

    def __init__(self, omci_agent, handler):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """

        self.log = structlog.get_logger(device_id=handler.device_id)
        self.log.debug('function-entry')

        super(BrcmMibDownloadTask, self).__init__(BrcmMibDownloadTask.name,
                                                  omci_agent,
                                                  handler.device_id,
                                                  priority=BrcmMibDownloadTask.task_priority)
        self._handler = handler
        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None

        # Frame size
        self._max_gem_payload = BrcmMibDownloadTask.default_gem_payload

        # TODO: only using a single UNI/ethernet port
        self._uni_port = self._handler.uni_ports[0]

        # Port numbers
        self._pon_port_num = 3  # TODO why 3.  maybe this is the ani port number.  look at anis list

        self._input_tpid = BrcmMibDownloadTask.default_tpid
        self._output_tpid = BrcmMibDownloadTask.default_tpid

        self._vlan_tcis_1 = self.BRDCM_DEFAULT_VLAN
        self._cvid = self.BRDCM_DEFAULT_VLAN
        self._vlan_config_entity_id = self._vlan_tcis_1

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set

        # TODO: lots of magic numbers
        self._mac_bridge_service_profile_entity_id = 0x201
        self._ieee_mapper_service_profile_entity_id = 0x8001
        self._mac_bridge_port_ani_entity_id = 0x2102   # TODO: can we just use the entity id from the anis list?
        self._gal_enet_profile_entity_id = 0x1

    def cancel_deferred(self):
        self.log.debug('function-entry')
        super(BrcmMibDownloadTask, self).cancel_deferred()

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
        self.log.debug('function-entry')
        super(BrcmMibDownloadTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_mib_download)

    def stop(self):
        """
        Shutdown MIB Synchronization tasks
        """
        self.log.debug('function-entry')
        self.log.debug('stopping')

        self.cancel_deferred()
        super(BrcmMibDownloadTask, self).stop()

    def check_status_and_state(self, results, operation=''):
        """
        Check the results of an OMCI response.  An exception is thrown
        if the task was cancelled or an error was detected.

        :param results: (OmciFrame) OMCI Response frame
        :param operation: (str) what operation was being performed
        :return: True if successful, False if the entity existed (already created)
        """
        self.log.debug('function-entry')

        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')

        self.log.debug("OMCI Result: %s", operation,
                       omci_msg=omci_msg, status=status,
                       error_mask=error_mask, failed_mask=failed_mask,
                       unsupported_mask=unsupported_mask)

        if status == RC.Success:
            self.strobe_watchdog()
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
        self.log.debug('function-entry')
        self.log.info('perform-download')

        device = self._handler.adapter_agent.get_device(self.device_id)

        def resources_available():
            return (len(self._handler.uni_ports) > 0 and
                    len(self._handler.pon_port.tconts) and
                    len(self._handler.pon_port.gem_ports))

        if self._handler.enabled and resources_available():
            device.reason = 'performing-initial-mib-download'
            self._handler.adapter_agent.update_device(device)

            try:
                # Lock the UNI ports to prevent any alarms during initial configuration
                # of the ONU
                self.strobe_watchdog()
                yield self.enable_uni(self._uni_port, True)

                # Provision the initial bridge configuration
                yield self.perform_initial_bridge_setup()

                # And not all the service specific work
                yield self.perform_service_specific_steps()

                # And re-enable the UNIs if needed
                yield self.enable_uni(self._uni_port, False)

                self.deferred.callback('initial-download-success')

            except TimeoutError as e:
                self.deferred.errback(failure.Failure(e))

        else:
            e = MibResourcesFailure('Required resources are not available',
                                    tconts=len(self._handler.pon_port.tconts),
                                    gems=len(self._handler.pon_port.gem_ports),
                                    unis=len(self._handler.uni_ports))
            self.deferred.errback(failure.Failure(e))

    @inlineCallbacks
    def perform_initial_bridge_setup(self):
        self.log.debug('function-entry')

        omci_cc = self._onu_device.omci_cc
        frame = None
        # TODO: too many magic numbers

        try:
            ########################################################################################
            # Create GalEthernetProfile - Once per ONU/PON interface
            #
            #  EntityID will be referenced by:
            #            - GemInterworkingTp
            #  References:
            #            - Nothing

            msg = GalEthernetProfileFrame(
                self._gal_enet_profile_entity_id,
                max_gem_payload_size=self._max_gem_payload
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-gal-ethernet-profile')

            ################################################################################
            # Common - PON and/or UNI                                                      #
            ################################################################################
            # MAC Bridge Service Profile
            #
            #  EntityID will be referenced by:
            #            - MAC Bridge Port Configuration Data (PON & UNI)
            #  References:
            #            - Nothing

            # TODO: magic. event if static, assign to a meaningful variable name
            attributes = {
                'spanning_tree_ind': False,
                'learning_ind' : True,
                'priority' : 0x8000,
                'max_age' : 20 * 256,
                'hello_time' : 2 * 256,
                'forward_delay' : 15 * 256,
                'unknown_mac_address_discard' : True
            }
            msg = MacBridgeServiceProfileFrame(
                self._mac_bridge_service_profile_entity_id,
                attributes
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
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

            msg = Ieee8021pMapperServiceProfileFrame(self._ieee_mapper_service_profile_entity_id)
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
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

            # TODO: magic. make a static variable for tp_type
            msg = MacBridgePortConfigurationDataFrame(
                self._mac_bridge_port_ani_entity_id,
                bridge_id_pointer=self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                port_num=self._pon_port_num,                            # Port ID  ##TODO associated with what?
                tp_type=3,                                              # TP Type (IEEE 802.1p mapper service)
                tp_pointer=self._ieee_mapper_service_profile_entity_id  # TP ID, 8021p mapper ID
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
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

            # TODO: magic. make a static variable for forward_op
            msg = VlanTaggingFilterDataFrame(
                self._mac_bridge_port_ani_entity_id,  # Entity ID
                vlan_tcis=[self._vlan_tcis_1],        # VLAN IDs
                forward_operation=0x10
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-vlan-tagging-filter-data')

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
            #            - PPTP Ethernet or VEIP UNI

            # TODO: do this for all uni/ports...
            # TODO: magic. make a static variable for tp_type

            # default to PPTP
            tp_type = None
            if self._uni_port.type is UniType.VEIP:
                tp_type = 11
            elif self._uni_port.type is UniType.PPTP:
                tp_type = 1
            else:
                tp_type = 1

            msg = MacBridgePortConfigurationDataFrame(
                self._uni_port.entity_id,            # Entity ID - This is read-only/set-by-create !!!
                bridge_id_pointer=self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                port_num=self._uni_port.mac_bridge_port_num,   # Port ID
                tp_type=tp_type,                               # PPTP Ethernet or VEIP UNI
                tp_pointer=self._uni_port.entity_id            # Ethernet UNI ID
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-mac-bridge-port-configuration-data-part-2')

        except TimeoutError as e:
            self.log.warn('rx-timeout-1', e=e)
            raise

        except Exception as e:
            self.log.exception('omci-setup-1', e=e)
            raise

        returnValue(None)

    @inlineCallbacks
    def perform_service_specific_steps(self):
        self.log.debug('function-entry')

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
                free_entity_id = None
                for k, v in tcont_idents.items():
                    alloc_check = v.get('attributes', {}).get('alloc_id', 0)
                    # Some onu report both to indicate an available tcont
                    if alloc_check == 0xFF or alloc_check == 0xFFFF:
                        free_entity_id = k
                        break
                    else:
                        free_entity_id = None

                self.log.debug('tcont-loop', free_entity_id=free_entity_id)

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

            msg = Ieee8021pMapperServiceProfileFrame(
                self._ieee_mapper_service_profile_entity_id,  # 802.1p mapper Service Mapper Profile ID
                interwork_tp_pointers=gem_entity_ids          # Interworking TP IDs
            )
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-8021p-mapper-service-profile')

            ################################################################################
            # Create Extended VLAN Tagging Operation config (PON-side)
            #
            #  EntityID relates to the VLAN TCIS
            #  References:
            #            - VLAN TCIS from previously created VLAN Tagging filter data
            #            - PPTP Ethernet or VEIP UNI
            #

            # TODO: do this for all uni/ports...
            # TODO: magic.  static variable for assoc_type

            # default to PPTP
            association_type = None
            if self._uni_port.type is UniType.VEIP:
                association_type = 10
            elif self._uni_port.type is UniType.PPTP:
                association_type = 2
            else:
                association_type = 2

            attributes = dict(
                association_type=association_type,                  # Assoc Type, PPTP/VEIP Ethernet UNI
                associated_me_pointer=self._uni_port.entity_id,      # Assoc ME, PPTP/VEIP Entity Id

                # See VOL-1311 - Need to set table during create to avoid exception
                # trying to read back table during post-create-read-missing-attributes
                # But, because this is a R/W attribute. Some ONU may not accept the
                # value during create. It is repeated again in a set below.
                received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,  # This entry is not a double-tag rule
                    filter_outer_vid=4096,     # Do not filter on the outer VID value
                    filter_outer_tpid_de=0,    # Do not filter on the outer TPID field

                    filter_inner_priority=15,
                    filter_inner_vid=4096,
                    filter_inner_tpid_de=0  ,
                    filter_ether_type=0,

                    treatment_tags_to_remove=0,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,
                    treatment_outer_tpid_de=0,

                    treatment_inner_priority=0,
                    treatment_inner_vid=self._cvid,
                    treatment_inner_tpid_de=4,
                )
            )

            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                attributes=attributes
            )

            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-extended-vlan-tagging-operation-configuration-data')

            attributes = dict(
                # Specifies the TPIDs in use and that operations in the downstream direction are
                # inverse to the operations in the upstream direction
                input_tpid=self._input_tpid,    # input TPID
                output_tpid=self._output_tpid,  # output TPID
                downstream_mode=0,              # inverse of upstream

                # parameters: Entity Id ( 0x900), Filter Inner Vlan Id(0x1000-4096,do not filter on Inner vid,
                #             Treatment Inner Vlan Id : 2

                # Update uni side extended vlan filter
                # filter for untagged
                # probably for eapol
                # TODO: lots of magic
                # TODO: magic 0x1000 / 4096?
                received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,  # This entry is not a double-tag rule
                    filter_outer_vid=4096,     # Do not filter on the outer VID value
                    filter_outer_tpid_de=0,    # Do not filter on the outer TPID field

                    filter_inner_priority=15,
                    filter_inner_vid=4096,
                    filter_inner_tpid_de=0,
                    filter_ether_type=0,

                    treatment_tags_to_remove=0,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,
                    treatment_outer_tpid_de=0,

                    treatment_inner_priority=0,
                    treatment_inner_vid=self._cvid,
                    treatment_inner_tpid_de=4,
                )
            )

            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                attributes=attributes
            )

            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data')

        except TimeoutError as e:
            self.log.warn('rx-timeout-2', e=e)
            raise

        except Exception as e:
            self.log.exception('omci-setup-2', e=e)
            raise

        returnValue(None)

    @inlineCallbacks
    def enable_uni(self, uni_port, force_lock):
        """
        Lock or unlock a single uni port

        :param uni_port: UniPort to admin up/down
        :param force_lock: (boolean) If True, force lock regardless of enabled state
        """
        self.log.debug('function-entry')

        omci_cc = self._onu_device.omci_cc
        frame = None

        ################################################################################
        #  Lock/Unlock UNI  -  0 to Unlock, 1 to lock
        #
        #  EntityID is referenced by:
        #            - MAC bridge port configuration data for the UNI side
        #  References:
        #            - Nothing
        try:
            state = 1 if force_lock or not uni_port.enabled else 0
            msg = None
            if (uni_port.type is UniType.PPTP):
                msg = PptpEthernetUniFrame(uni_port.entity_id,
                                           attributes=dict(administrative_state=state))
            elif (uni_port.type is UniType.VEIP):
                msg = VeipUniFrame(uni_port.entity_id,
                                   attributes=dict(administrative_state=state))
            else:
                self.log.warn('unknown-uni-type', uni_port=uni_port)

            if msg:
               frame = msg.set()
               self.log.debug('openomci-msg', omci_msg=msg)
               results = yield omci_cc.send(frame)
               self.check_status_and_state(results, 'set-pptp-ethernet-uni-lock-restore')

        except TimeoutError as e:
            self.log.warn('rx-timeout', e=e)
            raise

        except Exception as e:
            self.log.exception('omci-failure', e=e)
            raise

        returnValue(None)



