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
from voltha.adapters.brcm_openomci_onu.pon_port \
    import BRDCM_DEFAULT_VLAN, TASK_PRIORITY, DEFAULT_TPID, DEFAULT_GEM_PAYLOAD

OP = EntityOperations
RC = ReasonCodes


class TechProfileDownloadFailure(Exception):
    """
    This error is raised by default when the download fails
    """


class TechProfileResourcesFailure(Exception):
    """
    This error is raised by when one or more resources required is not available
    """


class BrcmTpServiceSpecificTask(Task):
    """
    OpenOMCI Tech-Profile Download Task

    """

    name = "Broadcom Tech-Profile Download Task"

    def __init__(self, omci_agent, handler):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """

        self.log = structlog.get_logger(device_id=handler.device_id)
        self.log.debug('function-entry')

        super(BrcmTpServiceSpecificTask, self).__init__(BrcmTpServiceSpecificTask.name,
                                                        omci_agent,
                                                        handler.device_id,
                                                        priority=TASK_PRIORITY)
        self._handler = handler
        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None

        # Frame size
        self._max_gem_payload = DEFAULT_GEM_PAYLOAD

        # TODO: only using a single UNI/ethernet port
        self._uni_port = self._handler.uni_ports[0]
        self._uni_port_num = self._uni_port.mac_bridge_port_num
        self._ethernet_uni_entity_id = self._uni_port.entity_id

        self._pon = handler.pon_port

        # Port numbers
        self._ul_pon_port_num = self._pon.ul_pon_port_num
        self._dl_pon_port_num = self._pon.dl_pon_port_num
        self._input_tpid = DEFAULT_TPID
        self._output_tpid = DEFAULT_TPID

        self._vlan_tcis_1 = BRDCM_DEFAULT_VLAN
        self._cvid = BRDCM_DEFAULT_VLAN
        self._vlan_config_entity_id = self._vlan_tcis_1

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set

        self._mac_bridge_service_profile_entity_id = \
            self._handler.mac_bridge_service_profile_entity_id
        self._ul_ieee_mapper_service_profile_entity_id = \
            self._pon.ul_ieee_mapper_service_profile_entity_id
        self._dl_ieee_mapper_service_profile_entity_id = \
            self._pon.dl_ieee_mapper_service_profile_entity_id
        self._ul_mac_bridge_port_ani_entity_id = \
            self._pon.ul_mac_bridge_port_ani_entity_id
        self._dl_mac_bridge_port_ani_entity_id = \
            self._pon.dl_mac_bridge_port_ani_entity_id
        self._gal_enet_profile_entity_id = \
            self._handler.gal_enet_profile_entity_id

        self._free_ul_prior_q_entity_ids = set()
        self._free_dl_prior_q_entity_ids = set()

    def cancel_deferred(self):
        self.log.debug('function-entry')
        super(BrcmTpServiceSpecificTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start the Tech-Profile Download
        """
        self.log.debug('function-entry')
        super(BrcmTpServiceSpecificTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_service_specific_steps)

    def stop(self):
        """
        Shutdown Tech-Profile download tasks
        """
        self.log.debug('function-entry')
        self.log.debug('stopping')

        self.cancel_deferred()
        super(BrcmTpServiceSpecificTask, self).stop()

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

        self.log.debug("OMCI Result:", operation, omci_msg=omci_msg, status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            self.strobe_watchdog()
            return True

        elif status == RC.InstanceExists:
            return False

        raise TechProfileDownloadFailure(
            '{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'
            .format(operation, status, error_mask, failed_mask, unsupported_mask))

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
                results = yield tcont.add_to_hardware(omci_cc, free_entity_id)
                self.check_status_and_state(results, 'add-tcont')

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

            onu_g = self._onu_device.query_mib(OntG.class_id)
            # If the traffic management option attribute in the ONU-G ME is 0
            # (priority controlled) or 2 (priority and rate controlled), this
            # pointer specifies the priority queue ME serving this GEM port
            # network CTP. If the traffic management option attribute is 1
            # (rate controlled), this attribute redundantly points to the
            # T-CONT serving this GEM port network CTP.
            traffic_mgmt_opt = \
                onu_g.get('attributes', {}).get('traffic_management_options', 0)
            self.log.debug("traffic-mgmt-option", traffic_mgmt_opt=traffic_mgmt_opt)

            prior_q = self._onu_device.query_mib(PriorityQueueG.class_id)
            for k, v in prior_q.items():
                self.log.debug("prior-q", k=k, v=v)

                try:
                    _ = iter(v)
                except TypeError:
                    continue

                if 'instance_id' in v:
                    if v['instance_id'] & 0b1000000000000000:
                        self._free_ul_prior_q_entity_ids.add(k)
                    else:
                        self._free_dl_prior_q_entity_ids.add(k)
            self.log.debug("ul-prior-q", ul_prior_q=self._free_ul_prior_q_entity_ids)
            self.log.debug("dl-prior-q", dl_prior_q=self._free_dl_prior_q_entity_ids)

            for gem_port in self._handler.pon_port.gem_ports.itervalues():
                # TODO: Traffic descriptor will be available after meter bands are available
                tcont = gem_port.tcont
                if tcont is None:
                    self.log.error('unknown-tcont-reference', gem_id=gem_port.gem_id)
                    continue

                prior_q_entity_id = OmciNullPointer
                if gem_port.direction == "upstream":
                    prior_q_entity_id = self._free_ul_prior_q_entity_ids.pop()
                    # TODO: Need to restore on failure.  Need to check status/results
                    results = yield gem_port.add_to_hardware(omci_cc,
                                                   tcont.entity_id,
                                                   self._ul_ieee_mapper_service_profile_entity_id,
                                                   self._gal_enet_profile_entity_id,
                                                   prior_q_entity_id)
                    self.check_status_and_state(results, 'add-gem')
                elif gem_port.direction == "downstream":
                    prior_q_entity_id = self._free_dl_prior_q_entity_ids.pop()
                    # TODO: Need to restore on failure.  Need to check status/results
                    results = yield gem_port.add_to_hardware(omci_cc,
                                                   tcont.entity_id,
                                                   self._dl_ieee_mapper_service_profile_entity_id,
                                                   self._gal_enet_profile_entity_id,
                                                   prior_q_entity_id)
                    self.check_status_and_state(results, 'add-gem')

            ################################################################################
            # Update the IEEE 802.1p Mapper Service Profile config
            #
            #  EntityID was created prior to this call. This is a set
            #
            #  References:
            #            - Gem Interwork TPs are set here
            #

            ul_gem_entity_ids = [OmciNullPointer] * 8
            dl_gem_entity_ids = [OmciNullPointer] * 8
            for gem_port in self._handler.pon_port.gem_ports.itervalues():
                if gem_port.direction == "upstream":
                    for i, p in enumerate(gem_port.pbit_map):
                        if p == '1':
                            ul_gem_entity_ids[i] = gem_port.entity_id
                elif gem_port.direction == "downstream":
                    for i, p in enumerate(gem_port.pbit_map):
                        if p == '1':
                            dl_gem_entity_ids[i] = gem_port.entity_id

            msg = Ieee8021pMapperServiceProfileFrame(
                self._ul_ieee_mapper_service_profile_entity_id,  # 802.1p mapper Service Mapper Profile ID
                interwork_tp_pointers=ul_gem_entity_ids  # Interworking TP IDs
            )
            frame = msg.set()
            self.log.debug('openomci-msg', msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-8021p-mapper-service-profile-ul')

            msg = Ieee8021pMapperServiceProfileFrame(
                self._dl_ieee_mapper_service_profile_entity_id,  # 802.1p mapper Service Mapper Profile ID
                interwork_tp_pointers=dl_gem_entity_ids  # Interworking TP IDs
            )
            frame = msg.set()
            self.log.debug('openomci-msg', msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-8021p-mapper-service-profile-dl')

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
            if self._uni_port.type is UniType.VEIP:
                association_type = 10
            elif self._uni_port.type is UniType.PPTP:
                association_type = 2
            else:
                association_type = 2

            attributes = dict(
                association_type=association_type,  # Assoc Type, PPTP/VEIP Ethernet UNI
                associated_me_pointer=self._ethernet_uni_entity_id,  # Assoc ME, PPTP/VEIP Entity Id

                # See VOL-1311 - Need to set table during create to avoid exception
                # trying to read back table during post-create-read-missing-attributes
                # But, because this is a R/W attribute. Some ONU may not accept the
                # value during create. It is repeated again in a set below.
                input_tpid=self._input_tpid,  # input TPID
                output_tpid=self._output_tpid,  # output TPID
            )

            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                attributes=attributes
            )

            frame = msg.create()
            self.log.debug('openomci-msg', msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-extended-vlan-tagging-operation-configuration-data')

            attributes = dict(
                # Specifies the TPIDs in use and that operations in the downstream direction are
                # inverse to the operations in the upstream direction
                input_tpid=self._input_tpid,  # input TPID
                output_tpid=self._output_tpid,  # output TPID
                downstream_mode=0,              # inverse of upstream
            )

            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                attributes=attributes
            )

            frame = msg.set()
            self.log.debug('openomci-msg', msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data')

            attributes = dict(
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
                    filter_outer_vid=4096,  # Do not filter on the outer VID value
                    filter_outer_tpid_de=0,  # Do not filter on the outer TPID field

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
            self.log.debug('openomci-msg', msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data-table')

            self.deferred.callback("tech-profile-download-success")

        except TimeoutError as e:
            self.log.warn('rx-timeout-2', e=e)
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('omci-setup-2', e=e)
            self.deferred.errback(failure.Failure(e))
