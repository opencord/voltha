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

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, TimeoutError, failure, returnValue
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.tasks.task import Task
from voltha.extensions.omci.omci_defs import *
from voltha.adapters.adtran_onu.omci.omci import OMCI
from voltha.adapters.adtran_onu.uni_port import *
from voltha.adapters.adtran_onu.onu_tcont import OnuTCont
from voltha.adapters.adtran_onu.onu_gem_port import OnuGemPort

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


class AdtnTpServiceSpecificTask(Task):
    """
    Adtran OpenOMCI Tech-Profile Download Task
    """
    name = "Adtran Tech-Profile Download Task"
    task_priority = Task.DEFAULT_PRIORITY + 10
    default_tpid = 0x8100                       # TODO: Move to a better location
    default_gem_payload = 48

    def __init__(self, omci_agent, handler, uni_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        self.log = structlog.get_logger(device_id=handler.device_id, uni_id=uni_id)

        super(AdtnTpServiceSpecificTask, self).__init__(AdtnTpServiceSpecificTask.name,
                                                        omci_agent,
                                                        handler.device_id,
                                                        priority=AdtnTpServiceSpecificTask.task_priority,
                                                        exclusive=False)

        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None

        pon_port = handler.pon_port()
        self._uni_port = handler.uni_ports[uni_id]
        assert self._uni_port.uni_id == uni_id

        self._input_tpid = AdtnTpServiceSpecificTask.default_tpid
        self._output_tpid = AdtnTpServiceSpecificTask.default_tpid

        self._vlan_tcis_1 = OMCI.DEFAULT_UNTAGGED_VLAN
        self._cvid = OMCI.DEFAULT_UNTAGGED_VLAN
        self._vlan_config_entity_id = self._vlan_tcis_1
        self._max_gem_payload = AdtnTpServiceSpecificTask.default_gem_payload

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set

        self._mac_bridge_service_profile_entity_id = handler.mac_bridge_service_profile_entity_id
        self._ieee_mapper_service_profile_entity_id = pon_port.ieee_mapper_service_profile_entity_id
        self._mac_bridge_port_ani_entity_id = pon_port.mac_bridge_port_ani_entity_id
        self._gal_enet_profile_entity_id = handler.gal_enet_profile_entity_id

        # Extract the current set of TCONT and GEM Ports from the Handler's pon_port that are
        # relevant to this task's UNI. It won't change. But, the underlying pon_port may change
        # due to additional tasks on different UNIs. So, it we cannot use the pon_port affter
        # this initializer
        self._tconts = [tcont for tcont in pon_port.tconts.itervalues()
                        if tcont.uni_id == self._uni_port.uni_id]

        self._gem_ports = [gem_port for gem_port in pon_port.gem_ports.itervalues()
                           if gem_port.uni_id == self._uni_port.uni_id]

        self.tcont_me_to_queue_map = dict()
        self.uni_port_to_queue_map = dict()

    def cancel_deferred(self):
        self.log.debug('function-entry')
        super(AdtnTpServiceSpecificTask, self).cancel_deferred()

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
        super(AdtnTpServiceSpecificTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_service_specific_steps)

    def stop(self):
        """
        Shutdown Tech-Profile download tasks
        """
        self.log.debug('function-entry')
        self.log.debug('stopping')

        self.cancel_deferred()
        super(AdtnTpServiceSpecificTask, self).stop()

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

        self.log.debug("OMCI Result: %s", operation, omci_msg=omci_msg, status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            self.strobe_watchdog()
            return True

        elif status == RC.InstanceExists:
            return False           # For Creates issued during task retries

        raise TechProfileDownloadFailure(
            '{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'
            .format(operation, status, error_mask, failed_mask, unsupported_mask))

    @inlineCallbacks
    def perform_service_specific_steps(self):
        """
        Install the Technology Profile specific ME instances into the ONU. The
        initial bridge setup was performed after the capabilities were discovered.

        This task is called near the end of the ONU Tech profile setup when the
        ONU receives technology profile info from the OLT over the inter-adapter channel
        """
        self.log.debug('setting-up-tech-profile-me-instances')

        if len(self._tconts) == 0:
            self.deferred.errback(failure.Failure(TechProfileResourcesFailure('No TCONTs assigned')))
            returnValue('no-resources')

        if len(self._gem_ports) == 0:
            self.deferred.errback(failure.Failure(TechProfileResourcesFailure('No GEM Ports assigned')))
            returnValue('no-resources')

        omci_cc = self._onu_device.omci_cc
        self.strobe_watchdog()

        try:
            ################################################################################
            # TCONTS
            #
            #  EntityID will be referenced by:
            #            - GemPortNetworkCtp
            #  References:
            #            - ONU created TCONT (created on ONU tech profile startup)

            tcont_idents = self._onu_device.query_mib(Tcont.class_id)
            self.log.debug('tcont-idents', tcont_idents=tcont_idents)

            for tcont in self._tconts:
                if tcont.entity_id is not None:
                    continue             # Already installed

                free_alloc_ids = {OnuTCont.FREE_TCONT_ALLOC_ID,
                                  OnuTCont.FREE_GPON_TCONT_ALLOC_ID}

                free_entity_id = next((k for k, v in tcont_idents.items()
                                       if isinstance(k, int) and
                                       v.get('attributes', {}).get('alloc_id', 0) in
                                       free_alloc_ids), None)

                if free_entity_id is None:
                    self.log.error('no-available-tconts')
                    raise TechProfileResourcesFailure('No Available TConts')

                try:
                    prev_alloc_id = tcont_idents[free_entity_id].get('attributes').get('alloc_id')
                    results = yield tcont.add_to_hardware(omci_cc, free_entity_id, prev_alloc_id=prev_alloc_id)
                    self.check_status_and_state(results, 'create-tcont')

                except Exception as e:
                    self.log.exception('tcont-set', e=e, eid=free_entity_id)
                    raise

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

            traffic_mgmt_opt = onu_g.get('attributes', {}).get('traffic_management_options', 0)
            self.log.debug("traffic-mgmt-option", traffic_mgmt_opt=traffic_mgmt_opt)

            prior_q = self._onu_device.query_mib(PriorityQueueG.class_id)

            for k, v in prior_q.items():
                self.log.debug("prior-q", k=k, v=v)
                self.strobe_watchdog()

                try:
                    _ = iter(v)
                except TypeError:
                    continue

                if 'instance_id' in v:
                    related_port = v['attributes']['related_port']
                    if v['instance_id'] & 0b1000000000000000:
                        tcont_me = (related_port & 0xffff0000) >> 16

                        if tcont_me not in self.tcont_me_to_queue_map:
                            self.log.debug("prior-q-related-port-and-tcont-me",
                                           related_port=related_port,
                                           tcont_me=tcont_me)
                            self.tcont_me_to_queue_map[tcont_me] = list()

                        self.tcont_me_to_queue_map[tcont_me].append(k)
                    else:
                        uni_port = (related_port & 0xffff0000) >> 16

                        if uni_port == self._uni_port.entity_id:
                            if uni_port not in self.uni_port_to_queue_map:
                                self.log.debug("prior-q-related-port-and-uni-port-me",
                                               related_port=related_port,
                                               uni_port_me=uni_port)
                                self.uni_port_to_queue_map[uni_port] = list()

                            self.uni_port_to_queue_map[uni_port].append(k)

            self.log.debug("ul-prior-q", ul_prior_q=self.tcont_me_to_queue_map)
            self.log.debug("dl-prior-q", dl_prior_q=self.uni_port_to_queue_map)

            for gem_port in self._gem_ports:
                self.strobe_watchdog()
                if gem_port.entity_id is not None:
                    continue                        # Already installed

                # TODO: Traffic descriptor will be available after meter bands are available
                tcont = gem_port.tcont
                if tcont is None:
                    self.log.error('unknown-tcont-reference', gem_id=gem_port.gem_id)
                    continue

                ul_prior_q_entity_id = None
                dl_prior_q_entity_id = None

                if gem_port.direction in {OnuGemPort.UPSTREAM, OnuGemPort.BIDIRECTIONAL}:

                    # Sort the priority queue list in order of priority.
                    # 0 is highest priority and 0x0fff is lowest.
                    self.tcont_me_to_queue_map[tcont.entity_id].sort()
                    self.uni_port_to_queue_map[self._uni_port.entity_id].sort()

                    # Get the priority queue associated with p-bit that is
                    # mapped to the gem port.
                    # p-bit-7 is highest priority and p-bit-0 is lowest
                    # Gem port associated with p-bit-7 should be mapped to
                    # highest priority queue and gem port associated with p-bit-0
                    # should be mapped to lowest priority queue.
                    # The self.tcont_me_to_queue_map and self.uni_port_to_queue_map
                    # have priority queue entities ordered in descending order
                    # of priority
                    for i, p in enumerate(gem_port.pbit_map):
                        if p == '1':
                            ul_prior_q_entity_id = self.tcont_me_to_queue_map[tcont.entity_id][i]
                            dl_prior_q_entity_id = self.uni_port_to_queue_map[self._uni_port.entity_id][i]
                            break

                    assert ul_prior_q_entity_id is not None and dl_prior_q_entity_id is not None

                    # TODO: Need to restore on failure.  Need to check status/results
                    results = yield gem_port.add_to_hardware(omci_cc,
                                                             tcont.entity_id,
                                                             self._ieee_mapper_service_profile_entity_id +
                                                             self._uni_port.mac_bridge_port_num,
                                                             self._gal_enet_profile_entity_id,
                                                             ul_prior_q_entity_id, dl_prior_q_entity_id)
                    self.check_status_and_state(results, 'create-gem-port')

                elif gem_port.direction == OnuGemPort.DOWNSTREAM:
                    # Downstream is inverse of upstream
                    # TODO: could also be a case of multicast. Not supported for now
                    pass

            ################################################################################
            # Update the IEEE 802.1p Mapper Service Profile config
            #
            #  EntityID was created prior to this call. This is a set
            #
            #  References:
            #            - Gem Interwork TPs are set here
            #
            gem_entity_ids = [OmciNullPointer] * 8

            for gem_port in self._gem_ports:
                self.strobe_watchdog()
                self.log.debug("tp-gem-port", entity_id=gem_port.entity_id, uni_id=gem_port.uni_id)

                if gem_port.direction in {OnuGemPort.UPSTREAM, OnuGemPort.BIDIRECTIONAL}:
                    for i, p in enumerate(gem_port.pbit_map):
                        if p == '1':
                            gem_entity_ids[i] = gem_port.entity_id

                elif gem_port.direction == OnuGemPort.DOWNSTREAM:
                    # Downstream gem port p-bit mapper is inverse of upstream
                    # TODO: Could also be a case of multicast. Not supported for now
                    pass

            msg = Ieee8021pMapperServiceProfileFrame(
                self._ieee_mapper_service_profile_entity_id +
                self._uni_port.mac_bridge_port_num,   # 802.1p mapper Service Mapper Profile ID
                interwork_tp_pointers=gem_entity_ids  # Interworking TP IDs
            )
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-8021p-mapper-service-profile-ul')

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
            # if self._uni_port.type is UniType.VEIP:
            #     association_type = 10
            # elif self._uni_port.type is UniType.PPTP:
            #     association_type = 2
            # else:
            association_type = 2

            attributes = dict(
                association_type=association_type,                  # Assoc Type, PPTP/VEIP Ethernet UNI
                associated_me_pointer=self._uni_port.entity_id,     # Assoc ME, PPTP/VEIP Entity Id

                # See VOL-1311 - Need to set table during create to avoid exception
                # trying to read back table during post-create-read-missing-attributes
                # But, because this is a R/W attribute. Some ONU may not accept the
                # value during create. It is repeated again in a set below.
                input_tpid=self._input_tpid,    # input TPID
                output_tpid=self._output_tpid,  # output TPID
            )
            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._mac_bridge_service_profile_entity_id + self._uni_port.mac_bridge_port_num,  # Bridge Entity ID
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
            )
            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._mac_bridge_service_profile_entity_id + self._uni_port.mac_bridge_port_num,  # Bridge Entity ID
                attributes=attributes
            )
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data')

            attributes = dict(
                # parameters: Entity Id ( 0x900), Filter Inner Vlan Id(0x1000-4096,do not filter on Inner vid,
                #             Treatment Inner Vlan Id : 2

                # Update uni side extended vlan filter
                # filter for untagged
                # probably for eapol
                # TODO: lots of magic
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
            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                self._mac_bridge_service_profile_entity_id + self._uni_port.mac_bridge_port_num,  # Bridge Entity ID
                attributes=attributes
            )
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data-table')

            self.deferred.callback("tech-profile-download-success")

        except TimeoutError as e:
            self.log.warn('rx-timeout-2', e=e)
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('omci-setup-2', e=e)
            self.deferred.errback(failure.Failure(e))
