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
from twisted.internet.defer import inlineCallbacks, failure, returnValue
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.tasks.task import Task
from voltha.extensions.omci.omci_defs import *
from voltha.adapters.adtran_onu.flow.flow_entry import FlowEntry

OP = EntityOperations
RC = ReasonCodes


class ServiceInstallFailure(Exception):
    """
    This error is raised by default when the flow-install fails
    """


class AdtnInstallFlowTask(Task):
    """
    OpenOMCI MIB Flow Install Task

    Currently, the only service tech profiles expected by v2.0 will be for AT&T
    residential data service and DT residential data service.
    """
    task_priority = Task.DEFAULT_PRIORITY + 10
    name = "ADTRAN MIB Install Flow Task"

    def __init__(self, omci_agent, handler, flow_entry):
        """
        Class initialization

        :param omci_agent: (OpenOMCIAgent) OMCI Adapter agent
        :param handler: (AdtranOnuHandler) ONU Handler
        :param flow_entry: (FlowEntry) Flow to install
        """
        super(AdtnInstallFlowTask, self).__init__(AdtnInstallFlowTask.name,
                                                  omci_agent,
                                                  handler.device_id,
                                                  priority=AdtnInstallFlowTask.task_priority,
                                                  exclusive=False)
        self._handler = handler
        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None
        self._flow_entry = flow_entry
        self._install_by_delete = True

        # TODO: Cleanup below that is not needed
        is_upstream = flow_entry.flow_direction in FlowEntry.upstream_flow_types
        uni_port = flow_entry.in_port if is_upstream else flow_entry.out_port
        pon_port = flow_entry.out_port if is_upstream else flow_entry.in_port

        self._uni = handler.uni_port(uni_port)
        self._pon = handler.pon_port(pon_port)

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set
        #
        # TODO: Probably need to store many of these in the appropriate object (UNI, PON,...)
        #
        self._ethernet_uni_entity_id = self._handler.uni_ports[0].entity_id
        self._ieee_mapper_service_profile_entity_id = self._pon.ieee_mapper_service_profile_entity_id

        # Next to are specific
        self._mac_bridge_service_profile_entity_id = handler.mac_bridge_service_profile_entity_id

    def cancel_deferred(self):
        super(AdtnInstallFlowTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start the flow installation
        """
        super(AdtnInstallFlowTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_flow_install)

    def stop(self):
        """
        Shutdown flow install task
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(AdtnInstallFlowTask, self).stop()

    def check_status_and_state(self, results, operation=''):
        """
        Check the results of an OMCI response.  An exception is thrown
        if the task was cancelled or an error was detected.

        :param results: (OmciFrame) OMCI Response frame
        :param operation: (str) what operation was being performed
        :return: True if successful, False if the entity existed (already created)
        """
        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')

        self.log.debug(operation, status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            self.strobe_watchdog()
            return True

        elif status == RC.InstanceExists:
            return False

        elif status == RC.UnknownInstance and operation == 'delete':
            return True

        raise ServiceInstallFailure('{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'
                                    .format(operation, status, error_mask, failed_mask, unsupported_mask))

    @inlineCallbacks
    def perform_flow_install(self):
        """
        Send the commands to configure the flow.

        Currently this task uses the pre-installed default TCONT and GEM Port.  This will
        change when Technology Profiles are supported.
        """
        self.log.info('perform-flow-install', vlan_vid=self._flow_entry.vlan_vid)

        if self._flow_entry.vlan_vid == 0:
            return

        def resources_available():
            # TODO: Rework for non-xpon mode
            return (len(self._handler.uni_ports) > 0 and
                    len(self._pon.tconts) and
                    len(self._pon.gem_ports))

        if self._handler.enabled and resources_available():

            omci = self._onu_device.omci_cc
            brg_id = self._mac_bridge_service_profile_entity_id
            vlan_vid = self._flow_entry.vlan_vid

            if self._install_by_delete:
                # Delete any existing flow before adding this new one

                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(brg_id, attributes=None)
                frame = msg.delete()

                try:
                    results = yield omci.send(frame)
                    self.check_status_and_state(results, operation='delete')

                    attributes = dict(
                        association_type=2,  # Assoc Type, PPTP Ethernet UNI
                        associated_me_pointer=self._ethernet_uni_entity_id  # Assoc ME, PPTP Entity Id
                    )

                    frame = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        self._mac_bridge_service_profile_entity_id + self._uni.mac_bridge_port_num,
                        attributes=attributes
                    ).create()
                    results = yield omci.send(frame)
                    self.check_status_and_state(results, 'flow-recreate-before-set')

                    # TODO: Any of the following needed as well

                    # # Delete bridge ani side vlan filter
                    # msg = VlanTaggingFilterDataFrame(self._mac_bridge_port_ani_entity_id)
                    # frame = msg.delete()
                    #
                    # results = yield omci.send(frame)
                    # self.check_status_and_state(results, 'flow-delete-vlan-tagging-filter-data')
                    #
                    # # Re-Create bridge ani side vlan filter
                    # msg = VlanTaggingFilterDataFrame(
                    #         self._mac_bridge_port_ani_entity_id,  # Entity ID
                    #         vlan_tcis=[vlan_vid],             # VLAN IDs
                    #         forward_operation=0x10
                    # )
                    # frame = msg.create()
                    #
                    # results = yield omci.send(frame)
                    # self.check_status_and_state(results, 'flow-create-vlan-tagging-filter-data')

                except Exception as e:
                    self.log.exception('flow-delete-before-install-failure', e=e)
                    self.deferred.errback(failure.Failure(e))
                    returnValue(None)

            try:
                # Now set the VLAN Tagging Operation up as we want it
                # Update uni side extended vlan filter
                # filter for untagged
                # probably for eapol
                # TODO: lots of magic
                # attributes = dict(
                #         # This table filters and tags upstream frames
                #         received_frame_vlan_tagging_operation_table=
                #         VlanTaggingOperation(
                #                 filter_outer_priority=15,     # This entry is not a double-tag rule (ignore out tag rules)
                #                 filter_outer_vid=4096,        # Do not filter on the outer VID value
                #                 filter_outer_tpid_de=0,       # Do not filter on the outer TPID field
                #
                #                 filter_inner_priority=15,     # This is a no-tag rule, ignore all other VLAN tag filter fields
                #                 filter_inner_vid=4096,        # Do not filter on the inner VID
                #                 filter_inner_tpid_de=0,       # Do not filter on inner TPID field
                #                 filter_ether_type=0,          # Do not filter on EtherType
                #
                #                 treatment_tags_to_remove=0,   # Remove 0 tags
                #
                #                 treatment_outer_priority=15,  # Do not add an outer tag
                #                 treatment_outer_vid=0,        # n/a
                #                 treatment_outer_tpid_de=0,    # n/a
                #
                #                 treatment_inner_priority=0,    # Add an inner tag and insert this value as the priority
                #                 treatment_inner_vid=vlan_vid,  # Push this tag onto the frame
                #                 treatment_inner_tpid_de=4      # set TPID
                #         )
                # )
                # msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                #         self._mac_bridge_service_profile_entity_id + self._uni.mac_bridge_port_num,  # Bridge Entity ID
                #         attributes=attributes  # See above
                # )
                # frame = msg.set()
                #
                # results = yield omci.send(frame)
                # self.check_status_and_state(results,
                #                             'flow-set-ext-vlan-tagging-op-config-data-untagged')

                # Update uni side extended vlan filter
                # filter for vlan 0
                # TODO: lots of magic

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

                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        self._mac_bridge_service_profile_entity_id +
                        self._uni.mac_bridge_port_num,  # Bridge Entity ID
                        attributes=attributes           # See above
                )
                frame = msg.set()

                results = yield omci.send(frame)
                self.check_status_and_state(results, 'set-extended-vlan-tagging-operation-configuration-data')

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

                        treatment_inner_priority=0,    # Add an inner tag and insert this value as the priority
                        treatment_inner_vid=vlan_vid,  # use this value as the VID in the inner VLAN tag
                        treatment_inner_tpid_de=4,     # set TPID
                    )
                )

                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        self._mac_bridge_service_profile_entity_id +
                        self._uni.mac_bridge_port_num,  # Bridge Entity ID
                        attributes=attributes           # See above
                )
                frame = msg.set()

                results = yield omci.send(frame)
                self.check_status_and_state(results,
                                            'flow-set-ext-vlan-tagging-op-config-data-untagged')
                self.deferred.callback('flow-install-success')

            except Exception as e:
                # TODO: Better context info for this exception output...
                self.log.exception('failed-to-install-flow', e=e)
                self.deferred.errback(failure.Failure(e))

        else:
            # TODO: Provide better error reason, what was missing...
            e = ServiceInstallFailure('Required resources are not available')
            self.deferred.errback(failure.Failure(e))
