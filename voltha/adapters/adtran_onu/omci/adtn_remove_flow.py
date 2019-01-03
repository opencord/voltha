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
from twisted.internet.defer import inlineCallbacks, failure
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.tasks.task import Task
from voltha.extensions.omci.omci_defs import *
from voltha.adapters.adtran_onu.flow.flow_entry import FlowEntry
from voltha.adapters.adtran_onu.omci.omci import OMCI

OP = EntityOperations
RC = ReasonCodes


class ServiceRemovalFailure(Exception):
    """
    This error is raised by default when the flow-install fails
    """


class AdtnRemoveFlowTask(Task):
    """
    OpenOMCI MIB Flow Remove Task

    Currently, the only service tech profiles expected by v2.0 will be for AT&T
    residential data service and DT residential data service.
    """
    task_priority = Task.DEFAULT_PRIORITY + 10
    default_tpid = 0x8100                           # TODO: Locate to a better location

    name = "ADTRAN MIB Install Flow Task"

    def __init__(self, omci_agent, handler, flow_entry):
        """
        Class initialization

        :param omci_agent: (OpenOMCIAgent) OMCI Adapter agent
        :param handler: (AdtranOnuHandler) ONU Handler
        :param flow_entry: (FlowEntry) Flow to install
        """
        super(AdtnRemoveFlowTask, self).__init__(AdtnRemoveFlowTask.name,
                                                 omci_agent,
                                                 handler.device_id,
                                                 priority=AdtnRemoveFlowTask.task_priority,
                                                 exclusive=False)
        self._handler = handler
        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None
        self._flow_entry = flow_entry

        # TODO: Cleanup below that is not needed
        # self._vlan_tcis_1 = 0x900
        # self._input_tpid = AdtnRemoveFlowTask.default_tpid
        # self._output_tpid = AdtnRemoveFlowTask.default_tpid

        is_upstream = flow_entry.flow_direction in FlowEntry.upstream_flow_types
        uni_port = flow_entry.in_port if is_upstream else flow_entry.out_port
        pon_port = flow_entry.out_port if is_upstream else flow_entry.in_port

        self._uni = handler.uni_port(uni_port)
        self._pon = handler.pon_port(pon_port)

        self._vid = OMCI.DEFAULT_UNTAGGED_VLAN

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set
        #
        # TODO: Probably need to store many of these in the appropriate object (UNI, PON,...)
        #
        self._ieee_mapper_service_profile_entity_id = self._pon.ieee_mapper_service_profile_entity_id
        self._mac_bridge_port_ani_entity_id = self._pon.mac_bridge_port_ani_entity_id

        # Next to are specific
        self._mac_bridge_service_profile_entity_id = handler.mac_bridge_service_profile_entity_id

    def cancel_deferred(self):
        super(AdtnRemoveFlowTask, self).cancel_deferred()

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
        super(AdtnRemoveFlowTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_flow_removal)

    def stop(self):
        """
        Shutdown flow install task
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(AdtnRemoveFlowTask, self).stop()

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

        raise ServiceRemovalFailure(
            '{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'
            .format(operation, status, error_mask, failed_mask, unsupported_mask))

    @inlineCallbacks
    def perform_flow_removal(self):
        """
        Send the commands to configure the flow
        """
        self.log.info('perform-flow-removal')

        # TODO: This has not been fully implemented

        def resources_available():
            return (len(self._handler.uni_ports) > 0 and
                    len(self._pon.tconts) and
                    len(self._pon.gem_ports))

        if self._handler.enabled and resources_available():
            omci = self._onu_device.omci_cc
            try:
                # TODO: make this a member of the onu gem port or the uni port
                set_vlan_vid = self._flow_entry.set_vlan_vid

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
                #         vlan_tcis=[self._vlan_tcis_1],  # VLAN IDs
                #         forward_operation=0x10
                # )
                # frame = msg.create()
                # results = yield omci.send(frame)
                # self.check_status_and_state(results, 'flow-create-vlan-tagging-filter-data')

                # Update uni side extended vlan filter
                attributes = dict(
                        received_frame_vlan_tagging_operation_table=
                        VlanTaggingOperation(
                                filter_outer_priority=15,    # This entry is not a double-tag rule
                                filter_outer_vid=4096,       # Do not filter on the outer VID value
                                filter_outer_tpid_de=0,      # Do not filter on the outer TPID field

                                filter_inner_priority=15,    # This is a no-tag rule, ignore all other VLAN tag filter fields
                                filter_inner_vid=0x1000,     # Do not filter on the inner VID
                                filter_inner_tpid_de=0,      # Do not filter on inner TPID field

                                filter_ether_type=0,         # Do not filter on EtherType
                                treatment_tags_to_remove=0,  # Remove 0 tags

                                treatment_outer_priority=15,  # Do not add an outer tag
                                treatment_outer_vid=0,        # n/a
                                treatment_outer_tpid_de=0,    # n/a

                                treatment_inner_priority=0,     # Add an inner tag and insert this value as the priority
                                treatment_inner_vid=self._vid,  # use this value as the VID in the inner VLAN tag
                                treatment_inner_tpid_de=4,      # set TPID
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

                self.deferred.callback('flow-remove-success')

            except Exception as e:
                # TODO: Better context info for this exception output...
                self.log.exception('failed-to-remove-flow', e=e)
                self.deferred.errback(failure.Failure(e))

        else:
            # TODO: Provide better error reason, what was missing...
            e = ServiceRemovalFailure('Required resources are not available')
            self.deferred.errback(failure.Failure(e))
