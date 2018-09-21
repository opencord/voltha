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


class ServiceDownloadFailure(Exception):
    """
    This error is raised by default when the download fails
    """


class ServiceResourcesFailure(Exception):
    """
    This error is raised by when one or more resources required is not available
    """


class AdtnInstallFlowTask(Task):
    """
    OpenOMCI MIB Download Example - Service specific

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
    BRDCM_DEFAULT_VLAN = 4091

    name = "ADTRAN MIB Install Flow Task"

    def __init__(self, omci_agent, handler, match, action, is_upstream):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param handler: (AdtranOnuHandler) ONU Handler
        :param match: (dict) Flow match rules
        :param action: (dict) Flow action rules
        :param is_upstream: (bool) True if upstream flow is being installed
        """
        super(AdtnInstallFlowTask, self).__init__(AdtnInstallFlowTask.name,
                                                  omci_agent,
                                                  handler.device_id,
                                                  priority=AdtnInstallFlowTask.task_priority)
        self._handler = handler
        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None

        self._match = match
        self._action = action

        # TODO: Cleanup below that is not needed
        self._vlan_tcis_1 = 0x900
        self._input_tpid = AdtnInstallFlowTask.default_tpid
        self._output_tpid = AdtnInstallFlowTask.default_tpid

        if self._handler.xpon_support:
            device = self._handler.adapter_agent.get_device(self.device_id)
            self._cvid = device.vlan
        else:
            # TODO: TCIS below is just a test, may need 0x900...as in the xPON mode
            self._vlan_tcis_1 = AdtnInstallFlowTask.BRDCM_DEFAULT_VLAN
            self._cvid = AdtnInstallFlowTask.BRDCM_DEFAULT_VLAN

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set
        #
        # TODO: Probably need to store many of these in the appropriate object (UNI, PON,...)
        #
        self._ieee_mapper_service_profile_entity_id = 0x100
        self._gal_enet_profile_entity_id = 0x100

        # Next to are specific
        self._ethernet_uni_entity_id = self._handler.uni_ports[0].entity_id
        self._vlan_config_entity_id = self._vlan_tcis_1

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

        raise ServiceDownloadFailure('{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'
                                     .format(operation, status, error_mask, failed_mask, unsupported_mask))

    @inlineCallbacks
    def perform_flow_install(self):
        """
        Send the commands to configure the flow
        """
        self.log.info('perform-service-download')

        if self._handler.xpon_support:
            self.deferred.callback('flow-install-nop')  # xPON mode does not need this

        def resources_available():
            # TODO: Rework for non-xpon mode
            return (len(self._handler.uni_ports) > 0 and
                    len(self._handler.pon_port.tconts) and
                    len(self._handler.pon_port.gem_ports) and
                    self._action.get('set_vlan_vid') is not None)

        if self._handler.enabled and resources_available():
            omci = self._onu_device.omci_cc
            try:
                # TODO: make this a member of the onu gem port or the uni port
                _mac_bridge_service_profile_entity_id = 0x201
                _mac_bridge_port_ani_entity_id = 0x2102  # TODO: can we just use the entity id from the anis list?
                _set_vlan_vid = self._action['set_vlan_vid']

                # Delete bridge ani side vlan filter
                msg = VlanTaggingFilterDataFrame(_mac_bridge_port_ani_entity_id)
                frame = msg.delete()

                results = yield omci.send(frame)
                self.check_status_and_state(results, 'flow-delete-vlan-tagging-filter-data')

                # Re-Create bridge ani side vlan filter
                msg = VlanTaggingFilterDataFrame(
                        _mac_bridge_port_ani_entity_id,  # Entity ID
                        vlan_tcis=[_set_vlan_vid],  # VLAN IDs
                        forward_operation=0x10
                )
                frame = msg.create()

                results = yield omci.send(frame)
                self.check_status_and_state(results, 'flow-create-vlan-tagging-filter-data')

                # Update uni side extended vlan filter
                # filter for untagged
                # probably for eapol
                # TODO: magic 0x1000 / 4096?
                # TODO: lots of magic
                attributes = dict(
                        received_frame_vlan_tagging_operation_table=
                        VlanTaggingOperation(
                                filter_outer_priority=15,
                                filter_outer_vid=4096,
                                filter_outer_tpid_de=0,

                                filter_inner_priority=15,
                                filter_inner_vid=4096,
                                filter_inner_tpid_de=0,
                                filter_ether_type=0,

                                treatment_tags_to_remove=0,
                                treatment_outer_priority=15,
                                treatment_outer_vid=0,
                                treatment_outer_tpid_de=0,

                                treatment_inner_priority=0,
                                treatment_inner_vid=_set_vlan_vid,
                                treatment_inner_tpid_de=4
                        )
                )
                # TODO: Move this to a task
                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        _mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                        attributes=attributes  # See above
                )
                frame = msg.set()

                results = yield omci.send(frame)
                self.check_status_and_state(results,
                                            'flow-set-ext-vlan-tagging-op-config-data-untagged')

                # Update uni side extended vlan filter
                # filter for vlan 0
                # TODO: lots of magic
                attributes = dict(
                        received_frame_vlan_tagging_operation_table=
                        VlanTaggingOperation(
                                filter_outer_priority=15,
                                # This entry is not a double-tag rule
                                filter_outer_vid=4096,  # Do not filter on the outer VID value
                                filter_outer_tpid_de=0,
                                # Do not filter on the outer TPID field

                                filter_inner_priority=8,  # Filter on inner vlan
                                filter_inner_vid=0x0,  # Look for vlan 0
                                filter_inner_tpid_de=0,  # Do not filter on inner TPID field
                                filter_ether_type=0,  # Do not filter on EtherType

                                treatment_tags_to_remove=1,
                                treatment_outer_priority=15,
                                treatment_outer_vid=0,
                                treatment_outer_tpid_de=0,

                                treatment_inner_priority=8,
                                # Add an inner tag and insert this value as the priority
                                treatment_inner_vid=_set_vlan_vid,
                                # use this value as the VID in the inner VLAN tag
                                treatment_inner_tpid_de=4,  # set TPID
                        )
                )
                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        _mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                        attributes=attributes  # See above
                )
                frame = msg.set()

                results = yield omci.send(frame)
                self.check_status_and_state(results,
                                            'flow-set-ext-vlan-tagging-op-config-data-zero-tagged')
                self.deferred.callback('flow-install-success')

            except Exception as e:
                # TODO: Better context info for this exception output...
                self.log.exception('failed-to-install-flow', e=e)
                self.deferred.errback(failure.Failure(e))

        else:
            # TODO: Provide better error reason, what was missing...
            e = ServiceResourcesFailure('Required resources are not available')
            self.deferred.errback(failure.Failure(e))

    def check_status_and_state(self, result, operation=''):
        from voltha.extensions.omci.omci_defs import ReasonCodes
        self.log.debug('function-entry')
        omci_msg = result.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')

        self.log.debug("OMCI Result:", operation, omci_msg=omci_msg, status=status,
                       error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == ReasonCodes.Success:
            return True

        elif status == ReasonCodes.InstanceExists:
            return False
