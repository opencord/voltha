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
from voltha.extensions.omci.tasks.task import Task
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, failure, returnValue
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_me import *
from voltha.adapters.brcm_openomci_onu.uni_port import UniType
from voltha.adapters.brcm_openomci_onu.pon_port import BRDCM_DEFAULT_VLAN, DEFAULT_TPID

RC = ReasonCodes
OP = EntityOperations
RESERVED_VLAN = 4095


class BrcmVlanFilterException(Exception):
    pass


class BrcmVlanFilterTask(Task):
    """
    Apply Vlan Tagging Filter Data and Extended VLAN Tagging Operation Configuration on an ANI and UNI
    """
    task_priority = 200
    name = "Broadcom VLAN Filter Task"

    def __init__(self, omci_agent, device_id, uni_port, set_vlan_id, add_tag=True,
                 priority=task_priority):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param uni_port: (UniPort) UNI port
        :param set_vlan_id: (int) VLAN to filter for and set
        :param add_tag: (bool) Flag to identify VLAN Tagging or Untagging
        :param priority: (int) OpenOMCI Task priority (0..255) 255 is the highest
        """

        self.log = structlog.get_logger(device_id=device_id, uni_port=uni_port.port_number)

        super(BrcmVlanFilterTask, self).__init__(BrcmVlanFilterTask.name,
                                                 omci_agent,
                                                 device_id,
                                                 priority=priority,
                                                 exclusive=True)
        self._device = omci_agent.get_device(device_id)
        self._uni_port = uni_port
        self._set_vlan_id = set_vlan_id
        self._results = None
        self._local_deferred = None
        self._config = self._device.configuration
        self._add_tag = add_tag

        # Port numbers
        self._input_tpid = DEFAULT_TPID
        self._output_tpid = DEFAULT_TPID
        self._cvid = BRDCM_DEFAULT_VLAN

    def cancel_deferred(self):
        super(BrcmVlanFilterTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start Vlan Tagging Task
        """
        super(BrcmVlanFilterTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_vlan_tagging, add_tag=self._add_tag)

    @inlineCallbacks
    def perform_vlan_tagging(self, add_tag=True):
        """
        Perform the vlan tagging
        """
        if add_tag:
            self.log.info('setting-vlan-tagging')
        else:
            self.log.info('removing-vlan-tagging')

        try:
            # TODO: parameterize these from the handler, or objects in the handler
            # TODO: make this a member of the onu gem port or the uni port
            _mac_bridge_service_profile_entity_id = 0x201
            _mac_bridge_port_ani_entity_id = 0x2102  # TODO: can we just use the entity id from the anis list?

            vlan_tagging_entity_id = _mac_bridge_port_ani_entity_id + self._uni_port.mac_bridge_port_num
            extended_vlan_tagging_entity_id = _mac_bridge_service_profile_entity_id + \
                self._uni_port.mac_bridge_port_num

            # Delete bridge ani side vlan filter
            yield self._send_msg(VlanTaggingFilterDataFrame(vlan_tagging_entity_id), 'delete',
                                 'flow-delete-vlan-tagging-filter-data')

            forward_operation = 0x10  # VID investigation
            # When the PUSH VLAN is RESERVED_VLAN (4095), let ONU be transparent
            if self._set_vlan_id == RESERVED_VLAN:
                forward_operation = 0x00  # no investigation, ONU transparent

            if add_tag:
                # Re-Create bridge ani side vlan filter
                msg = VlanTaggingFilterDataFrame(
                    vlan_tagging_entity_id,  # Entity ID
                    vlan_tcis=[self._set_vlan_id],  # VLAN IDs
                    forward_operation=forward_operation
                )
                yield self._send_msg(msg, 'create', 'flow-create-vlan-tagging-filter-data')
            else:
                # Delete bridge ani side vlan filter
                msg = VlanTaggingFilterDataFrame(
                    vlan_tagging_entity_id  # Entity ID
                )
                yield self._send_msg(msg, 'delete', 'flow-delete-vlan-tagging-filter-data')

            # Delete uni side extended vlan filter
            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                extended_vlan_tagging_entity_id  # Bridge Entity ID
            )
            yield self._send_msg(msg, 'delete', 'flow-delete-ext-vlan-tagging-op-config-data')

            # Create uni side extended vlan filter
            if add_tag:
                # When flow is removed and immediately re-added tech_profile specific task is not re-played, hence
                # Extended VLAN Tagging Operation configuration which is part of tech_profile specific task is not
                # getting created. To create it, we do Extended VLAN Tagging Operation configuration here.
                # TODO: do this for all uni/ports...
                # TODO: magic.  static variable for assoc_type

                omci_cc = self._device.omci_cc
                # default to PPTP
                if self._uni_port.type is UniType.VEIP:
                    association_type = 10
                elif self._uni_port.type is UniType.PPTP:
                    association_type = 2
                else:
                    association_type = 2

                attributes = dict(
                    association_type=association_type,  # Assoc Type, PPTP/VEIP Ethernet UNI
                    associated_me_pointer=self._uni_port.entity_id,  # Assoc ME, PPTP/VEIP Entity Id

                    # See VOL-1311 - Need to set table during create to avoid exception
                    # trying to read back table during post-create-read-missing-attributes
                    # But, because this is a R/W attribute. Some ONU may not accept the
                    # value during create. It is repeated again in a set below.
                    input_tpid=self._input_tpid,  # input TPID
                    output_tpid=self._output_tpid,  # output TPID
                )

                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                    extended_vlan_tagging_entity_id,  # Bridge Entity ID
                    attributes=attributes
                )
                yield self._send_msg(msg, 'create', 'create-extended-vlan-tagging-operation-configuration-data')

                attributes = dict(
                    # Specifies the TPIDs in use and that operations in the downstream direction are
                    # inverse to the operations in the upstream direction
                    input_tpid=self._input_tpid,  # input TPID
                    output_tpid=self._output_tpid,  # output TPID
                    downstream_mode=0,  # inverse of upstream
                )

                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                    extended_vlan_tagging_entity_id,  # Bridge Entity ID
                    attributes=attributes
                )
                yield self._send_msg(msg, 'set', 'set-extended-vlan-tagging-operation-configuration-data')

                # parameters: Entity Id ( 0x900), Filter Inner Vlan Id(0x1000-4096,do not filter on Inner vid,
                #             Treatment Inner Vlan Id : 2

                # Update uni side extended vlan filter
                # filter for untagged
                # probably for eapol
                # TODO: lots of magic
                # TODO: magic 0x1000 / 4096?
                attributes = self._generate_attributes(
                    filter_outer_priority=15,  # This entry is not a double-tag rule
                    filter_outer_vid=4096,  # Do not filter on the outer VID value
                    filter_outer_tpid_de=0,  # Do not filter on the outer TPID field

                    filter_inner_priority=15, filter_inner_vid=4096, filter_inner_tpid_de=0, filter_ether_type=0,
                    treatment_tags_to_remove=0, treatment_outer_priority=15, treatment_outer_vid=0,
                    treatment_outer_tpid_de=0, treatment_inner_priority=0, treatment_inner_vid=self._cvid,
                    treatment_inner_tpid_de=4)

                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                    extended_vlan_tagging_entity_id,  # Bridge Entity ID
                    attributes=attributes
                )
                yield self._send_msg(msg, 'set', 'set-extended-vlan-tagging-operation-configuration-data-table')

                if self._set_vlan_id == RESERVED_VLAN:
                    # Transparently send any single tagged packet.
                    # Any other specific rules will take priority over this
                    attributes = self._generate_attributes(
                        filter_outer_priority=15, filter_outer_vid=4096, filter_outer_tpid_de=0,
                        filter_inner_priority=14, filter_inner_vid=4096, filter_inner_tpid_de=0, filter_ether_type=0,
                        treatment_tags_to_remove=0, treatment_outer_priority=15, treatment_outer_vid=0,
                        treatment_outer_tpid_de=0, treatment_inner_priority=15, treatment_inner_vid=0,
                        treatment_inner_tpid_de=4)

                    msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        extended_vlan_tagging_entity_id,  # Bridge Entity ID
                        attributes=attributes  # See above
                    )
                    yield self._send_msg(msg, 'set',
                                         'flow-set-ext-vlan-tagging-op-config-data-single-tag-fwd-transparent')
                else:
                    # Update uni side extended vlan filter
                    # filter for untagged
                    # probably for eapol
                    # TODO: Create constants for the operation values.  See omci spec
                    attributes = self._generate_attributes(
                        filter_outer_priority=15, filter_outer_vid=4096, filter_outer_tpid_de=0,
                        filter_inner_priority=15, filter_inner_vid=4096, filter_inner_tpid_de=0, filter_ether_type=0,
                        treatment_tags_to_remove=0, treatment_outer_priority=15, treatment_outer_vid=0,
                        treatment_outer_tpid_de=0, treatment_inner_priority=0, treatment_inner_vid=self._set_vlan_id,
                        treatment_inner_tpid_de=4)

                    msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        extended_vlan_tagging_entity_id,  # Bridge Entity ID
                        attributes=attributes  # See above
                    )
                    yield self._send_msg(msg, 'set', 'flow-set-ext-vlan-tagging-op-config-data-untagged')

                    # Update uni side extended vlan filter
                    # filter for vlan 0
                    # TODO: Create constants for the operation values.  See omci spec
                    attributes = self._generate_attributes(
                        filter_outer_priority=15,  # This entry is not a double-tag rule
                        filter_outer_vid=4096,  # Do not filter on the outer VID value
                        filter_outer_tpid_de=0,  # Do not filter on the outer TPID field

                        filter_inner_priority=8,  # Filter on inner vlan
                        filter_inner_vid=0x0,  # Look for vlan 0
                        filter_inner_tpid_de=0,  # Do not filter on inner TPID field
                        filter_ether_type=0,  # Do not filter on EtherType

                        treatment_tags_to_remove=1, treatment_outer_priority=15, treatment_outer_vid=0,
                        treatment_outer_tpid_de=0,

                        treatment_inner_priority=8,  # Add an inner tag and insert this value as the priority
                        treatment_inner_vid=self._set_vlan_id,  # use this value as the VID in the inner VLAN tag
                        treatment_inner_tpid_de=4)  # set TPID

                    msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                        extended_vlan_tagging_entity_id,  # Bridge Entity ID
                        attributes=attributes  # See above
                    )
                    yield self._send_msg(msg, 'set', 'flow-set-ext-vlan-tagging-op-config-data-zero-tagged')
            else:
                msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                    extended_vlan_tagging_entity_id  # Bridge Entity ID
                )
                yield self._send_msg(msg, 'delete', 'flow-delete-ext-vlan-tagging-op-config-data')

            self.deferred.callback(self)
        except Exception as e:
            self.log.exception('setting-vlan-tagging', e=e)
            self.deferred.errback(failure.Failure(e))

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

        self.log.debug("OMCI Result: %s", operation, omci_msg=omci_msg,
                       status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            self.strobe_watchdog()
            return True

        elif status == RC.InstanceExists:
            return False

    @inlineCallbacks
    def _send_msg(self, msg, operation, vlan_tagging_operation_msg):
        """
        Send frame to ONU.

        :param msg: (VlanTaggingFilterDataFrame/ExtendedVlanTaggingOperationConfigurationDataFrame) message used
        to generate OMCI frame
        :param operation: (str) type of CUD(Create/Update/Delete) operation
        :param vlan_tagging_operation_msg: (str) what operation was being performed
        """
        if operation == 'create':
            frame = msg.create()
        elif operation == 'set':
            frame = msg.set()
        else:
            frame = msg.delete()
        self.log.debug('openomci-msg', omci_msg=msg)
        self.strobe_watchdog()
        results = yield self._device.omci_cc.send(frame)
        self.check_status_and_state(results, vlan_tagging_operation_msg)

    def _generate_attributes(self, **kwargs):
        """
        Generate ExtendedVlanTaggingOperation attributes

        :return: (dict) ExtendedVlanTaggingOperation attributes dictinary
        """
        return dict(
            received_frame_vlan_tagging_operation_table=
            VlanTaggingOperation(
                filter_outer_priority=kwargs['filter_outer_priority'],
                filter_outer_vid=kwargs['filter_outer_vid'],
                filter_outer_tpid_de=kwargs['filter_outer_tpid_de'],

                filter_inner_priority=kwargs['filter_inner_priority'],
                filter_inner_vid=kwargs['filter_inner_vid'],
                filter_inner_tpid_de=kwargs['filter_inner_tpid_de'],
                filter_ether_type=kwargs['filter_ether_type'],

                treatment_tags_to_remove=kwargs['treatment_tags_to_remove'],
                treatment_outer_priority=kwargs['treatment_outer_priority'],
                treatment_outer_vid=kwargs['treatment_outer_vid'],
                treatment_outer_tpid_de=kwargs['treatment_outer_tpid_de'],

                treatment_inner_priority=kwargs['treatment_inner_priority'],
                treatment_inner_vid=kwargs['treatment_inner_vid'],
                treatment_inner_tpid_de=kwargs['treatment_inner_tpid_de'],
            )
        )
