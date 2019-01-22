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

RC = ReasonCodes
OP = EntityOperations


class BrcmVlanFilterException(Exception):
    pass


class BrcmVlanFilterTask(Task):
    """
    Apply Vlan Tagging Filter Data and Extended VLAN Tagging Operation Configuration on an ANI and UNI
    """
    task_priority = 200
    name = "Broadcom VLAN Filter Task"

    def __init__(self, omci_agent, device_id, uni_port, set_vlan_id, priority=task_priority):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param set_vlan_id: (int) VLAN to filter for and set
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
        self._local_deferred = reactor.callLater(0, self.perform_vlan_tagging)

    @inlineCallbacks
    def perform_vlan_tagging(self):
        """
        Perform the vlan tagging
        """
        self.log.info('setting-vlan-tagging')

        try:
            # TODO: parameterize these from the handler, or objects in the handler
            # TODO: make this a member of the onu gem port or the uni port
            _mac_bridge_service_profile_entity_id = 0x201
            _mac_bridge_port_ani_entity_id = 0x2102  # TODO: can we just use the entity id from the anis list?
            # Delete bridge ani side vlan filter
            msg = VlanTaggingFilterDataFrame(_mac_bridge_port_ani_entity_id + self._uni_port.mac_bridge_port_num)
            frame = msg.delete()
            self.log.debug('openomci-msg', omci_msg=msg)
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(frame)
            self.check_status_and_state(results, 'flow-delete-vlan-tagging-filter-data')

            # Re-Create bridge ani side vlan filter
            msg = VlanTaggingFilterDataFrame(
                _mac_bridge_port_ani_entity_id + self._uni_port.mac_bridge_port_num,  # Entity ID
                vlan_tcis=[self._set_vlan_id],  # VLAN IDs
                forward_operation=0x10
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(frame)
            self.check_status_and_state(results, 'flow-create-vlan-tagging-filter-data')

            # Re-Create bridge ani side vlan filter

            # Update uni side extended vlan filter
            # filter for untagged
            # probably for eapol
            # TODO: Create constants for the operation values.  See omci spec
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
                    treatment_inner_vid=self._set_vlan_id,
                    treatment_inner_tpid_de=4
                )
            )
            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                _mac_bridge_service_profile_entity_id + self._uni_port.mac_bridge_port_num,  # Bridge Entity ID
                attributes=attributes  # See above
            )
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(frame)
            self.check_status_and_state(results,
                                        'flow-set-ext-vlan-tagging-op-config-data-untagged')

            # Update uni side extended vlan filter
            # filter for vlan 0
            # TODO: Create constants for the operation values.  See omci spec
            attributes = dict(
                received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,  # This entry is not a double-tag rule
                    filter_outer_vid=4096,  # Do not filter on the outer VID value
                    filter_outer_tpid_de=0,  # Do not filter on the outer TPID field

                    filter_inner_priority=8,  # Filter on inner vlan
                    filter_inner_vid=0x0,  # Look for vlan 0
                    filter_inner_tpid_de=0,  # Do not filter on inner TPID field
                    filter_ether_type=0,  # Do not filter on EtherType

                    treatment_tags_to_remove=1,
                    treatment_outer_priority=15,
                    treatment_outer_vid=0,
                    treatment_outer_tpid_de=0,

                    treatment_inner_priority=8,  # Add an inner tag and insert this value as the priority
                    treatment_inner_vid=self._set_vlan_id,  # use this value as the VID in the inner VLAN tag
                    treatment_inner_tpid_de=4,  # set TPID
                )
            )
            msg = ExtendedVlanTaggingOperationConfigurationDataFrame(
                _mac_bridge_service_profile_entity_id + self._uni_port.mac_bridge_port_num,  # Bridge Entity ID
                attributes=attributes  # See above
            )
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(frame)
            self.check_status_and_state(results,
                                        'flow-set-ext-vlan-tagging-op-config-data-zero-tagged')

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
