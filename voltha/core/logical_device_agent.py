#
# Copyright 2017 the original author or authors.
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

"""
Model that captures the current state of a logical device
"""
from collections import OrderedDict

import structlog

from common.event_bus import EventBusClient
from common.frameio.frameio import hexify
from voltha.registry import registry
from voltha.core.config.config_proxy import CallbackType
from voltha.core.device_graph import DeviceGraph
from voltha.core.flow_decomposer import FlowDecomposer, \
    flow_stats_entry_from_flow_mod_message, group_entry_from_group_mod, \
    mk_flow_stat, in_port, vlan_vid, vlan_pcp, pop_vlan, output, set_field, \
    push_vlan, meter_entry_from_meter_mod, get_meter_id_from_flow, RouteHop
from voltha.protos import third_party
from voltha.protos import openflow_13_pb2 as ofp
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import Flows, Meters, FlowGroups, ofp_meter_config

_ = third_party

def mac_str_to_tuple(mac):
    return tuple(int(d, 16) for d in mac.split(':'))


class LogicalDeviceAgent(FlowDecomposer, DeviceGraph):

    def __init__(self, core, logical_device):
        try:
            self.core = core
            self.local_handler = core.get_local_handler()
            self.logical_device_id = logical_device.id

            self.root_proxy = core.get_proxy('/')
            self.flows_proxy = core.get_proxy(
                '/logical_devices/{}/flows'.format(logical_device.id))
            self.meters_proxy = core.get_proxy(
                '/logical_devices/{}/meters'.format(logical_device.id))
            self.groups_proxy = core.get_proxy(
                '/logical_devices/{}/flow_groups'.format(logical_device.id))
            self.self_proxy = core.get_proxy(
                '/logical_devices/{}'.format(logical_device.id))

            self.flows_proxy.register_callback(
                CallbackType.PRE_UPDATE, self._pre_process_flows)
            self.flows_proxy.register_callback(
                CallbackType.POST_UPDATE, self._flow_table_updated)
            self.groups_proxy.register_callback(
                CallbackType.POST_UPDATE, self._group_table_updated)
            self.self_proxy.register_callback(
                CallbackType.POST_ADD, self._port_added)
            self.self_proxy.register_callback(
                CallbackType.POST_REMOVE, self._port_removed)

            self.port_proxy = {}
            self.port_status_has_changed = {}

            self.event_bus = EventBusClient()
            self.packet_in_subscription = self.event_bus.subscribe(
                topic='packet-in:{}'.format(logical_device.id),
                callback=self.handle_packet_in_event)

            self.log = structlog.get_logger(logical_device_id=logical_device.id)

            self._routes = None
            self._no_flow_changes_required = False
            self._flows_ids_to_add = []
            self._flows_ids_to_remove = []
            self._flows_to_remove = []
            self._flow_with_unknown_meter = dict()

            self.accepts_direct_logical_flows = False
            self.device_id = self.self_proxy.get('/').root_device_id
            device_adapter_type = self.root_proxy.get('/devices/{}'.format(
                self.device_id)).adapter
            device_type = self.root_proxy.get('/device_types/{}'.format(
                device_adapter_type))

            if device_type is not None:
                self.accepts_direct_logical_flows = \
                    device_type.accepts_direct_logical_flows_update

            if self.accepts_direct_logical_flows:

                self.device_adapter_agent = registry(
                    'adapter_loader').get_agent(device_adapter_type).adapter

                self.log.debug('this device accepts direct logical flows',
                               device_adapter_type=device_adapter_type)



        except Exception, e:
            self.log.exception('init-error', e=e)

    def start(self, reconcile=False):
        self.log.debug('starting')
        if reconcile:
            # Register the callbacks for the ports
            ports = self.self_proxy.get('/ports')
            for port in ports:
                self._reconcile_port(port)
            self.log.debug('ports-reconciled', ports=ports)
        self.log.debug('started')
        return self

    def stop(self):
        self.log.debug('stopping')
        try:
            self.flows_proxy.unregister_callback(
                CallbackType.POST_UPDATE, self._flow_table_updated)
            self.groups_proxy.unregister_callback(
                CallbackType.POST_UPDATE, self._group_table_updated)
            self.self_proxy.unregister_callback(
                CallbackType.POST_ADD, self._port_added)
            self.self_proxy.unregister_callback(
                CallbackType.POST_REMOVE, self._port_removed)

            # Remove subscription to the event bus
            self.event_bus.unsubscribe(self.packet_in_subscription)
        except Exception, e:
            self.log.info('stop-exception', e=e)

        self.log.debug('stopped')

    def announce_flows_deleted(self, flows, reason=ofp.OFPRR_DELETE):
        for f in flows:
            self.announce_flow_deleted(f, reason)

    def announce_flow_deleted(self, flow, reason=ofp.OFPRR_DELETE):
        if flow.flags & ofp.OFPFF_SEND_FLOW_REM:
            self.local_handler.send_flow_removed_event(
                device_id=self.logical_device_id,
                flow_removed=ofp.ofp_flow_removed(
                    cookie=flow.cookie,
                    priority=flow.priority,
                    reason=reason,
                    table_id=flow.table_id,
                    match=flow.match
                )
            )

    def signal_flow_mod_error(self, code, flow_mod):
        pass  # TODO

    def signal_flow_removal(self, code, flow):
        pass  # TODO

    def signal_group_mod_error(self, code, group_mod):
        pass  # TODO

    def update_flow_table(self, flow_mod):

        command = flow_mod.command

        if command == ofp.OFPFC_ADD:
            self.flow_add(flow_mod)

        elif command == ofp.OFPFC_DELETE:
            self.flow_delete(flow_mod)

        elif command == ofp.OFPFC_DELETE_STRICT:
            self.flow_delete_strict(flow_mod)

        elif command == ofp.OFPFC_MODIFY:
            self.flow_modify(flow_mod)

        elif command == ofp.OFPFC_MODIFY_STRICT:
            self.flow_modify_strict(flow_mod)

        else:
            self.log.warn('unhandled-flow-mod', command=command, flow_mod=flow_mod)

    def update_meter_table(self, meter_mod):
        command = meter_mod.command

        if command == ofp.OFPMC_ADD:
            self.meter_add(meter_mod)

        elif command == ofp.OFPMC_MODIFY:
            self.meter_modify(meter_mod)

        elif command == ofp.OFPMC_DELETE:
            self.meter_delete(meter_mod)
        else:
            self.log.warn('unhandled-meter-mod', command=command, flow_mod=meter_mod)

    def update_group_table(self, group_mod):

        command = group_mod.command

        if command == ofp.OFPGC_DELETE:
            self.group_delete(group_mod)

        elif command == ofp.OFPGC_ADD:
            self.group_add(group_mod)

        elif command == ofp.OFPGC_MODIFY:
            self.group_modify(group_mod)

        else:
            self.log.warn('unhandled-group-mod',
                          command=command, group_mod=group_mod)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~ LOW LEVEL METER HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~

    def meter_add(self, meter_mod):
        assert isinstance(meter_mod, ofp.ofp_meter_mod)
        # read from model
        meters = OrderedDict((m.config.meter_id, m)
                             for m in self.meters_proxy.get('/').items)
        changed = False

        if meter_mod.meter_id in meters:
            self.signal_meter_mod_error(ofp.OFPMMFC_METER_EXISTS, meter_mod)
        else:
            meter_entry = meter_entry_from_meter_mod(meter_mod)
            meter_entry.stats.flow_count = self._flow_with_unknown_meter.get(meter_mod.meter_id, 0)
            self._flow_with_unknown_meter.pop(meter_mod.meter_id, None)
            meters[meter_mod.meter_id] = meter_entry
            changed = True

        if changed:
            self.meters_proxy.update('/', Meters(items=meters.values()))

    def meter_modify(self, meter_mod):
        assert isinstance(meter_mod, ofp.ofp_meter_mod)

        meters = OrderedDict((m.config.meter_id, m)
                             for m in self.meters_proxy.get('/').items)
        meter_id = meter_mod.meter_id
        changed = False

        if meter_id not in meters:
            self.signal_meter_mod_error(ofp.OFPMMFC_UNKNOWN_METER, meter_mod)
        else:
            # replace existing meter entry with new meter definition
            new_meter_entry = meter_entry_from_meter_mod(meter_mod)
            new_meter_entry.stats.flow_count = meters[meter_id].stats.flow_count
            meters[meter_id] = new_meter_entry
            changed = True

        if changed:
            self.meters_proxy.update('/', Meters(items=meters.values()))
            self.log.debug('meter-updated', meter_id=meter_id)

    def meter_delete(self, meter_mod):
        assert isinstance(meter_mod, ofp.ofp_meter_mod)

        meters = OrderedDict((m.config.meter_id, m)
                             for m in self.meters_proxy.get('/').items)
        meters_changed = False
        flows_changed = False

        meter_id = meter_mod.meter_id
        if meter_id not in meters:
            self.signal_meter_mod_error(ofp.OFPMMFC_UNKNOWN_METER, meter_mod)

        else:
            flows = list(self.flows_proxy.get('/').items)
            flows_changed, flows = self.flows_delete_by_meter_id(
                flows, meter_id)
            del meters[meter_id]
            meters_changed = True
            self.log.debug('meter-deleted', meter_id=meter_id)

        if meters_changed:
            self.meters_proxy.update('/', Meters(items=meters.values()))
        if flows_changed:
            self.flows_proxy.update('/', Meters(items=flows))


    @staticmethod
    def check_meter_id_overlapping(meters, meter_mod):
        for meter in meters:
            if meter.meter_id == meter_mod.meter_id:
                return meter
        return False

    def signal_meter_mod_error(self, error_code, meter_mod):
        pass  # TODO




    # ~~~~~~~~~~~~~~~~~~~~~~~~~ LOW LEVEL FLOW HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~

    def flow_add(self, mod):
        assert isinstance(mod, ofp.ofp_flow_mod)
        assert mod.cookie_mask == 0

        # read from model
        flows = list(self.flows_proxy.get('/').items)
        flow = flow_stats_entry_from_flow_mod_message(mod)

        changed = updated = False
        check_overlap = mod.flags & ofp.OFPFF_CHECK_OVERLAP
        if check_overlap:
            if self.find_overlapping_flows(flows, mod, True):
                self.signal_flow_mod_error(
                    ofp.OFPFMFC_OVERLAP, mod)
            else:
                # free to add as new flow
                flows.append(flow)
                changed = True
                self.log.debug('flow-added', flow=mod)

        else:
            idx = self.find_flow(flows, flow)
            if idx >= 0:
                old_flow = flows[idx]
                if not (mod.flags & ofp.OFPFF_RESET_COUNTS):
                    flow.byte_count = old_flow.byte_count
                    flow.packet_count = old_flow.packet_count
                flows[idx] = flow
                changed = updated = True
                self.log.debug('flow-updated')

            else:
                flows.append(flow)
                changed = True
                self.log.debug('flow-added')

        # write back to model
        if changed:
            self.flows_proxy.update('/', Flows(items=flows))
            if not updated:
                self.update_flow_count_of_meter_stats(mod, flow)

    def update_flow_count_of_meter_stats(self, mod, flow):
        command = mod.command
        meter_id = get_meter_id_from_flow(flow)
        if meter_id is not None:
            try:
                meters = OrderedDict((m.config.meter_id, m)
                                     for m in self.meters_proxy.get('/').items)
                meter = meters[meter_id]
                if meter is not None:
                    if command == ofp.OFPFC_ADD:
                        meter.stats.flow_count += 1
                    elif command == ofp.OFPFC_DELETE_STRICT:
                        meter.stats.flow_count -= 1
                    self.meters_proxy.update('/', Meters(items=meters.values()))
                    self.log.debug("meters updated based on flow count stats",
                               meters=meters.values())
            except KeyError:
                self.log.warn("meter id is not found in meters", meter_id=meter_id)
                self._flow_with_unknown_meter[meter_id] = \
                    self._flow_with_unknown_meter.get(meter_id, 0) + 1


    def flow_delete(self, mod):
        assert isinstance(mod, (ofp.ofp_flow_mod, ofp.ofp_flow_stats))

        # read from model
        flows = list(self.flows_proxy.get('/').items)

        # build a list of what to keep vs what to delete
        to_keep = []
        to_delete = []
        for f in flows:
            if self.flow_matches_spec(f, mod):
                to_delete.append(f)
            else:
                to_keep.append(f)

        # replace flow table with keepers
        flows = to_keep

        # write back
        if to_delete:
            self.flows_proxy.update('/', Flows(items=flows))
            self.log.debug("flow deleted", mod=mod)

        # from mod send announcement
        if isinstance(mod, ofp.ofp_flow_mod):
            # send notifications for discarded flow as required by OpenFlow
            self.announce_flows_deleted(to_delete)

    def flow_delete_strict(self, mod):
        assert isinstance(mod, ofp.ofp_flow_mod)

        # read from model
        flows = list(self.flows_proxy.get('/').items)
        changed = False

        flow = flow_stats_entry_from_flow_mod_message(mod)
        idx = self.find_flow(flows, flow)
        if (idx >= 0):
            self.update_flow_count_of_meter_stats(mod, flows[idx])
            del flows[idx]
            changed = True
        else:
            # TODO need to check what to do with this case
            self.log.warn('flow-cannot-delete', flow=flow)

        if changed:
            self.flows_proxy.update('/', Flows(items=flows))
            self.log.debug("flow deleted strictly", mod=mod)
            if isinstance(mod, ofp.ofp_flow_mod):
                self.announce_flow_deleted(flow)

    def flow_modify(self, mod):
        raise NotImplementedError()

    def flow_modify_strict(self, mod):
        raise NotImplementedError()

    def find_overlapping_flows(self, flows, mod, return_on_first=False):
        """
        Return list of overlapping flow(s)
        Two flows overlap if a packet may match both and if they have the
        same priority.
        :param mod: Flow request
        :param return_on_first: if True, return with the first entry
        :return:
        """
        return []  # TODO finish implementation

    @classmethod
    def find_flow(cls, flows, flow):
        for i, f in enumerate(flows):
            if cls.flow_match(f, flow):
                return i
        return -1

    @staticmethod
    def flow_match(f1, f2):
        keys_matter = ('table_id', 'priority', 'flags', 'cookie', 'match')
        for key in keys_matter:
            if getattr(f1, key) != getattr(f2, key):
                return False
        return True

    @classmethod
    def flow_matches_spec(cls, flow, flow_mod):
        """
        Return True if given flow (ofp_flow_stats) is "covered" by the
        wildcard flow_mod (ofp_flow_mod), taking into consideration of
        both exact mactches as well as masks-based match fields if any.
        Otherwise return False
        :param flow: ofp_flow_stats
        :param mod: ofp_flow_mod
        :return: Bool
        """

        assert isinstance(flow, ofp.ofp_flow_stats)
        assert isinstance(flow_mod, (ofp.ofp_flow_mod, ofp.ofp_flow_stats))

        if isinstance(flow_mod, ofp.ofp_flow_stats):
            return cls.flow_match(flow, flow_mod)

        # Check if flow.cookie is covered by mod.cookie and mod.cookie_mask
        if (flow.cookie & flow_mod.cookie_mask) != \
                (flow_mod.cookie & flow_mod.cookie_mask):
            return False

        # Check if flow.table_id is covered by flow_mod.table_id
        if flow_mod.table_id != ofp.OFPTT_ALL and \
                        flow.table_id != flow_mod.table_id:
            return False

        # Check out_port
        if (flow_mod.out_port & 0x7fffffff) != ofp.OFPP_ANY and \
                not cls.flow_has_out_port(flow, flow_mod.out_port):
            return False

        # Check out_group
        if (flow_mod.out_group & 0x7fffffff) != ofp.OFPG_ANY and \
                not cls.flow_has_out_group(flow, flow_mod.out_group):
            return False
        # Priority is ignored

        # Check match condition
        # If the flow_mod match field is empty, that is a special case and
        # indicates the flow entry matches
        match = flow_mod.match
        assert isinstance(match, ofp.ofp_match)
        if not match.oxm_fields:
            # If we got this far and the match is empty in the flow spec,
            # than the flow matches
            return True
        else:
            raise NotImplementedError(
                "flow_matches_spec(): No flow match analysis yet")

    @staticmethod
    def flow_has_out_port(flow, out_port):
        """
        Return True if flow has a output command with the given out_port
        """
        assert isinstance(flow, ofp.ofp_flow_stats)
        for instruction in flow.instructions:
            assert isinstance(instruction, ofp.ofp_instruction)
            if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                for action in instruction.actions.actions:
                    assert isinstance(action, ofp.ofp_action)
                    if action.type == ofp.OFPAT_OUTPUT and \
                        action.output.port == out_port:
                        return True

        # otherwise...
        return False

    @staticmethod
    def flow_has_out_group(flow, group_id):
        """
        Return True if flow has a output command with the given out_group
        """
        assert isinstance(flow, ofp.ofp_flow_stats)
        for instruction in flow.instructions:
            assert isinstance(instruction, ofp.ofp_instruction)
            if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                for action in instruction.actions.actions:
                    assert isinstance(action, ofp.ofp_action)
                    if action.type == ofp.OFPAT_GROUP and \
                        action.group.group_id == group_id:
                            return True

        # otherwise...
        return False

    @staticmethod
    def flow_has_meter(flow, meter_id):
        assert isinstance(flow, ofp.ofp_flow_stats)
        for instruction in flow.instructions:
            if instruction.type == ofp.OFPIT_METER and \
               instruction.meter.meter_id == meter_id:
                    return True

        return False


    def flows_delete_by_group_id(self, flows, group_id):
        """
        Delete any flow(s) referring to given group_id
        :param group_id:
        :return: None
        """
        to_keep = []
        to_delete = []
        for f in flows:
            if self.flow_has_out_group(f, group_id):
                to_delete.append(f)
            else:
                to_keep.append(f)

        # replace flow table with keepers
        flows = to_keep

        # send notification to deleted ones
        self.announce_flows_deleted(to_delete, reason=ofp.OFPRR_GROUP_DELETE)

        return bool(to_delete), flows

    def flows_delete_by_meter_id(self, flows, meter_id):

        to_keep = []
        to_delete = []
        for f in flows:
            if self.flow_has_meter(f, meter_id):
                to_delete.append(f)
            else:
                to_keep.append(f)

        flows = to_keep
        # we cant use OFPRR_MELETE_DELETE for 1.3.x
        self.announce_flows_deleted(flows)
        return bool(to_delete), flows

    # ~~~~~~~~~~~~~~~~~~~~~ LOW LEVEL GROUP HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~~~~

    def group_add(self, group_mod):
        assert isinstance(group_mod, ofp.ofp_group_mod)

        groups = OrderedDict((g.desc.group_id, g)
                             for g in self.groups_proxy.get('/').items)
        changed = False

        if group_mod.group_id in groups:
            self.signal_group_mod_error(ofp.OFPGMFC_GROUP_EXISTS, group_mod)
        else:
            group_entry = group_entry_from_group_mod(group_mod)
            groups[group_mod.group_id] = group_entry
            changed = True

        if changed:
            self.groups_proxy.update('/', FlowGroups(items=groups.values()))

    def group_delete(self, group_mod):
        assert isinstance(group_mod, ofp.ofp_group_mod)

        groups = OrderedDict((g.desc.group_id, g)
                             for g in self.groups_proxy.get('/').items)
        groups_changed = False
        flows_changed = False

        group_id = group_mod.group_id
        if group_id == ofp.OFPG_ALL:
            # TODO we must delete all flows that point to this group and
            # signal controller as requested by flow's flag
            groups = OrderedDict()
            groups_changed = True
            self.log.debug('all-groups-deleted')

        else:
            if group_id not in groups:
                # per openflow spec, this is not an error
                pass

            else:
                flows = list(self.flows_proxy.get('/').items)
                flows_changed, flows = self.flows_delete_by_group_id(
                    flows, group_id)
                del groups[group_id]
                groups_changed = True
                self.log.debug('group-deleted', group_id=group_id)

        if groups_changed:
            self.groups_proxy.update('/', FlowGroups(items=groups.values()))
        if flows_changed:
            self.flows_proxy.update('/', Flows(items=flows))

    def group_modify(self, group_mod):
        assert isinstance(group_mod, ofp.ofp_group_mod)

        groups = OrderedDict((g.desc.group_id, g)
                             for g in self.groups_proxy.get('/').items)
        changed = False

        if group_mod.group_id not in groups:
            self.signal_group_mod_error(
                ofp.OFPGMFC_INVALID_GROUP, group_mod)
        else:
            # replace existing group entry with new group definition
            group_entry = group_entry_from_group_mod(group_mod)
            groups[group_mod.group_id] = group_entry
            changed = True

        if changed:
            self.groups_proxy.update('/', FlowGroups(items=groups.values()))

    def port_enable(self, port_id):
        self.log.info("port-enable", port_id=port_id)

        proxy = self.port_proxy[port_id]
        port = proxy.get('/')
        port.ofp_port.config = port.ofp_port.config & ~ofp.OFPPC_PORT_DOWN
        proxy.update('/', port)

    def port_disable(self, port_id):
        self.log.info("port-disable", port_id=port_id)

        proxy = self.port_proxy[port_id]
        port = proxy.get('/')
        port.ofp_port.config = port.ofp_port.config & ~ofp.OFPPC_PORT_DOWN | ofp.OFPPC_PORT_DOWN
        proxy.update('/', port)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ PACKET_OUT ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def packet_out(self, ofp_packet_out):
        self.log.debug('packet-out')
        topic = 'packet-out:{}'.format(self.logical_device_id)
        self.event_bus.publish(topic, ofp_packet_out)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ PACKET_IN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def handle_packet_in_event(self, _, msg):
        logical_port_no, packet = msg
        self.log.debug('handle-packet-in', logical_port_no=logical_port_no)
        packet_in = ofp.ofp_packet_in(
            # buffer_id=0,
            reason=ofp.OFPR_ACTION,
            # table_id=0,
            # cookie=0,
            match=ofp.ofp_match(
                type=ofp.OFPMT_OXM,
                oxm_fields=[
                    ofp.ofp_oxm_field(
                        oxm_class=ofp.OFPXMC_OPENFLOW_BASIC,
                        ofb_field=in_port(logical_port_no)
                    )
                ]
            ),
            data=packet
        )
        self.packet_in(packet_in)

    def packet_in(self, ofp_packet_in):
        # self.log.info('packet-in', logical_device_id=self.logical_device_id)
        # pkt=ofp_packet_in, data=hexify(ofp_packet_in.data))
        self.local_handler.send_packet_in(
            self.logical_device_id, ofp_packet_in)

    # ~~~~~~~~~~~~~~~~~~~~~ FLOW TABLE UPDATE HANDLING ~~~~~~~~~~~~~~~~~~~~~~~~

    def _pre_process_flows(self, flows):
        """
        This method is invoked before a device flow table data model is
        updated. The resulting data is stored locally and the flow table is
        updated during the post-processing phase, i.e. via the POST_UPDATE
        callback
        :param flows: Desired flows
        :return: None
        """
        current_flows = self.flows_proxy.get('/')
        # self.log.debug('pre-processing-flows',
        #                logical_device_id=self.logical_device_id,
        #                desired_flows=flows,
        #                existing_flows=current_flows)

        current_flow_ids = set(f.id for f in current_flows.items)
        desired_flow_ids = set(f.id for f in flows.items)

        self._flows_ids_to_add = desired_flow_ids.difference(current_flow_ids)
        self._flows_ids_to_remove = current_flow_ids.difference(desired_flow_ids)
        self._flows_to_remove = []
        for f in current_flows.items:
            if f.id in self._flows_ids_to_remove:
                self._flows_to_remove.append(f)

        if len(self._flows_ids_to_add) + len(self._flows_ids_to_remove) == 0:
            # No changes of flows, just stats are changing
            self._no_flow_changes_required = True
        else:
            self._no_flow_changes_required = False

        self.log.debug('flows-preprocess-output', current_flows=len(
            current_flow_ids), pre_process_notify_flows=len(desired_flow_ids),
                      adding_flows=len(self._flows_ids_to_add),
                      removing_flows=len(self._flows_ids_to_remove))


    def _flow_table_updated(self, flows):
        self.log.debug('flow-table-updated',
                       logical_device_id=self.logical_device_id)

        if self._no_flow_changes_required:
            # Stats changes, no need to process further
            self.log.debug('flow-stats-update')
        else:

            groups = self.groups_proxy.get('/').items
            device_rules_map = self.decompose_rules(flows.items, groups)

            # TODO we have to evolve this into a policy-based, event based pattern
            # This is a raw implementation of the specific use-case with certain
            # built-in assumptions, and not yet device vendor specific. The policy-
            # based refinement will be introduced that later.


            # Temporary bypass for openolt

            if self.accepts_direct_logical_flows:
                #give the logical flows directly to the adapter
                self.log.debug('it is an direct logical flow bypass')
                if self.device_adapter_agent is None:
                    self.log.error('No device adapter agent',
                                   device_id=self.device_id,
                                   logical_device_id = self.logical_device_id)
                    return

                flows_to_add = []
                for f in flows.items:
                    if f.id in self._flows_ids_to_add:
                        flows_to_add.append(f)


                self.log.debug('flows to remove',
                               flows_to_remove=self._flows_to_remove,
                               flows_ids=self._flows_ids_to_remove)

                try:
                    self.device_adapter_agent.update_logical_flows(
                        self.device_id, flows_to_add, self._flows_to_remove,
                        groups, device_rules_map)
                except Exception as e:
                    self.log.error('logical flows bypass error', error=e,
                                   flows=flows)
            else:

                for device_id, (flows, groups) in device_rules_map.iteritems():

                    self.root_proxy.update('/devices/{}/flows'.format(device_id),
                                           Flows(items=flows.values()))
                    self.root_proxy.update('/devices/{}/flow_groups'.format(device_id),
                                           FlowGroups(items=groups.values()))

    # ~~~~~~~~~~~~~~~~~~~~ GROUP TABLE UPDATE HANDLING ~~~~~~~~~~~~~~~~~~~~~~~~

    def _group_table_updated(self, flow_groups):
        self.log.debug('group-table-updated',
                  logical_device_id=self.logical_device_id,
                  flow_groups=flow_groups)

        flows = self.flows_proxy.get('/').items
        device_flows_map = self.decompose_rules(flows, flow_groups.items)
        for device_id, (flows, groups) in device_flows_map.iteritems():
            self.root_proxy.update('/devices/{}/flows'.format(device_id),
                                   Flows(items=flows.values()))
            self.root_proxy.update('/devices/{}/flow_groups'.format(device_id),
                                   FlowGroups(items=groups.values()))

    # ~~~~~~~~~~~~~~~~~~~ APIs NEEDED BY FLOW DECOMPOSER ~~~~~~~~~~~~~~~~~~~~~~

    def _port_added(self, port):
        self.log.debug('port-added', port=port)
        assert isinstance(port, LogicalPort)
        self._port_list_updated(port)

        # Set a proxy and callback for that specific port
        self.port_proxy[port.id] = self.core.get_proxy(
            '/logical_devices/{}/ports/{}'.format(self.logical_device_id,
                                                  port.id))
        self.port_status_has_changed[port.id] = True
        self.port_proxy[port.id].register_callback(
            CallbackType.PRE_UPDATE, self._pre_port_changed)
        self.port_proxy[port.id].register_callback(
            CallbackType.POST_UPDATE, self._port_changed)

        self.local_handler.send_port_change_event(
            device_id=self.logical_device_id,
            port_status=ofp.ofp_port_status(
                reason=ofp.OFPPR_ADD,
                desc=port.ofp_port
            )
        )

    def _reconcile_port(self, port):
        self.log.debug('reconcile-port', port=port)
        assert isinstance(port, LogicalPort)
        self._port_list_updated(port)

        # Set a proxy and callback for that specific port
        self.port_proxy[port.id] = self.core.get_proxy(
            '/logical_devices/{}/ports/{}'.format(self.logical_device_id,
                                                  port.id))
        self.port_status_has_changed[port.id] = True
        self.port_proxy[port.id].register_callback(
            CallbackType.PRE_UPDATE, self._pre_port_changed)
        self.port_proxy[port.id].register_callback(
            CallbackType.POST_UPDATE, self._port_changed)

    def _port_removed(self, port):
        self.log.debug('port-removed', port=port)
        assert isinstance(port, LogicalPort)
        self._port_list_updated(port)

        # Remove the proxy references
        self.port_proxy[port.id].unregister_callback(
            CallbackType.PRE_UPDATE, self._pre_port_changed)
        self.port_proxy[port.id].unregister_callback(
            CallbackType.POST_UPDATE, self._port_changed)
        del self.port_proxy[port.id]
        del self.port_status_has_changed[port.id]


        self.local_handler.send_port_change_event(
            device_id=self.logical_device_id,
            port_status=ofp.ofp_port_status(
                reason=ofp.OFPPR_DELETE,
                desc=port.ofp_port
            )
        )

    def _pre_port_changed(self, port):
        old_port = self.port_proxy[port.id].get('/')
        if old_port.ofp_port != port.ofp_port:
            self.port_status_has_changed[port.id] = True
        else :
            self.port_status_has_changed[port.id] = False

    def _port_changed(self, port):
        self.log.debug('port-changed', port=port)
        if self.port_status_has_changed[port.id]:
            assert isinstance(port, LogicalPort)
            self.local_handler.send_port_change_event(
                device_id=self.logical_device_id,
                port_status=ofp.ofp_port_status(
                    reason=ofp.OFPPR_MODIFY,
                    desc=port.ofp_port
                )
            )

    def _port_list_updated(self, _):
        # invalidate the graph and the route table
        self._invalidate_cached_tables()

    def _invalidate_cached_tables(self):
        self._routes = None
        self._default_rules = None
        self._nni_logical_port_no = None

    def _assure_cached_tables_up_to_date(self):
        if self._routes is None:
            logical_ports = self.self_proxy.get('/ports')
            graph, self._routes = self.compute_routes(
                self.root_proxy, logical_ports)
            self._default_rules = self._generate_default_rules(graph)
            root_ports = [p for p in logical_ports if p.root_port]
            assert len(root_ports) == 1, 'Only one root port supported at this time'
            self._nni_logical_port_no = root_ports[0].ofp_port.port_no


    def _generate_default_rules(self, graph):

        def root_device_default_rules(device):
            flows = OrderedDict()
            groups = OrderedDict()
            return flows, groups

        def leaf_device_default_rules(device):
            ports = self.root_proxy.get('/devices/{}/ports'.format(device.id))
            upstream_ports = [
                port for port in ports if port.type == Port.PON_ONU \
                                            or port.type == Port.VENET_ONU
            ]
            assert len(upstream_ports) == 1
            downstream_ports = [
                port for port in ports if port.type == Port.ETHERNET_UNI
            ]

            # it is possible that the downstream ports are not
            # created, but the flow_decomposition has already
            # kicked in. In such scenarios, cut short the processing
            # and return.
            if len(downstream_ports) == 0:
                return None, None
            # assert len(downstream_ports) == 1
            upstream_port  = upstream_ports[0]
            flows = OrderedDict()
            for downstream_port in downstream_ports:
                flows.update(OrderedDict((f.id, f) for f in [
                    mk_flow_stat(
                        priority=500,
                        match_fields=[
                            in_port(downstream_port.port_no),
                            vlan_vid(ofp.OFPVID_PRESENT | 0)
                        ],
                        actions=[
                            set_field(vlan_vid(ofp.OFPVID_PRESENT | device.vlan)),
                            output(upstream_port.port_no)
                        ]
                    ),
                    mk_flow_stat(
                        priority=500,
                        match_fields=[
                            in_port(downstream_port.port_no),
                            vlan_vid(0)
                        ],
                        actions=[
                            push_vlan(0x8100),
                            set_field(vlan_vid(ofp.OFPVID_PRESENT | device.vlan)),
                            output(upstream_port.port_no)
                        ]
                    ),
                    mk_flow_stat(
                        priority=500,
                        match_fields=[
                            in_port(upstream_port.port_no),
                            vlan_vid(ofp.OFPVID_PRESENT | device.vlan)
                        ],
                        actions=[
                            set_field(vlan_vid(ofp.OFPVID_PRESENT | 0)),
                            output(downstream_port.port_no)
                        ]
                    ),
                ]))
            groups = OrderedDict()
            return flows, groups

        root_device_id = self.self_proxy.get('/').root_device_id
        rules = {}
        for node_key in graph.nodes():
            node = graph.node[node_key]
            device = node.get('device', None)
            if device is None:
                continue
            if device.id == root_device_id:
                rules[device.id] = root_device_default_rules(device)
            else:
                rules[device.id] = leaf_device_default_rules(device)
        return rules

    def get_route(self, ingress_port_no, egress_port_no):
        """
        Returns the ingress and egress devices corresponding to the ingress_port_no
        and egress_port.
        If egress_port_no is CONTROLLER the egress device is always the OLT, while
        the ingress device depends on if the ingress_port_no is UNI or NNI.
        If egress_port_no is not specified, a half route is returned with only
        the ingress device specified.
        """
        self._assure_cached_tables_up_to_date()
        self.log.info('getting-route', eg_port=egress_port_no, in_port=ingress_port_no,
                      nni_port=self._nni_logical_port_no)
        if egress_port_no is not None and \
                (egress_port_no & 0x7fffffff) == ofp.OFPP_CONTROLLER:
            self.log.info('controller-flow', eg_port=egress_port_no,
                          in_port=ingress_port_no,
                          nni_port=self._nni_logical_port_no)
            if ingress_port_no == self._nni_logical_port_no:
                root_device_ports = self.root_proxy.get('/devices/{}/ports'.
                                                        format(self.self_proxy.
                                                        get('/').root_device_id)
                                                        )
                root_device = self.root_proxy.get('/devices/{}'.
                                                   format(self.self_proxy.
                                                   get('/').root_device_id)
                                                   )
                for port in root_device_ports:
                    if port.type == Port.ETHERNET_NNI:
                        ingress_hop = RouteHop(root_device, port.port_no, port.port_no)
                        egress_hop = ingress_hop
                        return [ingress_hop, egress_hop]
                return None

            egress_port_no = self._nni_logical_port_no

        # If ingress_port is not specified (None), it may be a wildcarded
        # route if egress_port is OFPP_CONTROLLER or _nni_logical_port,
        # in which case we need to create a half-route where only the egress
        # hop is filled, the first hope is None
        if ingress_port_no is None and \
                        egress_port_no == self._nni_logical_port_no:
            # We can use the 2nd hop of any upstream route, so just find the
            # first upstream:
            for (ingress, egress), route in self._routes.iteritems():
                if egress == self._nni_logical_port_no:
                    return [None, route[1]]
            raise Exception('not a single upstream route')

        # If egress_port is not specified (None), we can also can return a
        # "half" route
        if egress_port_no is None:
            for (ingress, egress), route in self._routes.iteritems():
                if ingress == ingress_port_no:
                    return [route[0], None]

            # This can occur is a leaf device is disabled
            self.log.exception('no-downstream-route',
                               ingress_port_no=ingress_port_no,
                               egress_port_no=egress_port_no)
            return None

        return self._routes.get((ingress_port_no, egress_port_no))

    def get_all_default_rules(self):
        self._assure_cached_tables_up_to_date()
        return self._default_rules

    def get_wildcard_input_ports(self, exclude_port=None):
        logical_ports = self.self_proxy.get('/ports')
        return [port.ofp_port.port_no for port in logical_ports
                if port.ofp_port.port_no != exclude_port]
