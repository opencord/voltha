#
# Copyright 2016 the original author or authors.
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
import structlog

from voltha.protos import openflow_13_pb2 as ofp
from voltha.protos import voltha_pb2

log = structlog.get_logger()


def mac_str_to_tuple(mac):
    return tuple(int(d, 16) for d in mac.split(':'))


def flow_stats_entry_from_flow_mod_message(mod):
    flow = ofp.ofp_flow_stats(
        table_id=mod.table_id,
        priority=mod.priority,
        idle_timeout=mod.idle_timeout,
        hard_timeout=mod.hard_timeout,
        flags=mod.flags,
        cookie=mod.cookie,
        match=mod.match,
        instructions=mod.instructions
    )
    return flow


def group_entry_from_group_mod(mod):
    group = ofp.ofp_group_entry(
        desc=ofp.ofp_group_desc(
            type=mod.type,
            group_id=mod.group_id,
            buckets=mod.buckets
        ),
        stats=ofp.ofp_group_stats(
            group_id=mod.group_id
            # TODO do we need to instantiate bucket bins?
        )
    )
    return group


class DeviceModel(object):

    def __init__(self, tmp_id):
        self.info = voltha_pb2.LogicalDeviceDetails(
            id=str(tmp_id),
            datapath_id=tmp_id,
            desc=ofp.ofp_desc(
                mfr_desc="CORD/Voltha",
                hw_desc="Synthetized/logical device",
                sw_desc="Voltha 1.0",
                serial_num="1000219910",
                dp_desc="A logical device. Use the TBD API to learn more"
            ),
            switch_features=ofp.ofp_switch_features(
                n_buffers=256, # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    ofp.OFPC_FLOW_STATS
                    | ofp.OFPC_TABLE_STATS
                    | ofp.OFPC_PORT_STATS
                    | ofp.OFPC_GROUP_STATS
                )
            )
        )

        cap = ofp.OFPPF_1GB_FD | ofp.OFPPF_FIBER
        self.ports = [ofp.ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name=name,
                config=0,
                state=ofp.OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=ofp.OFPPF_1GB_FD,
                max_speed=ofp.OFPPF_1GB_FD
            ) for port_no, name in [(1, 'onu1'), (2, 'onu2'), (129, 'olt1')]]

        self.flows = []
        self.groups = {}

    def announce_flows_deleted(self, flows):
        for f in flows:
            self.announce_flow_deleted(f)

    def announce_flow_deleted(self, flow):
        if flow.flags & ofp.OFPFF_SEND_FLOW_REM:
            raise NotImplementedError("announce_flow_deleted")

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
            log.warn('unhandled-flow-mod', command=command, flow_mod=flow_mod)

    def list_flows(self):
        return self.flows

    def update_group_table(self, group_mod):

        command = group_mod.command

        if command == ofp.OFPGC_DELETE:
            self.group_delete(group_mod)

        elif command == ofp.OFPGC_ADD:
            self.group_add(group_mod)

        elif command == ofp.OFPGC_MODIFY:
            self.group_modify(group_mod)

        else:
            log.warn('unhandled-group-mod', command=command,
                     group_mod=group_mod)

    def list_groups(self):
        return self.groups.values()

    ## <=============== LOW LEVEL FLOW HANDLERS ==============================>

    def flow_add(self, mod):
        assert isinstance(mod, ofp.ofp_flow_mod)
        assert mod.cookie_mask == 0

        check_overlap = mod.flags & ofp.OFPFF_CHECK_OVERLAP
        if check_overlap:
            if self.find_overlapping_flows(mod, True):
                self.signal_flow_mod_error(
                    ofp.OFPFMFC_OVERLAP, mod)
            else:
                # free to add as new flow
                flow = flow_stats_entry_from_flow_mod_message(mod)
                self.flows.append(flow)

        else:
            flow = flow_stats_entry_from_flow_mod_message(mod)
            idx = self.find_flow(flow)
            if idx >= 0:
                old_flow = self.flows[idx]
                if not (mod.flags & ofp.OFPFF_RESET_COUNTS):
                    flow.byte_count = old_flow.byte_count
                    flow.packet_count = old_flow.packet_count
                self.flows[idx] = flow

            else:
                self.flows.append(flow)

    def flow_delete(self, mod):
        assert isinstance(mod, ofp.ofp_flow_mod)

        # build a list of what to keep vs what to delete
        to_keep = []
        to_delete = []
        for f in self.flows:
            if self.flow_matches_spec(f, mod):
                to_delete.append(f)
            else:
                to_keep.append(f)

        # replace flow table with keepers
        self.flows = to_keep

        # send notifications for discarded flow as required by OpenFlow
        self.announce_flows_deleted(to_delete)

    def flow_delete_strict(self, mod):
        raise NotImplementedError()

    def flow_modify(self, mod):
        raise NotImplementedError()

    def flow_modify_strict(self, mod):
        raise NotImplementedError()

    def find_overlapping_flows(self, mod, return_on_first=False):
        """
        Return list of overlapping flow(s)
        Two flows overlap if a packet may match both and if they have the
        same priority.
        :param mod: Flow request
        :param return_on_first: if True, return with the first entry
        :return:
        """
        return []  # TODO finish implementation

    def find_flow(self, flow):
        for i, f in enumerate(self.flows):
            if self.flow_match(f, flow):
                return i
        return -1

    def flow_match(self, f1, f2):
        keys_matter = ('table_id', 'priority', 'flags', 'cookie', 'match')
        for key in keys_matter:
            if getattr(f1, key) != getattr(f2, key):
                return False
        return True

    def flow_matches_spec(self, flow, flow_mod):
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
        assert isinstance(flow_mod, ofp.ofp_flow_mod)

        # Check if flow.cookie is covered by mod.cookie and mod.cookie_mask
        if (flow.cookie & flow_mod.cookie_mask) != \
                (flow_mod.cookie & flow_mod.cookie_mask):
            return False

        # Check if flow.table_id is covered by flow_mod.table_id
        if flow_mod.table_id != ofp.OFPTT_ALL and \
                        flow.table_id != flow_mod.table_id:
            return False

        # Check out_port
        if flow_mod.out_port != ofp.OFPP_ANY and \
                not self.flow_has_out_port(flow, flow_mod.out_port):
            return False

        # Check out_group
        if flow_mod.out_group != ofp.OFPG_ANY and \
                not self.flow_has_out_group(flow, flow_mod.out_group):
            return False

        # Priority is ignored

        # Check match condition
        # If the flow_mod match field is empty, that is a special case and
        # indicates the flow entry matches
        match = flow_mod.match
        assert isinstance(match, ofp.ofp_match)
        if not match.oxm_list:
            # If we got this far and the match is empty in the flow spec,
            # than the flow matches
            return True
        else:
            raise NotImplementedError(
                "flow_matches_spec(): No flow match analysis yet")

    def flow_has_out_port(self, flow, out_port):
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

    def flow_has_out_group(self, flow, group_id):
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

    def flows_delete_by_group_id(self, group_id):
        """
        Delete any flow(s) referring to given group_id
        :param group_id:
        :return: None
        """
        to_keep = []
        to_delete = []
        for f in self.flows:
            if self.flow_has_out_group(f, group_id):
                to_delete.append(f)
            else:
                to_keep.append(f)

        # replace flow table with keepers
        self.flows = to_keep

        # send notification to deleted ones
        self.announce_flows_deleted(to_delete)

    ## <=============== LOW LEVEL GROUP HANDLERS =============================>

    def group_add(self, group_mod):
        assert isinstance(group_mod, ofp.ofp_group_mod)
        if group_mod.group_id in self.groups:
            self.signal_group_mod_error(ofp.OFPGMFC_GROUP_EXISTS, group_mod)
        else:
            group_entry = group_entry_from_group_mod(group_mod)
            self.groups[group_mod.group_id] = group_entry

    def group_delete(self, group_mod):
        assert isinstance(group_mod, ofp.ofp_group_mod)
        group_id = group_mod.group_id
        if group_id == ofp.OFPG_ALL:
            # TODO we must delete all flows that point to this group and
            # signal controller as requested by flow's flag
            self.groups = {}
            log.debug('all-groups-deleted')

        else:
            if group_id not in self.groups:
                # per openflow spec, this is not an error
                pass

            else:
                self.flows_delete_by_group_id(group_id)
                del self.groups[group_id]
                log.debug('group-deleted', group_id=group_id)

    def group_modify(self, group_mod):
        assert isinstance(group_mod, ofp.ofp_group_mod)
        if group_mod.group_id not in self.groups:
            self.signal_group_mod_error(
                ofp.OFPGMFC_INVALID_GROUP, group_mod)
        else:
            # replace existing group entry with new group definition
            group_entry = group_entry_from_group_mod(group_mod)
            self.groups[group_mod.group_id] = group_entry
