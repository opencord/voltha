# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Internal state of the device
"""

import logging
from ofagent.utils import pp
import loxi.of13 as ofp


class GroupEntry(object):
    def __init__(self, group_desc, group_stats):
        assert isinstance(group_desc, ofp.group_desc_stats_entry)
        assert isinstance(group_stats, ofp.group_stats_entry)
        self.group_desc = group_desc
        self.group_stats = group_stats


def flow_stats_entry_from_flow_mod_message(fmm):
    assert isinstance(fmm, ofp.message.flow_mod)

    # extract a flow stats entry from a flow_mod message
    kw = fmm.__dict__

    # drop these from the object
    for k in ('xid', 'cookie_mask', 'out_port', 'buffer_id', 'out_group'):
        del kw[k]
    flow = ofp.flow_stats_entry(
        duration_sec=0,
        duration_nsec=0,
        packet_count=0,
        byte_count=0,
        **kw
    )
    return flow

def group_entry_from_group_mod_message(gmm):
    assert isinstance(gmm, ofp.message.group_mod)

    kw = gmm.__dict__

    # drop these attributes from the object:
    for k in ('xid',):
        del kw[k]

    group_desc = ofp.group_desc_stats_entry(
        group_type=gmm.group_type,
        group_id=gmm.group_id,
        buckets=gmm.buckets
    )

    group_stats = ofp.group_stats_entry(
        group_id=gmm.group_id
    )

    return GroupEntry(group_desc, group_stats)


class ObjectStore(object):

    def __init__(self):
        self.ports = []  # list of ofp.common.port_desc
        self.flows = []  # list of ofp.common.flow_stats_entry
        self.groups = {} # dict of (ofp.group_desc_stats_entry, ofp.group_stats_entry) tuples,
                         # keyed by the group_id field
        self.agent = None

    def set_agent(self, agent):
        """Set agent reference"""
        self.agent = agent

    def signal_flow_mod_error(self, code, flow_mod):
        """Forward error to agent"""
        if self.agent is not None:
            agent.signal_flow_mod_error(code, flow_mod)

    def signal_flow_removal(self, flow):
        """Forward flow removal notification to agent"""
        if self.agent is not None:
            agent.signal_flow_removal(flow)

    def signal_group_mod_error(self, code, group_mod):
        if self.agent is not None:
            agent.signal_group_mod_error(code, group_mod)

    ## <=========================== PORT HANDLERS ==================================>

    def port_list(self):
        return self.ports

    def port_add(self, port):
        self.ports.append(port)

    def port_stats(self):
        logging.warn("port_stats() not yet implemented")
        return []

    ## <=========================== FLOW HANDLERS ==================================>

    def flow_add(self, flow_add):
        assert isinstance(flow_add, ofp.message.flow_add)
        assert flow_add.cookie_mask == 0

        check_overlap = flow_add.flags & ofp.OFPFF_CHECK_OVERLAP
        if check_overlap:
            if self._flow_find_overlapping_flows(flow_add, return_on_first_hit=True):
                self.signal_flow_mod_error(ofp.OFPFMFC_OVERLAP, flow_add)
            else:
                # free to add as new flow
                flow = flow_stats_entry_from_flow_mod_message(flow_add)
                self.flows.append(flow)

        else:
            flow = flow_stats_entry_from_flow_mod_message(flow_add)
            idx = self._flow_find(flow)
            if idx >= 0:
                old_flow = self.flows[idx]
                assert isinstance(old_flow, ofp.common.flow_stats_entry)
                if not (flow_add.flags & ofp.OFPFF_RESET_COUNTS):
                    flow.byte_count = old_flow.byte_count
                    flow.packet_count = old_flow.packet_count
                self.flows[idx] = flow

            else:
                self.flows.append(flow)

    def flow_delete_strict(self, flow_delete_strict):
        assert isinstance(flow_delete_strict, ofp.message.flow_delete_strict)
        flow = flow_stats_entry_from_flow_mod_message(flow_delete_strict)
        idx = self._flow_find(flow)
        if (idx >= 0):
            del self.flows[idx]
            logging.info("flow removed:\n%s" % pp(flow))
        else:
            logging.error('Requesting strict delete of:\n%s\nwhen flow table is:\n\n' % pp(flow))
            for f in self.flows:
                print pp(f)

    def flow_delete(self, flow_delete):
        assert isinstance(flow_delete, ofp.message.flow_delete)

        # build a list of what to keep vs what to delete
        to_keep = []
        to_delete = []
        for f in self.flows:
            list_to_append = to_delete if self._flow_matches_spec(f, flow_delete) else to_keep
            list_to_append.append(f)

        # replace flow table with keepers
        self.flows = to_keep

        # send notifications for discarded flows as required by OF spec
        self._announce_flows_deleted(to_delete)

    def flow_modify_strict(self, flow_obj):
        raise Exception("flow_modify_strict(): Not implemented yet")

    def flow_modify(self, flow_obj):
        raise Exception("flow_modify(): Not implemented yet")

    def flow_list(self):
        return self.flows

    def _flow_find_overlapping_flows(self, flow_mod, return_on_first_hit=False):
        """
        Return list of overlapping flow(s)
        Two flows overlap if a packet may match both and if they have the same priority.
        """

    def _flow_find(self, flow):
        for i, f in enumerate(self.flows):
            if self._flows_match(f, flow):
                return i
        return -1

    def _flows_match(self, f1, f2):
        keys_matter = ('table_id', 'priority', 'flags', 'cookie', 'match')
        for key in keys_matter:
            if getattr(f1, key) != getattr(f2, key):
                return False
        return True

    def _flow_matches_spec(self, flow, flow_mod):
        """
        Return True if a given flow (flow_stats_entry) is "covered" by the wildcarded flow
        mod or delete spec (as defined in the flow_mod or flow_delete message); otherwise
        return False.
        """
        #import pdb
        #pdb.set_trace()

        assert isinstance(flow, ofp.common.flow_stats_entry)
        assert isinstance(flow_mod, (ofp.message.flow_delete, ofp.message.flow_mod))

        # Check if flow.cookie is a match for flow_mod cookie/cookie_mask
        if (flow.cookie & flow_mod.cookie_mask) != (flow_mod.cookie & flow_mod.cookie_mask):
            return False

        # Check if flow.table_id is covered by flow_mod.table_id
        if flow_mod.table_id != ofp.OFPTT_ALL and flow.table_id != flow_mod.table_id:
            return False

        # Check out_port
        if flow_mod.out_port != ofp.OFPP_ANY and not self._flow_has_out_port(flow, flow_mod.out_port):
            return False

        # Check out_group
        if flow_mod.out_group != ofp.OFPG_ANY and not self._flow_has_out_group(flow, flow_mod.out_group):
            return False

        # Priority is ignored

        # Check match condition
        # If the flow_mod match field is empty, that is a special case and indicate the flow entry matches
        match = flow_mod.match
        assert isinstance(match, ofp.common.match_v3)
        if not match.oxm_list:
            return True # If we got this far and the match is empty in the flow spec, than the flow matches
        else:
            raise NotImplementedError("_flow_matches_spec(): No flow match analysys yet")

    def _flow_has_out_port(self, flow, out_port):
        """Return True if flow has a output command with the given out_port"""
        assert isinstance(flow, ofp.common.flow_stats_entry)
        for instruction in flow.instructions:
            assert isinstance(instruction, ofp.instruction.instruction)
            if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                assert isinstance(instruction, ofp.instruction.apply_actions)
                for action in instruction.actions:
                    assert isinstance(action, ofp.action.action)
                    if action.type == ofp.OFPAT_OUTPUT:
                        assert isinstance(action, ofp.action.output)
                        if action.port == out_port:
                            return True

        # otherwise...
        return False

    def _flow_has_out_group(self, flow, out_group):
        """Return True if flow has a output command with the given out_group"""
        assert isinstance(flow, ofp.common.flow_stats_entry)
        for instruction in flow.instructions:
            assert isinstance(instruction, ofp.instruction.instruction)
            if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                assert isinstance(instruction, ofp.instruction.apply_actions)
                for action in instruction.actions:
                    assert isinstance(action, ofp.action.action)
                    if action.type == ofp.OFPAT_GROUP:
                        assert isinstance(action, ofp.action.group)
                        if action.group_id == out_group:
                            return True

        # otherwise...
        return False

    def _flows_delete_by_group_id(self, group_id):
        """Delete any flow referring to given group id"""
        to_keep = []
        to_delete = []
        for f in self.flows:
            list_to_append = to_delete if self._flow_has_out_group(f, group_id) else to_keep
            list_to_append.append(f)

        # replace flow table with keepers
        self.flows = to_keep

        # send notifications for discarded flows as required by OF spec
        self._announce_flows_deleted(to_delete)

    def _announce_flows_deleted(self, flows):
        for f in flows:
            self._announce_flow_deleted(f)

    def _announce_flow_deleted(self, flow):
        """Send notification to controller if flow is flagged with OFPFF_SEND_FLOW_REM flag"""
        if flow.flags & ofp.OFPFF_SEND_FLOW_REM:
            raise NotImplementedError("_announce_flow_deleted()")


    ## <=========================== GROUP HANDLERS =================================>

    def group_add(self, group_add):
        assert isinstance(group_add, ofp.message.group_add)
        if group_add.group_id in self.groups:
            self.signal_group_mod_error(ofp.OFPGMFC_GROUP_EXISTS, group_add)
        else:
            group_entry = group_entry_from_group_mod_message(group_add)
            self.groups[group_add.group_id] = group_entry

    def group_modify(self, group_modify):
        assert isinstance(group_modify, ofp.message.group_modify)
        if group_modify.group_id not in self.groups:
            self.signal_group_mod_error(ofp.OFPGMFC_INVALID_GROUP, group_modify)
        else:
            # replace existing group entry with new group definition
            group_entry = group_entry_from_group_mod_message(group_modify)
            self.groups[group_modify.group_id] = group_entry

    def group_delete(self, group_delete):
        assert isinstance(group_delete, ofp.message.group_mod)
        if group_delete.group_id == ofp.OFPG_ALL:  # drop all groups
            # we must delete all flows that point to this group and signal controller as
            # requested by the flows' flag

            self.groups = {}
            logging.info("all groups deleted")

        else:
            if group_delete.group_id not in self.groups:
                # per the spec, this is silent;y ignored
                return

            else:
                self._flows_delete_by_group_id(group_delete.group_id)
                del self.groups[group_delete.group_id]
                logging.info("group %d deleted" % group_delete.group_id)

    def group_list(self):
        return [group_entry.group_desc for group_entry in self.groups.values()]

    def group_stats(self):
        return [group_entry.group_stats for group_entry in self.groups.values()]

    ## <=========================== TABLE HANDLERS =================================>

    def table_stats(self):
        """Scan through flow entries and create table stats"""
        stats = {}
        for flow in self.flows:
            table_id = flow.table_id
            entry = stats.setdefault(table_id, ofp.common.table_stats_entry(table_id))
            entry.active_count += 1
            entry.lookup_count += 1  # FIXME how to count these?
            entry.matched_count += 1  # FIXME how to count these?
            stats[table_id] = entry
        return sorted(stats.values(), key=lambda e: e.table_id)
