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

from voltha.protos import openflow_13_pb2
from voltha.protos import voltha_pb2

log = structlog.get_logger()


def mac_str_to_tuple(mac):
    return tuple(int(d, 16) for d in mac.split(':'))


def flow_stats_entry_from_flow_mod_message(mod):
    flow = openflow_13_pb2.ofp_flow_stats(
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


class DeviceModel(object):

    def __init__(self, _):
        self.info = voltha_pb2.LogicalDeviceDetails(
            id='asdfa-1234124-asfd-949',
            datapath_id=1919191919191919,
            desc=openflow_13_pb2.ofp_desc(
                mfr_desc="CORD/Voltha",
                hw_desc="Synthetized/logical device",
                sw_desc="Voltha 1.0",
                serial_num="1000219910",
                dp_desc="A logical device. Use the TBD API to learn more"
            ),
            switch_features=openflow_13_pb2.ofp_switch_features(
                n_buffers=256, # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    openflow_13_pb2.OFPC_FLOW_STATS
                    | openflow_13_pb2.OFPC_TABLE_STATS
                    | openflow_13_pb2.OFPC_PORT_STATS
                    | openflow_13_pb2.OFPC_GROUP_STATS
                )
            )
        )

        cap = openflow_13_pb2.OFPPF_1GB_FD | openflow_13_pb2.OFPPF_FIBER
        self.ports = [openflow_13_pb2.ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name=name,
                config=0,
                state=openflow_13_pb2.OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=openflow_13_pb2.OFPPF_1GB_FD,
                max_speed=openflow_13_pb2.OFPPF_1GB_FD
            ) for port_no, name in [(1, 'onu1'), (2, 'onu2'), (129, 'olt1')]]

        self.flows = []
        self.groups = []

    def update_flow_table(self, flow_mod):

        command = flow_mod.command

        if command == openflow_13_pb2.OFPFC_ADD:
            self.flow_add(flow_mod)

        elif command == openflow_13_pb2.OFPFC_DELETE:
            self.flow_delete(flow_mod)

        elif command == openflow_13_pb2.OFPFC_DELETE_STRICT:
            self.flow_delete_strict(flow_mod)

        elif command == openflow_13_pb2.OFPFC_MODIFY:
            self.flow_modify(flow_mod)

        elif command == openflow_13_pb2.OFPFC_MODIFY_STRICT:
            self.flow_modify_strict(flow_mod)

        else:
            log.warn('unhandled-flow-mod', command=command, flow_mod=flow_mod)

    def list_flows(self):
        return self.flows

    ## <===============LOW LEVEL FLOW HANDLERS ===============================>

    def flow_add(self, mod):
        assert isinstance(mod, openflow_13_pb2.ofp_flow_mod)
        assert mod.cookie_mask == 0

        check_overlap = mod.flags & openflow_13_pb2.OFPFF_CHECK_OVERLAP
        if check_overlap:
            if self.find_overlapping_flows(mod, True):
                self.signal_flow_mod_error(
                    openflow_13_pb2.OFPFMFC_OVERLAP, mod)
            else:
                # free to add as new flow
                flow = flow_stats_entry_from_flow_mod_message(mod)
                self.flows.append(flow)

        else:
            flow = flow_stats_entry_from_flow_mod_message(mod)
            idx = self.find_flow(flow)
            if idx >= 0:
                old_flow = self.flows[idx]
                if not (mod.flags & openflow_13_pb2.OFPFF_RESET_COUNTS):
                    flow.byte_count = old_flow.byte_count
                    flow.packet_count = old_flow.packet_count
                self.flows[idx] = flow

            else:
                self.flows.append(flow)

    def flow_delete(self, mod):
        raise NotImplementedError()

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
        # TODO finish implementation
        return []

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
